"""
Sonnet-based deep scanning phase.

Layer 3 of the four-layer funnel. Sends code to Claude Sonnet
for security analysis. Scan depth varies by triage score:
- Score 4-5: full function-level analysis
- Score 2-3: only functions on taint paths
- Score 1 (spot-check sample): full analysis
"""

from mantis.engage.phases import Phase
from mantis.core.llm_client import AsyncLLMClient
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource
from mantis.config import load_config, get_api_key, get_model
import json


class DeepScanner:
    """Sonnet-powered source code security scanner."""

    def __init__(self, llm: AsyncLLMClient):
        self.llm = llm

    async def scan_file(self, file_path: str, depth: str = "full",
                        content: str = None) -> list[Finding]:
        """
        Scan a single file for security vulnerabilities.

        Args:
            file_path: Path to the source file
            depth: "full" (all functions), "taint_only", or "spot_check"
            content: File content (if already loaded)
        """
        if content is None:
            try:
                with open(file_path, "r", errors="replace") as f:
                    content = f.read()
            except Exception:
                return []

        # Truncate very large files
        if len(content) > 50000:
            content = content[:50000] + "\n\n... [TRUNCATED — file exceeds 50KB]"

        prompt = f"""You are an expert security code reviewer. Analyze this source code for security vulnerabilities.

FILE: {file_path}
SCAN DEPTH: {depth}

SOURCE CODE:
```
{content}
```

For each vulnerability found, provide:
1. Title (concise description)
2. Severity (critical/high/medium/low)
3. Line number(s)
4. Vulnerability type (SQLi, XSS, SSTI, Command Injection, Path Traversal, etc.)
5. CWE ID
6. Description of the vulnerability
7. Impact if exploited
8. Remediation recommendation
9. Confidence (0.0-1.0)

Respond ONLY with JSON array:
[
  {{
    "title": "...",
    "severity": "high",
    "line": 42,
    "vuln_type": "SQLi",
    "cwe": "CWE-89",
    "description": "...",
    "impact": "...",
    "remediation": "...",
    "confidence": 0.8
  }}
]

If no vulnerabilities found, respond with empty array: []
"""

        try:
            resp = await self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=4096,
            )

            # Parse response
            text = resp.content.strip()
            # Handle markdown code blocks
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                if text.endswith("```"):
                    text = text[:-3]
            data = json.loads(text)

            findings = []
            for item in data:
                findings.append(Finding(
                    title=item.get("title", ""),
                    description=item.get("description", ""),
                    source=FindingSource.CODE_REVIEW,
                    severity=Severity(item.get("severity", "medium")),
                    evidence_level=EvidenceLevel.STATIC_CORROBORATION,
                    file_path=file_path,
                    line_number=item.get("line"),
                    vuln_type=item.get("vuln_type", ""),
                    cwe=item.get("cwe"),
                    impact=item.get("impact", ""),
                    remediation=item.get("remediation", ""),
                    confidence=item.get("confidence", 0.5),
                ))
            return findings

        except (json.JSONDecodeError, Exception):
            return []


class DeepScanPhase(Phase):
    """Phase: deep scan source files using Claude Sonnet."""

    async def execute(self, context) -> dict:
        if not context.source_files:
            print("    No source files to scan")
            return {}

        config = load_config()
        api_key = get_api_key(config)
        model = get_model(config, "scanner")

        if not api_key:
            print("    No API key configured — skipping deep scan")
            return {}

        llm = AsyncLLMClient(api_key=api_key, model=model)
        scanner = DeepScanner(llm)

        findings = []
        # Scan files with static hits first (higher priority)
        prioritized = sorted(context.source_files,
                             key=lambda f: len(f.get("static_hits", "")),
                             reverse=True)

        scan_count = min(len(prioritized), 50)  # Cap at 50 files per run
        for i, file_meta in enumerate(prioritized[:scan_count]):
            filepath = file_meta.get("full_path", "")
            print(f"    [{i+1}/{scan_count}] Scanning {file_meta['path']}...")
            file_findings = await scanner.scan_file(filepath)
            findings.extend(file_findings)

        await llm.close()
        print(f"    Deep scan complete: {len(findings)} findings in {scan_count} files")
        return {"findings": findings}
