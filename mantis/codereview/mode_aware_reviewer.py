"""
Mode-aware code review — Mode 1/2/3 differentiation for source code analysis.

The base four-layer funnel (Preprocess → Static → Triage → Sonnet → Verify) is
the same. Modes differ in HOW MUCH AI involvement at each layer:

Mode 1 (Smart): Standard funnel.
  - Triage: Haiku scores files based on metadata only
  - Deep scan: Sonnet scans only files scoring 4+
  - Verify: Opus verifies findings
  - Variant hunter: 1 iteration

Mode 2 (Investigative): Funnel + spot-checking + cross-file analysis.
  - Spot-check ratio increased from 20% to 40% (catches more in score-1 files)
  - Sonnet ALSO scans files scoring 3 (broader coverage)
  - For each finding, asks Sonnet to look for related code in other files
  - Variant hunter: 2 iterations

Mode 3 (Deep): Full AI ownership of the review.
  - AI builds a "system understanding" — what the app does, its architecture
  - AI directs which files to scan in what order based on understanding
  - Sonnet scans ALL files with non-zero static hits OR scoring 2+
  - For each Critical/High finding, AI traces data flow across files via callgraph
  - Variant hunter: 3 iterations
  - Opus verifies + AI does cross-finding chaining analysis
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Optional

from mantis.core.scan_modes import ScanDepth, MODE_CONFIGS
from mantis.core.llm_client import AsyncLLMClient
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource
from mantis.config import load_config, get_api_key, get_model
from mantis.utils.verbose import log


@dataclass
class CodeReviewReport:
    mode: str
    findings: list = field(default_factory=list)
    files_total: int = 0
    files_triaged: int = 0
    files_deep_scanned: int = 0
    files_spot_checked: int = 0
    findings_verified: int = 0
    findings_false_positive: int = 0
    variants_found: int = 0
    ai_triage_calls: int = 0
    ai_scan_calls: int = 0
    ai_verify_calls: int = 0


class CodeReviewSystemAnalyst:
    """
    Mode 3 — AI builds a system-level understanding of the codebase
    before scanning any files. Determines architecture, entry points,
    auth model, data flows.
    """

    def __init__(self, llm: AsyncLLMClient):
        self.llm = llm

    async def analyze_codebase(self, file_metadata: list[dict]) -> dict:
        """
        Returns a structured understanding of the codebase:
        {
          'app_purpose': 'what this app does',
          'architecture': 'monolith|microservices|...',
          'language': 'python|java|...',
          'entry_points': ['file1.py', 'controllers/users.py'],
          'auth_files': ['auth/login.py'],
          'high_value_files': ['file paths the AI considers high-priority'],
          'data_stores': ['database', 'redis', 's3'],
          'frameworks': ['django', 'flask', ...],
        }
        """
        # Summarize file metadata compactly
        sample = file_metadata[:80]  # cap for token budget
        files_summary = [
            {"path": f["path"], "lang": f.get("language", ""),
             "loc": f.get("line_count", 0),
             "imports": (f.get("imports", []) or [])[:5],
             "funcs": (f.get("functions", []) or [])[:5]}
            for f in sample
        ]

        prompt = f"""You are a security architect analyzing a codebase.

FILE INVENTORY (sample of {len(sample)} of {len(file_metadata)} files):
{json.dumps(files_summary, indent=2)[:8000]}

Build a system-level understanding:
1. What does this application do? (1 sentence)
2. What's the architecture? (monolith / microservices / serverless / library)
3. Identify likely entry points (HTTP handlers, main files, controllers)
4. Identify auth/permission files
5. List the 10-15 highest-value files to security-review first

Respond ONLY with JSON:
{{
  "app_purpose": "...",
  "architecture": "...",
  "language": "...",
  "frameworks": ["..."],
  "entry_points": ["path/to/file"],
  "auth_files": ["..."],
  "high_value_files": ["..."],
  "data_stores": ["..."],
  "reasoning": "..."
}}"""

        try:
            log.ai_call("Sonnet", "codebase system analysis")
            resp = await self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0, max_tokens=2048,
            )
            text = resp.content.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                if text.endswith("```"):
                    text = text[:-3]
            return json.loads(text)
        except Exception as e:
            log.error("Codebase analysis failed", exc=e)
            return {}


class CrossFileAnalyzer:
    """
    Mode 2/3 — Given a finding in file A, ask AI to identify related
    code in other files that might be affected or vulnerable similarly.
    """

    def __init__(self, llm: AsyncLLMClient):
        self.llm = llm

    async def find_related_code(
        self, finding: Finding, all_files: list[dict],
    ) -> list[str]:
        """Return list of file paths the AI thinks should be examined too."""
        # Compact file index
        index = [
            {"path": f["path"], "funcs": (f.get("functions") or [])[:3]}
            for f in all_files[:200]
        ]

        prompt = f"""You found this vulnerability:
File: {finding.file_path}:{finding.line_number}
Type: {finding.vuln_type}
Title: {finding.title}

Codebase file index (path + top functions):
{json.dumps(index, indent=2)[:6000]}

Which other files likely have related code that should be examined?
Look for: caller of vulnerable function, similar patterns in different files, code that consumes the same data.

Respond ONLY with JSON:
{{"related_files": ["path1", "path2", ...]}}

Limit to 5 most-likely-related files."""

        try:
            log.ai_call("Sonnet", "cross-file analysis")
            resp = await self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0, max_tokens=512,
            )
            text = resp.content.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                if text.endswith("```"):
                    text = text[:-3]
            data = json.loads(text)
            return data.get("related_files", [])[:5]
        except Exception:
            return []


class ModeAwareCodeReviewer:
    """
    Mode-aware code review orchestrator.

    Wraps the existing four-layer funnel but adjusts behavior per mode.
    """

    def __init__(self, mode: ScanDepth = ScanDepth.SMART):
        self.mode = mode
        self.mode_config = MODE_CONFIGS[mode]
        self.report = CodeReviewReport(mode=mode.value)
        self._sonnet_client: Optional[AsyncLLMClient] = None
        self._system_analyst: Optional[CodeReviewSystemAnalyst] = None
        self._cross_file: Optional[CrossFileAnalyzer] = None

    async def initialize(self):
        config = load_config()
        api_key = get_api_key(config)
        if not api_key:
            log.warn("No API key — code review will skip AI layers")
            return
        if self.mode_config.interpret_responses or self.mode_config.full_ai_owned:
            self._sonnet_client = AsyncLLMClient(api_key=api_key, model=get_model(config, "scanner"))
            self._cross_file = CrossFileAnalyzer(self._sonnet_client)
            if self.mode_config.full_ai_owned:
                self._system_analyst = CodeReviewSystemAnalyst(self._sonnet_client)

    async def close(self):
        if self._sonnet_client:
            await self._sonnet_client.close()

    async def review_codebase(
        self, source_files: list[dict],
        triage_engine, deep_scanner, verifier, variant_hunter,
    ) -> list[Finding]:
        """
        Orchestrate the four-layer funnel with mode-specific behavior.

        Args:
            source_files: list of file metadata dicts from preprocessor
            triage_engine: existing AdaptiveTriageEngine instance
            deep_scanner: existing DeepScanner instance
            verifier: existing AdversarialVerifier instance
            variant_hunter: existing VariantHunter instance
        """
        self.report.files_total = len(source_files)
        findings = []

        # Mode 3: build system understanding first
        system_context = {}
        if self.mode == ScanDepth.DEEP and self._system_analyst:
            log.info("Mode 3: building system-level understanding of codebase")
            system_context = await self._system_analyst.analyze_codebase(source_files)
            log.info(f"  App: {system_context.get('app_purpose', 'unknown')}")
            log.info(f"  Frameworks: {system_context.get('frameworks', [])}")
            log.info(f"  High-value files: {len(system_context.get('high_value_files', []))}")

        # Layer 2: Triage (Haiku)
        triage_results = await triage_engine.triage_all(source_files)
        self.report.files_triaged = len(triage_results)
        self.report.ai_triage_calls = len(triage_results)

        # Determine deep-scan threshold by mode
        if self.mode == ScanDepth.SMART:
            deep_threshold = 4  # standard
        elif self.mode == ScanDepth.INVESTIGATIVE:
            deep_threshold = 3  # broader
        else:  # DEEP
            deep_threshold = 2  # widest

        # Prioritize high-value files in Mode 3
        if self.mode == ScanDepth.DEEP and system_context.get("high_value_files"):
            hv = set(system_context["high_value_files"])
            triage_results.sort(key=lambda r: (r.get("path") not in hv, -r.get("score", 0)))
        else:
            triage_results.sort(key=lambda r: -r.get("score", 0))

        # Layer 3: Deep scan files passing threshold
        to_scan = [r for r in triage_results if r.get("score", 0) >= deep_threshold]
        # Mode 2/3 also scan files with non-zero static hits regardless of triage score
        if self.mode != ScanDepth.SMART:
            for r in triage_results:
                if r.get("score", 0) < deep_threshold and r.get("static_hit_count", 0) > 0:
                    to_scan.append(r)

        log.info(f"Mode {self.mode.value}: deep-scanning {len(to_scan)} of {len(triage_results)} files")
        self.report.files_deep_scanned = len(to_scan)

        for r in to_scan:
            file_path = r.get("full_path") or r.get("path")
            if not file_path:
                continue
            log.scanner("sonnet_deep_scan", file_path, "", r.get("score", 0))
            self.report.ai_scan_calls += 1
            try:
                file_findings = await deep_scanner.scan_file(file_path)
                findings.extend(file_findings)
            except Exception as e:
                log.error(f"Deep scan failed on {file_path}", exc=e)

        # Spot-check ratio increases by mode
        spot_check_ratio = {ScanDepth.SMART: 0.20, ScanDepth.INVESTIGATIVE: 0.40, ScanDepth.DEEP: 0.60}[self.mode]
        score_1_files = [r for r in triage_results if r.get("score", 1) == 1]
        spot_check_count = int(len(score_1_files) * spot_check_ratio)
        if spot_check_count > 0:
            import random
            random.shuffle(score_1_files)
            for r in score_1_files[:spot_check_count]:
                file_path = r.get("full_path") or r.get("path")
                if not file_path:
                    continue
                log.scanner("sonnet_spot_check", file_path)
                self.report.files_spot_checked += 1
                try:
                    findings.extend(await deep_scanner.scan_file(file_path))
                except Exception:
                    continue

        # Mode 2/3: cross-file analysis for high-severity findings
        if self.mode != ScanDepth.SMART and self._cross_file:
            high_sev = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
            for finding in high_sev[:5]:  # Limit to top 5 to control cost
                related = await self._cross_file.find_related_code(finding, source_files)
                for path in related:
                    full = next((f.get("full_path") for f in source_files if f.get("path") == path), None)
                    if full:
                        try:
                            findings.extend(await deep_scanner.scan_file(full))
                        except Exception:
                            continue

        # Layer 4: Verification
        for finding in findings:
            if finding.source != FindingSource.CODE_REVIEW:
                continue
            try:
                content = ""
                if finding.file_path:
                    with open(finding.file_path, "r", errors="replace") as f:
                        content = f.read()
                is_real = await verifier.verify(finding, content)
                self.report.ai_verify_calls += 1
                if is_real:
                    finding.mark_verified(True)
                    self.report.findings_verified += 1
                else:
                    finding.mark_verified(False)
                    self.report.findings_false_positive += 1
            except Exception:
                continue

        # Variant hunt with mode-specific iteration count
        verified = [f for f in findings if getattr(f, "verified", False)]
        iterations = {ScanDepth.SMART: 1, ScanDepth.INVESTIGATIVE: 2, ScanDepth.DEEP: 3}[self.mode]
        for _ in range(iterations):
            new_variants = []
            for finding in verified:
                variants = variant_hunter.find_variants(finding, source_files)
                new_variants.extend(variants)
            if not new_variants:
                break
            findings.extend(new_variants)
            self.report.variants_found += len(new_variants)
            verified = new_variants  # next iteration seeds from new variants

        return findings
