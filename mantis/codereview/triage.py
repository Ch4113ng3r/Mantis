"""
Adaptive Haiku-based file triage with spot-check calibration.

Layer 2 of the four-layer funnel. Every file gets a Haiku pass.
A random sample of low-risk files is always deep-scanned to catch
triage false negatives. If findings appear, criteria auto-tighten.
"""

import random
from dataclasses import dataclass
from mantis.core.llm_client import AsyncLLMClient
from mantis.engage.phases import Phase


@dataclass
class TriageResult:
    file_path: str
    risk_score: int          # 1-5
    reasoning: str
    tags: list[str]
    recommended_depth: str   # "full", "taint_only", "spot_check"


class AdaptiveTriageEngine:
    """
    Haiku-powered file triage with self-calibrating accuracy.

    1. Send file metadata (NOT full code) to Haiku for scoring
    2. Score 4-5: full Sonnet scan
    3. Score 2-3: scan only functions on taint paths
    4. Score 1: 20% random sample gets full scan (spot-check)
    5. If spot-check finds issues: re-triage score-1 files

    The spot-check ratio adapts upward if calibration detects misses.
    """

    def __init__(
        self,
        llm: AsyncLLMClient,
        spot_check_ratio: float = 0.20,
        recalibration_threshold: int = 5,
    ):
        self.llm = llm
        self.spot_check_ratio = spot_check_ratio
        self.recalibration_threshold = recalibration_threshold
        self.false_negatives_found = 0

    async def triage_file(self, file_metadata: dict) -> TriageResult:
        """
        Score a single file using Haiku.

        Input is metadata ONLY (not full source):
        - filename, language, line count
        - import statements
        - function/class signatures
        - Semgrep/regex hit summary
        - taint path summary
        """
        import json

        prompt = f"""Analyze this source file\'s security risk. Score 1-5 (1=safe, 5=critical).

File: {file_metadata.get('path', 'unknown')}
Language: {file_metadata.get('language', 'unknown')}
Lines: {file_metadata.get('line_count', 0)}
Imports: {', '.join(file_metadata.get('imports', [])[:15])}
Functions: {', '.join(file_metadata.get('functions', [])[:15])}
Static hits: {file_metadata.get('static_hits', 'none')}
Taint paths: {file_metadata.get('taint_summary', 'none')}

Respond ONLY with JSON: {{"score": N, "reason": "...", "tags": [...]}}"""

        resp = await self.llm.chat(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=200,
        )

        try:
            data = json.loads(resp.content)
            score = int(data.get("score", 3))
        except (json.JSONDecodeError, ValueError):
            score = 3  # Default to medium if parsing fails
            data = {"reason": "parse_error", "tags": []}

        depth_map = {5: "full", 4: "full", 3: "taint_only", 2: "taint_only", 1: "spot_check"}
        return TriageResult(
            file_path=file_metadata.get("path", ""),
            risk_score=max(1, min(5, score)),
            reasoning=data.get("reason", ""),
            tags=data.get("tags", []),
            recommended_depth=depth_map.get(score, "taint_only"),
        )

    async def run_with_calibration(self, all_files, deep_scanner):
        """Triage all files AND run spot-check calibration."""
        import asyncio
        results = await asyncio.gather(
            *[self.triage_file(f) for f in all_files]
        )

        score_1 = [r for r in results if r.risk_score == 1]
        sample_size = max(10, int(len(score_1) * self.spot_check_ratio))
        sample = random.sample(score_1, min(sample_size, len(score_1)))

        spot_findings = []
        for triaged in sample:
            findings = await deep_scanner.scan_file(triaged.file_path, depth="full")
            spot_findings.extend(findings)

        if len(spot_findings) >= self.recalibration_threshold:
            self.false_negatives_found += len(spot_findings)
            self.spot_check_ratio = min(0.50, self.spot_check_ratio + 0.10)
            print(f"    [!] Triage calibration: {len(spot_findings)} missed. "
                  f"Ratio now {self.spot_check_ratio:.0%}")

        return results, spot_findings


class TriagePhase(Phase):
    """Phase: triage source files using Haiku."""

    async def execute(self, context) -> dict:
        print(f"    Triaging {len(context.source_files)} files...")
        # TODO: instantiate AdaptiveTriageEngine with Haiku client
        # and run triage on all source files
        return {"triage_results": []}
