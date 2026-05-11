"""
Scan depth modes — Mode 1 (Smart), Mode 2 (Investigative), Mode 3 (Deep).
v1.5: Mode 2 wired properly (interpreter actually called), Mode 3 has expanded
investigator with full HTTP control and scanner-as-tools.
"""

import asyncio
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx

from mantis.core.ai_classifier import AIClassifier, ClassificationResult
from mantis.core.scope import EngagementScope, VulnScope
from mantis.core.llm_client import AsyncLLMClient
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource, HTTPEvidence
from mantis.core.token_tracker import TokenBudget
from mantis.config import load_config, get_api_key, get_model
from mantis.webapp.scanners import orchestrator
from mantis.utils.verbose import log


class ScanDepth(Enum):
    SMART = "smart"
    INVESTIGATIVE = "investigative"
    DEEP = "deep"


@dataclass
class ScannerObservation:
    """Scanner observation data — feeds Mode 2 interpreter."""
    scanner_name: str
    vuln_class: str
    target_url: str
    parameter: str
    payload: str
    method: str
    baseline_status: int
    baseline_size: int
    baseline_snippet: str
    probe_status: int
    probe_size: int
    probe_snippet: str
    is_anomalous: bool = False
    anomaly_reason: str = ""


@dataclass
class ModeConfig:
    name: str
    classify_endpoints: bool = True
    interpret_responses: bool = False
    full_ai_owned: bool = False
    min_score_to_scan: int = 2
    interpret_score_threshold: int = 3
    deep_investigate_score: int = 5
    max_concurrent: int = 5
    budget_warning_usd: float = 5.0
    estimated_cost_per_endpoint: float = 0.001
    description: str = ""


MODE_CONFIGS = {
    ScanDepth.SMART: ModeConfig(
        name="smart",
        classify_endpoints=True,
        interpret_responses=False,
        full_ai_owned=False,
        min_score_to_scan=2,
        budget_warning_usd=5.0,
        estimated_cost_per_endpoint=0.001,
        description="AI-directed DAST. Haiku classifies each endpoint, runs only high-priority scanners.",
    ),
    ScanDepth.INVESTIGATIVE: ModeConfig(
        name="investigative",
        classify_endpoints=True,
        interpret_responses=True,
        full_ai_owned=False,
        min_score_to_scan=2,
        interpret_score_threshold=3,
        deep_investigate_score=4,
        budget_warning_usd=40.0,
        estimated_cost_per_endpoint=0.05,
        description="AI interprets ambiguous responses and runs investigations on suspicious endpoints.",
    ),
    ScanDepth.DEEP: ModeConfig(
        name="deep",
        classify_endpoints=True,
        interpret_responses=True,
        full_ai_owned=True,
        min_score_to_scan=1,
        interpret_score_threshold=2,
        deep_investigate_score=3,
        max_concurrent=2,
        budget_warning_usd=200.0,
        estimated_cost_per_endpoint=0.30,
        description="AI owns the loop with full HTTP control. Investigator-first, scanners confirm.",
    ),
}


@dataclass
class ScanReport:
    mode: str
    findings: list = field(default_factory=list)
    observations: list = field(default_factory=list)
    endpoints_scanned: int = 0
    endpoints_classified: int = 0
    scanners_dispatched: int = 0
    scanners_skipped: int = 0
    ai_classifications: int = 0
    ai_interpretations: int = 0
    ai_investigations: int = 0
    interpretations_promoted_to_findings: int = 0
    estimated_cost_usd: float = 0.0


class ResponseInterpreter:
    """Mode 2 — AI interprets ambiguous responses (v1.5: actually called)."""

    def __init__(self, llm: AsyncLLMClient):
        self.llm = llm

    async def interpret(self, observation: ScannerObservation) -> dict:
        log.ai_call("Sonnet", f"interpret {observation.vuln_class}", input_tokens=800)
        prompt = f"""You are analyzing a probe response to determine if a vulnerability exists.

ENDPOINT: {observation.target_url}
METHOD: {observation.method}
PARAMETER: {observation.parameter}
VULN CLASS BEING TESTED: {observation.vuln_class}
SCANNER: {observation.scanner_name}
PAYLOAD: {observation.payload[:300]}

BASELINE (no payload):
  Status: {observation.baseline_status}
  Size: {observation.baseline_size} bytes
  Snippet: "{observation.baseline_snippet[:400]}"

PROBE (with payload):
  Status: {observation.probe_status}
  Size: {observation.probe_size} bytes
  Snippet: "{observation.probe_snippet[:400]}"

Anomaly flag: {observation.is_anomalous}
Anomaly reason: {observation.anomaly_reason}

Is the probe response evidence of {observation.vuln_class}?

Respond ONLY with JSON:
{{
  "is_vulnerable": true|false,
  "confidence": 0.0-1.0,
  "reasoning": "(1-2 sentences)",
  "next_action": "confirm|escalate|skip",
  "suggested_followup_payload": "optional",
  "severity_estimate": "low|medium|high|critical"
}}"""

        try:
            resp = await self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0, max_tokens=512,
            )
            text = resp.content.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                if text.endswith("```"):
                    text = text[:-3]
            result = json.loads(text)
            log.interpretation(
                observation.target_url,
                "VULN" if result.get("is_vulnerable") else "CLEAN",
                result.get("confidence", 0.0),
                result.get("reasoning", ""),
            )
            return result
        except Exception as e:
            log.error("Interpretation failed", exc=e)
            return {"is_vulnerable": False, "confidence": 0.0,
                    "reasoning": "AI parse failure", "next_action": "skip"}

    def build_finding_from_interpretation(
        self, observation: ScannerObservation, interpretation: dict,
    ) -> Finding:
        sev_map = {"low": Severity.LOW, "medium": Severity.MEDIUM,
                   "high": Severity.HIGH, "critical": Severity.CRITICAL}
        return Finding(
            title=f"AI-Confirmed {observation.vuln_class.upper()} in '{observation.parameter}'",
            description=(
                f"AI interpretation identified vulnerability in {observation.target_url}. "
                f"Reasoning: {interpretation.get('reasoning', '')}"
            ),
            source=FindingSource.WEBAPP,
            severity=sev_map.get(interpretation.get("severity_estimate", "medium"), Severity.MEDIUM),
            evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
            target=observation.target_url,
            endpoint=observation.target_url,
            vuln_type=observation.vuln_class.upper(),
            payload=observation.payload,
            evidence=[HTTPEvidence(
                request_method=observation.method,
                request_url=observation.target_url,
                request_headers={},
                request_body=f"{observation.parameter}={observation.payload}",
                response_status=observation.probe_status,
                response_headers={},
                response_body=observation.probe_snippet[:2000],
                notes=f"AI interpretation: {interpretation.get('reasoning', '')}",
            )],
            confidence=interpretation.get("confidence", 0.6),
            tags=["mode2_ai_interpreted", f"mode2:{observation.vuln_class}"],
        )


class ExpandedAIInvestigator:
    """Mode 2/3 investigator with full HTTP control (v1.5)."""

    def __init__(self, llm, http, engagement_context=None):
        self.llm = llm
        self.http = http
        self.engagement_context = engagement_context or {}

    async def investigate(self, endpoint, params, vuln_class, method="GET",
                          initial_finding=None, max_turns=15):
        from mantis.exploit.playbooks import get_playbook, format_for_prompt

        playbook = get_playbook(vuln_class)
        playbook_context = format_for_prompt(playbook) if playbook else ""

        ctx_summary = ""
        if self.engagement_context:
            fws = self.engagement_context.get("detected_frameworks", set())
            if fws:
                ctx_summary = f"Detected frameworks on target: {', '.join(sorted(fws))}\n"
            apats = self.engagement_context.get("auth_patterns", set())
            if apats:
                ctx_summary += f"Observed auth patterns: {', '.join(sorted(apats))}\n"

        system = f"""You are investigating {endpoint} for {vuln_class} vulnerability.

PARAMETERS AVAILABLE: {', '.join(params) if params else '(none yet)'}
METHOD: {method}

ENGAGEMENT CONTEXT:
{ctx_summary or '(no accumulated context yet)'}

{playbook_context}

Available actions (JSON response):
- {{"action": "probe", "payload": "...", "param": "...", "method": "GET|POST|...", "headers": {{...}}, "expected": "..."}}
- {{"action": "multi_probe", "params": {{"k":"v",...}}, "method": "...", "headers": {{...}}, "expected": "..."}}
- {{"action": "send_raw", "method": "...", "body": "...", "content_type": "...", "headers": {{...}}, "expected": "..."}}
- {{"action": "found", "title": "...", "severity": "low|medium|high|critical", "evidence": "..."}}
- {{"action": "give_up", "reason": "..."}}

Investigate methodically: hypothesis → test → observe → refine. {max_turns} turns max."""

        history = [{"role": "user", "content": "Begin investigation. State your hypothesis and first probe."}]
        findings = []

        for turn in range(max_turns):
            try:
                log.ai_call("Sonnet", f"investigate {vuln_class} turn {turn+1}")
                resp = await self.llm.chat(
                    messages=history, system=system,
                    temperature=0.0, max_tokens=1500,
                )
                text = resp.content.strip()
                if text.startswith("```"):
                    text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                    if text.endswith("```"):
                        text = text[:-3]
                action = json.loads(text)
            except Exception as e:
                log.error(f"Investigator parse fail turn {turn+1}", exc=e)
                break

            history.append({"role": "assistant", "content": resp.content})
            atype = action.get("action", "")
            log.investigation(endpoint, vuln_class, atype, str(action)[:300])

            if atype == "found":
                sev_map = {"low": Severity.LOW, "medium": Severity.MEDIUM,
                           "high": Severity.HIGH, "critical": Severity.CRITICAL}
                findings.append(Finding(
                    title=action.get("title", f"AI-investigated {vuln_class}"),
                    description=action.get("evidence", ""),
                    source=FindingSource.WEBAPP,
                    severity=sev_map.get(action.get("severity", "medium"), Severity.MEDIUM),
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=endpoint, endpoint=endpoint,
                    vuln_type=vuln_class,
                    confidence=0.85,
                    tags=["ai_investigated", f"investigation:{vuln_class}"],
                ))
                break

            if atype == "give_up":
                break

            observation = await self._execute_action(endpoint, method, params, action)
            history.append({"role": "user", "content": observation})

        return findings

    async def _execute_action(self, endpoint, default_method, default_params, action):
        atype = action.get("action", "")
        if atype == "probe":
            return await self._exec_probe(endpoint, default_method, action)
        if atype == "multi_probe":
            return await self._exec_multi_probe(endpoint, action)
        if atype == "send_raw":
            return await self._exec_send_raw(endpoint, action)
        return f"Unknown action: {atype}. Use probe/multi_probe/send_raw/found/give_up."

    async def _exec_probe(self, endpoint, default_method, action):
        payload = action.get("payload", "")
        param = action.get("param", "")
        method = (action.get("method") or default_method).upper()
        headers = action.get("headers", {}) or {}
        try:
            if method == "GET":
                r = await self.http.get(endpoint, params={param: payload}, headers=headers, timeout=10)
            else:
                r = await self.http.request(method, endpoint, data={param: payload}, headers=headers, timeout=10)
            log.http(method, endpoint, r.status_code, len(r.text))
            return (f"Probe: {method} {endpoint} {param}={payload[:100]}\n"
                    f"Headers: {headers}\n"
                    f"Response: HTTP {r.status_code}, {len(r.text)}b\n"
                    f"Headers (subset): {dict(list(r.headers.items())[:5])}\n"
                    f"Body: {r.text[:1000]}")
        except Exception as e:
            return f"Probe failed: {type(e).__name__}: {e}"

    async def _exec_multi_probe(self, endpoint, action):
        params = action.get("params", {})
        method = action.get("method", "POST").upper()
        headers = action.get("headers", {}) or {}
        try:
            if method == "GET":
                r = await self.http.get(endpoint, params=params, headers=headers, timeout=10)
            else:
                r = await self.http.request(method, endpoint, data=params, headers=headers, timeout=10)
            log.http(method, endpoint, r.status_code, len(r.text))
            return (f"Multi-probe: {method} {endpoint}\nParams: {params}\nHeaders: {headers}\n"
                    f"Response: HTTP {r.status_code}, {len(r.text)}b\nBody: {r.text[:1000]}")
        except Exception as e:
            return f"Multi-probe failed: {type(e).__name__}: {e}"

    async def _exec_send_raw(self, endpoint, action):
        method = action.get("method", "POST").upper()
        body = action.get("body", "")
        ct = action.get("content_type", "application/x-www-form-urlencoded")
        headers = action.get("headers", {}) or {}
        headers["Content-Type"] = ct
        try:
            r = await self.http.request(method, endpoint, content=body, headers=headers, timeout=10)
            log.http(method, endpoint, r.status_code, len(r.text))
            return (f"Raw: {method} {endpoint}\nContent-Type: {ct}\nBody: {body[:300]}\n"
                    f"Headers: {headers}\nResponse: HTTP {r.status_code}, {len(r.text)}b\nBody: {r.text[:1000]}")
        except Exception as e:
            return f"Raw send failed: {type(e).__name__}: {e}"


AIInvestigator = ExpandedAIInvestigator


class PageTargetedAgent:
    """Mode 3 plain-English page targeting."""

    def __init__(self, llm, http, engagement_context=None):
        self.llm = llm
        self.http = http
        self.engagement_context = engagement_context or {}

    async def investigate_page(self, url, description, max_turns=30):
        log.info(f"Page-targeted investigation: {url}")
        log.info(f"Description: {description}")
        plan = await self._build_test_plan(url, description)
        findings = []
        for tc in plan.get("test_cases", []):
            log.info(f"Test case: {tc.get('description', '')}")
            findings.extend(await self._execute_test_case(url, tc, max_turns // 3))
        if len(findings) >= 2:
            findings.extend(await self._chain_findings(url, findings))
        return findings

    async def _build_test_plan(self, url, description):
        prompt = f"""You are a senior penetration tester planning targeted tests.

TARGET URL: {url}
OPERATOR'S DESCRIPTION: "{description}"

Build a focused test plan with 3-8 test cases. For each:
1. What vulnerability classes are most relevant?
2. What inputs/parameters to test?
3. What specific payloads to try first?
4. What does success look like?

Respond ONLY with JSON:
{{
  "page_summary": "what this page does",
  "test_cases": [
    {{
      "description": "...",
      "vuln_class": "ssti|xss|sqli|...",
      "target": "URL/param/feature",
      "payloads_to_try": ["..."],
      "success_criteria": "...",
      "priority": "high|medium|low"
    }}
  ]
}}"""
        try:
            log.ai_call("Sonnet", "page-targeted planning")
            r = await self.llm.chat(messages=[{"role": "user", "content": prompt}],
                                    temperature=0.0, max_tokens=2048)
            text = r.content.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                if text.endswith("```"):
                    text = text[:-3]
            plan = json.loads(text)
            log.info(f"Plan: {len(plan.get('test_cases', []))} test cases")
            return plan
        except Exception as e:
            log.error("Plan generation failed", exc=e)
            return {"test_cases": []}

    async def _execute_test_case(self, url, tc, max_turns=10):
        inv = ExpandedAIInvestigator(self.llm, self.http, self.engagement_context)
        return await inv.investigate(
            endpoint=url, params=[],
            vuln_class=tc.get("vuln_class", "unknown"),
            method=tc.get("method", "GET"),
            max_turns=max_turns,
        )

    async def _chain_findings(self, url, findings):
        summary = [{"id": f.id, "title": f.title, "vuln_type": f.vuln_type,
                    "severity": f.severity.value, "endpoint": f.endpoint}
                   for f in findings]
        prompt = f"""You discovered these on {url}:
{json.dumps(summary, indent=2)}

Can any be chained for higher impact?

Respond ONLY with JSON:
{{"chains":[{{"title":"...","finding_ids":["..."],"exploitation":"...",
"combined_severity":"critical|high|medium","combined_impact":"..."}}]}}"""

        try:
            log.ai_call("Sonnet", "chain analysis")
            r = await self.llm.chat(messages=[{"role": "user", "content": prompt}],
                                    temperature=0.0, max_tokens=2048)
            text = r.content.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                if text.endswith("```"):
                    text = text[:-3]
            data = json.loads(text)
        except Exception:
            return []

        out = []
        for chain in data.get("chains", []):
            out.append(Finding(
                title=f"Chain: {chain.get('title', '')}",
                description=chain.get("exploitation", ""),
                source=FindingSource.CORRELATION,
                severity=Severity(chain.get("combined_severity", "high")),
                evidence_level=EvidenceLevel.ROOT_CAUSE_EXPLAINED,
                target=url, endpoint=url, vuln_type="Attack Chain",
                impact=chain.get("combined_impact", ""),
                confidence=0.8, tags=["chain", "page_targeted"],
            ))
        return out


class ModeAwareScanner:
    """Main entry — mode-aware dispatch."""

    def __init__(self, mode=ScanDepth.SMART, budget=None, scope=None):
        self.mode = mode
        self.mode_config = MODE_CONFIGS[mode]
        self.budget = budget
        self.scope = scope  # EngagementScope or None
        self.report = ScanReport(mode=mode.value)
        self._classifier = None
        self._interpreter = None
        self._investigator = None
        self._haiku_client = None
        self._sonnet_client = None

    async def initialize(self):
        if not self.mode_config.classify_endpoints:
            return
        config = load_config()
        api_key = get_api_key(config)
        if not api_key:
            log.warn("No API key — AI disabled, falling back to deterministic")
            return
        self._haiku_client = AsyncLLMClient(api_key=api_key, model=get_model(config, "triage"))
        self._classifier = AIClassifier(self._haiku_client)
        log.info(f"AI classifier ready ({get_model(config, 'triage')})")
        if self.mode_config.interpret_responses or self.mode_config.full_ai_owned:
            self._sonnet_client = AsyncLLMClient(api_key=api_key, model=get_model(config, "scanner"))
            self._interpreter = ResponseInterpreter(self._sonnet_client)
            log.info(f"AI interpreter ready ({get_model(config, 'scanner')})")

    async def close(self):
        if self._haiku_client:
            await self._haiku_client.close()
        if self._sonnet_client:
            await self._sonnet_client.close()

    async def scan_endpoint(self, http, url, params, method="GET"):
        if not self._classifier:
            return await orchestrator.scan_endpoint(http, url, params, method)

        baseline_status, baseline_text, baseline_headers = await self._get_baseline(http, url, method)
        ep_dict = {"url": url, "method": method, "params": params}
        summary = self._classifier.summarize(ep_dict, baseline_text, baseline_status, baseline_headers)
        classification = await self._classifier.classify(summary)
        log.classification(url, classification.endpoint_purpose, classification.scanner_priorities)
        self.report.ai_classifications += 1
        self.report.endpoints_classified += 1

        if self.mode == ScanDepth.SMART:
            findings = await self._mode1_scan(http, url, params, method, classification, baseline_status, baseline_text)
        elif self.mode == ScanDepth.INVESTIGATIVE:
            findings = await self._mode2_scan(http, url, params, method, classification, baseline_status, baseline_text)
        else:
            findings = await self._mode3_scan(http, url, params, method, classification, baseline_status, baseline_text)

        self.report.endpoints_scanned += 1
        return findings

    async def _get_baseline(self, http, url, method):
        try:
            log.http(method, url + " (baseline)")
            r = await http.request(method, url, timeout=10)
            return r.status_code, r.text, dict(r.headers)
        except Exception as e:
            log.error(f"Baseline fetch failed", exc=e)
            return 0, "", {}

    async def _mode1_scan(self, http, url, params, method, classification, baseline_status, baseline_text):
        findings = []
        priorities = classification.scanner_priorities
        sem = asyncio.Semaphore(self.mode_config.max_concurrent)

        async def run(scanner_name, scanner_fn, *args):
            score = priorities.get(scanner_name, 0)
            if score < self.mode_config.min_score_to_scan:
                self.report.scanners_skipped += 1
                log.scanner_skipped(scanner_name, f"score={score}")
                return None
            # Apply scope vuln filter
            if self.scope and self.scope.vuln_scope != VulnScope.ALL:
                # Reverse map: which vuln class is this scanner for?
                from mantis.core.ai_classifier import VULN_CLASS_TO_SCANNERS
                applies = False
                for vuln_class, scanner_list in VULN_CLASS_TO_SCANNERS.items():
                    if scanner_name in scanner_list:
                        if self.scope.matches_vuln_class(vuln_class):
                            applies = True
                            break
                if not applies:
                    self.report.scanners_skipped += 1
                    log.scanner_skipped(scanner_name, "filtered by scope")
                    return None
            self.report.scanners_dispatched += 1
            log.scanner(scanner_name, url, args[2] if len(args) > 2 else "", score)
            async with sem:
                try:
                    return await scanner_fn(*args)
                except Exception as e:
                    log.error(f"Scanner {scanner_name} crashed", exc=e)
                    return None

        tasks = []
        for p in params[:10]:
            for name, fn in orchestrator.PARAM_SCANNERS:
                tasks.append(run(name, fn, http, url, p, method))
            for name, fn in orchestrator.PARAM_NO_METHOD:
                tasks.append(run(name, fn, http, url, p))
        for name, fn in orchestrator.ENDPOINT_SCANNERS:
            tasks.append(run(name, fn, http, url))
        for name, fn in orchestrator.ENDPOINT_METHOD_SCANNERS:
            tasks.append(run(name, fn, http, url, method))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                findings.append(r)
                log.finding(r.title, r.severity.value, r.confidence)
            elif isinstance(r, list):
                for f in r:
                    if isinstance(f, Finding):
                        findings.append(f)
                        log.finding(f.title, f.severity.value, f.confidence)
        return findings

    async def _mode2_scan(self, http, url, params, method, classification, baseline_status, baseline_text):
        findings = await self._mode1_scan(http, url, params, method, classification, baseline_status, baseline_text)
        if not self._interpreter or not self._sonnet_client:
            return findings

        # AI interpretation of probes (the key v1.5 fix)
        interp_findings = await self._mode2_interpret(http, url, params, method, classification, baseline_status, baseline_text)
        findings.extend(interp_findings)

        # Investigation on high-score classes
        if not self._investigator:
            self._investigator = ExpandedAIInvestigator(
                self._sonnet_client, http,
                self._classifier.engagement_context if self._classifier else None,
            )
        for vc, sc in classification.vulnerability_scores.items():
            if sc >= self.mode_config.deep_investigate_score:
                # Apply scope vuln filter
                if self.scope and not self.scope.matches_vuln_class(vc):
                    continue
                self.report.ai_investigations += 1
                log.info(f"Mode 2 investigation: {vc} (score={sc})")
                try:
                    inv = await self._investigator.investigate(
                        endpoint=url, params=params, vuln_class=vc, method=method, max_turns=8,
                    )
                    findings.extend(inv)
                    for f in inv:
                        log.finding(f.title, f.severity.value, f.confidence)
                except Exception as e:
                    log.error(f"Investigation of {vc} failed", exc=e)
        return findings

    async def _mode2_interpret(self, http, url, params, method, classification, baseline_status, baseline_text):
        """v1.5: actually calls the ResponseInterpreter on probe responses."""
        findings = []
        probe_set = {
            "sqli": ["'", "\" OR \"1\"=\"1", "1;--"],
            "xss": ["<mantis_xss>", "'\"><script>"],
            "ssti": ["{{7*7}}", "${7*7}"],
            "cmdi": ["; id", "| whoami"],
            "path_traversal": ["../../../etc/passwd"],
            "open_redirect": ["https://evil.com", "//evil.com"],
            "xxe": ['<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "test">]><r>&x;</r>'],
            "ldap": ["*)(uid=*", "admin)("],
        }
        for vc, sc in classification.vulnerability_scores.items():
            if sc < self.mode_config.interpret_score_threshold:
                continue
            if vc not in probe_set or not params:
                continue
            # Apply scope vuln filter
            if self.scope and not self.scope.matches_vuln_class(vc):
                continue
            for payload in probe_set[vc][:2]:
                param = params[0]
                try:
                    if method.upper() == "GET":
                        r = await http.get(url, params={param: payload}, timeout=10)
                    else:
                        r = await http.post(url, data={param: payload}, timeout=10)
                    log.http(method, url, r.status_code, len(r.text))
                    obs = ScannerObservation(
                        scanner_name=f"mode2_probe_{vc}", vuln_class=vc,
                        target_url=url, parameter=param, payload=payload, method=method,
                        baseline_status=baseline_status, baseline_size=len(baseline_text),
                        baseline_snippet=baseline_text[:500],
                        probe_status=r.status_code, probe_size=len(r.text),
                        probe_snippet=r.text[:500],
                        is_anomalous=(r.status_code != baseline_status
                                      or abs(len(r.text) - len(baseline_text)) > 100
                                      or payload in r.text),
                        anomaly_reason="status/size differential or payload reflection",
                    )
                    self.report.observations.append(obs)
                    if obs.is_anomalous:
                        self.report.ai_interpretations += 1
                        interp = await self._interpreter.interpret(obs)
                        if interp.get("is_vulnerable") and interp.get("confidence", 0) >= 0.6:
                            f = self._interpreter.build_finding_from_interpretation(obs, interp)
                            findings.append(f)
                            log.finding(f.title, f.severity.value, f.confidence)
                            self.report.interpretations_promoted_to_findings += 1
                except Exception as e:
                    log.error(f"Mode 2 probe failed {vc}", exc=e)
        return findings

    async def _mode3_scan(self, http, url, params, method, classification, baseline_status, baseline_text):
        findings = []
        if not self._sonnet_client:
            return await self._mode1_scan(http, url, params, method, classification, baseline_status, baseline_text)
        if not self._investigator:
            self._investigator = ExpandedAIInvestigator(
                self._sonnet_client, http,
                self._classifier.engagement_context if self._classifier else None,
            )
        for vc, sc in classification.vulnerability_scores.items():
            if sc < 2:
                continue
            # Apply scope vuln filter
            if self.scope and not self.scope.matches_vuln_class(vc):
                continue
            self.report.ai_investigations += 1
            log.info(f"Mode 3 investigation: {vc} (score={sc})")
            try:
                inv = await self._investigator.investigate(
                    endpoint=url, params=params, vuln_class=vc, method=method, max_turns=15,
                )
                findings.extend(inv)
                for f in inv:
                    log.finding(f.title, f.severity.value, f.confidence)
            except Exception as e:
                log.error(f"Mode 3 investigation {vc} failed", exc=e)
        det = await self._mode1_scan(http, url, params, method, classification, baseline_status, baseline_text)
        findings.extend(det)
        return findings

    def estimate_cost(self, endpoint_count):
        base = endpoint_count * self.mode_config.estimated_cost_per_endpoint
        return (base * 0.5, base * 2.0)
