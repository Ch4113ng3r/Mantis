"""
AI-driven endpoint classifier (Mode 1 foundation).

Sends compact structured endpoint metadata to Haiku and gets back a
list of likely vulnerability classes with scores. This determines
WHICH of the 51 deterministic scanners to run on each endpoint.

The classifier never sees raw HTTP response bodies during probing —
it sees compressed structural summaries. This keeps token cost at
~$0.001 per endpoint vs ~$0.05+ for sending full responses.

Output: dict[scanner_name -> score 1-5] used by orchestrator to
selectively dispatch scanners. Endpoints scoring 1 on a vulnerability
class skip that scanner entirely; endpoints scoring 5 always run it.
"""

import json
import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs

from mantis.core.llm_client import AsyncLLMClient


# Map of vulnerability classes to scanner names in orchestrator
# Used to translate AI's vuln_class output into scanner invocations
VULN_CLASS_TO_SCANNERS = {
    "sqli": ["sqli_error", "sqli_boolean", "sqli_time"],
    "xss": ["xss_reflected", "csti", "dangling_markup"],
    "ssti": ["ssti"],
    "cmdi": ["command_injection"],
    "path_traversal": ["path_traversal"],
    "ssrf": [],   # OOB only
    "xxe": ["xxe_xml_body"],
    "ldap": ["ldap"],
    "xpath": ["xpath"],
    "nosql": ["nosql"],
    "crlf": ["crlf"],
    "ssi": ["ssi_injection"],
    "email_header": ["email_header_injection"],
    "hpp": ["hpp"],
    "prototype_pollution": [],
    "open_redirect": ["open_redirect"],
    "csrf": ["csrf"],
    "cors": ["cors"],
    "clickjacking": ["clickjacking"],
    "jsonp": ["jsonp_hijacking"],
    "postmessage": ["postmessage"],
    "dom_clobbering": ["dom_clobbering"],
    "css_injection": ["css_injection"],
    "web_storage": ["web_storage"],
    "verb_tampering": ["verb_tampering"],
    "method_override": ["method_override"],
    "content_type_confusion": ["content_type_confusion"],
    "host_header": ["host_header"],
    "subdomain_takeover": ["subdomain_takeover"],
    "request_smuggling": ["request_smuggling"],
    "websocket": ["websocket"],
    "token_leakage": ["token_leakage"],
    "session_fixation": ["session_cookie"],
    "mfa_bypass": ["mfa_step_skip"],
    "file_upload": ["file_upload"],
    "imagetragick": ["imagetragick"],
    "zipslip": ["zipslip"],
    "pdf_ssrf": ["pdf_generation_ssrf"],
    "csv_injection": ["csv_injection"],
    "cache_poisoning": ["cache_poisoning"],
    "padding_oracle": ["padding_oracle"],
    "timing_attack": ["timing_attack_auth"],
    "race_condition": ["race_condition"],
    "mass_assignment": ["mass_assignment"],
    "negative_quantity": [],  # handled in advanced
}


@dataclass
class EndpointSummary:
    """Compact structured summary of an endpoint for AI classification."""
    url_pattern: str              # /api/users/{id} not /api/users/123
    method: str
    parameters: list              # parameter names + likely types
    response_status: int = 0
    response_content_type: str = ""
    response_size_bucket: str = ""  # "tiny<1K", "small<10K", "medium<100K", "large"
    response_snippet: str = ""    # first ~200 chars of body, sanitized
    framework_signals: list = field(default_factory=list)
    auth_required: bool = False
    has_form: bool = False
    has_file_upload: bool = False
    url_hints: list = field(default_factory=list)  # ["admin", "search", "redirect"]


@dataclass
class ClassificationResult:
    """AI's verdict on an endpoint."""
    endpoint_purpose: str         # "Search functionality" etc
    detected_frameworks: list = field(default_factory=list)
    vulnerability_scores: dict = field(default_factory=dict)  # vuln_class -> 1-5
    scanner_priorities: dict = field(default_factory=dict)    # scanner_name -> 1-5
    reasoning: str = ""
    recommended_payloads: list = field(default_factory=list)  # AI-suggested context-specific payloads
    risk_tier: str = "medium"     # low/medium/high


class AIClassifier:
    """
    Mode 1 endpoint classifier.

    For each discovered endpoint, performs ONE Haiku call to classify
    what the endpoint does and which vulnerability classes are most
    likely. Output drives selective scanner dispatch.

    Usage:
        classifier = AIClassifier(haiku_client)
        summary = classifier.summarize(endpoint_dict, response_obj)
        result = await classifier.classify(summary)
        # result.scanner_priorities tells orchestrator which scanners to run
    """

    def __init__(self, llm: AsyncLLMClient, engagement_context: dict = None):
        self.llm = llm
        # Engagement-wide accumulated knowledge — shared across all classifications
        self.engagement_context = engagement_context or {
            "detected_frameworks": set(),
            "auth_patterns": set(),
            "url_conventions": set(),
            "known_endpoints": [],
        }
        # Classification cache: same endpoint pattern → reuse classification
        self.cache: dict[str, ClassificationResult] = {}

    def summarize(self, endpoint: dict, response_text: str = "",
                  response_status: int = 0, response_headers: dict = None) -> EndpointSummary:
        """
        Build a compact 500-token structured summary from an endpoint observation.

        Strips response down to: status, content-type, size bucket, first 200 chars,
        framework signals, URL hints. Never includes full response body.
        """
        url = endpoint.get("url", "")
        parsed = urlparse(url)

        # Normalize URL: replace numeric IDs, UUIDs, slugs with patterns
        path = parsed.path
        path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
        path = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "/{uuid}", path,
        )
        path = re.sub(r"/[a-z0-9]{20,}(?=/|$)", "/{slug}", path)
        url_pattern = f"{parsed.scheme}://{parsed.netloc}{path}"

        # Detect URL hints — words in the path that suggest functionality
        hint_keywords = {
            "admin", "auth", "login", "logout", "signup", "register",
            "password", "reset", "search", "query", "filter", "sort",
            "upload", "download", "file", "import", "export",
            "user", "users", "account", "profile", "settings",
            "api", "graphql", "rest", "rpc", "webhook",
            "redirect", "callback", "oauth", "saml", "sso",
            "payment", "billing", "checkout", "cart", "order",
            "delete", "remove", "drop", "purge",
            "config", "settings", "internal", "debug", "trace",
            "fetch", "load", "import", "include", "render",
        }
        url_hints = [
            kw for kw in hint_keywords
            if kw in url.lower() or kw in (" ".join(endpoint.get("params", []))).lower()
        ]

        # Extract parameters and guess types
        params = []
        for p in endpoint.get("params", []):
            param_info = {"name": p}
            # Type hints from name
            if any(t in p.lower() for t in ["id", "_id", "uuid"]):
                param_info["likely_type"] = "identifier"
            elif any(t in p.lower() for t in ["url", "uri", "link", "callback", "redirect"]):
                param_info["likely_type"] = "url"
            elif any(t in p.lower() for t in ["email", "mail"]):
                param_info["likely_type"] = "email"
            elif any(t in p.lower() for t in ["file", "filename", "path"]):
                param_info["likely_type"] = "file_path"
            elif any(t in p.lower() for t in ["query", "search", "q", "term"]):
                param_info["likely_type"] = "search"
            elif any(t in p.lower() for t in ["html", "content", "body", "template"]):
                param_info["likely_type"] = "html_content"
            elif any(t in p.lower() for t in ["price", "amount", "qty", "quantity"]):
                param_info["likely_type"] = "numeric"
            else:
                param_info["likely_type"] = "string"
            params.append(param_info)

        # Response analysis (without sending full body)
        content_type = (response_headers or {}).get("content-type", "").lower()
        if "html" in content_type:
            content_type = "text/html"
        elif "json" in content_type:
            content_type = "application/json"
        elif "xml" in content_type:
            content_type = "application/xml"

        size = len(response_text) if response_text else 0
        if size < 1024:
            size_bucket = "tiny<1K"
        elif size < 10240:
            size_bucket = "small<10K"
        elif size < 102400:
            size_bucket = "medium<100K"
        else:
            size_bucket = "large"

        # Response snippet — first ~200 chars, sanitized for token efficiency
        snippet = (response_text or "")[:200]
        snippet = re.sub(r"\s+", " ", snippet).strip()

        # Framework signals from response body
        framework_signals = []
        body_lower = (response_text or "").lower()
        signals = {
            "wp-content": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
            "csrftoken": "Django", "_csrf": "Express/Django",
            "phpsessid": "PHP", "jsessionid": "Java/Servlet",
            "laravel": "Laravel", "rails": "Ruby on Rails",
            "spring": "Spring", "django": "Django",
            "react": "React", "angular": "Angular", "vue.js": "Vue.js",
            "next.js": "Next.js", "graphql": "GraphQL",
        }
        for sig, fw in signals.items():
            if sig in body_lower:
                framework_signals.append(fw)
                self.engagement_context["detected_frameworks"].add(fw)

        # Detect form indicators
        has_form = "<form" in body_lower or endpoint.get("method", "GET") == "POST"
        has_file_upload = "multipart/form-data" in body_lower or 'type="file"' in body_lower

        return EndpointSummary(
            url_pattern=url_pattern,
            method=endpoint.get("method", "GET"),
            parameters=params,
            response_status=response_status,
            response_content_type=content_type,
            response_size_bucket=size_bucket,
            response_snippet=snippet,
            framework_signals=framework_signals,
            auth_required=endpoint.get("auth_required", False),
            has_form=has_form,
            has_file_upload=has_file_upload,
            url_hints=url_hints,
        )

    async def classify(self, summary: EndpointSummary) -> ClassificationResult:
        """
        Send the summary to Haiku and get back vulnerability scores.

        ~$0.001 per call. Cached by endpoint pattern signature.
        """
        # Cache key — pattern + method + param names
        cache_key = hashlib.sha256(
            f"{summary.url_pattern}:{summary.method}:{','.join(sorted(p['name'] for p in summary.parameters))}".encode()
        ).hexdigest()[:16]
        if cache_key in self.cache:
            return self.cache[cache_key]

        prompt = self._build_classification_prompt(summary)

        try:
            resp = await self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=1024,
            )
            result = self._parse_classification(resp.content, summary)
        except Exception as e:
            # Fallback: return all-medium scores on AI failure (still runs scanners)
            result = self._fallback_classification(summary)

        # Cache it
        self.cache[cache_key] = result

        # Accumulate engagement knowledge
        if result.detected_frameworks:
            self.engagement_context["detected_frameworks"].update(result.detected_frameworks)

        return result

    def _build_classification_prompt(self, summary: EndpointSummary) -> str:
        """Build the structured prompt for endpoint classification."""
        accumulated_context = ""
        if self.engagement_context["detected_frameworks"]:
            accumulated_context = (
                f"\nKnown engagement context:\n"
                f"- Frameworks observed elsewhere on this target: "
                f"{', '.join(sorted(self.engagement_context['detected_frameworks']))}\n"
            )

        param_summary = ", ".join(
            f"{p['name']}({p['likely_type']})" for p in summary.parameters
        ) or "(none)"

        url_hints_str = ", ".join(summary.url_hints) or "(none)"

        return f"""You are a security engineer analyzing a web endpoint to determine likely vulnerabilities.

ENDPOINT:
URL pattern: {summary.url_pattern}
Method: {summary.method}
Parameters: {param_summary}
URL keywords detected: {url_hints_str}
Response: HTTP {summary.response_status}, {summary.response_content_type}, size: {summary.response_size_bucket}
Response snippet: "{summary.response_snippet[:200]}"
Framework signals: {', '.join(summary.framework_signals) or '(none)'}
Has form: {summary.has_form}
Has file upload: {summary.has_file_upload}
Auth required: {summary.auth_required}
{accumulated_context}

TASK:
1. Describe what this endpoint does (1 sentence).
2. List frameworks/technologies detected.
3. Score these vulnerability classes 1-5 based on likelihood given the endpoint's purpose:
   - sqli: SQL injection (DB-backed search/filter/auth endpoints)
   - xss: Cross-site scripting (HTML reflection contexts)
   - ssti: Server-side template injection (template rendering)
   - cmdi: OS command injection (file/process operations)
   - path_traversal: LFI (file parameters)
   - ssrf: SSRF (URL/callback parameters)
   - xxe: XXE (XML input)
   - ldap: LDAP injection (LDAP-backed auth)
   - xpath: XPath injection (XML data store queries)
   - nosql: NoSQL injection (MongoDB/Couch backends)
   - crlf: CRLF injection (header manipulation)
   - open_redirect: Open redirect (redirect/return params)
   - csrf: CSRF (state-changing actions)
   - cors: CORS misconfiguration (API endpoints)
   - clickjacking: Clickjacking (sensitive UI)
   - jsonp: JSONP hijacking (callback params)
   - postmessage: postMessage flaws (JS apps)
   - dom_clobbering: DOM clobbering (HTML injection points)
   - css_injection: CSS injection (style reflection)
   - file_upload: Upload bypass (file upload endpoints)
   - imagetragick: Image processing RCE (image uploads)
   - zipslip: Archive extraction flaws (zip uploads)
   - pdf_ssrf: PDF generation SSRF (export/report features)
   - csv_injection: Formula injection (CSV exports)
   - cache_poisoning: Cache poisoning (cached endpoints)
   - host_header: Host header injection (any endpoint)
   - verb_tampering: HTTP method confusion
   - mass_assignment: Mass assignment (PATCH/PUT with objects)
   - race_condition: Race conditions (single-use ops)
   - bola: BOLA/IDOR (object-id params)
   - mfa_bypass: MFA bypass (auth flows)
   - session_fixation: Session flaws (session-related)
   - token_leakage: Token in URL (sensitive params in URL)
   - websocket: WebSocket flaws (WS endpoints)
   - subdomain_takeover: Dangling DNS (any external URL)
4. For each vuln class scored 4-5, suggest one specific high-priority payload tailored to this endpoint's tech stack.

Respond ONLY with JSON (no markdown):
{{
  "purpose": "1-sentence description",
  "frameworks": ["Framework1", "Framework2"],
  "risk_tier": "low|medium|high",
  "vulnerability_scores": {{
    "sqli": 1-5,
    "xss": 1-5,
    "ssti": 1-5,
    ...
  }},
  "high_priority_payloads": [
    {{"vuln": "sqli", "payload": "...", "reasoning": "..."}},
    ...
  ]
}}
Only include vulnerability_scores entries where the score is >= 2."""

    def _parse_classification(self, text: str, summary: EndpointSummary) -> ClassificationResult:
        """Parse Haiku's JSON response into a ClassificationResult."""
        text = text.strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try to extract JSON from text
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(0))
                except json.JSONDecodeError:
                    return self._fallback_classification(summary)
            else:
                return self._fallback_classification(summary)

        vuln_scores = data.get("vulnerability_scores", {})
        # Translate vuln_class scores → scanner_name priorities
        scanner_priorities = {}
        for vuln_class, score in vuln_scores.items():
            if not isinstance(score, (int, float)):
                continue
            score = int(score)
            scanners = VULN_CLASS_TO_SCANNERS.get(vuln_class, [])
            for scanner_name in scanners:
                # Highest score wins if same scanner appears for multiple vuln classes
                scanner_priorities[scanner_name] = max(
                    scanner_priorities.get(scanner_name, 0), score,
                )

        return ClassificationResult(
            endpoint_purpose=data.get("purpose", "Unknown"),
            detected_frameworks=data.get("frameworks", []),
            vulnerability_scores=vuln_scores,
            scanner_priorities=scanner_priorities,
            recommended_payloads=data.get("high_priority_payloads", []),
            risk_tier=data.get("risk_tier", "medium"),
        )

    def _fallback_classification(self, summary: EndpointSummary) -> ClassificationResult:
        """
        Default classification when AI call fails — run everything at medium priority.

        This guarantees scanning still happens even if API is unavailable.
        """
        all_scanners = {}
        for vuln_class, scanners in VULN_CLASS_TO_SCANNERS.items():
            for s in scanners:
                all_scanners[s] = 3  # Medium priority for everything
        return ClassificationResult(
            endpoint_purpose="(AI classification failed — using fallback)",
            scanner_priorities=all_scanners,
            risk_tier="medium",
        )
