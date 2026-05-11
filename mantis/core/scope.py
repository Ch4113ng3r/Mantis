"""
Scope selector for flexible MANTIS engagements.

Allows the operator to scope engagements by:
- Target scope: full_app | navigation_path | specific_endpoint | specific_page_description
- Vuln scope: all | single | list

Combinations enable precise testing:
    full app + all vulnerabilities (comprehensive scan)
    full app + single vulnerability (hunt all instances of XSS across app)
    full app + selected vulnerabilities (test only SQLi, XSS, SSTI)
    navigation path + all (test the /admin/* subtree for everything)
    specific endpoint + single (test /login for SQLi only)
    specific endpoint + selected (test /api/upload for path_traversal, file_upload)
    page description + all (Mode 3 plain-English investigation)
    page description + selected (Mode 3 plain English with vuln filter)
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class TargetScope(Enum):
    FULL_APP = "full_app"
    NAVIGATION_PATH = "navigation_path"  # e.g. /admin/*, /api/v2/*
    SPECIFIC_ENDPOINT = "specific_endpoint"
    PAGE_DESCRIPTION = "page_description"


class VulnScope(Enum):
    ALL = "all"
    SINGLE = "single"
    SELECTED = "selected"


@dataclass
class EngagementScope:
    """
    Complete scope definition for an engagement.

    Used by:
    - Crawler (limits URL discovery)
    - Classifier (focuses AI classification)
    - Orchestrator (limits scanner dispatch)
    - Reporter (filters output)
    """
    target_scope: TargetScope = TargetScope.FULL_APP
    vuln_scope: VulnScope = VulnScope.ALL
    target_url: str = ""

    # For NAVIGATION_PATH: pattern like "/admin/*" or "/api/v2/users/*"
    navigation_pattern: str = ""

    # For SPECIFIC_ENDPOINT: exact URL or method+url
    specific_url: str = ""
    specific_method: str = "GET"

    # For PAGE_DESCRIPTION: plain English description for Mode 3 page agent
    page_description: str = ""

    # For SINGLE/SELECTED vuln scope: list of vuln class names
    selected_vulns: list = field(default_factory=list)

    def matches_url(self, url: str) -> bool:
        """Return True if a discovered URL is in scope."""
        if self.target_scope == TargetScope.FULL_APP:
            # Same-domain check
            target_host = urlparse(self.target_url).hostname or ""
            url_host = urlparse(url).hostname or ""
            return target_host == url_host

        if self.target_scope == TargetScope.NAVIGATION_PATH:
            # Pattern match with * wildcard
            pattern = self.navigation_pattern
            if not pattern:
                return True
            # Convert glob to regex
            regex = re.escape(pattern).replace(r"\*", ".*")
            target_host = urlparse(self.target_url).hostname or ""
            url_parsed = urlparse(url)
            if url_parsed.hostname and url_parsed.hostname != target_host:
                return False
            return bool(re.search(regex, url_parsed.path or ""))

        if self.target_scope == TargetScope.SPECIFIC_ENDPOINT:
            return url.rstrip("/") == self.specific_url.rstrip("/")

        if self.target_scope == TargetScope.PAGE_DESCRIPTION:
            # Page description always uses the specific URL
            return url.rstrip("/") == self.target_url.rstrip("/")

        return True

    def matches_vuln_class(self, vuln_class: str) -> bool:
        """Return True if a vuln class should be tested under this scope (fuzzy match)."""
        if self.vuln_scope == VulnScope.ALL:
            return True
        for selected in self.selected_vulns:
            if _fuzzy_vuln_match(selected, vuln_class):
                return True
        return False

    def filter_endpoints(self, endpoints: list) -> list:
        """Filter a list of endpoint dicts to those in scope."""
        if self.target_scope == TargetScope.FULL_APP:
            return endpoints
        if self.target_scope == TargetScope.SPECIFIC_ENDPOINT:
            return [e for e in endpoints if e.get("url", "").rstrip("/") == self.specific_url.rstrip("/")]
        if self.target_scope == TargetScope.PAGE_DESCRIPTION:
            return [e for e in endpoints if e.get("url", "").rstrip("/") == self.target_url.rstrip("/")]
        if self.target_scope == TargetScope.NAVIGATION_PATH:
            return [e for e in endpoints if self.matches_url(e.get("url", ""))]
        return endpoints

    def filter_classification_scanners(self, scanner_priorities: dict) -> dict:
        """
        Filter the AI classifier's scanner priorities by vuln scope.

        If operator said "only test SQLi and XSS", return only the SQLi/XSS
        scanner priorities. Skip everything else.
        """
        if self.vuln_scope == VulnScope.ALL:
            return scanner_priorities

        # Map vuln class names to scanner names
        from mantis.core.ai_classifier import VULN_CLASS_TO_SCANNERS

        selected_lower = [v.lower() for v in self.selected_vulns]
        allowed_scanners = set()
        for vuln_class, scanners in VULN_CLASS_TO_SCANNERS.items():
            if vuln_class.lower() in selected_lower:
                allowed_scanners.update(scanners)

        return {k: v for k, v in scanner_priorities.items() if k in allowed_scanners}

    def describe(self) -> str:
        """Human-readable description of the scope."""
        parts = []

        # Target
        if self.target_scope == TargetScope.FULL_APP:
            parts.append(f"target: full app ({self.target_url})")
        elif self.target_scope == TargetScope.NAVIGATION_PATH:
            parts.append(f"target: path {self.navigation_pattern} on {self.target_url}")
        elif self.target_scope == TargetScope.SPECIFIC_ENDPOINT:
            parts.append(f"target: {self.specific_method} {self.specific_url}")
        elif self.target_scope == TargetScope.PAGE_DESCRIPTION:
            parts.append(f"target: page at {self.target_url} ('{self.page_description[:80]}')")

        # Vulns
        if self.vuln_scope == VulnScope.ALL:
            parts.append("vulns: all classes")
        elif self.vuln_scope == VulnScope.SINGLE:
            parts.append(f"vuln: {self.selected_vulns[0] if self.selected_vulns else '(none)'}")
        elif self.vuln_scope == VulnScope.SELECTED:
            parts.append(f"vulns: {', '.join(self.selected_vulns)}")

        return " | ".join(parts)


def parse_scope_from_cli(
    target: str,
    only_vuln: str = "",
    vulns: str = "",
    path: str = "",
    endpoint: str = "",
    page_description: str = "",
    method: str = "GET",
) -> EngagementScope:
    """
    Build an EngagementScope from CLI flags.

    Flag semantics:
        --target https://app.com           → FULL_APP + ALL
        --only-vuln SQLi --target ...      → FULL_APP + SINGLE
        --vulns SQLi,XSS,SSTI --target ... → FULL_APP + SELECTED
        --path /admin/* --target ...       → NAVIGATION_PATH + ALL (or +SINGLE/SELECTED)
        --endpoint /api/login --target ... → SPECIFIC_ENDPOINT + ALL (or +SINGLE/SELECTED)
        --page-description "..." --target  → PAGE_DESCRIPTION + ALL (or filtered)
    """
    scope = EngagementScope(target_url=target)

    # Determine target scope (most specific wins)
    if page_description:
        scope.target_scope = TargetScope.PAGE_DESCRIPTION
        scope.page_description = page_description
    elif endpoint:
        scope.target_scope = TargetScope.SPECIFIC_ENDPOINT
        # If endpoint is just a path, join with target
        if endpoint.startswith("/"):
            base = target.rstrip("/")
            scope.specific_url = base + endpoint
        else:
            scope.specific_url = endpoint
        scope.specific_method = method.upper()
    elif path:
        scope.target_scope = TargetScope.NAVIGATION_PATH
        scope.navigation_pattern = path
    else:
        scope.target_scope = TargetScope.FULL_APP

    # Determine vuln scope
    if only_vuln:
        scope.vuln_scope = VulnScope.SINGLE
        scope.selected_vulns = [only_vuln.strip()]
    elif vulns:
        parts = [v.strip() for v in vulns.split(",") if v.strip()]
        if len(parts) == 1:
            scope.vuln_scope = VulnScope.SINGLE
        else:
            scope.vuln_scope = VulnScope.SELECTED
        scope.selected_vulns = parts
    else:
        scope.vuln_scope = VulnScope.ALL

    return scope



# Synonym dictionary — maps user-input forms to canonical class names
VULN_SYNONYMS = {
    # SQL Injection variants
    "sqli": ["sql injection", "sql-injection", "sql_injection", "sqlinjection", "sqli", "sql"],
    # XSS variants
    "xss": ["xss", "cross site scripting", "cross-site scripting", "cross_site_scripting",
            "reflected xss", "stored xss", "dom xss", "dom-xss"],
    # SSTI
    "ssti": ["ssti", "server side template injection", "server-side template injection",
             "template injection", "jinja injection", "twig injection"],
    # Command Injection
    "cmdi": ["cmdi", "command injection", "command-injection", "command_injection",
             "os command injection", "shell injection", "rce", "remote code execution"],
    # Path Traversal
    "path_traversal": ["path traversal", "path-traversal", "lfi", "local file inclusion",
                        "directory traversal", "file inclusion", "path traversal"],
    # SSRF
    "ssrf": ["ssrf", "server side request forgery", "server-side request forgery"],
    # XXE
    "xxe": ["xxe", "xml external entity", "xml-external-entity",
            "external entity", "xml injection"],
    # LDAP
    "ldap": ["ldap", "ldap injection", "ldap-injection"],
    # XPath
    "xpath": ["xpath", "xpath injection", "xpath-injection"],
    # NoSQL
    "nosql": ["nosql", "nosql injection", "mongodb injection", "no-sql"],
    # CRLF
    "crlf": ["crlf", "crlf injection", "http response splitting", "header injection"],
    # SSI
    "ssi": ["ssi", "ssi injection", "server side includes"],
    # Open Redirect
    "open_redirect": ["open redirect", "open-redirect", "open_redirect", "redirect", "openredirect"],
    # CSRF
    "csrf": ["csrf", "cross site request forgery", "cross-site request forgery", "xsrf"],
    # CORS
    "cors": ["cors", "cors misconfiguration", "cross origin", "cross-origin"],
    # Clickjacking
    "clickjacking": ["clickjacking", "ui redress", "ui-redress", "frame injection"],
    # JSONP
    "jsonp": ["jsonp", "jsonp hijacking", "json hijacking"],
    # postMessage
    "postmessage": ["postmessage", "post message", "postmessage origin"],
    # DOM Clobbering
    "dom_clobbering": ["dom clobbering", "dom-clobbering", "dom_clobbering"],
    # CSS Injection
    "css_injection": ["css injection", "css-injection", "css_injection"],
    # Web Storage
    "web_storage": ["web storage", "localstorage", "sessionstorage", "web-storage"],
    # Verb Tampering
    "verb_tampering": ["verb tampering", "verb-tampering", "http method tampering",
                        "http verb", "method override"],
    # Method Override
    "method_override": ["method override", "method-override", "http method override"],
    # Content-Type Confusion
    "content_type_confusion": ["content type confusion", "content-type confusion",
                                 "ct confusion"],
    # Host Header
    "host_header": ["host header", "host-header", "host header injection"],
    # Subdomain Takeover
    "subdomain_takeover": ["subdomain takeover", "subdomain-takeover", "dangling dns"],
    # Smuggling
    "request_smuggling": ["request smuggling", "http smuggling", "http desync", "desync"],
    # WebSocket
    "websocket": ["websocket", "ws", "cswsh", "websocket hijacking"],
    # Token Leakage
    "token_leakage": ["token leakage", "token leak", "referer leak", "referrer leak"],
    # Session
    "session_fixation": ["session fixation", "session-fixation", "session management"],
    # MFA
    "mfa_bypass": ["mfa bypass", "mfa-bypass", "2fa bypass", "two factor bypass"],
    # File Upload
    "file_upload": ["file upload", "file-upload", "upload bypass", "extension bypass"],
    # ImageTragick
    "imagetragick": ["imagetragick", "image-tragick", "image processing rce",
                      "imagemagick rce"],
    # ZipSlip
    "zipslip": ["zipslip", "zip slip", "zip-slip", "archive traversal"],
    # PDF SSRF
    "pdf_ssrf": ["pdf ssrf", "pdf-ssrf", "pdf generation ssrf", "wkhtmltopdf ssrf"],
    # CSV Injection
    "csv_injection": ["csv injection", "csv-injection", "formula injection",
                       "spreadsheet injection"],
    # Cache Poisoning
    "cache_poisoning": ["cache poisoning", "cache-poisoning", "web cache poisoning"],
    # Padding Oracle
    "padding_oracle": ["padding oracle", "padding-oracle", "cbc padding"],
    # Timing Attack
    "timing_attack": ["timing attack", "timing-attack", "timing oracle"],
    # Race Condition
    "race_condition": ["race condition", "race-condition", "toctou", "race"],
    # Mass Assignment
    "mass_assignment": ["mass assignment", "mass-assignment", "mass_assignment",
                         "autobind", "auto-binding"],
    # Prototype Pollution
    "prototype_pollution": ["prototype pollution", "prototype-pollution", "proto pollution"],
    # HPP
    "hpp": ["hpp", "http parameter pollution", "parameter pollution"],
    # JWT
    "jwt": ["jwt", "json web token", "jwt attack", "jwt vulnerabilities"],
    # OAuth
    "oauth": ["oauth", "oauth2", "oauth flaws", "oidc"],
    # GraphQL
    "graphql": ["graphql", "graphql injection", "graphql introspection"],
    # gRPC
    "grpc_reflection": ["grpc", "grpc reflection", "grpc-reflection"],
    # ReDoS
    "redos": ["redos", "re-dos", "regex dos", "catastrophic backtracking"],
    # Exposed files
    "exposed_files": ["exposed files", "exposed-files", "sensitive files",
                       ".git exposure", "git exposure"],
    # Source maps
    "source_maps": ["source maps", "source-maps", "js maps", "sourcemap"],
    # API versioning
    "api_versioning": ["api versioning", "api-versioning", "api version bypass"],
    # BOLA
    "bola": ["bola", "idor", "insecure direct object reference",
              "broken object level authorization"],
    # BFLA
    "bfla": ["bfla", "broken function level authorization"],
    # Insecure Deserialization
    "insecure_deserialization": ["insecure deserialization", "deserialization",
                                   "unsafe deserialization", "java deserialization",
                                   "pickle deserialization"],
    # Information Disclosure
    "information_disclosure": ["information disclosure", "info disclosure",
                                "info leak", "data exposure"],
    # SAML
    "saml": ["saml", "saml sso", "saml vulnerabilities", "xsw", "signature wrapping"],
    # Rate Limiting
    "rate_limiting": ["rate limiting", "rate limit", "rate-limit", "throttle bypass"],
    # Password Reset
    "password_reset": ["password reset", "password-reset", "password recovery",
                        "reset token"],
}


def _normalize(s: str) -> str:
    """Normalize a string for matching: lowercase, strip, collapse spaces/dashes/underscores."""
    return s.lower().strip().replace("-", " ").replace("_", " ")


def _fuzzy_vuln_match(user_input: str, canonical: str) -> bool:
    """
    Fuzzy match user input against a canonical vuln class name.

    Returns True if:
    - User input exactly matches the canonical name (case-insensitive)
    - User input is a known synonym in VULN_SYNONYMS
    - User input is a substring match against the canonical or its synonyms
    - Levenshtein distance is small (typo tolerance)
    """
    if not user_input or not canonical:
        return False

    ui = _normalize(user_input)
    can = _normalize(canonical)

    # Exact match
    if ui == can:
        return True

    # Synonym match — check if user_input is a synonym of canonical
    for canon_key, synonyms in VULN_SYNONYMS.items():
        if _normalize(canon_key) == can:
            if ui in [_normalize(s) for s in synonyms]:
                return True

    # Reverse: canonical might be a synonym of user_input
    for canon_key, synonyms in VULN_SYNONYMS.items():
        normalized_syns = [_normalize(s) for s in synonyms]
        if ui in normalized_syns and _normalize(canon_key) == can:
            return True

    # Substring match (both directions)
    if ui in can or can in ui:
        return True

    # Levenshtein for typos (only for short strings to avoid noise)
    if len(ui) <= 20 and len(can) <= 20:
        if _levenshtein(ui, can) <= 2:
            return True

    return False


def _levenshtein(a: str, b: str) -> int:
    """Simple Levenshtein distance for typo tolerance."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        cur = [i + 1]
        for j, cb in enumerate(b):
            ins = prev[j + 1] + 1
            del_ = cur[j] + 1
            sub = prev[j] + (ca != cb)
            cur.append(min(ins, del_, sub))
        prev = cur
    return prev[-1]


def expand_vuln_input_to_canonical(user_input: str) -> list[str]:
    """
    Given a user's vuln string, return all canonical class names it could mean.
    Useful for showing the operator what their input matched against.
    """
    matched = []
    for canon_key in VULN_SYNONYMS:
        if _fuzzy_vuln_match(user_input, canon_key):
            matched.append(canon_key)
    return matched
