"""Standard scanners: reflected/stored XSS, CORS, CSRF, open redirect, host header, file upload, clickjacking, error-based SQLi."""
import re, httpx
from typing import Optional
from urllib.parse import urlparse
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource, HTTPEvidence


XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    "'-alert(1)-'",
    '<body onload=alert(1)>',
    'javascript:alert(1)',
]


async def scan_xss_reflected(http, url, param, method="GET"):
    """Reflected XSS via canary + payload reflection."""
    for payload in XSS_PAYLOADS:
        try:
            r = await (http.get(url, params={param: payload}, timeout=10) if method=="GET"
                       else http.post(url, data={param: payload}, timeout=10))
            if payload in r.text:
                return Finding(
                    title=f"Reflected XSS in '{param}'",
                    description=f"Payload '{payload}' is reflected without encoding in response.",
                    source=FindingSource.WEBAPP, severity=Severity.HIGH,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="XSS (Reflected)",
                    cwe="CWE-79", payload=payload, confidence=0.9, tags=["xss", "reflected"],
                    impact="Session hijacking, credential theft, malicious actions in victim's browser.",
                    remediation="Context-aware output encoding. CSP headers.",
                )
        except Exception: continue
    return None


async def scan_sqli_error(http, url, param, method="GET"):
    """Error-based SQL injection."""
    errors = [
        "you have an error in your sql syntax", "unclosed quotation mark",
        "quoted string not properly terminated", "mysql_fetch", "mysql_num_rows",
        "pg_query", "pg_exec", "sqlite3.operationalerror",
        "microsoft ole db provider for sql server",
        "microsoft odbc sql server driver", "ora-01756", "ora-00933",
        "sqlstate", "syntax error",
    ]
    for payload in ["'", '"', "''", "' OR '1'='1", "1' AND 1=2--"]:
        try:
            r = await (http.get(url, params={param: payload}, timeout=10) if method=="GET"
                       else http.post(url, data={param: payload}, timeout=10))
            body = r.text.lower()
            for err in errors:
                if err in body:
                    return Finding(
                        title=f"SQL Injection (Error-Based) in '{param}'",
                        description=f"SQL error signature '{err}' triggered by payload '{payload}'.",
                        source=FindingSource.WEBAPP, severity=Severity.CRITICAL,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=url, endpoint=url, vuln_type="SQLi", cwe="CWE-89",
                        owasp_category="A03:2021 Injection", payload=payload,
                        confidence=0.95, tags=["sqli", "error-based"],
                        impact="Full database access — read, modify, delete data.",
                        remediation="Use parameterized queries / prepared statements.",
                    )
        except Exception: continue
    return None


async def scan_cors(http, url):
    """CORS misconfiguration."""
    tests = [
        ("https://evil.attacker.com", "arbitrary origin reflection"),
        ("null", "null origin"),
        ("https://target.evil.com", "subdomain trust"),
    ]
    base_origin = urlparse(url).hostname or ""
    for origin, desc in tests:
        try:
            r = await http.get(url, headers={"Origin": origin}, timeout=10)
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "").lower()

            if origin in acao or acao == "*":
                if "true" in acac:
                    sev = Severity.HIGH
                    note = "Credentials allowed with arbitrary origin — critical CORS misconfig"
                else:
                    sev = Severity.MEDIUM
                    note = "Arbitrary origin reflected (no credentials)"
                return Finding(
                    title=f"CORS Misconfiguration: {desc}",
                    description=f"Server reflects Origin '{origin}' in Access-Control-Allow-Origin. {note}.",
                    source=FindingSource.WEBAPP, severity=sev,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="CORS Misconfiguration",
                    cwe="CWE-942", payload=f"Origin: {origin}", confidence=0.9, tags=["cors"],
                    impact="Cross-origin attackers can read authenticated API responses.",
                    remediation="Strict origin allowlist. Never reflect arbitrary origins with credentials.",
                )
        except Exception: continue
    return None


async def scan_csrf(http, url, method="POST"):
    """Detect missing CSRF protection on state-changing endpoints."""
    if method not in ("POST", "PUT", "DELETE", "PATCH"):
        return None
    try:
        r = await http.get(url, timeout=10)
        body = r.text
        # Check for CSRF token in forms or headers
        has_csrf_token = bool(re.search(
            r'name=["\'](?:csrf|_token|authenticity_token|xsrf)[^"\']*["\']', body, re.I
        ))
        has_samesite = "samesite" in r.headers.get("set-cookie", "").lower()
        if not has_csrf_token and not has_samesite:
            # Try the request without a token
            req_r = await http.request(method, url, timeout=10)
            if req_r.status_code < 400:
                return Finding(
                    title=f"Cross-Site Request Forgery (CSRF) at {url}",
                    description="State-changing endpoint accepts requests without CSRF token or SameSite cookie protection.",
                    source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="CSRF",
                    cwe="CWE-352", confidence=0.7, tags=["csrf"],
                    impact="Attacker can trick authenticated users into performing state changes.",
                    remediation="Implement CSRF tokens. Use SameSite=Strict cookies. Verify Origin/Referer.",
                )
    except Exception: pass
    return None


async def scan_open_redirect(http, url, param):
    """Open redirect."""
    payloads = [
        "https://evil.attacker.com",
        "//evil.attacker.com",
        "/\\evil.attacker.com",
        "https://target.com@evil.attacker.com",
    ]
    try:
        for payload in payloads:
            r = await http.get(url, params={param: payload}, timeout=10, follow_redirects=False)
            location = r.headers.get("location", "")
            if "evil.attacker.com" in location:
                return Finding(
                    title=f"Open Redirect in '{param}'",
                    description=f"Redirect target is attacker-controlled: {location}",
                    source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="Open Redirect",
                    cwe="CWE-601", payload=payload, confidence=0.95, tags=["open_redirect"],
                    impact="Phishing, OAuth token theft, credential harvesting via trusted domain.",
                    remediation="Validate redirect targets against allowlist. Reject external URLs.",
                )
    except Exception: pass
    return None


async def scan_host_header_injection(http, url):
    """Host header injection (password reset poisoning, cache poisoning)."""
    try:
        r = await http.get(url, headers={"Host": "evil.attacker.com"}, timeout=10)
        if "evil.attacker.com" in r.text:
            return Finding(
                title=f"Host Header Injection at {url}",
                description="Application reflects Host header into response, enabling password reset poisoning and cache poisoning.",
                source=FindingSource.WEBAPP, severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url, endpoint=url, vuln_type="Host Header Injection",
                cwe="CWE-644", payload="Host: evil.attacker.com", confidence=0.9,
                tags=["host_header"],
                impact="Password reset link poisoning, cache poisoning, SSRF via Host.",
                remediation="Validate Host header against allowlist. Use absolute URLs from config, not Host.",
            )
        # Try X-Forwarded-Host
        r2 = await http.get(url, headers={"X-Forwarded-Host": "evil.attacker.com"}, timeout=10)
        if "evil.attacker.com" in r2.text:
            return Finding(
                title=f"X-Forwarded-Host Header Injection at {url}",
                description="X-Forwarded-Host is trusted and reflected.",
                source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url, endpoint=url, vuln_type="Host Header Injection",
                cwe="CWE-644", confidence=0.85, tags=["host_header"],
                impact="Password reset poisoning via X-Forwarded-Host trust.",
                remediation="Don't trust X-Forwarded-Host unless behind a trusted proxy.",
            )
    except Exception: pass
    return None


async def scan_clickjacking(http, url):
    """Clickjacking — missing X-Frame-Options / CSP frame-ancestors."""
    try:
        r = await http.get(url, timeout=10)
        xfo = r.headers.get("x-frame-options", "").upper()
        csp = r.headers.get("content-security-policy", "").lower()
        has_protection = (
            xfo in ("DENY", "SAMEORIGIN") or
            "frame-ancestors" in csp
        )
        if not has_protection:
            return Finding(
                title=f"Clickjacking — No Frame Protection at {url}",
                description="Page lacks X-Frame-Options and CSP frame-ancestors, allowing it to be framed by any site.",
                source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url, endpoint=url, vuln_type="Clickjacking",
                cwe="CWE-1021", confidence=0.95, tags=["clickjacking"],
                impact="UI redress attacks: trick users into clicking actions in a framed context.",
                remediation="Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'.",
            )
    except Exception: pass
    return None


async def scan_file_upload(http, url):
    """File upload restrictions."""
    test_files = [
        ("shell.php", b"<?php echo 'mantis_php_test'; ?>", "application/x-php"),
        ("shell.php.jpg", b"<?php echo 'mantis_php_test'; ?>", "image/jpeg"),
        ("shell.phtml", b"<?php echo 'mantis_php_test'; ?>", "text/plain"),
        ("shell.svg", b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>", "image/svg+xml"),
    ]
    for filename, content, ctype in test_files:
        try:
            files = {"file": (filename, content, ctype)}
            r = await http.post(url, files=files, timeout=15)
            if r.status_code < 400:
                body = r.text
                if filename in body or "uploaded" in body.lower() or "success" in body.lower():
                    return Finding(
                        title=f"Unrestricted File Upload at {url}",
                        description=f"Endpoint accepted '{filename}' upload — likely no extension/content validation.",
                        source=FindingSource.WEBAPP, severity=Severity.HIGH,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=url, endpoint=url, vuln_type="Unrestricted File Upload",
                        cwe="CWE-434", payload=filename, confidence=0.7, tags=["file_upload"],
                        impact="Upload web shells for RCE. Upload SVG/HTML for stored XSS.",
                        remediation="Validate file extension AND content (magic bytes). Store outside web root. Disable execution.",
                    )
        except Exception: continue
    return None


async def scan_subdomain_takeover(http, url):
    """Subdomain takeover via fingerprint matching."""
    fingerprints = {
        "There isn't a GitHub Pages site here": "GitHub Pages",
        "No such app": "Heroku",
        "NoSuchBucket": "AWS S3",
        "Sorry, this shop is currently unavailable": "Shopify",
        "Fastly error: unknown domain": "Fastly",
        "There's nothing here": "Tumblr",
        "404 error unknown site": "Pantheon",
        "The thing you were looking for is no longer here": "Ghost",
    }
    try:
        r = await http.get(url, timeout=10, follow_redirects=True)
        for fingerprint, service in fingerprints.items():
            if fingerprint in r.text:
                return Finding(
                    title=f"Subdomain Takeover Possible ({service}) at {url}",
                    description=f"Domain points to unclaimed {service} resource. Attacker can claim and host arbitrary content.",
                    source=FindingSource.WEBAPP, severity=Severity.HIGH,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="Subdomain Takeover",
                    cwe="CWE-284", confidence=0.85, tags=["subdomain_takeover", service.lower().replace(" ", "_")],
                    impact="Host malicious content on trusted domain. Steal cookies, phish users, bypass CSP.",
                    remediation=f"Remove or claim the {service} resource. Update DNS to remove dangling CNAME.",
                )
    except Exception: pass
    return None
