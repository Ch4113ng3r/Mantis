"""HTTP protocol scanners: verb tampering, method override, Content-Type confusion, request smuggling probe, WebSocket smuggling."""
import asyncio, httpx
from typing import Optional
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource


async def scan_verb_tampering(http, url):
    """HTTP verb tampering — using unusual methods to bypass access control."""
    try:
        # GET baseline
        get_r = await http.get(url, timeout=10)
        baseline_status = get_r.status_code

        # If GET is blocked (401/403), try HEAD, OPTIONS, alternative methods
        if baseline_status in (401, 403):
            for method in ["HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH", "TRACE"]:
                try:
                    r = await http.request(method, url, timeout=10)
                    if r.status_code < 400 or (r.status_code != baseline_status and r.status_code < 500):
                        return Finding(
                            title=f"HTTP Verb Tampering at {url}",
                            description=f"GET returned {baseline_status} (blocked), but {method} returned {r.status_code}.",
                            source=FindingSource.WEBAPP, severity=Severity.HIGH,
                            evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                            target=url, endpoint=url, vuln_type="HTTP Verb Tampering",
                            cwe="CWE-650", payload=method, confidence=0.85, tags=["verb_tampering"],
                            impact="Bypass access controls by using non-standard HTTP methods.",
                            remediation="Apply access controls to all HTTP methods, not just GET/POST.",
                        )
                except Exception: continue
    except Exception: pass
    return None


async def scan_http_method_override(http, url):
    """X-HTTP-Method-Override header bypass."""
    try:
        # Try DELETE via X-HTTP-Method-Override on a POST
        r = await http.post(url, headers={"X-HTTP-Method-Override": "DELETE"}, timeout=10)
        baseline = await http.delete(url, timeout=10)
        if baseline.status_code in (401, 403, 405) and r.status_code < 400:
            return Finding(
                title=f"HTTP Method Override Bypass at {url}",
                description="X-HTTP-Method-Override header bypasses method-based access controls.",
                source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url, endpoint=url, vuln_type="HTTP Method Override",
                cwe="CWE-650", confidence=0.85, tags=["method_override"],
                impact="Bypass restrictions on dangerous methods (DELETE, PUT) via header override.",
                remediation="Don't process X-HTTP-Method-Override or apply same access control to overridden method.",
            )
    except Exception: pass
    return None


async def scan_content_type_confusion(http, url, param):
    """Content-Type confusion — sending JSON as form-encoded or vice versa."""
    try:
        # If endpoint expects JSON, try form-encoded
        json_r = await http.post(url, json={param: "test"}, timeout=10)
        form_r = await http.post(url, data={param: "test"}, timeout=10)

        # If both work the same way, framework might allow Content-Type bypass
        if (json_r.status_code < 400 and form_r.status_code < 400
            and abs(len(json_r.text) - len(form_r.text)) < 100):
            # Try sending JSON with text/plain Content-Type (some Spring/Django bypass)
            text_r = await http.post(
                url,
                content='{"' + param + '":"test"}',
                headers={"Content-Type": "text/plain"},
                timeout=10,
            )
            if text_r.status_code < 400:
                return Finding(
                    title=f"Content-Type Confusion at {url}",
                    description="Endpoint accepts multiple content types including text/plain for JSON body — may bypass CSRF protection.",
                    source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="Content-Type Confusion",
                    cwe="CWE-436", confidence=0.7, tags=["content_type"],
                    impact="Bypass CSRF protection (no preflight for text/plain) or input validation.",
                    remediation="Strict Content-Type validation. Reject unexpected content types.",
                )
    except Exception: pass
    return None


async def scan_request_smuggling_basic(http, url):
    """Basic CL.TE / TE.CL probe via httpx (limited — full smuggling requires raw socket)."""
    # Note: full HTTP smuggling testing requires raw HTTP control which httpx doesn't provide.
    # This is a basic probe that detects whether the server processes Transfer-Encoding alongside Content-Length.
    try:
        # Send a request with both CL and TE headers
        body = "0\r\n\r\n"
        r = await http.post(
            url,
            content=body,
            headers={
                "Content-Length": str(len(body)),
                "Transfer-Encoding": "chunked",
            },
            timeout=10,
        )
        # Hard to determine from a single request — flag for manual review
        if r.status_code in (200, 400):
            return Finding(
                title=f"Potential HTTP Request Smuggling at {url} (needs manual verification)",
                description="Server accepts requests with both Content-Length and Transfer-Encoding. Requires manual testing with smuggler tool.",
                source=FindingSource.WEBAPP, severity=Severity.HIGH,
                evidence_level=EvidenceLevel.SUSPICION,
                target=url, endpoint=url, vuln_type="HTTP Request Smuggling",
                cwe="CWE-444", confidence=0.3, tags=["smuggling", "manual_review"],
                impact="If exploitable: bypass front-end controls, hijack other users' requests, cache poisoning.",
                remediation="Reject requests with both CL and TE. Use HTTP/2 end-to-end.",
            )
    except Exception: pass
    return None


async def scan_websocket_endpoints(http, url):
    """Detect WebSocket endpoints and check for cross-origin protection."""
    try:
        r = await http.get(url, headers={
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "x3JJHMbDL1EzLkh9GBhXDw==",
            "Origin": "https://evil.attacker.com",
        }, timeout=10)
        if r.status_code in (101, 200) and "upgrade" in r.headers.get("connection", "").lower():
            return Finding(
                title=f"WebSocket Endpoint Accepts Cross-Origin Upgrade at {url}",
                description="WebSocket endpoint accepted upgrade request from arbitrary origin.",
                source=FindingSource.WEBAPP, severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url, endpoint=url, vuln_type="Cross-Site WebSocket Hijacking",
                cwe="CWE-346", confidence=0.8, tags=["websocket", "cswsh"],
                impact="Cross-site WebSocket hijacking — attacker can interact with WebSocket as victim.",
                remediation="Validate Origin header on WebSocket upgrade. Use authentication tokens.",
            )
    except Exception: pass
    return None
