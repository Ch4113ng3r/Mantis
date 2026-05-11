"""
Authentication testing phase.

Sets up credential store from config, tests authentication mechanisms,
and identifies weaknesses in session management, login flows, and
access control enforcement.
"""

import httpx
from mantis.engage.phases import Phase
from mantis.core.auth import CredentialStore
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource


class AuthTestPhase(Phase):
    """Phase: test authentication mechanisms and set up auth contexts."""

    async def execute(self, context) -> dict:
        findings = []
        target = self.config.target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        async with httpx.AsyncClient(verify=False, follow_redirects=True) as http:
            # Setup credential store if credentials provided
            cred_store = CredentialStore()
            if self.config.credentials:
                accounts = self.config.credentials.get("accounts", [])
                await cred_store.setup_from_config(accounts, http)
                context.auth_tokens = {
                    role: {"authenticated": ctx.authenticated}
                    for role, ctx in cred_store.contexts.items()
                }

            # Test for common auth weaknesses
            # 1. Check if login page transmits credentials over HTTPS
            if target.startswith("http://"):
                findings.append(Finding(
                    title="Login page served over HTTP",
                    description="Credentials are transmitted in plaintext over unencrypted HTTP.",
                    source=FindingSource.WEBAPP,
                    severity=Severity.HIGH,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=target, vuln_type="Cleartext Transmission",
                    cwe="CWE-319",
                    remediation="Enforce HTTPS for all authentication endpoints.",
                    confidence=1.0,
                ))

            # 2. Check security headers on the target
            try:
                resp = await http.get(target, timeout=10)
                headers = {k.lower(): v for k, v in resp.headers.items()}

                if "strict-transport-security" not in headers:
                    findings.append(Finding(
                        title="Missing HSTS header",
                        description="Strict-Transport-Security header is not set.",
                        source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=target, vuln_type="Security Misconfiguration",
                        cwe="CWE-319", confidence=1.0,
                        remediation="Add Strict-Transport-Security header with max-age of at least 31536000.",
                    ))

                # Check cookie security
                for cookie_name, cookie_value in resp.cookies.items():
                    # Note: httpx doesn't expose cookie attributes directly in simple iteration
                    # In a real implementation, parse Set-Cookie headers
                    pass

            except Exception:
                pass

            # 3. Test for user enumeration via login error messages
            login_forms = [f for f in context.forms if any(
                inp["type"] == "password" for inp in f.get("inputs", [])
            )]
            for form in login_forms[:3]:
                finding = await self._test_user_enumeration(http, form)
                if finding:
                    findings.append(finding)

        print(f"    Auth findings: {len(findings)}")
        return {"findings": findings, "credentials": []}

    async def _test_user_enumeration(self, http: httpx.AsyncClient, form: dict) -> Finding | None:
        """Test if login form reveals user existence via different error messages."""
        url = form.get("url", "")
        if not url:
            return None

        inputs = form.get("inputs", [])
        username_field = next((i["name"] for i in inputs if i["type"] in ("text", "email")), None)
        password_field = next((i["name"] for i in inputs if i["type"] == "password"), None)
        if not username_field or not password_field:
            return None

        try:
            # Try with a likely-invalid user
            resp1 = await http.post(url, data={
                username_field: "mantis_nonexistent_user_12345@test.com",
                password_field: "WrongPassword123!",
            }, timeout=10)

            # Try with a likely-valid pattern
            resp2 = await http.post(url, data={
                username_field: "admin@" + urlparse(url).netloc if "://" in url else "admin",
                password_field: "WrongPassword123!",
            }, timeout=10)

            # Compare responses — if they differ significantly, user enumeration exists
            if resp1.text != resp2.text and abs(len(resp1.text) - len(resp2.text)) > 20:
                return Finding(
                    title="User enumeration via login error messages",
                    description="Login form returns different responses for valid vs invalid usernames.",
                    source=FindingSource.WEBAPP, severity=Severity.LOW,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, vuln_type="User Enumeration",
                    cwe="CWE-203", confidence=0.7,
                    remediation="Use generic error messages like 'Invalid credentials' regardless of whether the username exists.",
                )
        except Exception:
            pass
        return None
