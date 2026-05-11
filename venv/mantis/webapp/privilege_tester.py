"""
Privilege escalation and access control tester.

Tests BOLA, BFLA, and vertical/horizontal privilege escalation by
replaying requests across different authentication contexts and
comparing responses.

Requires at least two auth contexts (e.g., admin + user) configured
in the credential store.
"""

import httpx
from typing import Optional

from mantis.core.auth import CredentialStore, AuthContext
from mantis.core.findings import (
    Finding, Severity, EvidenceLevel, FindingSource, HTTPEvidence,
)
from mantis.engage.phases import Phase


class PrivilegeTester:
    """
    Tests access control by replaying requests across auth contexts.

    The core technique:
    1. Make a request as the authorized role (e.g., admin)
    2. Record the response
    3. Replay the exact same request as a lower-privilege role
    4. Compare responses — if the data is the same, access control is broken

    This catches BOLA (accessing other users' objects), BFLA (calling
    admin functions as regular user), and vertical privilege escalation.
    """

    def __init__(self, cred_store: CredentialStore, http: httpx.AsyncClient):
        self.creds = cred_store
        self.http = http

    async def test_bola(
        self,
        url: str,
        object_id_param: str,
        owner_role: str = "user",
        attacker_role: str = "unauthenticated",
        method: str = "GET",
    ) -> Optional[Finding]:
        """
        Test for Broken Object Level Authorization (BOLA/IDOR).

        Makes a request as the owner, then replays with the attacker's
        session. If the attacker gets the same data, BOLA exists.
        """
        # Request as owner (should succeed)
        owner_ctx = self.creds.get(owner_role)
        if not owner_ctx or not owner_ctx.authenticated:
            return None

        h, c = owner_ctx.apply_to_request()
        owner_resp = await self.http.request(method, url, headers=h, cookies=c)

        if owner_resp.status_code >= 400:
            return None  # Owner can't even access it

        # Replay as attacker (should fail)
        attacker_resp = await self.creds.replay_as(
            self.http, method, url, attacker_role,
        )

        # Compare — if attacker gets 200 with similar content, BOLA confirmed
        if attacker_resp.status_code < 400:
            # Check if response bodies are similar (not just same status)
            owner_body = owner_resp.text[:1000]
            attacker_body = attacker_resp.text[:1000]

            # Simple similarity: if attacker gets >50% of the same content
            if len(attacker_body) > 50 and self._similarity(owner_body, attacker_body) > 0.5:
                return Finding(
                    title=f"BOLA: {attacker_role} can access {owner_role}'s data",
                    description=(
                        f"The endpoint {url} returns {owner_role}'s data when "
                        f"accessed as {attacker_role}. The object ID parameter "
                        f"'{object_id_param}' is not properly authorized."
                    ),
                    source=FindingSource.WEBAPP,
                    severity=Severity.HIGH,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url,
                    endpoint=url,
                    vuln_type="BOLA",
                    cwe="CWE-639",
                    owasp_category="API1:2023 Broken Object Level Authorization",
                    evidence=[
                        HTTPEvidence(
                            request_method=method,
                            request_url=url,
                            request_headers=dict(owner_resp.request.headers),
                            request_body=None,
                            response_status=owner_resp.status_code,
                            response_headers=dict(owner_resp.headers),
                            response_body=owner_body,
                            notes=f"Request as {owner_role} — returns data",
                        ),
                        HTTPEvidence(
                            request_method=method,
                            request_url=url,
                            request_headers=dict(attacker_resp.request.headers),
                            request_body=None,
                            response_status=attacker_resp.status_code,
                            response_headers=dict(attacker_resp.headers),
                            response_body=attacker_body,
                            notes=f"Request as {attacker_role} — ALSO returns data (BOLA!)",
                        ),
                    ],
                    reproduction_steps=[
                        f"1. Authenticate as {owner_role}",
                        f"2. Access {url} — note the response data",
                        f"3. Authenticate as {attacker_role}",
                        f"4. Access the same URL — observe the same data is returned",
                        f"5. The '{object_id_param}' parameter is not authorization-checked",
                    ],
                    impact=(
                        f"Any {attacker_role} can access any {owner_role}'s data "
                        f"by manipulating the {object_id_param} parameter. "
                        f"This enables mass data harvesting."
                    ),
                    remediation=(
                        "Implement object-level authorization checks. Verify that "
                        "the authenticated user owns or has permission to access "
                        "the requested object before returning data."
                    ),
                    confidence=0.9,
                )
        return None

    async def test_bfla(
        self,
        url: str,
        method: str = "POST",
        body: str = None,
        admin_role: str = "admin",
        user_role: str = "user",
    ) -> Optional[Finding]:
        """
        Test for Broken Function Level Authorization (BFLA).

        Tries to call admin-only endpoints as a regular user.
        """
        # First verify admin can do it
        admin_resp = await self.creds.replay_as(
            self.http, method, url, admin_role, body=body,
        )
        if admin_resp.status_code >= 400:
            return None  # Even admin can't — not a valid endpoint

        # Try as regular user
        user_resp = await self.creds.replay_as(
            self.http, method, url, user_role, body=body,
        )

        if user_resp.status_code < 400:
            return Finding(
                title=f"BFLA: {user_role} can access admin function at {url}",
                description=(
                    f"The admin-only endpoint {method} {url} is accessible "
                    f"by {user_role} role without proper authorization."
                ),
                source=FindingSource.WEBAPP,
                severity=Severity.CRITICAL,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url,
                endpoint=url,
                vuln_type="BFLA",
                cwe="CWE-285",
                owasp_category="API5:2023 Broken Function Level Authorization",
                impact="Regular users can perform administrative actions.",
                remediation="Implement role-based access control on all endpoints.",
                confidence=0.9,
            )
        return None

    async def test_vertical_privesc(
        self,
        endpoints: list[dict],
        low_role: str = "user",
        high_role: str = "admin",
    ) -> list[Finding]:
        """Test all discovered endpoints for vertical privilege escalation."""
        findings = []
        for ep in endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET")

            # Try accessing with low-privilege role
            resp = await self.creds.replay_as(self.http, method, url, low_role)

            if resp.status_code < 400:
                # Check if this endpoint has admin-indicative patterns
                admin_indicators = [
                    "/admin", "/manage", "/config", "/settings",
                    "/users/", "/roles", "/permissions", "/delete",
                    "/system", "/audit", "/logs",
                ]
                if any(ind in url.lower() for ind in admin_indicators):
                    findings.append(Finding(
                        title=f"Vertical Privilege Escalation: {low_role} accessing {url}",
                        description=f"Admin endpoint {method} {url} accessible as {low_role}.",
                        source=FindingSource.WEBAPP,
                        severity=Severity.HIGH,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=url, endpoint=url,
                        vuln_type="Privilege Escalation",
                        cwe="CWE-269",
                        confidence=0.7,
                    ))
        return findings

    def _similarity(self, a: str, b: str) -> float:
        """Simple Jaccard similarity between two strings."""
        if not a or not b:
            return 0.0
        words_a = set(a.lower().split())
        words_b = set(b.lower().split())
        intersection = words_a & words_b
        union = words_a | words_b
        return len(intersection) / len(union) if union else 0.0
