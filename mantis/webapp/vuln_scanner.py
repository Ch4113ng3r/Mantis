"""
Web application vulnerability scanner.

Contains detection functions for common web vulnerabilities
(XSS, SQLi, SSTI, etc.) and the VulnScanPhase for the pipeline.
"""

import httpx
from typing import Optional
from mantis.engage.phases import Phase
from mantis.core.findings import (
    Finding, Severity, EvidenceLevel, FindingSource, HTTPEvidence,
)


async def test_xss_reflected(
    http: httpx.AsyncClient, url: str, param: str,
) -> Optional[Finding]:
    """Test a URL parameter for reflected XSS."""
    payloads = [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "\'-alert(1)-\'",
        '{{7*7}}',  # Also checks for SSTI
    ]
    for payload in payloads:
        try:
            resp = await http.get(url, params={param: payload})
            if payload in resp.text:
                return Finding(
                    title=f"Reflected XSS in \'{param}\' parameter",
                    description=(
                        f"The parameter \'{param}\' at {url} reflects "
                        f"user input without sanitization."
                    ),
                    source=FindingSource.WEBAPP,
                    severity=Severity.HIGH,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url,
                    vuln_type="XSS", cwe="CWE-79",
                    owasp_category="A03:2021 Injection",
                    payload=payload,
                    evidence=[HTTPEvidence(
                        request_method="GET",
                        request_url=f"{url}?{param}={payload}",
                        request_headers=dict(resp.request.headers),
                        request_body=None,
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body=resp.text[:5000],
                        notes=f"Payload reflected in response body",
                    )],
                    reproduction_steps=[
                        f"1. Navigate to {url}",
                        f"2. Set parameter \'{param}\' to: {payload}",
                        f"3. Observe the payload reflected without encoding",
                    ],
                    impact=(
                        "An attacker can execute arbitrary JavaScript in the "
                        "victim\'s browser, stealing sessions or performing actions."
                    ),
                    remediation=(
                        "Implement context-aware output encoding. Use "
                        "Content-Security-Policy headers."
                    ),
                    confidence=0.9,
                )
        except Exception:
            continue
    return None


async def test_sqli(
    http: httpx.AsyncClient, url: str, param: str, method: str = "GET",
) -> Optional[Finding]:
    """Test a parameter for SQL injection using error-based detection."""
    sql_errors = [
        "you have an error in your sql syntax",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "mysql_fetch", "pg_query", "sqlite3.operationalerror",
        "microsoft ole db provider for sql server",
        "ora-01756",
    ]
    payloads = ["\'", "\' OR \'1\'=\'1", "1 AND 1=1", "1\' AND \'1\'=\'2"]

    for payload in payloads:
        try:
            if method.upper() == "GET":
                resp = await http.get(url, params={param: payload})
            else:
                resp = await http.post(url, data={param: payload})

            body_lower = resp.text.lower()
            for error_sig in sql_errors:
                if error_sig in body_lower:
                    return Finding(
                        title=f"SQL Injection in \'{param}\' parameter",
                        description=(
                            f"Error-based SQL injection detected in "
                            f"\'{param}\' at {url}."
                        ),
                        source=FindingSource.WEBAPP,
                        severity=Severity.CRITICAL,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=url, endpoint=url,
                        vuln_type="SQLi", cwe="CWE-89",
                        owasp_category="A03:2021 Injection",
                        payload=payload,
                        evidence=[HTTPEvidence(
                            request_method=method,
                            request_url=url,
                            request_headers={},
                            request_body=f"{param}={payload}",
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            response_body=resp.text[:5000],
                            notes=f"SQL error signature found: {error_sig}",
                        )],
                        impact="Full database access — read, modify, delete all data.",
                        remediation="Use parameterized queries / prepared statements.",
                        confidence=0.95,
                    )
        except Exception:
            continue
    return None


class VulnScanPhase(Phase):
    """Phase: scan discovered endpoints for web vulnerabilities."""

    async def execute(self, context) -> dict:
        findings = []

        # Initialize OOB callback server if not disabled
        oob_scanner = None
        try:
            from mantis.core.callback_server import CallbackServer
            from mantis.core.oob_scanner import OOBScanner
            from mantis.config import load_config
            config = load_config()
            oob_config = config.get("oob", {})
            if oob_config.get("enabled", True):
                cb_server = CallbackServer(
                    mode=oob_config.get("mode", "interactsh"),
                    local_port=oob_config.get("local_port", 8888),
                    external_url=oob_config.get("external_url", ""),
                )
                await cb_server.start()
        except Exception as e:
            print(f"    OOB server init skipped: {e}")
            cb_server = None

        async with httpx.AsyncClient(verify=False) as http:
            # Standard injection scanning
            for ep in context.endpoints[:50]:
                url = ep.get("url", "")
                for param in ep.get("params", []):
                    result = await test_xss_reflected(http, url, param)
                    if result:
                        findings.append(result)
                    result = await test_sqli(http, url, param)
                    if result:
                        findings.append(result)

            # OOB blind vulnerability scanning
            if cb_server:
                oob_scanner = OOBScanner(cb_server, http)
                oob_endpoints = context.endpoints[:30]  # Cap OOB tests
                print(f"    Running OOB blind tests on {len(oob_endpoints)} endpoints...")
                for ep in oob_endpoints:
                    url = ep.get("url", "")
                    params = ep.get("params", [])
                    if params:
                        oob_findings = await oob_scanner.scan_endpoint(
                            url=url, params=params,
                            method=ep.get("method", "GET"),
                            wait_seconds=oob_config.get("wait_seconds", 10),
                        )
                        findings.extend(oob_findings)

                # Final sweep for any late callbacks
                late_results = await cb_server.check_all_pending()
                for cb_id, callbacks in late_results:
                    finding = cb_server.build_finding(cb_id, callbacks)
                    if finding:
                        findings.append(finding)

                await cb_server.stop()

        oob_count = len([f for f in findings if "oob_confirmed" in f.tags])
        std_count = len(findings) - oob_count
        print(f"    Found {std_count} standard + {oob_count} OOB-confirmed vulnerabilities")
        return {"findings": findings}
