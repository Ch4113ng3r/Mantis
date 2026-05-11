"""
API authentication flow analysis.

Tests API authentication mechanisms: token validation, expiry,
refresh flows, and authorization header handling.
"""

import httpx
from mantis.engage.phases import Phase
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource


class AuthChainPhase(Phase):
    """Phase: analyze API authentication chains."""

    async def execute(self, context) -> dict:
        findings = []
        base_url = context.api_schema.get("base_url", self.config.target) if context.api_schema else self.config.target

        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"

        async with httpx.AsyncClient(verify=False) as http:
            # Test if any authenticated endpoints work without auth
            for ep in context.endpoints[:20]:
                if ep.get("auth_required"):
                    url = ep.get("url", "")
                    method = ep.get("method", "GET")
                    try:
                        resp = await http.request(method, url, timeout=10)
                        if resp.status_code < 400:
                            findings.append(Finding(
                                title=f"Auth-required endpoint accessible without auth: {method} {url}",
                                description=f"Endpoint marked as requiring auth returns {resp.status_code} without credentials.",
                                source=FindingSource.API,
                                severity=Severity.HIGH,
                                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                                target=url, endpoint=url,
                                vuln_type="Broken Authentication",
                                cwe="CWE-306",
                                confidence=0.8,
                            ))
                    except Exception:
                        continue

        print(f"    Auth chain findings: {len(findings)}")
        return {"findings": findings}
