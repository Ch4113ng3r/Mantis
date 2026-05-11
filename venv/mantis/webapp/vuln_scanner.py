"""
Comprehensive web vulnerability scanner phase (v1.3).

Runs the full battery of 60+ vulnerability scanners across 7 categories
plus OOB blind vulnerability detection and SAML SSO testing.

See mantis/webapp/scanners/ for individual scanner implementations.
"""

import httpx
from mantis.engage.phases import Phase
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource, HTTPEvidence
from mantis.webapp.scanners import orchestrator


async def test_xss_reflected(http, url, param):
    """Legacy compat — delegates to standard scanner."""
    from mantis.webapp.scanners import standard
    return await standard.scan_xss_reflected(http, url, param)


async def test_sqli(http, url, param, method="GET"):
    """Legacy compat — delegates to standard scanner."""
    from mantis.webapp.scanners import standard
    return await standard.scan_sqli_error(http, url, param, method)


class VulnScanPhase(Phase):
    """Phase: comprehensive vulnerability scanning of all discovered attack surface."""

    async def execute(self, context) -> dict:
        findings = []

        # ── Initialize OOB callback infrastructure ──
        cb_server = None
        oob_cfg = {}
        try:
            from mantis.core.callback_server import CallbackServer
            from mantis.config import load_config
            cfg = load_config()
            oob_cfg = cfg.get("oob", {})
            if oob_cfg.get("enabled", True):
                cb_server = CallbackServer(
                    mode=oob_cfg.get("mode", "interactsh"),
                    local_port=oob_cfg.get("local_port", 8888),
                    external_url=oob_cfg.get("external_url", ""),
                )
                await cb_server.start()
        except Exception as e:
            print(f"    OOB init skipped: {e}")
            cb_server = None

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True,
            headers={"User-Agent": "MANTIS/1.3 Scanner"},
            timeout=httpx.Timeout(15.0),
        ) as http:

            # Site-level scans (exposed files, source maps, gRPC reflection)
            if context.endpoints:
                base_url = context.endpoints[0].get("url", self.config.target)
                print(f"    Running site-level scans...")
                try:
                    site_findings = await orchestrator.scan_site(http, base_url)
                    findings.extend(site_findings)
                    print(f"      Site-level findings: {len(site_findings)}")
                except Exception as e:
                    print(f"      Site-level scan error: {e}")

            # Endpoint-level scans
            scanned = 0
            for ep in context.endpoints[:50]:
                url = ep.get("url", "")
                params = ep.get("params", [])
                method = ep.get("method", "GET")
                try:
                    ep_findings = await orchestrator.scan_endpoint(http, url, params, method)
                    findings.extend(ep_findings)
                    scanned += 1
                except Exception:
                    continue
            print(f"    Scanned {scanned} endpoints — {len(findings)} findings so far")

            # OOB blind vulnerability scanning
            if cb_server:
                try:
                    from mantis.core.oob_scanner import OOBScanner
                    oob_scanner = OOBScanner(cb_server, http)
                    oob_eps = context.endpoints[:30]
                    print(f"    Running OOB blind tests on {len(oob_eps)} endpoints...")
                    for ep in oob_eps:
                        url = ep.get("url", "")
                        params = ep.get("params", [])
                        if params:
                            try:
                                oob_findings = await oob_scanner.scan_endpoint(
                                    url=url, params=params,
                                    method=ep.get("method", "GET"),
                                    wait_seconds=oob_cfg.get("wait_seconds", 10),
                                )
                                findings.extend(oob_findings)
                            except Exception: continue
                    # Final OOB sweep for late callbacks
                    try:
                        late = await cb_server.check_all_pending()
                        for cb_id, callbacks in late:
                            f = cb_server.build_finding(cb_id, callbacks)
                            if f: findings.append(f)
                    except Exception: pass
                    await cb_server.stop()
                except Exception as e:
                    print(f"    OOB scanning error: {e}")

            # SAML scanning (if SAML auth was used during auth_test phase)
            try:
                if hasattr(context, 'auth_tokens') and context.auth_tokens:
                    from mantis.webapp.saml_scanner import SAMLScanner
                    for role, info in context.auth_tokens.items():
                        if isinstance(info, dict) and info.get("saml_metadata"):
                            saml_meta = info["saml_metadata"]
                            acs_url = saml_meta.get("acs_url", "")
                            saml_response = saml_meta.get("saml_response", "")
                            if acs_url and saml_response:
                                print(f"    Running SAML SSO vulnerability tests...")
                                saml_scanner = SAMLScanner(http)
                                saml_findings = await saml_scanner.scan(
                                    acs_url=acs_url, saml_response_b64=saml_response,
                                )
                                findings.extend(saml_findings)
                                break
            except Exception:
                pass

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            if f.id not in seen:
                seen.add(f.id)
                unique.append(f)

        oob_count = sum(1 for f in unique if "oob_confirmed" in f.tags)
        std_count = len(unique) - oob_count
        print(f"    TOTAL: {std_count} standard + {oob_count} OOB ({len(unique)} unique findings)")
        return {"findings": unique}
