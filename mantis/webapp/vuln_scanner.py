"""
Comprehensive web vulnerability scanner phase (v1.4 — mode-aware).

Runs the full battery of 51 scanners with AI-directed dispatch (Mode 1/2/3).
See mantis/core/scan_modes.py for mode definitions.
"""

import httpx
from mantis.engage.phases import Phase
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource, HTTPEvidence
from mantis.core.scan_modes import ModeAwareScanner, ScanDepth, MODE_CONFIGS


async def test_xss_reflected(http, url, param):
    """Legacy compat — delegates to standard scanner."""
    from mantis.webapp.scanners import standard
    return await standard.scan_xss_reflected(http, url, param)


async def test_sqli(http, url, param, method="GET"):
    """Legacy compat — delegates to standard scanner."""
    from mantis.webapp.scanners import standard
    return await standard.scan_sqli_error(http, url, param, method)


class VulnScanPhase(Phase):
    """Phase: comprehensive vulnerability scanning with AI-directed dispatch."""

    async def execute(self, context) -> dict:
        findings = []

        # Determine scan mode from config or CLI flag
        scan_depth_str = getattr(self.config, "scan_depth", "smart")
        try:
            mode = ScanDepth(scan_depth_str)
        except ValueError:
            mode = ScanDepth.SMART

        mode_config = MODE_CONFIGS[mode]
        print(f"    Scan mode: {mode.value.upper()} — {mode_config.description[:80]}")

        # Estimate cost before starting
        endpoint_count = len(context.endpoints)
        low, high = (
            endpoint_count * mode_config.estimated_cost_per_endpoint * 0.5,
            endpoint_count * mode_config.estimated_cost_per_endpoint * 2.0,
        )
        print(f"    Estimated AI cost: ${low:.2f} - ${high:.2f} for {endpoint_count} endpoints")

        # Warn if budget is exceeded
        if high > mode_config.budget_warning_usd:
            print(f"    [!] WARNING: estimated cost exceeds mode warning threshold "
                  f"(${mode_config.budget_warning_usd})")

        # Initialize the mode-aware scanner
        scanner = ModeAwareScanner(mode=mode, scope=getattr(self.config, 'scope', None))
        await scanner.initialize()

        # Initialize OOB callback infrastructure
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

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True,
            headers={"User-Agent": "MANTIS/1.4 Scanner"},
            timeout=httpx.Timeout(15.0),
        ) as http:

            # Site-level scans (these always run regardless of mode)
            if context.endpoints:
                base_url = context.endpoints[0].get("url", self.config.target)
                print(f"    Running site-level scans...")
                try:
                    from mantis.webapp.scanners import orchestrator
                    site_findings = await orchestrator.scan_site(http, base_url)
                    findings.extend(site_findings)
                    print(f"      Site-level findings: {len(site_findings)}")
                except Exception as e:
                    print(f"      Site-level scan error: {e}")

            # Mode-aware endpoint scanning
            scanned = 0
            for ep in context.endpoints[:100]:  # Cap for sanity
                url = ep.get("url", "")
                params = ep.get("params", [])
                method = ep.get("method", "GET")
                try:
                    ep_findings = await scanner.scan_endpoint(http, url, params, method)
                    findings.extend(ep_findings)
                    scanned += 1
                except Exception as e:
                    continue

            print(f"    Scanned {scanned} endpoints — "
                  f"{scanner.report.scanners_dispatched} scanners dispatched, "
                  f"{scanner.report.scanners_skipped} skipped via AI classification")
            print(f"    AI calls: {scanner.report.ai_classifications} classifications, "
                  f"{scanner.report.ai_investigations} investigations")
            print(f"    Findings so far: {len(findings)}")

            # OOB blind vulnerability scanning (always runs unless disabled)
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
                            except Exception:
                                continue
                    # Final OOB sweep
                    try:
                        late = await cb_server.check_all_pending()
                        for cb_id, callbacks in late:
                            f = cb_server.build_finding(cb_id, callbacks)
                            if f:
                                findings.append(f)
                    except Exception:
                        pass
                    await cb_server.stop()
                except Exception as e:
                    print(f"    OOB scanning error: {e}")

            # SAML scanning (if SAML auth was used)
            try:
                if hasattr(context, "auth_tokens") and context.auth_tokens:
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

        await scanner.close()

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            if f.id not in seen:
                seen.add(f.id)
                unique.append(f)

        oob_count = sum(1 for f in unique if "oob_confirmed" in f.tags)
        ai_count = sum(1 for f in unique if "ai_investigated" in f.tags or "page_targeted" in f.tags)
        det_count = len(unique) - oob_count - ai_count
        print(f"    TOTAL: {det_count} deterministic + {oob_count} OOB + {ai_count} AI-investigated "
              f"({len(unique)} unique findings)")
        return {"findings": unique}
