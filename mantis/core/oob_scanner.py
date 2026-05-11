"""
OOB vulnerability scanner.

Integrates the CallbackServer with active scanning to detect
blind vulnerabilities that produce no visible response change
but trigger outbound requests from the server.

Tested vulnerability classes:
- Blind SSRF (URL parameters, webhooks, import features)
- Blind XXE (XML input points, file uploads)
- Blind Command Injection (all input parameters)
- Blind SQLi with OOB exfiltration (DNS/HTTP)
- Blind/Stored XSS (callback via JavaScript execution)
"""

import asyncio
import httpx
from typing import Optional

from mantis.core.callback_server import CallbackServer
from mantis.core.findings import Finding


class OOBScanner:
    """
    Scans endpoints for blind vulnerabilities using OOB callbacks.

    Usage:
        scanner = OOBScanner(callback_server, http_client)
        findings = await scanner.scan_endpoint(
            url="https://target.com/api/fetch",
            params=["url", "redirect", "file"],
            method="POST",
        )
    """

    def __init__(self, callback: CallbackServer, http: httpx.AsyncClient):
        self.cb = callback
        self.http = http

    async def scan_endpoint(
        self,
        url: str,
        params: list[str],
        method: str = "GET",
        headers: dict = None,
        wait_seconds: int = 10,
    ) -> list[Finding]:
        """
        Test all parameters on an endpoint for blind vulnerabilities.

        For each parameter, injects OOB payloads for SSRF, command
        injection, and SQL injection. Then waits and checks for callbacks.
        """
        findings = []
        injected_ids: list[str] = []

        # Phase 1: Inject all OOB payloads
        for param in params:
            for vuln_type in ["ssrf", "cmdi", "sqli"]:
                cb_id = self.cb.generate_id(vuln_type, url, param)
                oob_payloads = self.cb.get_oob_payloads(cb_id, vuln_type)

                for payload_info in oob_payloads[:3]:  # Top 3 per type
                    payload = payload_info["payload"]
                    callback_url = self.cb.register_payload(
                        cb_id=cb_id,
                        vuln_type=vuln_type,
                        target_url=url,
                        parameter=param,
                        payload=payload,
                        max_wait=wait_seconds,
                    )

                    # Inject the payload
                    try:
                        if method.upper() == "GET":
                            await self.http.get(
                                url, params={param: payload},
                                headers=headers or {}, timeout=10,
                            )
                        else:
                            await self.http.request(
                                method.upper(), url,
                                data={param: payload},
                                headers=headers or {}, timeout=10,
                            )
                        injected_ids.append(cb_id)
                    except Exception:
                        continue

        if not injected_ids:
            return findings

        # Phase 2: Wait for callbacks
        await asyncio.sleep(wait_seconds)

        # Phase 3: Check for received callbacks
        results = await self.cb.check_all_pending()
        for cb_id, callbacks in results:
            finding = self.cb.build_finding(cb_id, callbacks)
            if finding:
                findings.append(finding)

        return findings

    async def scan_for_blind_xxe(
        self,
        url: str,
        method: str = "POST",
        wait_seconds: int = 10,
    ) -> list[Finding]:
        """
        Test an endpoint specifically for blind XXE.

        Sends XML payloads with external entity references
        pointing to the callback server.
        """
        findings = []

        cb_id = self.cb.generate_id("xxe", url, "xml_body")
        xxe_payloads = self.cb.get_oob_payloads(cb_id, "xxe")

        for payload_info in xxe_payloads:
            payload = payload_info["payload"]
            self.cb.register_payload(
                cb_id=cb_id, vuln_type="xxe",
                target_url=url, parameter="xml_body",
                payload=payload, max_wait=wait_seconds,
            )

            try:
                await self.http.request(
                    method, url,
                    content=payload,
                    headers={"Content-Type": "application/xml"},
                    timeout=10,
                )
            except Exception:
                continue

        await asyncio.sleep(wait_seconds)

        results = await self.cb.check_all_pending()
        for cb_id, callbacks in results:
            finding = self.cb.build_finding(cb_id, callbacks)
            if finding:
                findings.append(finding)

        return findings

    async def scan_for_blind_xss(
        self,
        url: str,
        params: list[str],
        method: str = "POST",
        wait_seconds: int = 30,
    ) -> list[Finding]:
        """
        Inject stored XSS payloads with OOB callbacks.

        These won't fire immediately — they fire when another user
        views the stored content. Set a longer wait time.
        """
        findings = []

        for param in params:
            cb_id = self.cb.generate_id("xss", url, param)
            xss_payloads = self.cb.get_oob_payloads(cb_id, "xss")

            for payload_info in xss_payloads[:2]:
                payload = payload_info["payload"]
                self.cb.register_payload(
                    cb_id=cb_id, vuln_type="xss",
                    target_url=url, parameter=param,
                    payload=payload, max_wait=wait_seconds,
                )

                try:
                    if method.upper() == "GET":
                        await self.http.get(url, params={param: payload}, timeout=10)
                    else:
                        await self.http.request(method, url, data={param: payload}, timeout=10)
                except Exception:
                    continue

        # For stored XSS, callbacks may come much later
        await asyncio.sleep(min(wait_seconds, 15))

        results = await self.cb.check_all_pending()
        for cb_id, callbacks in results:
            finding = self.cb.build_finding(cb_id, callbacks)
            if finding:
                findings.append(finding)

        return findings
