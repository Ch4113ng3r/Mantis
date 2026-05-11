"""
Subdomain enumeration using multiple sources.

Sources: crt.sh (Certificate Transparency logs), DNS brute-force,
web archive (Wayback Machine), and optional APIs.
"""

import asyncio
import httpx
from typing import Optional
from mantis.engage.phases import Phase


class SubdomainEnumerator:
    """Discovers subdomains using multiple parallel techniques."""

    def __init__(self, http_client: httpx.AsyncClient):
        self.http = http_client

    async def enumerate(self, domain: str) -> list[str]:
        """Run all subdomain discovery methods in parallel."""
        tasks = [
            self._crt_sh(domain),
            self._dns_brute(domain),
            self._web_archive(domain),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_subs = set()
        for result in results:
            if isinstance(result, list):
                all_subs.update(result)
        return sorted(all_subs)

    async def _crt_sh(self, domain: str) -> list[str]:
        """Query Certificate Transparency logs via crt.sh."""
        try:
            resp = await self.http.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=30.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                subs = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if (line.endswith(f".{domain}") or line == domain) and "*" not in line:
                            subs.add(line)
                return list(subs)
        except Exception:
            pass
        return []

    async def _dns_brute(self, domain: str) -> list[str]:
        """Brute-force common subdomain prefixes via DNS resolution."""
        prefixes = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
            "blog", "shop", "app", "portal", "secure", "vpn", "remote", "cdn",
            "static", "docs", "wiki", "support", "status", "dashboard", "panel",
            "login", "auth", "sso", "graphql", "ws", "internal", "intranet",
            "jira", "confluence", "gitlab", "jenkins", "ci", "deploy", "k8s",
            "s3", "backup", "db", "redis", "elastic", "grafana", "prometheus",
            "m", "mobile", "beta", "sandbox", "uat", "qa", "preprod",
            "v1", "v2", "api2", "proxy", "gateway", "edge",
        ]
        found = []
        sem = asyncio.Semaphore(50)

        async def check(prefix):
            async with sem:
                subdomain = f"{prefix}.{domain}"
                try:
                    loop = asyncio.get_event_loop()
                    await loop.getaddrinfo(subdomain, None)
                    found.append(subdomain)
                except Exception:
                    pass

        await asyncio.gather(*[check(p) for p in prefixes])
        return found

    async def _web_archive(self, domain: str) -> list[str]:
        """Query Wayback Machine for historical subdomains."""
        try:
            resp = await self.http.get(
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}&output=json&fl=original&collapse=urlkey",
                timeout=30.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                subs = set()
                for row in data[1:]:  # Skip header
                    from urllib.parse import urlparse
                    host = urlparse(row[0]).hostname
                    if host and (host.endswith(f".{domain}") or host == domain):
                        subs.add(host)
                return list(subs)
        except Exception:
            pass
        return []


class SubdomainPhase(Phase):
    """Phase: enumerate subdomains for external engagements."""

    async def execute(self, context) -> dict:
        domain = self.config.target
        async with httpx.AsyncClient() as client:
            enumerator = SubdomainEnumerator(client)
            subs = await enumerator.enumerate(domain)
        print(f"    Discovered {len(subs)} subdomains")
        return {"subdomains": subs}
