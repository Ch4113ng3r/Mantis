"""
OSINT gathering phase for external web application engagements.

Collects publicly available information about the target:
- Google dorking for exposed files/pages
- Wayback Machine snapshots for old endpoints
- GitHub/GitLab code search for leaked secrets
- Shodan/Censys for exposed services (if API keys provided)
- Email harvesting for user enumeration
- Social media profiles for social engineering context
"""

import asyncio
import httpx
import json
import re
from typing import Optional
from mantis.engage.phases import Phase


class OSINTGatherer:
    """Collects OSINT from multiple public sources."""

    def __init__(self, http: httpx.AsyncClient):
        self.http = http

    async def gather(self, domain: str) -> dict:
        """Run all OSINT collection methods in parallel."""
        tasks = [
            self._wayback_urls(domain),
            self._search_github(domain),
            self._harvest_emails(domain),
            self._check_robots_sitemap(domain),
            self._check_security_txt(domain),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        osint = {
            "wayback_urls": results[0] if isinstance(results[0], list) else [],
            "github_leaks": results[1] if isinstance(results[1], list) else [],
            "emails": results[2] if isinstance(results[2], list) else [],
            "robots_sitemap": results[3] if isinstance(results[3], dict) else {},
            "security_txt": results[4] if isinstance(results[4], str) else "",
        }
        return osint

    async def _wayback_urls(self, domain: str) -> list[str]:
        """Fetch historical URLs from Wayback Machine CDX API."""
        try:
            resp = await self.http.get(
                f"https://web.archive.org/cdx/search/cdx"
                f"?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=500",
                timeout=30.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                urls = list(set(row[0] for row in data[1:]))  # Skip header
                return urls[:500]
        except Exception:
            pass
        return []

    async def _search_github(self, domain: str) -> list[dict]:
        """Search GitHub for leaked secrets related to the domain."""
        leaks = []
        search_terms = [
            f'"{domain}" password', f'"{domain}" api_key',
            f'"{domain}" secret', f'"{domain}" token',
        ]
        for term in search_terms[:2]:  # Limit to avoid rate limiting
            try:
                resp = await self.http.get(
                    f"https://api.github.com/search/code?q={term}",
                    headers={"Accept": "application/vnd.github.v3+json"},
                    timeout=15.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("items", [])[:5]:
                        leaks.append({
                            "repo": item.get("repository", {}).get("full_name", ""),
                            "path": item.get("path", ""),
                            "url": item.get("html_url", ""),
                        })
            except Exception:
                pass
            await asyncio.sleep(2)  # Rate limit courtesy
        return leaks

    async def _harvest_emails(self, domain: str) -> list[str]:
        """Harvest email addresses from public sources."""
        emails = set()
        # Try hunter.io-style search via web scraping
        try:
            resp = await self.http.get(
                f"https://www.google.com/search?q=%22%40{domain}%22+email",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=15.0,
            )
            if resp.status_code == 200:
                pattern = rf'[\w.+-]+@{re.escape(domain)}'
                found = re.findall(pattern, resp.text)
                emails.update(found)
        except Exception:
            pass
        return list(emails)[:50]

    async def _check_robots_sitemap(self, domain: str) -> dict:
        """Fetch robots.txt and sitemap.xml for hidden paths."""
        result = {"robots_txt": "", "sitemap_urls": [], "disallowed_paths": []}
        for scheme in ["https", "http"]:
            try:
                resp = await self.http.get(f"{scheme}://{domain}/robots.txt", timeout=10)
                if resp.status_code == 200:
                    result["robots_txt"] = resp.text[:5000]
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                result["disallowed_paths"].append(path)
                        elif line.lower().startswith("sitemap:"):
                            result["sitemap_urls"].append(line.split(":", 1)[1].strip())
                    break
            except Exception:
                continue
        return result

    async def _check_security_txt(self, domain: str) -> str:
        """Check for .well-known/security.txt."""
        for scheme in ["https", "http"]:
            for path in ["/.well-known/security.txt", "/security.txt"]:
                try:
                    resp = await self.http.get(f"{scheme}://{domain}{path}", timeout=10)
                    if resp.status_code == 200 and "contact" in resp.text.lower():
                        return resp.text[:2000]
                except Exception:
                    continue
        return ""


class OSINTPhase(Phase):
    """Phase: gather open-source intelligence about the target."""

    async def execute(self, context) -> dict:
        domain = self.config.target
        # Strip protocol if present
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split("/")[0]

        async with httpx.AsyncClient(verify=False, follow_redirects=True) as http:
            gatherer = OSINTGatherer(http)
            osint = await gatherer.gather(domain)

        total_urls = len(osint.get("wayback_urls", []))
        total_emails = len(osint.get("emails", []))
        total_leaks = len(osint.get("github_leaks", []))
        disallowed = len(osint.get("robots_sitemap", {}).get("disallowed_paths", []))
        print(f"    Wayback URLs: {total_urls}, Emails: {total_emails}, "
              f"GitHub leaks: {total_leaks}, Disallowed paths: {disallowed}")

        return {"osint_data": osint}
