"""
Web spider/crawler phase.

Crawls the target application to discover endpoints, forms,
parameters, and other attack surface. Respects scope, depth limits,
and exclusion patterns from configuration.
"""

import asyncio
import httpx
import re
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from mantis.engage.phases import Phase


class WebCrawler:
    """Async web crawler that discovers endpoints and parameters."""

    def __init__(self, http: httpx.AsyncClient, max_depth: int = 5,
                 max_urls: int = 500, exclude_patterns: list = None):
        self.http = http
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.exclude_patterns = exclude_patterns or ["*/logout*", "*/static/*", "*/assets/*"]
        self.visited: set[str] = set()
        self.endpoints: list[dict] = []
        self.forms: list[dict] = []
        self.parameters: list[dict] = []

    async def crawl(self, start_url: str) -> dict:
        """Crawl starting from the given URL."""
        await self._crawl_recursive(start_url, depth=0)
        return {
            "endpoints": self.endpoints,
            "forms": self.forms,
            "parameters": self.parameters,
            "total_urls": len(self.visited),
        }

    async def _crawl_recursive(self, url: str, depth: int):
        if depth > self.max_depth or len(self.visited) >= self.max_urls:
            return
        normalized = self._normalize_url(url)
        if normalized in self.visited:
            return
        if self._is_excluded(normalized):
            return

        self.visited.add(normalized)
        try:
            resp = await self.http.get(url, timeout=10, follow_redirects=True)
            if "text/html" not in resp.headers.get("content-type", ""):
                return

            # Record this endpoint
            parsed = urlparse(str(resp.url))
            params = list(parse_qs(parsed.query).keys())
            self.endpoints.append({
                "url": str(resp.url).split("?")[0],
                "method": "GET",
                "params": params,
                "status": resp.status_code,
            })
            if params:
                for p in params:
                    self.parameters.append({"url": str(resp.url).split("?")[0], "param": p, "method": "GET"})

            # Parse HTML for links and forms
            soup = BeautifulSoup(resp.text, "html.parser")
            base_url = str(resp.url)

            # Extract links
            links = set()
            for tag in soup.find_all(["a", "link"], href=True):
                href = urljoin(base_url, tag["href"])
                if self._is_same_scope(href, base_url):
                    links.add(href)
            for tag in soup.find_all(["script", "img", "iframe"], src=True):
                src = urljoin(base_url, tag["src"])
                if self._is_same_scope(src, base_url):
                    links.add(src)

            # Extract forms
            for form in soup.find_all("form"):
                action = urljoin(base_url, form.get("action", ""))
                method = form.get("method", "GET").upper()
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    if name:
                        inputs.append({
                            "name": name,
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", ""),
                        })
                        self.parameters.append({"url": action, "param": name, "method": method})
                if inputs:
                    self.forms.append({
                        "url": action, "method": method, "inputs": inputs,
                    })
                    self.endpoints.append({
                        "url": action, "method": method,
                        "params": [i["name"] for i in inputs],
                    })

            # Crawl discovered links
            tasks = []
            for link in links:
                if len(self.visited) < self.max_urls:
                    tasks.append(self._crawl_recursive(link, depth + 1))
            if tasks:
                await asyncio.gather(*tasks[:10])  # Limit concurrency per page

        except Exception:
            pass

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")

    def _is_same_scope(self, url: str, base_url: str) -> bool:
        return urlparse(url).netloc == urlparse(base_url).netloc

    def _is_excluded(self, url: str) -> bool:
        import fnmatch
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(url, pattern):
                return True
        return False


class CrawlPhase(Phase):
    """Phase: crawl the target to discover attack surface."""

    async def execute(self, context) -> dict:
        target = self.config.target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        max_depth = 5
        max_urls = 500

        async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                      headers={"User-Agent": "MANTIS/1.0"}) as http:
            crawler = WebCrawler(http, max_depth=max_depth, max_urls=max_urls)
            result = await crawler.crawl(target)

        print(f"    Crawled {result['total_urls']} URLs, "
              f"{len(result['endpoints'])} endpoints, "
              f"{len(result['forms'])} forms, "
              f"{len(result['parameters'])} parameters")
        return result
