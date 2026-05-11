"""Tool definitions for the web application pentest agent."""

import httpx
from mantis.core.agent import ToolSpec


def get_webapp_tools() -> list[ToolSpec]:
    """Return all tools available for web app pentesting."""
    return [
        ToolSpec(
            name="http_request",
            description="Send an HTTP request to any URL and get the full response including headers, status, and body.",
            parameters={"type": "object", "properties": {
                "method": {"type": "string", "enum": ["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"]},
                "url": {"type": "string"},
                "headers": {"type": "object", "default": {}},
                "body": {"type": "string", "default": ""},
                "follow_redirects": {"type": "boolean", "default": True},
            }, "required": ["method", "url"]},
            handler=_http_request,
            category="webapp",
        ),
        ToolSpec(
            name="crawl_page",
            description="Fetch a page and extract all links, forms, and parameters from the HTML.",
            parameters={"type": "object", "properties": {
                "url": {"type": "string"},
            }, "required": ["url"]},
            handler=_crawl_page,
            category="webapp",
        ),
        ToolSpec(
            name="test_param_injection",
            description="Test a URL parameter for common injection vulnerabilities (SQLi, XSS, SSTI).",
            parameters={"type": "object", "properties": {
                "url": {"type": "string"},
                "param": {"type": "string"},
                "method": {"type": "string", "default": "GET"},
            }, "required": ["url", "param"]},
            handler=_test_injection,
            category="webapp",
        ),
        ToolSpec(
            name="check_headers",
            description="Analyze HTTP response headers for security misconfigurations.",
            parameters={"type": "object", "properties": {
                "url": {"type": "string"},
            }, "required": ["url"]},
            handler=_check_headers,
            category="webapp",
        ),
        ToolSpec(
            name="record_finding",
            description="Record a discovered vulnerability finding with all details.",
            parameters={"type": "object", "properties": {
                "title": {"type": "string"},
                "description": {"type": "string"},
                "severity": {"type": "string", "enum": ["critical","high","medium","low","info"]},
                "vuln_type": {"type": "string", "default": ""},
                "target": {"type": "string", "default": ""},
                "impact": {"type": "string", "default": ""},
                "remediation": {"type": "string", "default": ""},
            }, "required": ["title", "description", "severity"]},
            handler=_record_finding,
            category="webapp",
        ),
    ]


async def _http_request(method, url, headers=None, body="", follow_redirects=True):
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.request(method, url, headers=headers or {},
                                     content=body or None, follow_redirects=follow_redirects)
    return {"status": resp.status_code, "headers": dict(resp.headers),
            "body": resp.text[:15000], "url": str(resp.url)}


async def _crawl_page(url):
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.get(url, follow_redirects=True)
    soup = BeautifulSoup(resp.text, "html.parser")
    links = list(set(urljoin(url, a["href"]) for a in soup.find_all("a", href=True)))[:50]
    forms = []
    for form in soup.find_all("form"):
        forms.append({
            "action": urljoin(url, form.get("action", "")),
            "method": form.get("method", "GET").upper(),
            "inputs": [{"name": i.get("name",""), "type": i.get("type","text")}
                       for i in form.find_all(["input","textarea","select"]) if i.get("name")],
        })
    return {"links": links[:50], "forms": forms, "title": soup.title.string if soup.title else ""}


async def _test_injection(url, param, method="GET"):
    from mantis.webapp.vuln_scanner import test_xss_reflected, test_sqli
    results = []
    async with httpx.AsyncClient(verify=False, timeout=15) as http:
        xss = await test_xss_reflected(http, url, param)
        if xss:
            results.append({"type": "XSS", "title": xss.title, "severity": xss.severity.value})
        sqli = await test_sqli(http, url, param, method)
        if sqli:
            results.append({"type": "SQLi", "title": sqli.title, "severity": sqli.severity.value})
    return {"tested": param, "findings": results, "total": len(results)}


async def _check_headers(url):
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        resp = await client.get(url, follow_redirects=True)
    headers = {k.lower(): v for k, v in resp.headers.items()}
    security_headers = {
        "strict-transport-security": headers.get("strict-transport-security", "MISSING"),
        "content-security-policy": headers.get("content-security-policy", "MISSING"),
        "x-frame-options": headers.get("x-frame-options", "MISSING"),
        "x-content-type-options": headers.get("x-content-type-options", "MISSING"),
        "referrer-policy": headers.get("referrer-policy", "MISSING"),
        "permissions-policy": headers.get("permissions-policy", "MISSING"),
    }
    missing = [k for k, v in security_headers.items() if v == "MISSING"]
    return {"security_headers": security_headers, "missing": missing, "server": headers.get("server", "")}


async def _record_finding(title, description, severity, vuln_type="", target="", impact="", remediation=""):
    import json
    return json.dumps({"recorded": True, "title": title, "severity": severity})
