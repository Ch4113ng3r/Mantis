"""Tool definitions for the API pentest agent."""

from mantis.core.agent import ToolSpec


def get_api_tools() -> list[ToolSpec]:
    """Return all tools available for API pentesting."""
    return [
        ToolSpec(
            name="http_request",
            description="Send an HTTP request with full control over method, headers, and body.",
            parameters={"type": "object", "properties": {
                "method": {"type": "string", "enum": ["GET","POST","PUT","DELETE","PATCH"]},
                "url": {"type": "string"},
                "headers": {"type": "object", "default": {}},
                "body": {"type": "string", "default": ""},
            }, "required": ["method", "url"]},
            handler=_api_request,
            category="api",
        ),
        ToolSpec(
            name="graphql_query",
            description="Send a GraphQL query or mutation.",
            parameters={"type": "object", "properties": {
                "url": {"type": "string"},
                "query": {"type": "string"},
                "variables": {"type": "object", "default": {}},
            }, "required": ["url", "query"]},
            handler=_graphql_query,
            category="api",
        ),
        ToolSpec(
            name="record_finding",
            description="Record a discovered vulnerability.",
            parameters={"type": "object", "properties": {
                "title": {"type": "string"},
                "description": {"type": "string"},
                "severity": {"type": "string"},
            }, "required": ["title", "description", "severity"]},
            handler=_record_finding,
            category="api",
        ),
    ]


async def _api_request(method, url, headers=None, body=""):
    import httpx
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.request(method, url, headers=headers or {},
                                     content=body or None, follow_redirects=True)
    return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text[:15000]}


async def _graphql_query(url, query, variables=None):
    import httpx, json
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.post(url,
            json={"query": query, "variables": variables or {}},
            headers={"Content-Type": "application/json"})
    return {"status": resp.status_code, "body": resp.text[:15000]}


async def _record_finding(title, description, severity):
    import json
    return json.dumps({"recorded": True, "title": title, "severity": severity})
