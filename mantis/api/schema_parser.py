"""
API schema ingestion for OpenAPI, GraphQL, and Postman.

Parses the spec into a unified EndpointMap that the scanning
agent uses to systematically test every endpoint.
"""

import json
import httpx
from dataclasses import dataclass, field
from typing import Optional
from mantis.engage.phases import Phase

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class APIEndpoint:
    path: str
    method: str
    parameters: list[dict] = field(default_factory=list)
    request_body: Optional[dict] = None
    response_schema: Optional[dict] = None
    auth_required: bool = False
    auth_type: str = ""
    tags: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class EndpointMap:
    base_url: str
    endpoints: list[APIEndpoint] = field(default_factory=list)
    auth_schemes: dict = field(default_factory=dict)
    total_endpoints: int = 0


def parse_openapi(spec_path_or_url: str) -> EndpointMap:
    """Parse OpenAPI/Swagger spec into EndpointMap."""
    # Load spec
    if spec_path_or_url.startswith(("http://", "https://")):
        import urllib.request
        with urllib.request.urlopen(spec_path_or_url) as resp:
            raw = resp.read().decode()
    else:
        with open(spec_path_or_url) as f:
            raw = f.read()

    # Parse YAML or JSON
    try:
        if HAS_YAML:
            spec = yaml.safe_load(raw)
        else:
            spec = json.loads(raw)
    except Exception:
        spec = json.loads(raw)

    # Extract base URL
    servers = spec.get("servers", [{"url": ""}])
    base_url = servers[0].get("url", "") if servers else ""

    # Extract security schemes
    auth_schemes = {}
    components = spec.get("components", {})
    for scheme_name, scheme_data in components.get("securitySchemes", {}).items():
        auth_schemes[scheme_name] = {
            "type": scheme_data.get("type", ""),
            "scheme": scheme_data.get("scheme", ""),
            "in": scheme_data.get("in", ""),
            "name": scheme_data.get("name", ""),
        }

    # Extract endpoints
    endpoints = []
    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                continue
            if not isinstance(details, dict):
                continue

            params = []
            for p in details.get("parameters", []):
                params.append({
                    "name": p.get("name"),
                    "type": p.get("schema", {}).get("type", "string"),
                    "required": p.get("required", False),
                    "location": p.get("in", "query"),
                })

            security = details.get("security", spec.get("security", []))

            endpoints.append(APIEndpoint(
                path=path,
                method=method.upper(),
                parameters=params,
                request_body=details.get("requestBody"),
                auth_required=bool(security),
                tags=details.get("tags", []),
                description=details.get("summary", details.get("description", "")),
            ))

    return EndpointMap(
        base_url=base_url,
        endpoints=endpoints,
        auth_schemes=auth_schemes,
        total_endpoints=len(endpoints),
    )


def parse_graphql_introspection(url: str) -> EndpointMap:
    """Introspect a GraphQL endpoint."""
    introspection_query = '{"query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind } } } } } }"}'
    try:
        import urllib.request
        req = urllib.request.Request(url, data=introspection_query.encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())

        endpoints = []
        schema = data.get("data", {}).get("__schema", {})
        for type_info in schema.get("types", []):
            if type_info["name"].startswith("__"):
                continue
            for field_info in (type_info.get("fields") or []):
                endpoints.append(APIEndpoint(
                    path=f"/{type_info['name']}.{field_info['name']}",
                    method="POST",  # GraphQL always POST
                    parameters=[{"name": a["name"], "type": a.get("type", {}).get("name", ""), "required": False, "location": "body"}
                                for a in (field_info.get("args") or [])],
                    description=f"GraphQL {type_info['kind']}: {type_info['name']}.{field_info['name']}",
                    tags=[type_info["kind"]],
                ))
        return EndpointMap(base_url=url, endpoints=endpoints, total_endpoints=len(endpoints))
    except Exception:
        return EndpointMap(base_url=url)


def parse_postman_collection(path: str) -> EndpointMap:
    """Parse a Postman Collection v2.1 into EndpointMap."""
    with open(path) as f:
        collection = json.load(f)

    endpoints = []

    def _extract_items(items, base_url=""):
        for item in items:
            if "item" in item:  # Folder
                _extract_items(item["item"], base_url)
            elif "request" in item:
                req = item["request"]
                url_data = req.get("url", {})
                if isinstance(url_data, str):
                    url = url_data
                else:
                    raw = url_data.get("raw", "")
                    url = raw

                method = req.get("method", "GET").upper()
                params = []
                for q in url_data.get("query", []) if isinstance(url_data, dict) else []:
                    params.append({"name": q.get("key", ""), "type": "string",
                                   "required": False, "location": "query"})

                endpoints.append(APIEndpoint(
                    path=url, method=method, parameters=params,
                    description=item.get("name", ""),
                ))

    _extract_items(collection.get("item", []))
    return EndpointMap(base_url="", endpoints=endpoints, total_endpoints=len(endpoints))


class SchemaIngestPhase(Phase):
    """Phase: ingest API specification and build endpoint map."""

    async def execute(self, context) -> dict:
        spec_path = self.config.openapi_spec
        if not spec_path:
            print("    No API spec provided (--spec flag). Skipping schema ingestion.")
            return {}

        # Detect spec type and parse
        if spec_path.endswith(".json") or spec_path.endswith(".yaml") or spec_path.endswith(".yml"):
            endpoint_map = parse_openapi(spec_path)
        elif "graphql" in spec_path.lower():
            endpoint_map = parse_graphql_introspection(spec_path)
        elif "postman" in spec_path.lower():
            endpoint_map = parse_postman_collection(spec_path)
        else:
            endpoint_map = parse_openapi(spec_path)  # Default to OpenAPI

        # Convert to context format
        endpoints = []
        for ep in endpoint_map.endpoints:
            base = endpoint_map.base_url.rstrip("/")
            url = f"{base}{ep.path}" if base else ep.path
            endpoints.append({
                "url": url, "method": ep.method,
                "params": [p["name"] for p in ep.parameters],
                "auth_required": ep.auth_required,
                "description": ep.description,
            })

        print(f"    Ingested {len(endpoints)} endpoints from {spec_path}")
        return {
            "endpoints": endpoints,
            "api_schema": {
                "base_url": endpoint_map.base_url,
                "auth_schemes": endpoint_map.auth_schemes,
                "total_endpoints": endpoint_map.total_endpoints,
            },
        }
