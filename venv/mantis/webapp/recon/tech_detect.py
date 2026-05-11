"""
Technology fingerprinting phase.

Identifies web server, framework, CMS, JavaScript libraries,
and other technologies from HTTP headers, HTML content, and cookies.
"""

import httpx
import re
from mantis.engage.phases import Phase


# Fingerprint database: header/body patterns -> technology
FINGERPRINTS = {
    # Server headers
    "server": {
        "nginx": "Nginx", "apache": "Apache", "iis": "Microsoft IIS",
        "cloudflare": "Cloudflare", "gunicorn": "Gunicorn (Python)",
        "uvicorn": "Uvicorn (Python)", "werkzeug": "Werkzeug (Flask)",
        "openresty": "OpenResty", "litespeed": "LiteSpeed",
        "caddy": "Caddy", "envoy": "Envoy",
    },
    # X-Powered-By
    "x-powered-by": {
        "php": "PHP", "asp.net": "ASP.NET", "express": "Express.js (Node.js)",
        "next.js": "Next.js", "nuxt": "Nuxt.js", "django": "Django",
        "flask": "Flask", "rails": "Ruby on Rails", "spring": "Spring (Java)",
    },
    # HTML body patterns
    "body": {
        "wp-content": "WordPress", "wp-includes": "WordPress",
        "drupal": "Drupal", "joomla": "Joomla",
        "shopify": "Shopify", "magento": "Magento",
        "react": "React", "angular": "Angular", "vue.js": "Vue.js",
        "jquery": "jQuery", "bootstrap": "Bootstrap",
        "laravel": "Laravel (PHP)", "symfony": "Symfony (PHP)",
        "django": "Django", "flask": "Flask",
        "next.js": "Next.js", "nuxt": "Nuxt.js", "gatsby": "Gatsby",
        "__next": "Next.js", "_nuxt": "Nuxt.js",
        "ember": "Ember.js", "backbone": "Backbone.js",
        "graphql": "GraphQL", "swagger-ui": "Swagger/OpenAPI",
    },
    # Cookie patterns
    "cookies": {
        "phpsessid": "PHP", "asp.net_sessionid": "ASP.NET",
        "jsessionid": "Java (Servlet)", "csrftoken": "Django",
        "laravel_session": "Laravel", "_rails": "Ruby on Rails",
        "connect.sid": "Express.js",
    },
}


class TechDetector:
    """Fingerprint technologies from HTTP responses."""

    def __init__(self, http: httpx.AsyncClient):
        self.http = http

    async def detect(self, target: str) -> dict:
        """Detect technologies from the target's HTTP response."""
        techs = {}
        for scheme in ["https", "http"]:
            url = f"{scheme}://{target}"
            try:
                resp = await self.http.get(url, timeout=15, follow_redirects=True)
                techs.update(self._analyze_headers(resp))
                techs.update(self._analyze_body(resp.text))
                techs.update(self._analyze_cookies(resp.cookies))
                # Check common paths for technology indicators
                tech_paths = await self._check_tech_paths(scheme, target)
                techs.update(tech_paths)
                break  # Success, no need to try other scheme
            except Exception:
                continue
        return techs

    def _analyze_headers(self, resp: httpx.Response) -> dict:
        techs = {}
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

        for header_name, patterns in [("server", FINGERPRINTS["server"]),
                                       ("x-powered-by", FINGERPRINTS["x-powered-by"])]:
            value = headers.get(header_name, "")
            for pattern, tech in patterns.items():
                if pattern in value:
                    techs[tech] = {"source": header_name, "value": resp.headers.get(header_name, "")}

        # Security headers analysis
        security_headers = {}
        for h in ["strict-transport-security", "content-security-policy",
                   "x-frame-options", "x-content-type-options", "x-xss-protection",
                   "referrer-policy", "permissions-policy"]:
            if h in headers:
                security_headers[h] = headers[h]
        if security_headers:
            techs["_security_headers"] = security_headers

        return techs

    def _analyze_body(self, body: str) -> dict:
        techs = {}
        body_lower = body.lower()
        for pattern, tech in FINGERPRINTS["body"].items():
            if pattern in body_lower:
                techs[tech] = {"source": "html_body"}
        # Extract version numbers from meta generators
        gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)', body, re.I)
        if gen_match:
            techs["_generator"] = gen_match.group(1)
        return techs

    def _analyze_cookies(self, cookies) -> dict:
        techs = {}
        cookie_names = [c.lower() for c in cookies.keys()] if cookies else []
        for pattern, tech in FINGERPRINTS["cookies"].items():
            for cookie_name in cookie_names:
                if pattern in cookie_name:
                    techs[tech] = {"source": "cookie", "cookie_name": cookie_name}
        return techs

    async def _check_tech_paths(self, scheme: str, target: str) -> dict:
        """Check common paths that indicate specific technologies."""
        techs = {}
        checks = [
            ("/wp-login.php", "WordPress"),
            ("/wp-json/wp/v2/", "WordPress REST API"),
            ("/api/v1/swagger.json", "Swagger API"),
            ("/graphql", "GraphQL"),
            ("/.well-known/openid-configuration", "OpenID Connect"),
            ("/actuator/health", "Spring Boot Actuator"),
            ("/elmah.axd", "ASP.NET ELMAH"),
        ]
        for path, tech in checks:
            try:
                resp = await self.http.get(f"{scheme}://{target}{path}", timeout=5)
                if resp.status_code < 404:
                    techs[tech] = {"source": "path_probe", "path": path, "status": resp.status_code}
            except Exception:
                continue
        return techs


class TechDetectPhase(Phase):
    """Phase: fingerprint technologies used by the target."""

    async def execute(self, context) -> dict:
        target = self.config.target
        for prefix in ("https://", "http://"):
            if target.startswith(prefix):
                target = target[len(prefix):]
        target = target.split("/")[0]

        async with httpx.AsyncClient(verify=False, follow_redirects=True) as http:
            detector = TechDetector(http)
            techs = await detector.detect(target)

        tech_names = [k for k in techs if not k.startswith("_")]
        print(f"    Technologies detected: {', '.join(tech_names[:10]) or 'none'}")
        return {"technologies": techs}
