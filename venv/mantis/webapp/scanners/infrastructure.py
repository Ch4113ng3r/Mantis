"""Infrastructure scanners: exposed .git/.svn/.env, debug endpoints, source maps, exposed Swagger, ReDoS, API versioning bypass."""
import re, asyncio, time, httpx
from urllib.parse import urlparse, urljoin
from typing import Optional
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource


EXPOSED_PATHS = [
    ("/.git/config", "git config file", "[core]"),
    ("/.git/HEAD", "git HEAD", "ref: refs/"),
    ("/.svn/entries", "SVN metadata", "dir"),
    ("/.hg/store", "Mercurial metadata", "data"),
    ("/.env", "environment file", "="),
    ("/.env.local", "environment file (local)", "="),
    ("/.env.production", "environment file (prod)", "="),
    ("/config.php.bak", "PHP config backup", "<?php"),
    ("/web.config", "ASP.NET config", "<configuration"),
    ("/application.properties", "Spring config", "="),
    ("/wp-config.php.bak", "WordPress config backup", "<?php"),
    ("/database.yml", "Rails DB config", "production:"),
    ("/.DS_Store", "macOS metadata", "\x00"),
    ("/server-status", "Apache mod_status", "Apache Status"),
    ("/server-info", "Apache mod_info", "Apache"),
    ("/phpinfo.php", "PHP info disclosure", "PHP Version"),
    ("/info.php", "PHP info disclosure", "PHP Version"),
    ("/debug", "debug endpoint", "debug"),
    ("/actuator", "Spring Actuator", "_links"),
    ("/actuator/health", "Spring health endpoint", "status"),
    ("/actuator/env", "Spring env endpoint", "activeProfiles"),
    ("/actuator/heapdump", "Spring heap dump", ""),
    ("/api/swagger.json", "Swagger spec", "swagger"),
    ("/swagger-ui.html", "Swagger UI", "swagger"),
    ("/swagger-ui/", "Swagger UI", "swagger"),
    ("/api-docs", "API documentation", "openapi"),
    ("/.well-known/security.txt", "security.txt", "Contact:"),
]


async def scan_exposed_files(http, base_url):
    """Check common paths for exposed sensitive files."""
    findings = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    sem = asyncio.Semaphore(10)

    async def check_path(path, description, marker):
        async with sem:
            url = base + path
            try:
                r = await http.get(url, timeout=8, follow_redirects=False)
                if r.status_code == 200 and (not marker or marker in r.text[:1000]):
                    severity = Severity.HIGH
                    if any(x in path for x in [".git", ".env", "heapdump", "actuator/env"]):
                        severity = Severity.CRITICAL
                    return Finding(
                        title=f"Exposed {description} at {url}",
                        description=f"Sensitive file/endpoint accessible: {path}",
                        source=FindingSource.WEBAPP, severity=severity,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=url, endpoint=url, vuln_type="Sensitive File Exposure",
                        cwe="CWE-200", confidence=0.95, tags=["info_disclosure", "exposed_file"],
                        impact=f"Direct access to {description}. May reveal credentials, source code, or internal state.",
                        remediation=f"Block access to {path}. Move sensitive files outside web root.",
                    )
            except Exception: pass
            return None

    tasks = [check_path(path, desc, marker) for path, desc, marker in EXPOSED_PATHS]
    results = await asyncio.gather(*tasks)
    findings = [r for r in results if r]
    return findings


async def scan_source_maps(http, url):
    """Check for exposed JavaScript source maps."""
    findings = []
    try:
        r = await http.get(url, timeout=10)
        # Find JS files
        js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', r.text)
        for js in js_files[:20]:
            map_url = urljoin(url, js + ".map")
            try:
                map_r = await http.get(map_url, timeout=5)
                if map_r.status_code == 200 and ("sourcemap" in map_r.text.lower() or '"version"' in map_r.text[:200]):
                    findings.append(Finding(
                        title=f"Exposed Source Map at {map_url}",
                        description=f"JavaScript source map exposed, revealing original source code structure.",
                        source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=map_url, endpoint=map_url, vuln_type="Exposed Source Map",
                        cwe="CWE-540", confidence=0.95, tags=["info_disclosure", "source_map"],
                        impact="Reveals minified source structure, file paths, and sometimes secrets in comments.",
                        remediation="Don't deploy .map files to production. Set hidden-source-map in build config.",
                    ))
                    if len(findings) >= 3: break
            except Exception: continue
    except Exception: pass
    return findings


async def scan_api_versioning_bypass(http, url):
    """Test if older API versions lack security controls present in v2/v3."""
    findings = []
    parsed = urlparse(url)
    if "/v2/" in parsed.path or "/v3/" in parsed.path:
        # Try v1
        for old_version in ["v1", "v0"]:
            old_path = re.sub(r"/v[23]/", f"/{old_version}/", parsed.path)
            old_url = parsed._replace(path=old_path).geturl()
            try:
                # Compare auth requirements
                new_r = await http.get(url, timeout=10)
                old_r = await http.get(old_url, timeout=10)
                if new_r.status_code in (401, 403) and old_r.status_code == 200:
                    return [Finding(
                        title=f"API Versioning Bypass at {old_url}",
                        description=f"Older API version ({old_version}) bypasses auth required by current version.",
                        source=FindingSource.WEBAPP, severity=Severity.HIGH,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=old_url, endpoint=old_url, vuln_type="API Versioning Bypass",
                        cwe="CWE-289", confidence=0.85, tags=["api_versioning"],
                        impact="Bypass auth/access controls via older API versions.",
                        remediation="Deprecate old API versions or apply same controls. Use API gateway with version-aware policies.",
                    )]
            except Exception: continue
    return findings


async def scan_redos(http, url, param):
    """ReDoS — Regular expression Denial of Service via catastrophic backtracking."""
    # Common ReDoS-vulnerable patterns + triggering inputs
    redos_inputs = [
        "a" * 30 + "!",          # Triggers (a+)+ patterns
        "a" * 20 + "X" + "a" * 20,
        "(((((((((((((((a))))))))))))))",
    ]
    try:
        baseline_start = time.time()
        await http.get(url, params={param: "normal"}, timeout=10)
        baseline = time.time() - baseline_start

        for input_str in redos_inputs:
            t0 = time.time()
            try:
                await http.get(url, params={param: input_str}, timeout=15)
                elapsed = time.time() - t0
                if elapsed > 5 and elapsed > baseline * 5:
                    return Finding(
                        title=f"Regular Expression DoS (ReDoS) in '{param}'",
                        description=f"Crafted input caused {elapsed:.1f}s delay (baseline: {baseline:.2f}s).",
                        source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=url, endpoint=url, vuln_type="ReDoS",
                        cwe="CWE-1333", payload=input_str, confidence=0.85, tags=["redos", "dos"],
                        impact="Application can be DoS'd by sending crafted strings that trigger catastrophic backtracking.",
                        remediation="Use linear-time regex engines (RE2). Audit regex for nested quantifiers like (a+)+.",
                    )
            except httpx.TimeoutException:
                return Finding(
                    title=f"ReDoS Causing Timeout in '{param}'",
                    description=f"Crafted input caused server timeout (>15s).",
                    source=FindingSource.WEBAPP, severity=Severity.HIGH,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="ReDoS",
                    cwe="CWE-1333", payload=input_str, confidence=0.9, tags=["redos", "dos"],
                    impact="Full DoS via single request — catastrophic regex backtracking.",
                    remediation="Use RE2 or audit/fix vulnerable regex patterns.",
                )
    except Exception: pass
    return None


async def scan_grpc_reflection(http, base_url):
    """Check for exposed gRPC reflection."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    paths = ["/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", "/grpc.health.v1.Health/Check"]
    for path in paths:
        try:
            r = await http.post(base + path, headers={"Content-Type": "application/grpc"}, timeout=10)
            if "grpc-status" in r.headers or r.status_code in (200, 400):
                return Finding(
                    title=f"gRPC Reflection Service Exposed at {base + path}",
                    description="gRPC reflection allows enumeration of all services, methods, and protobuf schemas.",
                    source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=base + path, endpoint=path, vuln_type="gRPC Reflection",
                    cwe="CWE-200", confidence=0.7, tags=["grpc", "info_disclosure"],
                    impact="Attacker enumerates internal API structure, finds undocumented endpoints.",
                    remediation="Disable gRPC reflection in production.",
                )
        except Exception: continue
    return None
