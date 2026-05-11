"""Injection-class scanners: SSTI, blind SQLi, CMDi, LFI, XPath, LDAP, NoSQL, prototype pollution, HPP, CRLF, XXE."""
import asyncio, time, re, httpx
from typing import Optional
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource, HTTPEvidence


SSTI_PROBES = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/Velocity"),
    ("<%= 7*7 %>", "49", "ERB/Ruby"),
    ("#{7*7}", "49", "Smarty/Ruby"),
    ("${{7*7}}", "49", "Polyglot"),
    ("@(7*7)", "49", "Razor"),
    ("[[${7*7}]]", "49", "Thymeleaf"),
]


async def scan_ssti(http, url, param, method="GET"):
    for payload, expected, engine in SSTI_PROBES:
        try:
            r = await (http.get(url, params={param: payload}, timeout=10) if method=="GET"
                       else http.post(url, data={param: payload}, timeout=10))
            if expected in r.text and payload not in r.text:
                return Finding(
                    title=f"Server-Side Template Injection ({engine}) in '{param}'",
                    description=f"Parameter '{param}' is evaluated by {engine}. Payload {payload} returned {expected}.",
                    source=FindingSource.WEBAPP, severity=Severity.CRITICAL,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="SSTI", cwe="CWE-1336",
                    owasp_category="A03:2021 Injection", payload=payload,
                    impact="SSTI typically escalates to RCE. Complete server compromise possible.",
                    remediation="Never pass user input to template engines. Use sandboxed templates with explicit context.",
                    confidence=0.95, tags=["ssti", f"engine:{engine}"],
                )
        except Exception: continue
    return None


async def scan_sqli_boolean(http, url, param, method="GET"):
    pairs = [("1 AND 1=1", "1 AND 1=2"), ("1' AND '1'='1", "1' AND '1'='2")]
    for true_p, false_p in pairs:
        try:
            t = await (http.get(url, params={param: true_p}, timeout=10) if method=="GET"
                       else http.post(url, data={param: true_p}, timeout=10))
            f = await (http.get(url, params={param: false_p}, timeout=10) if method=="GET"
                       else http.post(url, data={param: false_p}, timeout=10))
            if abs(len(t.text)-len(f.text)) > 100 or t.status_code != f.status_code:
                return Finding(
                    title=f"Blind Boolean SQL Injection in '{param}'",
                    description=f"'{param}' shows differential: TRUE={t.status_code}/{len(t.text)}B FALSE={f.status_code}/{len(f.text)}B.",
                    source=FindingSource.WEBAPP, severity=Severity.CRITICAL,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="SQLi (Blind Boolean)", cwe="CWE-89",
                    payload=true_p, impact="Database extraction via boolean blind injection.",
                    remediation="Use parameterized queries.", confidence=0.85, tags=["sqli", "blind"],
                )
        except Exception: continue
    return None


async def scan_sqli_time(http, url, param, method="GET"):
    payloads = ["'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--", "' AND pg_sleep(5)--"]
    for payload in payloads:
        try:
            t0 = time.time()
            r = await (http.get(url, params={param: payload}, timeout=15) if method=="GET"
                       else http.post(url, data={param: payload}, timeout=15))
            elapsed = time.time() - t0
            if elapsed >= 4.0:
                t1 = time.time()
                await (http.get(url, params={param: "1"}, timeout=10) if method=="GET"
                       else http.post(url, data={param: "1"}, timeout=10))
                normal = time.time() - t1
                if elapsed > normal * 2:
                    return Finding(
                        title=f"Time-Based Blind SQL Injection in '{param}'",
                        description=f"'{param}' triggered {elapsed:.1f}s delay (normal: {normal:.1f}s).",
                        source=FindingSource.WEBAPP, severity=Severity.CRITICAL,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=url, endpoint=url, vuln_type="SQLi (Time-Based)",
                        cwe="CWE-89", payload=payload, confidence=0.9, tags=["sqli", "time"],
                        impact="Full DB access via time-based blind injection.",
                        remediation="Use parameterized queries.",
                    )
        except Exception: continue
    return None


async def scan_command_injection(http, url, param, method="GET"):
    for payload in ["; sleep 5", "| sleep 5", "&& sleep 5", "; ping -c 5 127.0.0.1"]:
        try:
            t0 = time.time()
            await (http.get(url, params={param: payload}, timeout=15) if method=="GET"
                   else http.post(url, data={param: payload}, timeout=15))
            if time.time() - t0 >= 4.0:
                return Finding(
                    title=f"OS Command Injection in '{param}'",
                    description=f"Payload '{payload}' caused timing delay confirming OS command execution.",
                    source=FindingSource.WEBAPP, severity=Severity.CRITICAL,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="Command Injection",
                    cwe="CWE-78", payload=payload, confidence=0.95, tags=["cmdi", "rce"],
                    impact="Arbitrary OS command execution. Full server compromise.",
                    remediation="Never pass user input to shell. Use subprocess with list args.",
                )
        except Exception: continue
    return None


PATH_PAYLOADS = ["../../../etc/passwd", "....//....//....//etc/passwd",
                 "..%2f..%2f..%2fetc%2fpasswd", "..\\..\\..\\windows\\win.ini",
                 "/etc/passwd", "file:///etc/passwd"]


async def scan_path_traversal(http, url, param, method="GET"):
    linux_markers = ["root:x:0:0:", "daemon:x:", "/bin/bash"]
    win_markers = ["[fonts]", "[extensions]", "for 16-bit"]
    for payload in PATH_PAYLOADS:
        try:
            r = await (http.get(url, params={param: payload}, timeout=10) if method=="GET"
                       else http.post(url, data={param: payload}, timeout=10))
            for markers, os_t in [(linux_markers, "linux"), (win_markers, "windows")]:
                if sum(1 for m in markers if m in r.text) >= 2:
                    return Finding(
                        title=f"Path Traversal / LFI in '{param}'",
                        description=f"Payload '{payload}' returned {os_t} system file content.",
                        source=FindingSource.WEBAPP, severity=Severity.HIGH,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=url, endpoint=url, vuln_type="Path Traversal",
                        cwe="CWE-22", payload=payload, confidence=0.95, tags=["lfi"],
                        impact="Read arbitrary files. May expose source, config, credentials, or chain to RCE.",
                        remediation="Validate paths against allowlist. Use os.path.normpath.",
                    )
        except Exception: continue
    return None


async def scan_xpath(http, url, param, method="GET"):
    try:
        t = await (http.get(url, params={param: "' or '1'='1"}, timeout=10) if method=="GET"
                   else http.post(url, data={param: "' or '1'='1"}, timeout=10))
        errors = ["xpath", "XPathException", "Invalid XPath"]
        if any(e.lower() in t.text.lower() for e in errors):
            return Finding(
                title=f"XPath Injection in '{param}'",
                description="XPath errors triggered by injection payloads.",
                source=FindingSource.WEBAPP, severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url, endpoint=url, vuln_type="XPath Injection",
                cwe="CWE-643", payload="' or '1'='1", confidence=0.8, tags=["xpath"],
                impact="Bypass auth or extract XML data.",
                remediation="Use parameterized XPath queries.",
            )
    except Exception: pass
    return None


async def scan_ldap(http, url, param, method="GET"):
    errors = ["ldap_search", "Invalid DN", "LDAP error", "ldap.SERVER_DOWN"]
    for payload in ["*", "*)(&", "*)(|(objectClass=*))", "admin)(&)"]:
        try:
            r = await (http.get(url, params={param: payload}, timeout=10) if method=="GET"
                       else http.post(url, data={param: payload}, timeout=10))
            if any(e.lower() in r.text.lower() for e in errors):
                return Finding(
                    title=f"LDAP Injection in '{param}'",
                    description="LDAP error messages triggered.",
                    source=FindingSource.WEBAPP, severity=Severity.HIGH,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="LDAP Injection",
                    cwe="CWE-90", payload=payload, confidence=0.8, tags=["ldap"],
                    impact="Auth bypass or directory enumeration.",
                    remediation="Parameterize LDAP queries and escape special chars.",
                )
        except Exception: continue
    return None


async def scan_nosql(http, url, param, method="GET"):
    try:
        if method == "GET":
            normal = await http.get(url, params={param: "test"}, timeout=10)
            r = await http.get(f"{url}?{param}[$ne]=test", timeout=10)
        else:
            normal = await http.post(url, json={param: "test"}, timeout=10)
            r = await http.post(url, json={param: {"$ne": ""}}, timeout=10)
        if r.status_code < 400 and abs(len(r.text)-len(normal.text)) > 200:
            return Finding(
                title=f"NoSQL Injection in '{param}'",
                description=f"Parameter accepts MongoDB operators ({method}).",
                source=FindingSource.WEBAPP, severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url, endpoint=url, vuln_type="NoSQL Injection",
                cwe="CWE-943", payload="$ne operator", confidence=0.8, tags=["nosqli"],
                impact="Auth bypass and data extraction via NoSQL operators.",
                remediation="Validate input schema; reject objects with $ keys.",
            )
    except Exception: pass
    return None


async def scan_prototype_pollution(http, url, method="POST"):
    try:
        if method == "GET":
            await http.get(url, params={"__proto__[mantisPP]": "yes"}, timeout=10)
        else:
            await http.post(url, json={"__proto__": {"mantisPP": "yes"}}, timeout=10)
        probe = await http.get(url, timeout=10)
        if "mantisPP" in probe.text:
            return Finding(
                title="Prototype Pollution",
                description="__proto__ injection persists across requests.",
                source=FindingSource.WEBAPP, severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url, endpoint=url, vuln_type="Prototype Pollution",
                cwe="CWE-1321", confidence=0.85, tags=["prototype_pollution"],
                impact="Can lead to XSS, privesc, DoS, or RCE in Node.js.",
                remediation="Use Object.create(null). Validate JSON, reject __proto__ keys.",
            )
    except Exception: pass
    return None


async def scan_hpp(http, url, param):
    try:
        r_dup = await http.get(f"{url}?{param}=A&{param}=B", timeout=10)
        r_a = await http.get(url, params={param: "A"}, timeout=10)
        r_b = await http.get(url, params={param: "B"}, timeout=10)
        if (len(r_dup.text) != len(r_a.text) and len(r_dup.text) != len(r_b.text)
            and abs(len(r_a.text)-len(r_b.text)) > 50):
            return Finding(
                title=f"HTTP Parameter Pollution in '{param}'",
                description="Duplicate parameters handled non-trivially.",
                source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url, endpoint=url, vuln_type="HPP",
                cwe="CWE-235", confidence=0.6, tags=["hpp"],
                impact="Bypass WAF, validation, or business logic.",
                remediation="Reject duplicate params or define explicit handling.",
            )
    except Exception: pass
    return None


async def scan_crlf(http, url, param):
    for payload in ["%0d%0aX-Mantis-Test: injected", "%0aX-Mantis-Test: injected"]:
        try:
            r = await http.get(url, params={param: payload}, timeout=10)
            if "x-mantis-test" in [k.lower() for k in r.headers.keys()]:
                return Finding(
                    title=f"CRLF Injection in '{param}'",
                    description="Arbitrary HTTP response headers injectable.",
                    source=FindingSource.WEBAPP, severity=Severity.HIGH,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="CRLF Injection",
                    cwe="CWE-113", payload=payload, confidence=0.95, tags=["crlf"],
                    impact="HTTP response splitting, cache poisoning, header-based XSS.",
                    remediation="Strip CR/LF from values used in HTTP headers.",
                )
        except Exception: continue
    return None


async def scan_xxe_xml_body(http, url, method="POST"):
    payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    try:
        r = await http.request(method, url, content=payload,
                                headers={"Content-Type": "application/xml"}, timeout=10)
        if "root:x:0:0" in r.text or "/bin/bash" in r.text:
            return Finding(
                title=f"XML External Entity (XXE) at {url}",
                description="Endpoint parses XML with external entities enabled.",
                source=FindingSource.WEBAPP, severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=url, endpoint=url, vuln_type="XXE",
                cwe="CWE-611", payload=payload, confidence=0.95, tags=["xxe"],
                impact="File read, SSRF, or DoS via XML external entities.",
                remediation="Disable DTD/external entity processing. Use defusedxml (Python).",
            )
    except Exception: pass
    return None
