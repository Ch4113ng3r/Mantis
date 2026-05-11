"""
Master scanner orchestrator.

Runs every scanner in the right context (parameter-level, endpoint-level,
or site-level) against discovered attack surface. This is what gets wired
into the VulnScanPhase.
"""

import asyncio
import httpx
from typing import Optional

from . import injection, standard, client_side, auth_session, http_protocol, server_processing, infrastructure, advanced


# Scanner registries by scope
PARAM_SCANNERS = [
    # name, function — called as fn(http, url, param, method)
    ("ssti", injection.scan_ssti),
    ("sqli_error", standard.scan_sqli_error),
    ("sqli_boolean", injection.scan_sqli_boolean),
    ("sqli_time", injection.scan_sqli_time),
    ("xss_reflected", standard.scan_xss_reflected),
    ("command_injection", injection.scan_command_injection),
    ("path_traversal", injection.scan_path_traversal),
    ("xpath", injection.scan_xpath),
    ("ldap", injection.scan_ldap),
    ("nosql", injection.scan_nosql),
    ("crlf", injection.scan_crlf),
    ("css_injection", client_side.scan_css_injection),
    ("dangling_markup", client_side.scan_dangling_markup),
    ("csti", client_side.scan_csti),
    ("ssi_injection", advanced.scan_ssi_injection),
    ("email_header_injection", advanced.scan_email_header_injection),
]

# Scanners that take (http, url, param) without method
PARAM_NO_METHOD = [
    ("hpp", injection.scan_hpp),
    ("open_redirect", standard.scan_open_redirect),
]

# Endpoint-level scanners — called as fn(http, url) or fn(http, url, method)
ENDPOINT_SCANNERS = [
    ("cors", standard.scan_cors),
    ("xxe_xml_body", injection.scan_xxe_xml_body),
    ("clickjacking", standard.scan_clickjacking),
    ("host_header", standard.scan_host_header_injection),
    ("subdomain_takeover", standard.scan_subdomain_takeover),
    ("dom_clobbering", client_side.scan_dom_clobbering),
    ("jsonp_hijacking", client_side.scan_jsonp_hijacking),
    ("postmessage", client_side.scan_postmessage),
    ("web_storage", client_side.scan_web_storage_leak),
    ("verb_tampering", http_protocol.scan_verb_tampering),
    ("method_override", http_protocol.scan_http_method_override),
    ("request_smuggling", http_protocol.scan_request_smuggling_basic),
    ("websocket", http_protocol.scan_websocket_endpoints),
    ("content_type_confusion", http_protocol.scan_content_type_confusion),
    ("token_leakage", auth_session.scan_token_leakage_referer),
    ("session_cookie", auth_session.scan_session_fixation),
    ("mfa_step_skip", auth_session.scan_mfa_step_skip),
    ("file_upload", standard.scan_file_upload),
    ("imagetragick", server_processing.scan_imagetragick),
    ("zipslip", server_processing.scan_zipslip),
    ("pdf_generation_ssrf", server_processing.scan_pdf_generation_ssrf),
    ("csv_injection", server_processing.scan_csv_injection),
    ("cache_poisoning", advanced.scan_cache_poisoning),
    ("padding_oracle", advanced.scan_padding_oracle),
    ("timing_attack_auth", advanced.scan_timing_attack_auth),
]

# Endpoint-level scanners that need method
ENDPOINT_METHOD_SCANNERS = [
    ("csrf", standard.scan_csrf),
    ("race_condition", advanced.scan_race_condition),
    ("mass_assignment", advanced.scan_mass_assignment),
]

# Site-level scanners — called once per target
SITE_SCANNERS = [
    ("exposed_files", infrastructure.scan_exposed_files),
    ("source_maps", infrastructure.scan_source_maps),
    ("api_versioning_bypass", infrastructure.scan_api_versioning_bypass),
    ("redos", infrastructure.scan_redos),
    ("grpc_reflection", infrastructure.scan_grpc_reflection),
]


async def scan_endpoint(http: httpx.AsyncClient, url: str, params: list, method: str = "GET"):
    """Run all applicable scanners against an endpoint."""
    findings = []
    sem = asyncio.Semaphore(5)

    # Parameter-level scanners
    async def run_param_scanner(name, fn, param, with_method=True):
        async with sem:
            try:
                if with_method:
                    result = await fn(http, url, param, method)
                else:
                    result = await fn(http, url, param)
                if result:
                    findings.append(result)
            except Exception: pass

    param_tasks = []
    for param in params[:10]:  # Cap params for speed
        for name, fn in PARAM_SCANNERS:
            param_tasks.append(run_param_scanner(name, fn, param, True))
        for name, fn in PARAM_NO_METHOD:
            param_tasks.append(run_param_scanner(name, fn, param, False))
    if param_tasks:
        await asyncio.gather(*param_tasks, return_exceptions=True)

    # Endpoint-level scanners
    async def run_endpoint_scanner(name, fn, with_method=False):
        async with sem:
            try:
                if with_method:
                    result = await fn(http, url, method)
                else:
                    result = await fn(http, url)
                if result:
                    if isinstance(result, list):
                        findings.extend(result)
                    else:
                        findings.append(result)
            except Exception: pass

    endpoint_tasks = []
    for name, fn in ENDPOINT_SCANNERS:
        endpoint_tasks.append(run_endpoint_scanner(name, fn, False))
    for name, fn in ENDPOINT_METHOD_SCANNERS:
        endpoint_tasks.append(run_endpoint_scanner(name, fn, True))
    if endpoint_tasks:
        await asyncio.gather(*endpoint_tasks, return_exceptions=True)

    # Prototype pollution (no param)
    try:
        pp = await injection.scan_prototype_pollution(http, url, method)
        if pp: findings.append(pp)
    except Exception: pass

    return findings


async def scan_site(http: httpx.AsyncClient, base_url: str):
    """Run site-level scanners once per target."""
    findings = []
    for name, fn in SITE_SCANNERS:
        try:
            result = await fn(http, base_url)
            if result:
                if isinstance(result, list):
                    findings.extend(result)
                else:
                    findings.append(result)
        except Exception: pass
    return findings
