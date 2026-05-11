"""
Engagement mode definitions.

Each mode specifies which phases run and which tools are loaded.
The operator selects a mode via CLI; the EngagementRunner assembles
the pipeline automatically.
"""

ENGAGEMENT_MODES = {
    "network": {
        "phases": [
            "port_scan", "service_detect", "vuln_scan",
            "exploit", "report",
        ],
        "tools": ["network"],
        "description": "Network infrastructure pentest",
    },
    "webapp": {
        "phases": [
            "crawl", "auth_test", "vuln_scan",
            "business_logic", "exploit", "report",
        ],
        "tools": ["webapp"],
        "description": "Internal web application pentest (no recon)",
    },
    "webapp_external": {
        "phases": [
            "osint", "subdomain_enum", "tech_detect", "dns_enum",
            "crawl", "auth_test", "vuln_scan",
            "business_logic", "exploit", "report",
        ],
        "tools": ["webapp", "recon"],
        "description": "External web app pentest with full recon",
    },
    "api": {
        "phases": [
            "schema_ingest", "auth_chain", "endpoint_scan",
            "business_logic", "exploit", "report",
        ],
        "tools": ["api"],
        "description": "API-focused pentest (OpenAPI/GraphQL/Postman)",
    },
    "code_review": {
        "phases": [
            "preprocess", "static_scan", "triage",
            "deep_scan", "verify", "variant_hunt", "report",
        ],
        "tools": ["codereview"],
        "description": "Source code security review",
    },
    "code_review+webapp": {
        "phases": [
            # Code review phases
            "preprocess", "static_scan", "triage", "deep_scan", "verify",
            # Web app phases
            "crawl", "auth_test", "vuln_scan", "business_logic",
            # Combined phase — cross-references code and runtime findings
            "correlate",
            # Final phases
            "exploit", "report",
        ],
        "tools": ["codereview", "webapp"],
        "description": "Code review + web app pentest with correlation",
    },
    "full": {
        "phases": [
            # Recon
            "osint", "subdomain_enum", "tech_detect", "dns_enum",
            # Network
            "port_scan", "service_detect",
            # Web app
            "crawl", "auth_test", "vuln_scan", "business_logic",
            # API
            "schema_ingest", "endpoint_scan",
            # Code review
            "preprocess", "static_scan", "triage", "deep_scan", "verify",
            # Combined
            "correlate", "exploit", "report",
        ],
        "tools": ["all"],
        "description": "Full engagement — everything",
    },
}
