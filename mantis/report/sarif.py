"""SARIF output for CI/CD integration (GitHub Code Scanning, Azure DevOps)."""

import json
from mantis.core.findings import Finding


def generate_sarif(findings: list[Finding], tool_name: str = "MANTIS") -> dict:
    """Generate a SARIF 2.1.0 report from findings."""
    rules = []
    results = []

    for i, f in enumerate(findings):
        rule_id = f.cwe or f"MANTIS-{i:04d}"
        rules.append({
            "id": rule_id,
            "name": f.vuln_type,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[1]}.html" if f.cwe else "",
        })
        result = {
            "ruleId": rule_id,
            "level": {"critical": "error", "high": "error", "medium": "warning",
                      "low": "note", "info": "note"}.get(f.severity.value, "warning"),
            "message": {"text": f.description},
        }
        if f.file_path:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": f.line_number or 1},
                },
            }]
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": "1.0.0",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }
