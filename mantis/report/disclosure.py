"""
Disclosure template generator.

Generates pre-filled MITRE CVE request and HackerOne templates
for verified findings with evidence_level >= root_cause_explained.

Output: one file per finding in the results directory.
"""

import os
import json
from datetime import datetime
from mantis.core.findings import Finding, EvidenceLevel


def generate_disclosure_templates(
    findings: list[Finding],
    output_dir: str,
    vendor_name: str = "VENDOR",
    reporter_name: str = "Security Researcher",
    reporter_email: str = "researcher@example.com",
):
    """
    Generate disclosure templates for qualifying findings.

    Only findings with evidence_level >= ROOT_CAUSE_EXPLAINED are included,
    as lower evidence levels don't have enough detail for responsible disclosure.
    """
    qualifying_levels = {
        EvidenceLevel.ROOT_CAUSE_EXPLAINED,
        EvidenceLevel.EXPLOIT_DEMONSTRATED,
        EvidenceLevel.PATCH_VALIDATED,
    }

    disclosure_dir = os.path.join(output_dir, "disclosures")
    os.makedirs(disclosure_dir, exist_ok=True)

    count = 0
    for finding in findings:
        if finding.evidence_level not in qualifying_levels:
            continue
        if finding.false_positive:
            continue

        count += 1

        # MITRE CVE Request template
        cve_template = f"""MITRE CVE Request — Pre-filled Template
========================================
Date: {datetime.utcnow().strftime('%Y-%m-%d')}
Finding ID: {finding.id}

1. VULNERABILITY TYPE
   CWE: {finding.cwe or 'TBD'}
   Type: {finding.vuln_type}

2. VENDOR / PRODUCT
   Vendor: {vendor_name}
   Product: {finding.target}
   Version: TBD — confirm affected versions

3. VULNERABILITY DESCRIPTION
   {finding.description}

4. ATTACK TYPE
   Context: {'Remote' if 'http' in (finding.target or '').lower() else 'Local'}
   Authentication Required: TBD

5. IMPACT
   {finding.impact}
   CVSS Score: {finding.cvss_score or 'TBD'}
   CVSS Vector: {finding.cvss_vector or 'TBD'}

6. AFFECTED COMPONENT
   Endpoint: {finding.endpoint or 'N/A'}
   File: {finding.file_path or 'N/A'}
   Line: {finding.line_number or 'N/A'}

7. REPRODUCTION STEPS
{chr(10).join('   ' + step for step in finding.reproduction_steps) if finding.reproduction_steps else '   See finding evidence.'}

8. ROOT CAUSE
   {finding.taint_path or finding.mechanism or 'See description above.'}

9. SUGGESTED FIX
   {finding.remediation}

10. DISCOVERER
    Name: {reporter_name}
    Email: {reporter_email}
    Tool: MANTIS AI-Powered Penetration Testing Framework

11. REFERENCES
    Evidence Level: {finding.evidence_level.value}
    Confidence: {finding.confidence}
"""

        cve_path = os.path.join(disclosure_dir, f"{finding.id}_cve_request.txt")
        with open(cve_path, "w") as f:
            f.write(cve_template)

        # HackerOne Report template
        h1_template = f"""HackerOne Report — Pre-filled Template
========================================
Title: {finding.title}
Severity: {finding.severity.value.capitalize()}
Weakness: {finding.cwe or finding.vuln_type}

## Summary
{finding.description}

## Steps to Reproduce
{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(finding.reproduction_steps)) if finding.reproduction_steps else 'See technical details below.'}

## Impact
{finding.impact}

## Technical Details
- Vulnerability Type: {finding.vuln_type}
- CWE: {finding.cwe or 'N/A'}
- Endpoint: {finding.endpoint or 'N/A'}
- Payload: {finding.payload or 'N/A'}
- Evidence Level: {finding.evidence_level.value}

## Suggested Fix
{finding.remediation}

## Supporting Material
Finding ID: {finding.id}
Discovered: {finding.timestamp}
Tool: MANTIS v1.0
"""

        h1_path = os.path.join(disclosure_dir, f"{finding.id}_hackerone.md")
        with open(h1_path, "w") as f:
            f.write(h1_template)

    return count
