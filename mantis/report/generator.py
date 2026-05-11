"""
Multi-format report generator.

Produces Markdown, JSON, HTML, and SARIF reports from engagement findings.
Includes executive summary, finding details, attack chains, evidence,
and remediation guidance.
"""

import os
import json
from datetime import datetime
from mantis.engage.phases import Phase
from mantis.core.findings import Finding
from mantis.report.sarif import generate_sarif


class ReportGenerator:
    """Generate reports in multiple formats."""

    def __init__(self, session_id: str, target: str, mode: str):
        self.session_id = session_id
        self.target = target
        self.mode = mode
        self.timestamp = datetime.utcnow().isoformat()

    def generate_all(self, findings: list[Finding], output_dir: str,
                     formats: list[str] = None, chains: list = None):
        """Generate reports in all requested formats."""
        formats = formats or ["markdown", "json", "html"]
        os.makedirs(output_dir, exist_ok=True)

        if "json" in formats:
            self._write_json(findings, output_dir, chains)
        if "markdown" in formats:
            self._write_markdown(findings, output_dir, chains)
        if "html" in formats:
            self._write_html(findings, output_dir, chains)
        if "sarif" in formats:
            self._write_sarif(findings, output_dir)

    def _write_json(self, findings: list[Finding], output_dir: str, chains=None):
        data = {
            "mantis_version": "1.1.0",
            "session_id": self.session_id,
            "target": self.target,
            "mode": self.mode,
            "timestamp": self.timestamp,
            "summary": self._build_summary(findings),
            "findings": [f.to_dict() for f in findings],
            "chains": [c.__dict__ if hasattr(c, '__dict__') else c for c in (chains or [])],
        }
        path = os.path.join(output_dir, "report.json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _write_markdown(self, findings: list[Finding], output_dir: str, chains=None):
        lines = []
        lines.append(f"# MANTIS Security Assessment Report\n")
        lines.append(f"**Target:** {self.target}  ")
        lines.append(f"**Mode:** {self.mode}  ")
        lines.append(f"**Session:** {self.session_id}  ")
        lines.append(f"**Date:** {self.timestamp}  \n")

        # Executive summary
        summary = self._build_summary(findings)
        lines.append("## Executive Summary\n")
        lines.append(f"Total findings: **{summary['total']}**\n")
        for sev, count in summary["by_severity"].items():
            lines.append(f"- {sev.capitalize()}: {count}")
        lines.append("")

        # Attack chains
        if chains:
            lines.append("## Attack Chains\n")
            for chain in chains:
                title = chain.title if hasattr(chain, 'title') else chain.get('title', '')
                impact = chain.combined_impact if hasattr(chain, 'combined_impact') else chain.get('combined_impact', '')
                lines.append(f"### {title}\n")
                lines.append(f"**Combined Impact:** {impact}\n")
                lines.append("")

        # Findings by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        for sev in severity_order:
            sev_findings = [f for f in findings if f.severity.value == sev and not f.false_positive]
            if not sev_findings:
                continue
            lines.append(f"## {sev.capitalize()} Findings\n")
            for f in sev_findings:
                lines.append(f"### {f.id}: {f.title}\n")
                lines.append(f"**Type:** {f.vuln_type} | **CWE:** {f.cwe or 'N/A'} | "
                             f"**Confidence:** {f.confidence:.0%} | "
                             f"**Evidence:** {f.evidence_level.value}\n")
                lines.append(f"**Target:** {f.target or f.file_path or 'N/A'}")
                if f.line_number:
                    lines.append(f" (line {f.line_number})")
                lines.append(f"\n\n{f.description}\n")
                if f.impact:
                    lines.append(f"**Impact:** {f.impact}\n")
                if f.remediation:
                    lines.append(f"**Remediation:** {f.remediation}\n")
                if f.reproduction_steps:
                    lines.append("**Reproduction Steps:**\n")
                    for step in f.reproduction_steps:
                        lines.append(f"  {step}")
                    lines.append("")
                lines.append("---\n")

        path = os.path.join(output_dir, "report.md")
        with open(path, "w") as f:
            f.write("\n".join(lines))

    def _write_html(self, findings: list[Finding], output_dir: str, chains=None):
        """Generate a self-contained HTML report."""
        summary = self._build_summary(findings)
        sev_colors = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107",
                       "low": "#28a745", "info": "#17a2b8"}

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MANTIS Report — {self.target}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f8f9fa; color: #212529; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #1a1a2e; }} h2 {{ color: #0f3460; border-bottom: 2px solid #dee2e6; padding-bottom: 8px; }}
.summary {{ display: flex; gap: 16px; margin: 20px 0; flex-wrap: wrap; }}
.stat {{ background: white; padding: 16px 24px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; min-width: 120px; }}
.stat .number {{ font-size: 2em; font-weight: bold; }} .stat .label {{ color: #6c757d; font-size: 0.9em; }}
.finding {{ background: white; border-radius: 8px; padding: 20px; margin: 16px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 4px solid #dee2e6; }}
.finding.critical {{ border-left-color: #dc3545; }} .finding.high {{ border-left-color: #fd7e14; }}
.finding.medium {{ border-left-color: #ffc107; }} .finding.low {{ border-left-color: #28a745; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: white; font-size: 0.85em; font-weight: bold; }}
code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
</style></head><body><div class="container">
<h1>MANTIS Security Assessment Report</h1>
<p><strong>Target:</strong> {self.target} | <strong>Mode:</strong> {self.mode} | <strong>Date:</strong> {self.timestamp}</p>
<div class="summary">
  <div class="stat"><div class="number">{summary['total']}</div><div class="label">Total Findings</div></div>"""

        for sev in ["critical", "high", "medium", "low"]:
            count = summary["by_severity"].get(sev, 0)
            html += f'\n  <div class="stat"><div class="number" style="color:{sev_colors[sev]}">{count}</div><div class="label">{sev.capitalize()}</div></div>'

        html += "</div><h2>Findings</h2>"

        for f in sorted(findings, key=lambda x: ["critical","high","medium","low","info"].index(x.severity.value)):
            if f.false_positive:
                continue
            sev = f.severity.value
            html += f"""
<div class="finding {sev}">
  <h3><span class="badge" style="background:{sev_colors.get(sev,'#6c757d')}">{sev.upper()}</span> {f.title}</h3>
  <p><strong>Type:</strong> {f.vuln_type} | <strong>CWE:</strong> {f.cwe or 'N/A'} | <strong>Evidence:</strong> {f.evidence_level.value}</p>
  <p>{f.description}</p>
  {'<p><strong>Impact:</strong> ' + f.impact + '</p>' if f.impact else ''}
  {'<p><strong>Remediation:</strong> ' + f.remediation + '</p>' if f.remediation else ''}
</div>"""

        html += "</div></body></html>"
        path = os.path.join(output_dir, "report.html")
        with open(path, "w") as f:
            f.write(html)

    def _write_sarif(self, findings: list[Finding], output_dir: str):
        sarif = generate_sarif(findings)
        path = os.path.join(output_dir, "report.sarif")
        with open(path, "w") as f:
            json.dump(sarif, f, indent=2)

    def _build_summary(self, findings: list[Finding]) -> dict:
        active = [f for f in findings if not f.false_positive]
        by_severity = {}
        for f in active:
            sev = f.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
        return {"total": len(active), "by_severity": by_severity}


class ReportPhase(Phase):
    """Phase: generate final reports in all configured formats."""

    async def execute(self, context) -> dict:
        output_dir = os.path.expanduser(f"~/.mantis/results/{self.config.session_id}")
        generator = ReportGenerator(
            session_id=self.config.session_id,
            target=self.config.target,
            mode=self.config.mode,
        )

        active_findings = [f for f in context.findings if not f.false_positive]
        generator.generate_all(active_findings, output_dir,
                               formats=["markdown", "json", "html", "sarif"])

        print(f"    Reports written to {output_dir}/")
        print(f"      report.md, report.json, report.html, report.sarif")
        return {}
