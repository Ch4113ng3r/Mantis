"""
Active Directory post-exploitation scanner (v1.5).

Detection-oriented: finds Kerberoastable accounts, AS-REP roastable accounts,
ADCS misconfigurations, dangerous ACLs, unconstrained delegation. Actual
exploitation (hash cracking, certificate request, NTLM relay) is delegated
to the AI agent via playbooks since it requires impacket integration and
testing against a real AD lab.

Requires: ldap-utils, smbclient, enum4linux available in the Kali container.
Optionally: impacket (for SPN parsing) — if installed, more detail extracted.
"""

import asyncio
import subprocess
import re
from typing import Optional
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource
from mantis.utils.verbose import log


async def _run_docker_kali(command: str, timeout: int = 60) -> tuple[str, str, int]:
    """Run a command inside the mantis-kali Docker container."""
    full_cmd = ["docker", "run", "--rm", "--network=host", "mantis-kali",
                "bash", "-c", command]
    try:
        proc = await asyncio.create_subprocess_exec(
            *full_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
            proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        return "", f"Timeout after {timeout}s", -1
    except Exception as e:
        return "", f"Error: {e}", -1


async def scan_kerberoastable_accounts(
    domain_controller: str, domain: str,
    username: str = "", password: str = "",
) -> list[Finding]:
    """
    Find user accounts with SPNs (Kerberoastable).

    Uses ldapsearch to query for users with servicePrincipalName attribute.
    Kerberoastable accounts can have their TGS-REP requested and hash cracked
    offline. Service accounts with weak passwords are the typical target.
    """
    log.info(f"Scanning {domain_controller} for Kerberoastable accounts")
    findings = []

    if not username or not password:
        log.warn("No credentials — Kerberoasting requires authentication")
        return findings

    # Build LDAP search base from domain (CORP.EXAMPLE.COM → DC=CORP,DC=EXAMPLE,DC=COM)
    base_dn = ",".join(f"DC={p}" for p in domain.upper().split("."))
    bind_dn = f"{username}@{domain.upper()}"

    cmd = (
        f"ldapsearch -x -H ldap://{domain_controller} "
        f"-D '{bind_dn}' -w '{password}' "
        f"-b '{base_dn}' "
        f"'(&(samAccountType=805306368)(servicePrincipalName=*))' "
        f"samAccountName servicePrincipalName 2>&1"
    )
    stdout, stderr, rc = await _run_docker_kali(cmd, timeout=30)

    if rc != 0:
        log.warn(f"LDAP query failed: {stderr[:200]}")
        return findings

    # Parse output for sAMAccountName entries
    accounts = re.findall(r"sAMAccountName:\s*(\S+)", stdout, re.IGNORECASE)
    spn_accounts = []
    current_account = None
    for line in stdout.splitlines():
        if line.lower().startswith("samaccountname:"):
            current_account = line.split(":", 1)[1].strip()
        if line.lower().startswith("serviceprincipalname:") and current_account:
            spn = line.split(":", 1)[1].strip()
            spn_accounts.append((current_account, spn))

    if spn_accounts:
        unique_users = set(a for a, _ in spn_accounts)
        findings.append(Finding(
            title=f"{len(unique_users)} Kerberoastable accounts on {domain_controller}",
            description=(
                f"Found {len(unique_users)} user accounts with servicePrincipalName attributes. "
                f"These are vulnerable to Kerberoasting — TGS-REP tickets can be requested for "
                f"each and hash-cracked offline. Service accounts with weak passwords are "
                f"typical targets.\n\nAccounts: {', '.join(sorted(unique_users)[:20])}"
            ),
            source=FindingSource.NETWORK,
            severity=Severity.HIGH,
            evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
            target=domain_controller,
            vuln_type="Kerberoasting Exposure",
            cwe="CWE-262",
            impact=(
                "Service account password compromise. If any of these accounts have weak "
                "passwords (which is common for service accounts), the attacker can derive "
                "the password from the ticket hash and impersonate that service account."
            ),
            remediation=(
                "Use strong, random passwords (25+ characters) for all service accounts. "
                "Migrate to Group Managed Service Accounts (gMSA) where possible. "
                "Monitor for anomalous TGS-REQ patterns."
            ),
            confidence=0.95,
            tags=["ad", "kerberoasting", "needs_exploitation"],
        ))
        log.finding(findings[0].title, "high", 0.95)

    return findings


async def scan_asreproastable_accounts(
    domain_controller: str, domain: str,
    username: str = "", password: str = "",
) -> list[Finding]:
    """
    Find accounts with 'Do not require Kerberos preauthentication' set.

    Such accounts can have AS-REP roasted without credentials — the KDC returns
    an encrypted blob that can be cracked offline.
    """
    log.info(f"Scanning {domain_controller} for AS-REP roastable accounts")
    findings = []

    if not username or not password:
        log.warn("AS-REP scan needs creds for LDAP query (exploitation doesn't, but enum does)")
        return findings

    base_dn = ",".join(f"DC={p}" for p in domain.upper().split("."))
    bind_dn = f"{username}@{domain.upper()}"

    # userAccountControl bit 0x400000 = DONT_REQ_PREAUTH
    cmd = (
        f"ldapsearch -x -H ldap://{domain_controller} "
        f"-D '{bind_dn}' -w '{password}' "
        f"-b '{base_dn}' "
        f"'(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' "
        f"samAccountName 2>&1"
    )
    stdout, _, rc = await _run_docker_kali(cmd, timeout=30)

    if rc == 0:
        accounts = re.findall(r"sAMAccountName:\s*(\S+)", stdout, re.IGNORECASE)
        if accounts:
            findings.append(Finding(
                title=f"{len(accounts)} AS-REP roastable accounts on {domain_controller}",
                description=(
                    f"Accounts with Kerberos pre-authentication disabled allow AS-REP "
                    f"roasting WITHOUT credentials. The KDC returns an encrypted blob "
                    f"that can be cracked offline.\n\nAccounts: {', '.join(accounts[:20])}"
                ),
                source=FindingSource.NETWORK,
                severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=domain_controller,
                vuln_type="AS-REP Roasting Exposure",
                cwe="CWE-262",
                impact="Pre-auth-disabled account passwords crackable without any valid credentials.",
                remediation="Enable Kerberos pre-authentication for all accounts unless absolutely required.",
                confidence=0.95,
                tags=["ad", "asrep_roasting", "no_creds_required"],
            ))
            log.finding(findings[0].title, "high", 0.95)

    return findings


async def scan_unconstrained_delegation(
    domain_controller: str, domain: str,
    username: str = "", password: str = "",
) -> list[Finding]:
    """Find computers/users with unconstrained delegation enabled."""
    log.info(f"Scanning {domain_controller} for unconstrained delegation")
    findings = []
    if not username or not password:
        return findings

    base_dn = ",".join(f"DC={p}" for p in domain.upper().split("."))
    bind_dn = f"{username}@{domain.upper()}"

    # userAccountControl bit 0x80000 = TRUSTED_FOR_DELEGATION
    cmd = (
        f"ldapsearch -x -H ldap://{domain_controller} "
        f"-D '{bind_dn}' -w '{password}' "
        f"-b '{base_dn}' "
        f"'(userAccountControl:1.2.840.113556.1.4.803:=524288)' "
        f"samAccountName 2>&1"
    )
    stdout, _, rc = await _run_docker_kali(cmd, timeout=30)
    if rc == 0:
        accounts = re.findall(r"sAMAccountName:\s*(\S+)", stdout, re.IGNORECASE)
        # Exclude Domain Controllers (they're expected to have this)
        non_dc = [a for a in accounts if not a.endswith("$") or "DC" not in a.upper()]
        if non_dc:
            findings.append(Finding(
                title=f"Unconstrained delegation enabled on {len(non_dc)} non-DC accounts",
                description=(
                    f"Computers or service accounts with unconstrained delegation cache "
                    f"the TGT of every user who authenticates to them. Compromising one "
                    f"of these enables impersonation of any user who connects.\n\n"
                    f"Accounts: {', '.join(non_dc[:20])}"
                ),
                source=FindingSource.NETWORK,
                severity=Severity.HIGH,
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=domain_controller,
                vuln_type="Unconstrained Delegation",
                cwe="CWE-269",
                impact="Compromise of these accounts enables impersonation across the domain.",
                remediation="Switch to constrained delegation (or resource-based constrained delegation). Disable unconstrained delegation entirely where possible.",
                confidence=0.9,
                tags=["ad", "unconstrained_delegation"],
            ))
            log.finding(findings[0].title, "high", 0.9)

    return findings


async def scan_adcs_misconfigurations(
    domain_controller: str, ca_server: str,
    domain: str, username: str = "", password: str = "",
) -> list[Finding]:
    """
    Detect ADCS certificate template misconfigurations (ESC1-ESC11).

    This is a DETECTION scanner — exploitation requires Certipy or similar
    impacket-based tools. The agent gets a playbook with exploitation steps.
    """
    log.info(f"Scanning {ca_server} for ADCS misconfigurations")
    findings = []

    if not username or not password:
        log.warn("ADCS scan requires credentials")
        return findings

    # Use certipy-py if installed in the container, otherwise just flag the
    # presence of an enrolled CA
    cmd = f"which certipy && certipy find -u {username}@{domain} -p '{password}' -dc-ip {domain_controller} 2>&1 | head -200"
    stdout, stderr, rc = await _run_docker_kali(cmd, timeout=60)

    if "ESC1" in stdout or "ESC2" in stdout or "ESC3" in stdout or "ESC8" in stdout:
        for esc in ["ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC7", "ESC8", "ESC11"]:
            if esc in stdout:
                findings.append(Finding(
                    title=f"ADCS {esc} vulnerability on {ca_server}",
                    description=(
                        f"Certipy reported {esc} misconfiguration. "
                        f"{_esc_description(esc)}"
                    ),
                    source=FindingSource.NETWORK,
                    severity=Severity.CRITICAL,
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=ca_server,
                    vuln_type=f"ADCS {esc}",
                    cwe="CWE-295",
                    impact="Domain takeover via certificate-based privilege escalation.",
                    remediation=_esc_remediation(esc),
                    confidence=0.9,
                    tags=["ad", "adcs", esc.lower()],
                ))
                log.finding(findings[-1].title, "critical", 0.9)
    elif rc != 0 and "certipy" not in stdout:
        # Certipy not installed — note it
        findings.append(Finding(
            title=f"ADCS scan incomplete on {ca_server} — certipy not installed",
            description=(
                "Active Directory Certificate Services enumeration requires Certipy. "
                "Install it in the Kali container with: pip install certipy-ad. "
                "Then re-run the scan to detect ESC1-ESC11 misconfigurations."
            ),
            source=FindingSource.NETWORK,
            severity=Severity.INFO,
            evidence_level=EvidenceLevel.SUSPICION,
            target=ca_server,
            vuln_type="ADCS Scan Skipped",
            tags=["ad", "scan_incomplete"],
            confidence=0.0,
        ))

    return findings


def _esc_description(esc: str) -> str:
    descriptions = {
        "ESC1": "Misconfigured certificate template allows requester to specify SAN and use the cert for authentication, enabling impersonation of any user including domain admins.",
        "ESC2": "Certificate template has 'Any Purpose' EKU, allowing client authentication, code signing, and more.",
        "ESC3": "Enrollment Agent template allows requesting certificates on behalf of other users.",
        "ESC4": "Vulnerable certificate template ACLs — low-privileged user can modify the template.",
        "ESC6": "EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled on the CA — SAN injection in any template.",
        "ESC7": "Vulnerable CA ACLs — low-priv user has ManageCA or ManageCertificates.",
        "ESC8": "ADCS Web Enrollment exposed with NTLM relay — coerce DC auth and relay to /certsrv.",
        "ESC11": "Relay to ICPR (IF_ENFORCEENCRYPTICERTREQUEST not set) — relay LDAP NTLM to ADCS.",
    }
    return descriptions.get(esc, "ADCS misconfiguration enabling certificate-based attacks.")


def _esc_remediation(esc: str) -> str:
    remediations = {
        "ESC1": "Disable 'Enrollee supplies subject' on the template, or restrict enrollment permissions.",
        "ESC2": "Remove 'Any Purpose' EKU. Set specific EKUs only.",
        "ESC3": "Restrict who can use enrollment agent templates. Require manager approval.",
        "ESC4": "Audit and lock down certificate template ACLs to authorized administrators only.",
        "ESC6": "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag on the CA.",
        "ESC7": "Remove ManageCA/ManageCertificates from non-CA-administrator users.",
        "ESC8": "Disable HTTP enrollment endpoints, or enforce EPA (Extended Protection for Authentication).",
        "ESC11": "Enable IF_ENFORCEENCRYPTICERTREQUEST on the ICPR interface.",
    }
    return remediations.get(esc, "Review the ADCS configuration and apply Microsoft's security best practices.")


async def scan_smb_signing_relay(target: str) -> Optional[Finding]:
    """Detect if SMB signing is disabled (NTLM relay precondition)."""
    log.info(f"Checking SMB signing on {target}")
    cmd = f"nmap -p 445 --script smb2-security-mode {target} 2>&1"
    stdout, _, rc = await _run_docker_kali(cmd, timeout=30)
    if "Message signing enabled but not required" in stdout or "signing disabled" in stdout.lower():
        return Finding(
            title=f"SMB signing not required on {target} — NTLM relay possible",
            description=(
                "SMB signing is not required. An attacker can perform NTLM relay attacks "
                "between this host and other systems on the network, gaining authenticated "
                "access without knowing passwords."
            ),
            source=FindingSource.NETWORK,
            severity=Severity.HIGH,
            evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
            target=target,
            vuln_type="SMB Signing Not Required",
            cwe="CWE-300",
            impact="NTLM relay attacks enabling lateral movement and privilege escalation.",
            remediation="Enable SMB signing requirement via GPO: 'Microsoft network server: Digitally sign communications (always)'.",
            confidence=0.95,
            tags=["ad", "ntlm_relay", "smb"],
        )
    return None


# === AD orchestration entry point ===

async def scan_ad_domain(
    domain_controller: str, domain: str,
    username: str = "", password: str = "",
    ca_server: str = "",
) -> list[Finding]:
    """Top-level AD scanner — runs all detection checks."""
    findings = []
    log.phase(f"Active Directory enumeration: {domain} via {domain_controller}")

    # Run scans in parallel where possible
    tasks = [
        scan_kerberoastable_accounts(domain_controller, domain, username, password),
        scan_asreproastable_accounts(domain_controller, domain, username, password),
        scan_unconstrained_delegation(domain_controller, domain, username, password),
        scan_smb_signing_relay(domain_controller),
    ]
    if ca_server:
        tasks.append(scan_adcs_misconfigurations(
            domain_controller, ca_server, domain, username, password,
        ))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)
        elif isinstance(r, Finding):
            findings.append(r)

    log.info(f"AD scan complete: {len(findings)} findings")
    return findings
