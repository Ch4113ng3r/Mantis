"""
Mode-aware network scanner — extends ModeAwareScanner pattern to network.

Mode 1: After port scan, AI Haiku classifies each service and decides which
        Kali tools to run. Output is regex-parsed for findings.
Mode 2: Mode 1 plus AI interprets tool output (5000-line enum4linux dumps
        get sent to Sonnet for anomaly detection).
Mode 3: AI owns the engagement. After initial port scan, AI builds a hypothesis
        about the network (corporate AD, DMZ, internal, etc.) and dispatches
        tools strategically via a ReAct loop. Tools become the AI's hands.
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Optional

from mantis.core.llm_client import AsyncLLMClient
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource
from mantis.config import load_config, get_api_key, get_model
from mantis.core.scan_modes import ScanDepth, MODE_CONFIGS
from mantis.utils.verbose import log


# Map of network tool names to what they do
NETWORK_TOOL_CATALOG = {
    # SMB / Windows
    "enum4linux": "SMB enumeration — users, shares, password policy",
    "smb_vuln_check": "Check for EternalBlue, SMBGhost",
    "list_smb_shares": "List SMB shares (anonymous + auth)",
    # AD / Kerberos
    "enum_ldap": "LDAP enumeration of domain objects",
    "kerberos_enum": "Kerberos user enumeration via TGT brute",
    "ad_kerberoastable": "Find Kerberoastable accounts (SPN-enabled)",
    "ad_asreproastable": "Find AS-REP roastable accounts",
    "ad_unconstrained_delegation": "Find accounts with TRUSTED_FOR_DELEGATION",
    "ad_smb_signing": "Check SMB signing (NTLM relay precondition)",
    # SNMP
    "enum_snmp": "SNMP walk for system info",
    "snmp_brute": "Brute-force SNMP community strings",
    # DNS
    "enum_dns": "DNS enumeration",
    "dns_zone_transfer": "Attempt zone transfer (AXFR)",
    # Web
    "nikto_scan": "Web server vulnerability scanner",
    "dir_brute": "Directory brute-force via gobuster",
    "subdomain_brute": "Subdomain brute-force",
    "whatweb": "Web technology fingerprinting",
    "ssl_scan": "SSL/TLS cipher and cert analysis",
    "http_methods": "Check allowed HTTP methods",
    "scan_wordpress": "WordPress enumeration",
    # Vuln checks
    "check_heartbleed": "OpenSSL Heartbleed",
    "check_shellshock": "Bash Shellshock",
    "check_default_creds": "Default credentials check",
    "check_docker_api": "Exposed Docker API",
    "check_kubernetes": "Exposed Kubernetes API",
    "check_elasticsearch": "Unauthenticated Elasticsearch",
    "check_jenkins": "Exposed Jenkins API",
    "vuln_scan_full": "Nmap vulners NSE",
    # Databases
    "enum_mysql": "MySQL info gathering",
    "enum_mssql": "MSSQL info gathering",
    "check_redis": "Redis unauthenticated access",
    "check_mongo": "MongoDB info",
    # Services
    "check_ftp_anon": "Anonymous FTP check",
    "audit_ssh": "SSH algorithm audit",
    "check_rdp": "RDP info / BlueKeep",
    "enum_smtp": "SMTP user enumeration",
    # Lower-level
    "nmap_deep_scan": "Nmap service detection on specific ports",
    "nmap_vuln_scan": "Nmap vulnerability scripts",
    "banner_grab": "Banner grabbing on port",
    "searchsploit": "Search Exploit-DB for known CVEs",
}

# Service → suggested tools mapping (used in Mode 1 as fallback if AI fails)
SERVICE_DEFAULT_TOOLS = {
    "smb": ["enum4linux", "smb_vuln_check", "list_smb_shares", "ad_smb_signing"],
    "microsoft-ds": ["enum4linux", "smb_vuln_check", "list_smb_shares", "ad_smb_signing"],
    "netbios": ["nbtscan", "list_smb_shares"],
    "ldap": ["enum_ldap", "ad_kerberoastable", "ad_asreproastable", "ad_unconstrained_delegation"],
    "kerberos": ["kerberos_enum", "ad_kerberoastable", "ad_asreproastable"],
    "snmp": ["enum_snmp", "snmp_brute"],
    "dns": ["enum_dns", "dns_zone_transfer"],
    "http": ["nikto_scan", "whatweb", "http_methods", "dir_brute"],
    "https": ["nikto_scan", "whatweb", "http_methods", "dir_brute", "ssl_scan"],
    "ssl": ["ssl_scan", "check_heartbleed"],
    "tls": ["ssl_scan", "check_heartbleed"],
    "ssh": ["audit_ssh", "check_default_creds"],
    "ftp": ["check_ftp_anon", "check_default_creds"],
    "rdp": ["check_rdp"],
    "smtp": ["enum_smtp"],
    "mysql": ["enum_mysql", "check_default_creds"],
    "mssql": ["enum_mssql", "check_default_creds"],
    "ms-sql-s": ["enum_mssql", "check_default_creds"],
    "redis": ["check_redis"],
    "mongodb": ["check_mongo"],
    "elasticsearch": ["check_elasticsearch"],
    "docker": ["check_docker_api"],
    "kubernetes": ["check_kubernetes"],
    "jenkins": ["check_jenkins"],
}


@dataclass
class ServiceObservation:
    """Service detected on a host with associated tool output."""
    host: str
    port: int
    service_name: str
    banner: str = ""
    nmap_xml: str = ""
    tool_outputs: dict = field(default_factory=dict)  # tool_name -> output text


@dataclass
class NetworkScanReport:
    mode: str
    findings: list = field(default_factory=list)
    services_observed: list = field(default_factory=list)
    tools_dispatched: int = 0
    tools_skipped: int = 0
    ai_classifications: int = 0
    ai_interpretations: int = 0
    ai_investigations: int = 0


class NetworkServiceClassifier:
    """
    AI-driven network service classifier.

    For each detected service: send banner + port + service name to Haiku,
    get back which tools are worth running.
    """

    def __init__(self, llm: AsyncLLMClient):
        self.llm = llm
        self.cache: dict[str, dict] = {}

    async def classify(self, host: str, port: int, service_name: str, banner: str) -> dict:
        """
        Returns: {
            'tool_priorities': {tool_name: 1-5},
            'service_purpose': str,
            'reasoning': str,
            'risk_tier': 'low|medium|high',
        }
        """
        cache_key = f"{service_name}:{port}:{banner[:200]}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        log.ai_call("Haiku", f"classify network service {service_name}:{port}")

        catalog_lines = "\n".join(
            f"  - {name}: {desc}" for name, desc in NETWORK_TOOL_CATALOG.items()
        )

        prompt = f"""You are a network penetration tester. Classify this service and decide which tools to run.

HOST: {host}
PORT: {port}
SERVICE: {service_name}
BANNER: {banner[:500]}

AVAILABLE TOOLS:
{catalog_lines}

Respond ONLY with JSON:
{{
  "service_purpose": "1-sentence description of what this service is for",
  "risk_tier": "low|medium|high",
  "tool_priorities": {{
    "tool_name_1": 1-5,
    "tool_name_2": 1-5,
    ...
  }},
  "reasoning": "why these tools (1-2 sentences)"
}}

Score tools 1-5 (5 = run definitely, 1 = skip). Only include tools with score >= 2.
Be selective — running ALL tools wastes time. Pick the 3-7 most relevant for this service."""

        try:
            resp = await self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=1024,
            )
            text = resp.content.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                if text.endswith("```"):
                    text = text[:-3]
            result = json.loads(text)
            self.cache[cache_key] = result
            return result
        except Exception as e:
            log.error("Network classification failed", exc=e)
            return self._fallback(service_name)

    def _fallback(self, service_name: str) -> dict:
        """Default tool selection from service name when AI is unavailable."""
        defaults = SERVICE_DEFAULT_TOOLS.get(service_name.lower(), [])
        return {
            "service_purpose": f"({service_name} service — using default tool list)",
            "risk_tier": "medium",
            "tool_priorities": {t: 3 for t in defaults},
            "reasoning": "fallback (no AI)",
        }


class NetworkOutputInterpreter:
    """
    Mode 2 — Sonnet interprets large tool outputs to find anomalies that
    regex parsers miss.

    enum4linux can return 5000+ lines of SMB enumeration. Sonnet scans the
    full output for anything that looks like a vulnerability or unusual config.
    """

    def __init__(self, llm: AsyncLLMClient):
        self.llm = llm

    async def interpret(self, host: str, tool_name: str, tool_output: str,
                        service: str) -> list[Finding]:
        """Analyze tool output for findings."""
        # Truncate to 30KB to keep token cost manageable
        if len(tool_output) > 30000:
            tool_output = tool_output[:30000] + "\n... [truncated]"

        log.ai_call("Sonnet", f"interpret {tool_name} output ({len(tool_output)}b)")
        prompt = f"""You are analyzing penetration testing tool output for vulnerabilities.

TARGET: {host}
SERVICE: {service}
TOOL: {tool_name}

TOOL OUTPUT:
```
{tool_output}
```

Identify any vulnerabilities, misconfigurations, or noteworthy findings. Examples:
- Anonymous access to sensitive shares/data
- Default credentials accepted
- Known-vulnerable software versions
- Misconfigured services exposing internals
- Privilege escalation opportunities

Respond ONLY with JSON:
{{
  "findings": [
    {{
      "title": "Concise vuln title",
      "severity": "critical|high|medium|low|info",
      "vuln_type": "type name",
      "description": "what was found",
      "evidence": "specific output line(s) demonstrating the finding",
      "impact": "what an attacker can do",
      "remediation": "how to fix",
      "cwe": "CWE-XXX or empty",
      "confidence": 0.0-1.0
    }}
  ]
}}

If nothing of interest, return {{"findings": []}}."""

        try:
            resp = await self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0, max_tokens=2048,
            )
            text = resp.content.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                if text.endswith("```"):
                    text = text[:-3]
            data = json.loads(text)
        except Exception as e:
            log.error("Network interpretation failed", exc=e)
            return []

        findings = []
        sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                   "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
        for item in data.get("findings", []):
            findings.append(Finding(
                title=item.get("title", "Network finding"),
                description=item.get("description", "") + "\n\nEvidence:\n" + item.get("evidence", ""),
                source=FindingSource.NETWORK,
                severity=sev_map.get(item.get("severity", "medium"), Severity.MEDIUM),
                evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                target=host,
                vuln_type=item.get("vuln_type", "Network"),
                cwe=item.get("cwe", ""),
                impact=item.get("impact", ""),
                remediation=item.get("remediation", ""),
                confidence=item.get("confidence", 0.7),
                tags=["network", "ai_interpreted", f"tool:{tool_name}"],
            ))
        return findings


class NetworkInvestigator:
    """
    Mode 3 — AI owns the entire network engagement.

    After initial port scan, the AI gets a service inventory and runs a
    ReAct loop deciding which tools to run, in what order, based on what
    it observes. Tools become the AI's hands.
    """

    def __init__(self, llm: AsyncLLMClient, tool_executor):
        """
        Args:
            llm: Sonnet client for the reasoning loop
            tool_executor: callable that runs a tool: async fn(tool_name, **kwargs) -> str output
        """
        self.llm = llm
        self.tool_executor = tool_executor

    async def investigate_host(
        self, host: str, services: list[dict], max_turns: int = 30,
    ) -> list[Finding]:
        """Run an AI-owned investigation against a single host."""
        services_summary = json.dumps(services, indent=2)

        tool_lines = "\n".join(
            f"  - {name}: {desc}" for name, desc in NETWORK_TOOL_CATALOG.items()
        )

        system = f"""You are conducting an authorized penetration test against {host}.

DISCOVERED SERVICES:
{services_summary}

AVAILABLE TOOLS:
{tool_lines}

You have {max_turns} turns. Build a hypothesis about what this host is for
(corporate AD member, DMZ web server, internal API, etc.), then strategically
run tools to discover vulnerabilities. Read tool output carefully and chain
discoveries (e.g., LDAP enum reveals a service account → Kerberoast it).

Available actions (respond with JSON):
- {{"action": "run_tool", "tool": "tool_name", "args": {{"host": "...", "port": 0, ...}}, "purpose": "..."}}
- {{"action": "found", "title": "...", "severity": "...", "evidence": "...", "host": "..."}}
- {{"action": "done", "reason": "..."}}"""

        history = [{
            "role": "user",
            "content": "Begin the investigation. State your hypothesis about this host and your first action.",
        }]
        findings = []

        for turn in range(max_turns):
            try:
                log.ai_call("Sonnet", f"network investigation turn {turn+1}")
                resp = await self.llm.chat(
                    messages=history, system=system,
                    temperature=0.0, max_tokens=1500,
                )
                text = resp.content.strip()
                if text.startswith("```"):
                    text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                    if text.endswith("```"):
                        text = text[:-3]
                action = json.loads(text)
            except Exception as e:
                log.error(f"Network investigator turn {turn+1} parse fail", exc=e)
                break

            history.append({"role": "assistant", "content": resp.content})
            atype = action.get("action", "")
            log.investigation(host, "network", atype, str(action)[:300])

            if atype == "found":
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
                findings.append(Finding(
                    title=action.get("title", "AI-investigated network finding"),
                    description=action.get("evidence", ""),
                    source=FindingSource.NETWORK,
                    severity=sev_map.get(action.get("severity", "medium"), Severity.MEDIUM),
                    evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
                    target=action.get("host", host),
                    vuln_type="Network",
                    confidence=0.85,
                    tags=["network", "ai_investigated", "mode3"],
                ))
                history.append({"role": "user", "content": "Finding recorded. Continue investigating or use 'done'."})
                continue

            if atype == "done":
                break

            if atype == "run_tool":
                tool_name = action.get("tool", "")
                args = action.get("args", {})
                purpose = action.get("purpose", "")
                log.scanner(tool_name, host, "", 0)
                try:
                    output = await self.tool_executor(tool_name, **args)
                    observation = (
                        f"Tool: {tool_name}\nPurpose: {purpose}\nArgs: {args}\n"
                        f"Output (first 3000 chars):\n{output[:3000]}"
                    )
                except Exception as e:
                    observation = f"Tool {tool_name} failed: {type(e).__name__}: {e}"
                history.append({"role": "user", "content": observation})
                continue

        return findings


class ModeAwareNetworkScanner:
    """
    Mode-aware network scanner — the missing piece in v1.6.

    Mode 1: AI classifies each service, runs only high-priority tools, regex-parses output.
    Mode 2: Mode 1 + Sonnet interprets large tool outputs for anomalies.
    Mode 3: AI owns the investigation loop via NetworkInvestigator.
    """

    def __init__(self, mode: ScanDepth = ScanDepth.SMART, scope=None):
        self.mode = mode
        self.mode_config = MODE_CONFIGS[mode]
        self.scope = scope
        self.report = NetworkScanReport(mode=mode.value)
        self._haiku_client: Optional[AsyncLLMClient] = None
        self._sonnet_client: Optional[AsyncLLMClient] = None
        self._classifier: Optional[NetworkServiceClassifier] = None
        self._interpreter: Optional[NetworkOutputInterpreter] = None
        self._investigator: Optional[NetworkInvestigator] = None

    async def initialize(self):
        config = load_config()
        api_key = get_api_key(config)
        if not api_key:
            log.warn("No API key — network scanning will run default tools without AI")
            return
        self._haiku_client = AsyncLLMClient(api_key=api_key, model=get_model(config, "triage"))
        self._classifier = NetworkServiceClassifier(self._haiku_client)
        log.info(f"Network classifier ready ({get_model(config, 'triage')})")
        if self.mode_config.interpret_responses or self.mode_config.full_ai_owned:
            self._sonnet_client = AsyncLLMClient(api_key=api_key, model=get_model(config, "scanner"))
            self._interpreter = NetworkOutputInterpreter(self._sonnet_client)
            log.info(f"Network interpreter ready ({get_model(config, 'scanner')})")

    async def close(self):
        if self._haiku_client:
            await self._haiku_client.close()
        if self._sonnet_client:
            await self._sonnet_client.close()

    async def scan_host(
        self, host: str, services: list[dict], tool_executor,
    ) -> list[Finding]:
        """
        Run mode-aware network scanning on a single host.

        Args:
            host: target IP or hostname
            services: list of {port, name, banner} dicts from port scan
            tool_executor: async callable for running Kali tools
        """
        if self.mode == ScanDepth.SMART:
            return await self._mode1_scan(host, services, tool_executor)
        if self.mode == ScanDepth.INVESTIGATIVE:
            return await self._mode2_scan(host, services, tool_executor)
        # DEEP
        return await self._mode3_scan(host, services, tool_executor)

    async def _mode1_scan(self, host, services, tool_executor):
        """Mode 1: AI classifies each service, runs only high-priority tools."""
        findings = []
        for svc in services:
            port = svc.get("port", 0)
            svc_name = svc.get("name", "")
            banner = svc.get("banner", "")

            if self._classifier:
                classification = await self._classifier.classify(host, port, svc_name, banner)
                self.report.ai_classifications += 1
            else:
                classification = {"tool_priorities": {t: 3 for t in SERVICE_DEFAULT_TOOLS.get(svc_name.lower(), [])}}

            priorities = classification.get("tool_priorities", {})
            for tool_name, score in priorities.items():
                if score < self.mode_config.min_score_to_scan:
                    self.report.tools_skipped += 1
                    log.scanner_skipped(tool_name, f"score={score}")
                    continue
                self.report.tools_dispatched += 1
                log.scanner(tool_name, host, "", score)
                try:
                    output = await tool_executor(tool_name, host=host, port=port)
                    # Regex-parse for findings (deterministic, no AI)
                    findings.extend(self._regex_parse_output(host, port, svc_name, tool_name, output))
                except Exception as e:
                    log.error(f"Tool {tool_name} failed on {host}", exc=e)
        return findings

    async def _mode2_scan(self, host, services, tool_executor):
        """Mode 2: Mode 1 + AI interpretation of tool output."""
        findings = await self._mode1_scan(host, services, tool_executor)
        if not self._interpreter:
            return findings

        # For each tool that ran, send its output to AI for deeper analysis
        for svc in services:
            port = svc.get("port", 0)
            svc_name = svc.get("name", "")
            classification = {}
            if self._classifier:
                classification = await self._classifier.classify(host, port, svc_name, svc.get("banner", ""))
            priorities = classification.get("tool_priorities", {})
            for tool_name, score in priorities.items():
                if score < self.mode_config.interpret_score_threshold:
                    continue
                try:
                    output = await tool_executor(tool_name, host=host, port=port)
                    if output and len(output) > 100:
                        self.report.ai_interpretations += 1
                        ai_findings = await self._interpreter.interpret(host, tool_name, output, svc_name)
                        findings.extend(ai_findings)
                except Exception:
                    continue
        return findings

    async def _mode3_scan(self, host, services, tool_executor):
        """Mode 3: AI owns the investigation."""
        if not self._sonnet_client:
            return await self._mode1_scan(host, services, tool_executor)
        if not self._investigator:
            self._investigator = NetworkInvestigator(self._sonnet_client, tool_executor)
        self.report.ai_investigations += 1
        return await self._investigator.investigate_host(host, services, max_turns=30)

    def _regex_parse_output(self, host, port, service, tool_name, output: str) -> list[Finding]:
        """Lightweight regex parsing of tool output for obvious findings."""
        findings = []
        if not output:
            return findings
        out_lower = output.lower()

        # SMB-specific patterns
        if tool_name in ("enum4linux", "list_smb_shares"):
            if "anonymous login" in out_lower or "allow guest" in out_lower:
                findings.append(self._mk_finding(
                    host, port, "Anonymous SMB access enabled",
                    f"{tool_name} reports anonymous SMB access. Output snippet visible.",
                    Severity.HIGH, "SMB Anonymous Access", "CWE-284",
                ))
            if "ms17-010" in out_lower or "eternalblue" in out_lower:
                findings.append(self._mk_finding(
                    host, port, "EternalBlue (MS17-010) vulnerability",
                    "MS17-010 vulnerability detected.",
                    Severity.CRITICAL, "EternalBlue", "CWE-119",
                ))

        # Default credentials
        if "default credentials" in out_lower or "default password" in out_lower:
            findings.append(self._mk_finding(
                host, port, "Default credentials detected",
                f"Default credentials found on {service}:{port}",
                Severity.HIGH, "Default Credentials", "CWE-521",
            ))

        # Heartbleed
        if "heartbleed" in out_lower and "vulnerable" in out_lower:
            findings.append(self._mk_finding(
                host, port, "Heartbleed (CVE-2014-0160)",
                "OpenSSL Heartbleed vulnerability detected.",
                Severity.HIGH, "Heartbleed", "CWE-126",
            ))

        return findings

    def _mk_finding(self, host, port, title, desc, severity, vtype, cwe):
        return Finding(
            title=title, description=desc,
            source=FindingSource.NETWORK,
            severity=severity, evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
            target=f"{host}:{port}", vuln_type=vtype, cwe=cwe,
            confidence=0.85, tags=["network", "regex_parsed"],
        )
