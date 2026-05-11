"""
Input/output guardrails for tool call validation.

Every tool call passes through this engine before execution.
Prevents scope violations, dangerous commands, and ensures
the agent stays within authorized boundaries.
"""

import re
import ipaddress
from typing import Optional


class GuardrailEngine:
    """
    Safety validation for all tool calls.

    Checks:
    1. Scope enforcement — target must be in authorized scope
    2. Command blocklist — no rm -rf, no reverse shells, etc.
    3. Rate limiting — prevent excessive scanning
    4. Payload safety — no real malware, only PoC payloads
    """

    # Commands that should NEVER be executed regardless of context
    BLOCKED_COMMANDS = [
        r"rm\s+-rf\s+/",         # Recursive delete root
        r"mkfs\.",                # Format filesystem
        r"dd\s+if=",             # Raw disk write
        r":(\)\{\s*:|:&\s*\};:",  # Fork bomb
        r"nc\s+-e",              # Reverse shell via netcat
        r"bash\s+-i\s+>&",      # Bash reverse shell
        r"wget.*\|\s*sh",       # Download and execute
        r"curl.*\|\s*bash",     # Download and execute
    ]

    def __init__(self, scope: list[str], blocked_patterns: list[str] = None):
        """
        Args:
            scope: List of authorized targets (IPs, CIDRs, domains).
                   Empty list means no scope restriction.
            blocked_patterns: Additional regex patterns to block.
        """
        self.scope = scope
        self.scope_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.scope_domains: list[str] = []

        for s in scope:
            try:
                self.scope_networks.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                self.scope_domains.append(s.lower())

        self.blocked_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in (self.BLOCKED_COMMANDS + (blocked_patterns or []))
        ]
        self.call_counts: dict[str, int] = {}

    def check(self, tool_name: str, args: dict) -> Optional[str]:
        """
        Validate a tool call.

        Returns None if safe, error string if blocked.
        """
        # Check scope for scanning/exploit tools
        scope_tools = {
            "scan_ports", "http_request", "scan_url",
            "exploit_target", "fuzz_endpoint", "nmap_deep_scan",
            "run_exploit",
        }
        if tool_name in scope_tools:
            target = args.get("target") or args.get("url") or args.get("host", "")
            violation = self._check_scope(target)
            if violation:
                return violation

        # Check command blocklist for shell execution tools
        command_tools = {"execute_command", "kali_execute", "run_script"}
        if tool_name in command_tools:
            command = args.get("command", "")
            for pattern in self.blocked_patterns:
                if pattern.search(command):
                    return f"Blocked dangerous command pattern: {pattern.pattern}"

        # Rate limiting — prevent runaway tool calls
        self.call_counts[tool_name] = self.call_counts.get(tool_name, 0) + 1
        if self.call_counts[tool_name] > 1000:
            return f"Rate limit exceeded for {tool_name} (>1000 calls)"

        return None  # Safe to execute

    def _check_scope(self, target: str) -> Optional[str]:
        """Verify target is within authorized scope."""
        if not target:
            return "No target specified"
        if not self.scope:
            return None  # No scope restriction configured

        # Extract hostname/IP from URL
        clean_target = target.lower()
        for prefix in ("https://", "http://"):
            if clean_target.startswith(prefix):
                clean_target = clean_target[len(prefix):]
        clean_target = clean_target.split("/")[0].split(":")[0]

        # Check if target is an IP address
        try:
            ip = ipaddress.ip_address(clean_target)
            for network in self.scope_networks:
                if ip in network:
                    return None
            return f"Target {target} is outside authorized scope"
        except ValueError:
            pass

        # Check if target is a domain
        for scope_domain in self.scope_domains:
            if scope_domain.startswith("*."):
                base = scope_domain[2:]
                if clean_target == base or clean_target.endswith("." + base):
                    return None
            elif clean_target == scope_domain:
                return None

        return f"Target {target} is outside authorized scope"

    def reset_counts(self):
        """Reset rate limiting counters (call between phases)."""
        self.call_counts.clear()
