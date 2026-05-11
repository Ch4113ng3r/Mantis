"""
Scope selector for flexible MANTIS engagements.

Allows the operator to scope engagements by:
- Target scope: full_app | navigation_path | specific_endpoint | specific_page_description
- Vuln scope: all | single | list

Combinations enable precise testing:
    full app + all vulnerabilities (comprehensive scan)
    full app + single vulnerability (hunt all instances of XSS across app)
    full app + selected vulnerabilities (test only SQLi, XSS, SSTI)
    navigation path + all (test the /admin/* subtree for everything)
    specific endpoint + single (test /login for SQLi only)
    specific endpoint + selected (test /api/upload for path_traversal, file_upload)
    page description + all (Mode 3 plain-English investigation)
    page description + selected (Mode 3 plain English with vuln filter)
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class TargetScope(Enum):
    FULL_APP = "full_app"
    NAVIGATION_PATH = "navigation_path"  # e.g. /admin/*, /api/v2/*
    SPECIFIC_ENDPOINT = "specific_endpoint"
    PAGE_DESCRIPTION = "page_description"


class VulnScope(Enum):
    ALL = "all"
    SINGLE = "single"
    SELECTED = "selected"


@dataclass
class EngagementScope:
    """
    Complete scope definition for an engagement.

    Used by:
    - Crawler (limits URL discovery)
    - Classifier (focuses AI classification)
    - Orchestrator (limits scanner dispatch)
    - Reporter (filters output)
    """
    target_scope: TargetScope = TargetScope.FULL_APP
    vuln_scope: VulnScope = VulnScope.ALL
    target_url: str = ""

    # For NAVIGATION_PATH: pattern like "/admin/*" or "/api/v2/users/*"
    navigation_pattern: str = ""

    # For SPECIFIC_ENDPOINT: exact URL or method+url
    specific_url: str = ""
    specific_method: str = "GET"

    # For PAGE_DESCRIPTION: plain English description for Mode 3 page agent
    page_description: str = ""

    # For SINGLE/SELECTED vuln scope: list of vuln class names
    selected_vulns: list = field(default_factory=list)

    def matches_url(self, url: str) -> bool:
        """Return True if a discovered URL is in scope."""
        if self.target_scope == TargetScope.FULL_APP:
            # Same-domain check
            target_host = urlparse(self.target_url).hostname or ""
            url_host = urlparse(url).hostname or ""
            return target_host == url_host

        if self.target_scope == TargetScope.NAVIGATION_PATH:
            # Pattern match with * wildcard
            pattern = self.navigation_pattern
            if not pattern:
                return True
            # Convert glob to regex
            regex = re.escape(pattern).replace(r"\*", ".*")
            target_host = urlparse(self.target_url).hostname or ""
            url_parsed = urlparse(url)
            if url_parsed.hostname and url_parsed.hostname != target_host:
                return False
            return bool(re.search(regex, url_parsed.path or ""))

        if self.target_scope == TargetScope.SPECIFIC_ENDPOINT:
            return url.rstrip("/") == self.specific_url.rstrip("/")

        if self.target_scope == TargetScope.PAGE_DESCRIPTION:
            # Page description always uses the specific URL
            return url.rstrip("/") == self.target_url.rstrip("/")

        return True

    def matches_vuln_class(self, vuln_class: str) -> bool:
        """Return True if a vuln class should be tested under this scope."""
        if self.vuln_scope == VulnScope.ALL:
            return True
        if self.vuln_scope == VulnScope.SINGLE:
            return len(self.selected_vulns) == 1 and vuln_class.lower() in [
                v.lower() for v in self.selected_vulns
            ]
        if self.vuln_scope == VulnScope.SELECTED:
            return vuln_class.lower() in [v.lower() for v in self.selected_vulns]
        return True

    def filter_endpoints(self, endpoints: list) -> list:
        """Filter a list of endpoint dicts to those in scope."""
        if self.target_scope == TargetScope.FULL_APP:
            return endpoints
        if self.target_scope == TargetScope.SPECIFIC_ENDPOINT:
            return [e for e in endpoints if e.get("url", "").rstrip("/") == self.specific_url.rstrip("/")]
        if self.target_scope == TargetScope.PAGE_DESCRIPTION:
            return [e for e in endpoints if e.get("url", "").rstrip("/") == self.target_url.rstrip("/")]
        if self.target_scope == TargetScope.NAVIGATION_PATH:
            return [e for e in endpoints if self.matches_url(e.get("url", ""))]
        return endpoints

    def filter_classification_scanners(self, scanner_priorities: dict) -> dict:
        """
        Filter the AI classifier's scanner priorities by vuln scope.

        If operator said "only test SQLi and XSS", return only the SQLi/XSS
        scanner priorities. Skip everything else.
        """
        if self.vuln_scope == VulnScope.ALL:
            return scanner_priorities

        # Map vuln class names to scanner names
        from mantis.core.ai_classifier import VULN_CLASS_TO_SCANNERS

        selected_lower = [v.lower() for v in self.selected_vulns]
        allowed_scanners = set()
        for vuln_class, scanners in VULN_CLASS_TO_SCANNERS.items():
            if vuln_class.lower() in selected_lower:
                allowed_scanners.update(scanners)

        return {k: v for k, v in scanner_priorities.items() if k in allowed_scanners}

    def describe(self) -> str:
        """Human-readable description of the scope."""
        parts = []

        # Target
        if self.target_scope == TargetScope.FULL_APP:
            parts.append(f"target: full app ({self.target_url})")
        elif self.target_scope == TargetScope.NAVIGATION_PATH:
            parts.append(f"target: path {self.navigation_pattern} on {self.target_url}")
        elif self.target_scope == TargetScope.SPECIFIC_ENDPOINT:
            parts.append(f"target: {self.specific_method} {self.specific_url}")
        elif self.target_scope == TargetScope.PAGE_DESCRIPTION:
            parts.append(f"target: page at {self.target_url} ('{self.page_description[:80]}')")

        # Vulns
        if self.vuln_scope == VulnScope.ALL:
            parts.append("vulns: all classes")
        elif self.vuln_scope == VulnScope.SINGLE:
            parts.append(f"vuln: {self.selected_vulns[0] if self.selected_vulns else '(none)'}")
        elif self.vuln_scope == VulnScope.SELECTED:
            parts.append(f"vulns: {', '.join(self.selected_vulns)}")

        return " | ".join(parts)


def parse_scope_from_cli(
    target: str,
    only_vuln: str = "",
    vulns: str = "",
    path: str = "",
    endpoint: str = "",
    page_description: str = "",
    method: str = "GET",
) -> EngagementScope:
    """
    Build an EngagementScope from CLI flags.

    Flag semantics:
        --target https://app.com           → FULL_APP + ALL
        --only-vuln SQLi --target ...      → FULL_APP + SINGLE
        --vulns SQLi,XSS,SSTI --target ... → FULL_APP + SELECTED
        --path /admin/* --target ...       → NAVIGATION_PATH + ALL (or +SINGLE/SELECTED)
        --endpoint /api/login --target ... → SPECIFIC_ENDPOINT + ALL (or +SINGLE/SELECTED)
        --page-description "..." --target  → PAGE_DESCRIPTION + ALL (or filtered)
    """
    scope = EngagementScope(target_url=target)

    # Determine target scope (most specific wins)
    if page_description:
        scope.target_scope = TargetScope.PAGE_DESCRIPTION
        scope.page_description = page_description
    elif endpoint:
        scope.target_scope = TargetScope.SPECIFIC_ENDPOINT
        # If endpoint is just a path, join with target
        if endpoint.startswith("/"):
            base = target.rstrip("/")
            scope.specific_url = base + endpoint
        else:
            scope.specific_url = endpoint
        scope.specific_method = method.upper()
    elif path:
        scope.target_scope = TargetScope.NAVIGATION_PATH
        scope.navigation_pattern = path
    else:
        scope.target_scope = TargetScope.FULL_APP

    # Determine vuln scope
    if only_vuln:
        scope.vuln_scope = VulnScope.SINGLE
        scope.selected_vulns = [only_vuln.strip()]
    elif vulns:
        parts = [v.strip() for v in vulns.split(",") if v.strip()]
        if len(parts) == 1:
            scope.vuln_scope = VulnScope.SINGLE
        else:
            scope.vuln_scope = VulnScope.SELECTED
        scope.selected_vulns = parts
    else:
        scope.vuln_scope = VulnScope.ALL

    return scope
