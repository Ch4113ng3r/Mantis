"""
networkx-backed knowledge graph for cross-session intelligence.

Stores relationships between targets, services, vulnerabilities,
and findings. Enables queries like "what did we find on this host"
and cross-references between code review and runtime findings.
"""

import networkx as nx
import json
import os
from typing import Optional, Any


class KnowledgeGraph:
    """
    Directed graph storing pentest intelligence.

    Nodes: targets, services, findings, endpoints
    Edges: HAS_SERVICE, HAS_FINDING, CONFIRMED_BY, VARIANT_OF

    Persisted as JSON. Reloaded across sessions for cross-run intelligence.
    """

    def __init__(self, path: str = "~/.mantis/knowledge_graph.json"):
        self.path = os.path.expanduser(path)
        self.graph = nx.DiGraph()
        self._load()

    def _load(self):
        """Load graph from JSON if it exists."""
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    data = json.load(f)
                self.graph = nx.node_link_graph(data)
            except (json.JSONDecodeError, Exception):
                self.graph = nx.DiGraph()

    def save(self):
        """Persist graph to JSON file."""
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        data = nx.node_link_data(self.graph)
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def add_target(self, target: str, metadata: dict = None):
        """Add a target node (IP, domain, or URL)."""
        self.graph.add_node(target, type="target", **(metadata or {}))

    def add_finding(self, finding_id: str, target: str, data: dict):
        """Add a finding node linked to its target."""
        self.graph.add_node(finding_id, type="finding", **data)
        if target:
            self.add_target(target)
            self.graph.add_edge(target, finding_id, relation="HAS_FINDING")

    def add_service(self, target: str, port: int, service: str, version: str = ""):
        """Add a discovered service on a target."""
        node_id = f"{target}:{port}"
        self.graph.add_node(
            node_id, type="service", service=service,
            version=version, port=port,
        )
        self.add_target(target)
        self.graph.add_edge(target, node_id, relation="HAS_SERVICE")

    def add_endpoint(self, target: str, path: str, method: str, metadata: dict = None):
        """Add a discovered API/web endpoint."""
        node_id = f"{method}:{target}{path}"
        self.graph.add_node(node_id, type="endpoint", path=path, method=method, **(metadata or {}))
        self.add_target(target)
        self.graph.add_edge(target, node_id, relation="HAS_ENDPOINT")

    def get_findings(self, target: str) -> list[dict]:
        """Get all findings for a target."""
        findings = []
        if target not in self.graph:
            return findings
        for _, neighbor in self.graph.out_edges(target):
            node = self.graph.nodes[neighbor]
            if node.get("type") == "finding":
                findings.append(dict(node))
        return findings

    def get_services(self, target: str) -> list[dict]:
        """Get all services discovered on a target."""
        services = []
        if target not in self.graph:
            return services
        for _, neighbor in self.graph.out_edges(target):
            node = self.graph.nodes[neighbor]
            if node.get("type") == "service":
                services.append(dict(node))
        return services

    def correlate(self, code_finding_id: str, runtime_finding_id: str, reason: str):
        """Link a code review finding to a runtime finding."""
        self.graph.add_edge(
            code_finding_id, runtime_finding_id,
            relation="CONFIRMED_BY", reason=reason,
        )

    def ingest_tool_result(self, tool_name: str, args: dict, result: Any):
        """Auto-populate graph from tool execution results."""
        target = args.get("target") or args.get("url") or args.get("host")
        if target:
            self.add_target(target)

        # Ingest port scan results
        if tool_name == "scan_ports" and isinstance(result, dict):
            for port_info in result.get("open_ports", []):
                self.add_service(
                    target, port_info["port"],
                    port_info.get("service", "unknown"),
                    port_info.get("version", ""),
                )
