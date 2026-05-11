"""
Prometheus metrics exporter for MANTIS.

Exposes metrics on an HTTP endpoint for Prometheus scraping:
- mantis_findings_total (by severity, vuln_type, source)
- mantis_tool_calls_total (by tool_name, status)
- mantis_llm_tokens_total (by model, direction)
- mantis_llm_cost_usd_total (by model)
- mantis_phase_duration_seconds (by phase)
- mantis_engagement_duration_seconds

Start the metrics server:
    from mantis.core.metrics import MetricsServer
    server = MetricsServer(port=9090)
    server.start()  # runs in background thread

Scrape: curl http://localhost:9090/metrics
"""

import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Counter:
    """Simple Prometheus counter."""
    name: str
    help: str
    labels: list[str] = field(default_factory=list)
    values: dict = field(default_factory=dict)  # {label_tuple: float}

    def inc(self, amount: float = 1.0, **label_values):
        key = tuple(label_values.get(l, "") for l in self.labels)
        self.values[key] = self.values.get(key, 0.0) + amount

    def format(self) -> str:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} counter"]
        for label_vals, value in sorted(self.values.items()):
            if self.labels:
                label_str = ",".join(f'{l}="{v}"' for l, v in zip(self.labels, label_vals))
                lines.append(f"{self.name}{{{label_str}}} {value}")
            else:
                lines.append(f"{self.name} {value}")
        return "\n".join(lines)


@dataclass
class Gauge:
    """Simple Prometheus gauge."""
    name: str
    help: str
    value: float = 0.0

    def set(self, value: float):
        self.value = value

    def format(self) -> str:
        return (
            f"# HELP {self.name} {self.help}\n"
            f"# TYPE {self.name} gauge\n"
            f"{self.name} {self.value}"
        )


class MantisMetrics:
    """Central metrics registry for MANTIS."""

    def __init__(self):
        self.findings_total = Counter(
            "mantis_findings_total",
            "Total findings discovered",
            labels=["severity", "vuln_type", "source"],
        )
        self.tool_calls_total = Counter(
            "mantis_tool_calls_total",
            "Total tool calls executed",
            labels=["tool_name", "status"],
        )
        self.llm_tokens_total = Counter(
            "mantis_llm_tokens_total",
            "Total LLM tokens consumed",
            labels=["model", "direction"],
        )
        self.llm_cost_usd = Counter(
            "mantis_llm_cost_usd_total",
            "Total LLM cost in USD",
            labels=["model"],
        )
        self.phase_duration = Counter(
            "mantis_phase_duration_seconds",
            "Time spent in each phase",
            labels=["phase"],
        )
        self.active_findings = Gauge(
            "mantis_active_findings",
            "Current number of active findings",
        )
        self.engagement_start = Gauge(
            "mantis_engagement_start_timestamp",
            "Unix timestamp when engagement started",
        )

    def record_finding(self, severity: str, vuln_type: str, source: str):
        self.findings_total.inc(severity=severity, vuln_type=vuln_type, source=source)

    def record_tool_call(self, tool_name: str, success: bool):
        status = "success" if success else "error"
        self.tool_calls_total.inc(tool_name=tool_name, status=status)

    def record_tokens(self, model: str, input_tokens: int, output_tokens: int, cost: float):
        self.llm_tokens_total.inc(input_tokens, model=model, direction="input")
        self.llm_tokens_total.inc(output_tokens, model=model, direction="output")
        self.llm_cost_usd.inc(cost, model=model)

    def record_phase(self, phase: str, duration_seconds: float):
        self.phase_duration.inc(duration_seconds, phase=phase)

    def format_all(self) -> str:
        parts = [
            self.findings_total.format(),
            self.tool_calls_total.format(),
            self.llm_tokens_total.format(),
            self.llm_cost_usd.format(),
            self.phase_duration.format(),
            self.active_findings.format(),
            self.engagement_start.format(),
        ]
        return "\n\n".join(p for p in parts if p.strip())


# Global metrics instance
metrics = MantisMetrics()


class _MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            body = metrics.format_all().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress HTTP logs


class MetricsServer:
    """Background HTTP server for Prometheus scraping."""

    def __init__(self, port: int = 9090):
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self):
        self.server = HTTPServer(("0.0.0.0", self.port), _MetricsHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        print(f"[*] Prometheus metrics at http://localhost:{self.port}/metrics")

    def stop(self):
        if self.server:
            self.server.shutdown()
