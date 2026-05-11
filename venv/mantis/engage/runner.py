"""
Mode-aware engagement pipeline runner.

Takes an EngagementConfig, looks up the mode definition,
instantiates only the required phases, and runs them in sequence
with checkpointing between each phase.
"""

import asyncio
import importlib
import uuid
from dataclasses import dataclass, field
from typing import Literal, Optional

from .modes import ENGAGEMENT_MODES
from mantis.core.checkpoint import CheckpointStore, Checkpoint
from mantis.core.context import EngagementContext


@dataclass
class EngagementConfig:
    """Configuration for a single engagement run."""
    mode: str                                    # Key into ENGAGEMENT_MODES
    target: str                                  # Primary target
    scope: list[str] = field(default_factory=list)
    depth: Literal["quick", "standard", "deep"] = "standard"
    session_id: str = ""
    openapi_spec: Optional[str] = None           # Path or URL to API spec
    source_path: Optional[str] = None            # Path to source code repo
    credentials: Optional[dict] = None           # Auth credentials
    business_rules: Optional[str] = None         # Business context
    hunt_vuln: Optional[str] = None              # Specific vuln to hunt (Phase 5)
    budget_usd: float = 50.0

    def __post_init__(self):
        if not self.session_id:
            self.session_id = f"mantis-{uuid.uuid4().hex[:8]}"
        if not self.scope:
            self.scope = [self.target]


# Phase name -> (module_path, class_name) mapping
# Each phase is lazily imported only when the engagement mode requires it
PHASE_REGISTRY = {
    "osint":           ("mantis.webapp.recon.osint",       "OSINTPhase"),
    "subdomain_enum":  ("mantis.webapp.recon.subdomain",   "SubdomainPhase"),
    "tech_detect":     ("mantis.webapp.recon.tech_detect",  "TechDetectPhase"),
    "dns_enum":        ("mantis.webapp.recon.dns_enum",     "DNSEnumPhase"),
    "port_scan":       ("mantis.network.scanner",           "PortScanPhase"),
    "service_detect":  ("mantis.network.service_detect",    "ServiceDetectPhase"),
    "crawl":           ("mantis.webapp.crawler",            "CrawlPhase"),
    "auth_test":       ("mantis.webapp.auth_tester",        "AuthTestPhase"),
    "vuln_scan":       ("mantis.webapp.vuln_scanner",       "VulnScanPhase"),
    "business_logic":  ("mantis.webapp.business_logic",     "BusinessLogicPhase"),
    "schema_ingest":   ("mantis.api.schema_parser",         "SchemaIngestPhase"),
    "auth_chain":      ("mantis.api.auth_chain",            "AuthChainPhase"),
    "endpoint_scan":   ("mantis.api.endpoint_scanner",      "EndpointScanPhase"),
    "preprocess":      ("mantis.codereview.preprocessor",   "PreprocessPhase"),
    "static_scan":     ("mantis.codereview.static_scanner", "StaticScanPhase"),
    "triage":          ("mantis.codereview.triage",         "TriagePhase"),
    "deep_scan":       ("mantis.codereview.scanner",        "DeepScanPhase"),
    "verify":          ("mantis.codereview.verifier",       "VerifyPhase"),
    "variant_hunt":    ("mantis.codereview.variant_hunter", "VariantHuntPhase"),
    "correlate":       ("mantis.engage.correlate",          "CorrelationPhase"),
    "exploit":         ("mantis.exploit.executor",          "ExploitPhase"),
    "report":          ("mantis.report.generator",          "ReportPhase"),
}


class EngagementRunner:
    """
    Orchestrates a complete engagement.

    1. Load mode definition from ENGAGEMENT_MODES
    2. Instantiate only the required phases
    3. Run phases in sequence, passing context forward
    4. Checkpoint between each phase for crash recovery
    5. Generate final report
    """

    def __init__(self, config: EngagementConfig):
        self.config = config
        self.mode_def = ENGAGEMENT_MODES[config.mode]
        self.checkpoint_store = CheckpointStore()
        self.context = EngagementContext(
            target=config.target,
            scope=config.scope,
            mode=config.mode,
        )

    async def run(self) -> EngagementContext:
        """Execute all phases in the engagement."""
        phases = self._build_phases()

        # Resume from checkpoint if available
        cp = self.checkpoint_store.resume_or_start(
            self.config.session_id,
            {"target": self.config.target, "mode": self.config.mode},
        )
        completed = set(cp.completed_phases)

        print(f"[*] Starting {self.mode_def['description']}")
        print(f"[*] Target: {self.config.target}")
        print(f"[*] Phases: {' > '.join(self.mode_def['phases'])}")
        print()

        for phase_name, phase_impl in phases:
            if phase_name in completed:
                print(f"[=] Skipping {phase_name} (completed in previous run)")
                continue

            print(f"[>] Phase: {phase_name}")

            try:
                result = await phase_impl.execute(self.context)
                self.context.merge(result)
            except Exception as e:
                print(f"[!] Phase {phase_name} failed: {e}")
                # Save checkpoint so we can resume from this point
                cp.completed_phases = list(completed)
                cp.findings_so_far = [f.to_dict() for f in self.context.findings]
                self.checkpoint_store.save(cp)
                raise

            # Save checkpoint after each phase
            completed.add(phase_name)
            cp.completed_phases = list(completed)
            cp.findings_so_far = [f.to_dict() for f in self.context.findings]
            self.checkpoint_store.save(cp)

            print(f"[+] {phase_name} complete. "
                  f"Findings: {len(self.context.findings)}")

        return self.context

    def _build_phases(self) -> list[tuple[str, object]]:
        """Import and instantiate only the needed phases."""
        phases = []
        for phase_name in self.mode_def["phases"]:
            if phase_name in PHASE_REGISTRY:
                module_path, class_name = PHASE_REGISTRY[phase_name]
                try:
                    mod = importlib.import_module(module_path)
                    phase_cls = getattr(mod, class_name)
                    phases.append((phase_name, phase_cls(self.config)))
                except (ImportError, AttributeError) as e:
                    print(f"[!] Could not load phase {phase_name}: {e}")
                    print(f"    Module: {module_path}.{class_name}")
                    # Create a stub phase that returns empty results
                    from .phases import Phase
                    class StubPhase(Phase):
                        async def execute(self, context):
                            print(f"    [stub] {phase_name} not yet implemented")
                            return {}
                    phases.append((phase_name, StubPhase(self.config)))
        return phases
