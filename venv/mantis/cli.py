"""
MANTIS CLI — AI-Powered Penetration Testing Framework.

Commands:
    mantis engage --mode <mode> --target <target> [options]
    mantis hunt --vuln <type> --url <url> [options]
    mantis hunt --objective "plain English description" --url <url>
    mantis sessions
    mantis report --session <id>
    mantis setup
    mantis doctor
"""

import click
import asyncio
import uuid
import sys
import os


@click.group()
@click.version_option("1.3.0", prog_name="MANTIS")
def cli():
    """MANTIS — AI-Powered Penetration Testing Framework."""
    pass


@cli.command()
@click.option("--mode", type=click.Choice([
    "network", "webapp", "webapp_external", "api",
    "code_review", "code_review+webapp", "full",
]), required=True, help="Engagement mode")
@click.option("--target", required=True, help="Target URL, IP, or CIDR")
@click.option("--scope", multiple=True, help="Additional in-scope targets")
@click.option("--depth", type=click.Choice(["quick", "standard", "deep"]), default="standard")
@click.option("--spec", help="OpenAPI/Swagger spec path or URL")
@click.option("--source", help="Source code repo path for code review")
@click.option("--budget", type=float, default=50.0, help="Max token budget in USD")
@click.option("--resume", help="Resume a previous session by ID")
@click.option("--creds", help="Path to credentials YAML for auth testing")
@click.option("--metrics-port", type=int, default=0, help="Prometheus metrics port (0=disabled)")
@click.option("--export-disclosures", is_flag=True, help="Generate disclosure templates for verified findings")
@click.option("--oob-mode", type=click.Choice(["interactsh", "local", "webhook", "disabled"]), default="interactsh", help="OOB callback mode")
@click.option("--oob-port", type=int, default=8888, help="Port for local OOB callback server")
@click.option("--oob-url", default="", help="External URL for OOB callbacks (your public IP/domain)")
def engage(mode, target, scope, depth, spec, source, budget, resume, creds, metrics_port, export_disclosures, oob_mode, oob_port, oob_url):
    """Run a penetration testing engagement."""
    from mantis.engage.runner import EngagementRunner, EngagementConfig

    # Start Prometheus if requested
    if metrics_port > 0:
        from mantis.core.metrics import MetricsServer
        MetricsServer(port=metrics_port).start()

    config = EngagementConfig(
        mode=mode,
        target=target,
        scope=list(scope) if scope else [target],
        depth=depth,
        openapi_spec=spec,
        source_path=source,
        session_id=resume or f"mantis-{uuid.uuid4().hex[:8]}",
        budget_usd=budget,
    )

    print(f"\n{'=' * 60}")
    print(f"  MANTIS — AI-Powered Penetration Testing Framework v1.2")
    print(f"  Session: {config.session_id}")
    if metrics_port > 0:
        print(f"  Metrics: http://localhost:{metrics_port}/metrics")
    if oob_mode != "disabled":
        print(f"  OOB Callbacks: {oob_mode}" + (f" (port {oob_port})" if oob_mode == "local" else ""))
    print(f"{'=' * 60}\n")

    runner = EngagementRunner(config)
    context = asyncio.run(runner.run())

    # Export disclosure templates if requested
    if export_disclosures:
        from mantis.report.disclosure import generate_disclosure_templates
        results_dir = os.path.expanduser(f"~/.mantis/results/{config.session_id}")
        count = generate_disclosure_templates(context.findings, results_dir)
        if count:
            print(f"[*] Generated {count} disclosure templates in {results_dir}/disclosures/")

    print(f"\n{'=' * 60}")
    print(f"  ENGAGEMENT COMPLETE")
    print(f"  Total findings: {len(context.findings)}")
    counts = context.finding_count_by_severity()
    for sev, count in sorted(counts.items()):
        print(f"    {sev}: {count}")
    print(f"{'=' * 60}\n")


@cli.command()
@click.option("--vuln", default="", help="Vulnerability type (SSTI, SQLi, BOLA, etc.)")
@click.option("--url", required=True, help="Target URL")
@click.option("--functionality", default="", help="Target functionality description")
@click.option("--objective", default="", help="Plain English description of what to test (overrides --vuln)")
@click.option("--depth", type=click.Choice(["quick", "standard", "deep"]), default="standard")
def hunt(vuln, url, functionality, objective, depth):
    """
    Hunt for a specific vulnerability or test a business logic scenario.

    Examples:
        mantis hunt --vuln SSTI --url "https://target.com/search?q="
        mantis hunt --vuln BOLA --url "https://api.target.com" --functionality "user profiles"
        mantis hunt --objective "test if coupon codes can be reused" --url "https://shop.target.com/checkout"
        mantis hunt --objective "check if free trial can be extended indefinitely" --url "https://app.target.com"
    """
    from mantis.exploit.executor import ExploitationEngine, ExploitRequest

    # If --objective is provided, use it as the vuln_type (freeform text)
    effective_vuln = objective if objective else vuln
    if not effective_vuln:
        click.echo("Error: Provide either --vuln or --objective")
        return

    request = ExploitRequest(
        mode="hunt_specific",
        vuln_type=effective_vuln,
        target_url=url,
        target_functionality=functionality or objective,
    )

    label = objective if objective else f"{vuln} vulnerability"
    print(f"\n[*] Hunting: {label}")
    print(f"[*] Target: {url}\n")

    engine = ExploitationEngine()
    result = asyncio.run(engine.execute(request))
    print(f"Result: {'SUCCESS' if result.success else 'No findings'}")


@cli.command()
def sessions():
    """List all past engagement sessions."""
    from mantis.core.checkpoint import CheckpointStore
    store = CheckpointStore()
    sessions_list = store.list_sessions()
    if not sessions_list:
        print("No sessions found.")
        return
    print(f"{'Session ID':<20} {'Mode':<18} {'Target':<30} {'Findings':>8} {'Cost':>8}")
    print("-" * 90)
    for s in sessions_list:
        print(f"{s.get('session_id', 'N/A'):<20} "
              f"{(s.get('mode') or 'N/A'):<18} "
              f"{(s.get('target') or 'N/A'):<30} "
              f"{s.get('finding_count', 0):>8} "
              f"${s.get('total_cost_usd', 0.0):>7.2f}")


@cli.command()
def setup():
    """Interactive setup wizard."""
    print("MANTIS Setup Wizard")
    print("-" * 40)
    api_key = input("Anthropic API Key: ").strip()
    if api_key:
        os.makedirs(os.path.expanduser("~/.mantis"), exist_ok=True)
        config_path = os.path.expanduser("~/.mantis/config.yaml")
        with open(config_path, "w") as f:
            f.write(f"llm:\n  default_provider: anthropic\n  providers:\n    anthropic:\n      api_key: {api_key}\n")
        print(f"Config saved to {config_path}")
    else:
        print("Skipped. Set ANTHROPIC_API_KEY environment variable instead.")


@cli.command()
def doctor():
    """Check system dependencies and connectivity."""
    import shutil
    checks = [
        ("Python 3.10+", sys.version_info >= (3, 10)),
        ("httpx", _check_import("httpx")),
        ("click", _check_import("click")),
        ("rich", _check_import("rich")),
        ("networkx", _check_import("networkx")),
        ("pyyaml", _check_import("yaml")),
        ("Docker", shutil.which("docker") is not None),
        ("Git", shutil.which("git") is not None),
        ("API Key", bool(os.environ.get("ANTHROPIC_API_KEY") or _check_config_key())),
        ("SQLite (built-in)", _check_import("sqlite3")),
    ]
    all_ok = True
    for name, ok in checks:
        status = "[OK]" if ok else "[MISSING]"
        if not ok:
            all_ok = False
        print(f"  {status:>10}  {name}")
    if all_ok:
        print("\n  All checks passed. MANTIS is ready.")
    else:
        print("\n  Some dependencies are missing. Install them before running.")


def _check_import(module: str) -> bool:
    try:
        __import__(module)
        return True
    except ImportError:
        return False


def _check_config_key() -> bool:
    config_path = os.path.expanduser("~/.mantis/config.yaml")
    if os.path.exists(config_path):
        with open(config_path) as f:
            return "api_key" in f.read()
    return False


if __name__ == "__main__":
    cli()
