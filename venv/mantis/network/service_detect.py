"""Service detection phase using nmap."""

from mantis.engage.phases import Phase
from . import scanner


class ServiceDetectPhase(Phase):
    """Phase: detect services and versions on open ports."""

    async def execute(self, context) -> dict:
        if not context.open_ports:
            print("    No open ports to probe")
            return {}

        target = self.config.target
        port_list = ",".join(str(p["port"]) for p in context.open_ports)

        try:
            result = await scanner.nmap_scan(target, ports=port_list, args="-sV -sC")
            services = [
                {"port": p.port, "service": p.service, "version": p.version}
                for p in result.open_ports
            ]
            print(f"    Detected {len(services)} services")
            return {"services": services}
        except Exception as e:
            print(f"    Service detection failed (Docker/nmap issue?): {e}")
            return {}
