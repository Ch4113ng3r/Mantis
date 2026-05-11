"""
Async port scanner with nmap Docker integration.

Two scanning modes:
1. Pure Python async scanner — fast, no dependencies, basic
2. nmap via Docker — full service detection, script scanning
"""

import asyncio
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional

from mantis.engage.phases import Phase


@dataclass
class PortResult:
    port: int
    state: str          # open, closed, filtered
    service: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class ScanResult:
    target: str
    open_ports: list[PortResult]
    os_guess: str = ""
    scan_time_seconds: float = 0.0


async def async_port_scan(
    target: str,
    ports: list[int],
    timeout: float = 2.0,
    max_concurrent: int = 100,
) -> ScanResult:
    """
    Pure Python async port scanner.

    Opens TCP connections to each port concurrently. Fast but basic —
    no service detection, no script scanning. Use for initial sweeps.
    """
    open_ports: list[PortResult] = []
    semaphore = asyncio.Semaphore(max_concurrent)

    async def check_port(port: int):
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=timeout,
                )
                # Try to grab a banner
                banner = ""
                try:
                    writer.write(b"\r\n")
                    await writer.drain()
                    reader_task = asyncio.get_event_loop().create_task(
                        asyncio.wait_for(writer.transport.get_extra_info("socket").recv(1024), timeout=1.0)
                    )
                except Exception:
                    pass
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                open_ports.append(PortResult(port=port, state="open", banner=banner))
            except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                pass

    await asyncio.gather(*[check_port(p) for p in ports])
    open_ports.sort(key=lambda p: p.port)
    return ScanResult(target=target, open_ports=open_ports)


async def nmap_scan(
    target: str,
    ports: str = "1-10000",
    args: str = "-sV -sC",
    docker_image: str = "mantis-kali",
) -> ScanResult:
    """Run nmap inside the Kali Docker container."""
    cmd = [
        "docker", "run", "--rm", "--network=host",
        docker_image, "nmap", *args.split(),
        "-p", ports, "-oX", "-",
        target,
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return _parse_nmap_xml(target, stdout.decode(errors="replace"))


def _parse_nmap_xml(target: str, xml_output: str) -> ScanResult:
    """Parse nmap XML output into a ScanResult."""
    open_ports: list[PortResult] = []
    os_guess = ""
    try:
        root = ET.fromstring(xml_output)
        for port_elem in root.findall(".//port"):
            state = port_elem.find("state")
            service = port_elem.find("service")
            if state is not None and state.get("state") == "open":
                open_ports.append(PortResult(
                    port=int(port_elem.get("portid", 0)),
                    state="open",
                    service=service.get("name", "") if service is not None else "",
                    version=service.get("version", "") if service is not None else "",
                ))
        # OS detection
        for os_match in root.findall(".//osmatch"):
            os_guess = os_match.get("name", "")
            break
    except ET.ParseError:
        pass
    return ScanResult(target=target, open_ports=open_ports, os_guess=os_guess)


def parse_port_range(port_str: str) -> list[int]:
    """Parse port specification string into list of port numbers."""
    ports: list[int] = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


class PortScanPhase(Phase):
    """Phase: scan for open ports on target."""

    async def execute(self, context) -> dict:
        target = self.config.target
        port_range = parse_port_range("1-1000")  # Quick default
        result = await async_port_scan(target, port_range)
        print(f"    Found {len(result.open_ports)} open ports")
        return {
            "open_ports": [
                {"port": p.port, "service": p.service, "banner": p.banner}
                for p in result.open_ports
            ],
        }
