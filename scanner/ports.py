"""
scanner/ports.py

TCP port scanning via connect() probes, run concurrently with a bounded
thread pool. Classifies each port as open / closed / filtered and
attaches a best-guess service name from the well-known port table.

This is a "connect scan" (like nmap's -sT), which needs no special
privileges, unlike a raw SYN scan. It's slightly noisier on the target
but far more portable and reliable, which matches this project's goal
of accuracy/reliability over raw speed or stealth.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional

from utils.common import COMMON_PORTS, DEFAULT_TOP_PORTS
from utils.network import tcp_connect

logger = logging.getLogger("kitsune.ports")


@dataclass
class PortResult:
    port: int
    protocol: str          # currently always "tcp"
    state: str              # "open", "closed", "filtered"
    service_guess: Optional[str]
    rtt_ms: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service_guess": self.service_guess,
            "rtt_ms": self.rtt_ms,
        }


def scan_ports(host: str, ports: Optional[List[int]] = None, timeout: float = 1.0,
               concurrency: int = 100) -> List[PortResult]:
    """
    Scan `host` across `ports` (defaults to a curated top-ports list)
    and return a structured, sorted list of PortResult.

    Reliability notes:
    - Each probe has its own timeout, so one slow/filtered port can't
      stall the whole scan.
    - Concurrency is bounded by a ThreadPoolExecutor to avoid exhausting
      local file descriptors / overwhelming the target.
    """
    if ports is None:
        ports = DEFAULT_TOP_PORTS

    logger.info("Scanning %d port(s) on %s", len(ports), host)

    results: List[PortResult] = []
    with ThreadPoolExecutor(max_workers=min(concurrency, max(1, len(ports)))) as pool:
        futures = {pool.submit(tcp_connect, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                conn = future.result()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Port probe failed for %s:%d: %s", host, port, exc)
                results.append(PortResult(port=port, protocol="tcp", state="filtered",
                                           service_guess=COMMON_PORTS.get(port)))
                continue

            results.append(PortResult(
                port=port,
                protocol="tcp",
                state=conn.state,
                service_guess=COMMON_PORTS.get(port) if conn.state == "open" else None,
                rtt_ms=conn.rtt_ms,
            ))

    results.sort(key=lambda r: r.port)
    open_count = sum(1 for r in results if r.state == "open")
    logger.info("Port scan complete on %s: %d open, %d closed, %d filtered",
                host, open_count,
                sum(1 for r in results if r.state == "closed"),
                sum(1 for r in results if r.state == "filtered"))
    return results


def open_ports_only(results: List[PortResult]) -> List[PortResult]:
    """Convenience filter used by later pipeline stages."""
    return [r for r in results if r.state == "open"]
