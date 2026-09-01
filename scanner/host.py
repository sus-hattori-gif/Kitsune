"""
scanner/host.py

Host discovery: determine which hosts in a target/CIDR are active.

Strategy (in order):
1. ICMP ping via the system 'ping' binary (no raw sockets / root needed).
2. If ICMP appears blocked (no replies at all across the sweep) or the
   ping binary itself is unavailable, fall back to a lightweight TCP
   connect probe against a handful of commonly-open ports. A host that
   responds (open or actively refused) on any of these is considered up.

This mirrors how real networks behave: ICMP is frequently filtered by
firewalls even when the host is very much alive and serving TCP traffic.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional

from utils.common import ParsedTarget, parse_target
from utils.network import ConnectResult, ping_probe, tcp_connect

logger = logging.getLogger("kitsune.host")

# Ports used for the TCP fallback liveness check when ICMP is filtered.
FALLBACK_PROBE_PORTS = [80, 443, 22, 445, 3389]


@dataclass
class HostResult:
    ip: str
    up: bool
    method: str                    # "icmp", "tcp-fallback", or "none"
    rtt_ms: Optional[float] = None
    ttl: Optional[int] = None
    probed_ports: List[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "up": self.up,
            "method": self.method,
            "rtt_ms": self.rtt_ms,
            "ttl": self.ttl,
            "probed_ports": self.probed_ports,
        }


def _tcp_fallback_check(ip: str, timeout: float) -> HostResult:
    """Try a small set of common ports; any response (even refused) means the host is up."""
    best_rtt = None
    responded = False
    tried = []
    for port in FALLBACK_PROBE_PORTS:
        tried.append(port)
        result: ConnectResult = tcp_connect(ip, port, timeout=timeout)
        if result.state in ("open", "closed"):
            responded = True
            if result.rtt_ms is not None and (best_rtt is None or result.rtt_ms < best_rtt):
                best_rtt = result.rtt_ms
            # Don't bother probing further ports once we know the host is up
            break
    return HostResult(ip=ip, up=responded, method="tcp-fallback" if responded else "none",
                       rtt_ms=best_rtt, probed_ports=tried)


def _probe_single_host(ip: str, timeout: float, tcp_fallback: bool) -> HostResult:
    ping_result = ping_probe(ip, timeout_seconds=timeout)
    if ping_result["alive"]:
        return HostResult(ip=ip, up=True, method="icmp",
                           rtt_ms=ping_result["rtt_ms"], ttl=ping_result["ttl"])

    if tcp_fallback:
        return _tcp_fallback_check(ip, timeout)

    return HostResult(ip=ip, up=False, method="none")


def discover_hosts(target: str, timeout: float = 1.5, concurrency: int = 32,
                    max_hosts: int = 1024) -> List[HostResult]:
    """
    Discover active hosts for a single IP, hostname, or CIDR range.

    Runs ICMP first; if the whole sweep comes back with zero ICMP replies
    (a strong sign ICMP is filtered network-wide) it re-checks every host
    with the TCP fallback so a filtered network doesn't get reported as
    entirely dead.
    """
    parsed: ParsedTarget = parse_target(target, max_hosts=max_hosts)
    logger.info("Discovering hosts for %s (%d candidate host(s))", target, len(parsed.hosts))

    results: List[HostResult] = []
    with ThreadPoolExecutor(max_workers=min(concurrency, max(1, len(parsed.hosts)))) as pool:
        futures = {pool.submit(_probe_single_host, ip, timeout, False): ip for ip in parsed.hosts}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001
                logger.warning("Host probe failed for %s: %s", ip, exc)
                results.append(HostResult(ip=ip, up=False, method="error"))

    icmp_up_count = sum(1 for r in results if r.up)
    if icmp_up_count == 0 and len(results) > 0:
        logger.info("No ICMP replies received; retrying with TCP fallback probing")
        with ThreadPoolExecutor(max_workers=min(concurrency, max(1, len(parsed.hosts)))) as pool:
            futures = {pool.submit(_tcp_fallback_check, ip, timeout): ip for ip in parsed.hosts}
            results = []
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001
                    logger.warning("TCP fallback probe failed for %s: %s", ip, exc)
                    results.append(HostResult(ip=ip, up=False, method="error"))

    results.sort(key=lambda r: tuple(int(part) for part in r.ip.split(".")) if r.ip.count(".") == 3 else (0,))
    up = sum(1 for r in results if r.up)
    logger.info("Host discovery complete: %d/%d host(s) up", up, len(results))
    return results
