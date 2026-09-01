"""
scanner/os_detect.py

Lightweight, non-destructive OS fingerprinting.

Combines several weak signals into a single weighted guess with an
explicit confidence score:
  - TTL from the initial host-discovery ping (classic OS families cluster
    around default TTLs: 64 = Linux/Unix/macOS, 128 = Windows, 255 =
    network gear/older Unix)
  - Open port fingerprint (e.g. 3389 strongly suggests Windows, 22+80
    with no 3389/135/445 suggests Linux)
  - Service banners already collected (e.g. "Ubuntu", "Win32", "IIS")

This is deliberately simple and explicitly probabilistic -- it must
never be reported as a certainty. No raw packet crafting or TCP/IP
stack-quirk analysis is performed (that would need raw sockets/root);
this stays within what's reachable from an unprivileged TCP connect
scan plus a system ping.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from scanner.banner import ServiceResult
from scanner.ports import PortResult

logger = logging.getLogger("kitsune.os_detect")

WINDOWS_PORTS = {135, 139, 445, 3389}
LINUX_LEANING_PORTS = {22, 111, 2049}
NETWORK_DEVICE_PORTS = {23, 161}


@dataclass
class OSResult:
    os_guess: str
    confidence: int                 # 0-100
    indicators: List[str] = field(default_factory=list)
    status: str = "ok"              # "ok" or "insufficient-data"

    def to_dict(self) -> dict:
        return {
            "os_guess": self.os_guess,
            "confidence": self.confidence,
            "indicators": self.indicators,
            "status": self.status,
        }


def _score_from_ttl(ttl: Optional[int]) -> tuple:
    """Return (os_family_or_None, score, indicator_text)."""
    if ttl is None:
        return None, 0, None
    # Real-world TTLs are the original value minus hop count, so we bucket
    # by "nearest common starting TTL from below".
    if ttl <= 64:
        return "Linux/Unix", 35, f"TTL {ttl} (<=64, consistent with Linux/Unix/macOS default 64)"
    if ttl <= 128:
        return "Windows", 35, f"TTL {ttl} (<=128, consistent with Windows default 128)"
    return "Network device/Unix (old)", 20, f"TTL {ttl} (<=255, consistent with network gear or legacy Unix)"


def _score_from_ports(open_ports: List[int]) -> List[tuple]:
    scores = []
    win_hits = open_ports & WINDOWS_PORTS
    if win_hits:
        scores.append(("Windows", 30 + 5 * len(win_hits),
                        f"Windows-associated port(s) open: {sorted(win_hits)}"))
    linux_hits = open_ports & LINUX_LEANING_PORTS
    if linux_hits:
        scores.append(("Linux/Unix", 15 + 5 * len(linux_hits),
                        f"Unix-associated port(s) open: {sorted(linux_hits)}"))
    net_hits = open_ports & NETWORK_DEVICE_PORTS
    if net_hits:
        scores.append(("Network device/Unix (old)", 10,
                        f"Management port(s) open: {sorted(net_hits)}"))
    return scores


def _score_from_banners(services: List[ServiceResult]) -> List[tuple]:
    scores = []
    for svc in services:
        text = f"{svc.banner or ''} {svc.version_hint or ''}".lower()
        if not text.strip():
            continue
        if "ubuntu" in text or "debian" in text:
            scores.append(("Linux/Unix (Debian-based)", 40, f"Banner on port {svc.port} mentions Debian/Ubuntu"))
        elif "centos" in text or "red hat" in text or "rhel" in text or "fedora" in text:
            scores.append(("Linux/Unix (RHEL-based)", 40, f"Banner on port {svc.port} mentions RHEL/CentOS/Fedora"))
        elif "win32" in text or "windows" in text or "iis" in text:
            scores.append(("Windows", 45, f"Banner on port {svc.port} mentions Windows/IIS"))
        elif "openssh" in text:
            scores.append(("Linux/Unix", 20, f"OpenSSH banner on port {svc.port} (common on Unix-likes)"))
        elif "nginx" in text or "apache" in text:
            scores.append(("Linux/Unix", 10, f"Web server banner on port {svc.port} typically runs on Unix-likes"))
        elif "microsoft" in text:
            scores.append(("Windows", 35, f"Banner on port {svc.port} mentions Microsoft"))
    return scores


def fingerprint_os(host_ttl: Optional[int], port_results: List[PortResult],
                    service_results: Optional[List[ServiceResult]] = None) -> OSResult:
    """
    Combine TTL, open-port fingerprint, and banner hints into a single
    weighted OS guess. Returns an "insufficient-data" result rather than
    a wild guess when nothing useful was collected.
    """
    service_results = service_results or []
    open_ports = {p.port for p in port_results if p.state == "open"}

    votes: List[tuple] = []

    ttl_os, ttl_score, ttl_indicator = _score_from_ttl(host_ttl)
    if ttl_os:
        votes.append((ttl_os, ttl_score, ttl_indicator))

    votes.extend(_score_from_ports(open_ports))
    votes.extend(_score_from_banners(service_results))

    if not votes:
        return OSResult(os_guess="Unknown", confidence=0,
                         indicators=["No TTL, port, or banner signals available"],
                         status="insufficient-data")

    tally: dict = {}
    indicators: List[str] = []
    for os_name, score, indicator in votes:
        tally[os_name] = tally.get(os_name, 0) + score
        if indicator:
            indicators.append(indicator)

    best_os = max(tally, key=tally.get)
    raw_score = tally[best_os]
    confidence = max(1, min(95, raw_score))  # never claim 100% certainty

    logger.info("OS fingerprint for target: %s (%d%% confidence)", best_os, confidence)
    return OSResult(os_guess=best_os, confidence=confidence, indicators=indicators, status="ok")
