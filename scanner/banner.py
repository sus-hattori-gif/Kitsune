"""
scanner/banner.py

Banner grabbing / lightweight service detection for open TCP ports.

Approach:
- For most services, simply connect and read whatever the server sends
  first (many protocols, like SSH/FTP/SMTP, greet the client unprompted).
- For a small set of well-known ports where the server waits for the
  client to speak first (HTTP/HTTPS), send a minimal, safe probe request.
- Never send anything destructive or protocol-fuzzing; this is detection,
  not exploitation.
- All reads/connects are time-bounded so an unusual or hanging service
  can't stall the whole scan.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional

from scanner.ports import PortResult, open_ports_only
from utils.network import read_banner

logger = logging.getLogger("kitsune.banner")

# Ports that expect the client to send something first (request-response
# protocols) rather than greeting on connect.
_CLIENT_FIRST_PROBES = {
    80: b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nConnection: close\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nConnection: close\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nConnection: close\r\n\r\n",
}

_VERSION_PATTERNS = [
    re.compile(r"SSH-\d\.\d-([\w.\-_]+)"),
    re.compile(r"Server:\s*([^\r\n]+)", re.IGNORECASE),
    re.compile(r"220[- ]([^\r\n]*)"),   # FTP/SMTP greeting banners
]


@dataclass
class ServiceResult:
    port: int
    protocol: str
    service_guess: Optional[str]
    banner: Optional[str]
    version_hint: Optional[str]

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service_guess": self.service_guess,
            "banner": self.banner,
            "version_hint": self.version_hint,
        }


def _extract_version(text: str) -> Optional[str]:
    for pattern in _VERSION_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1).strip()
    return None


def _decode_banner(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace").strip()


def grab_banner_for_port(host: str, port_result: PortResult, timeout: float = 2.0) -> ServiceResult:
    """Grab a banner for a single open port. Never raises."""
    port = port_result.port
    probe = _CLIENT_FIRST_PROBES.get(port)
    if probe:
        probe = probe.replace(b"%HOST%", host.encode("ascii", errors="ignore"))

    raw = read_banner(host, port, timeout=timeout, probe=probe)
    if not raw:
        return ServiceResult(port=port, protocol="tcp",
                              service_guess=port_result.service_guess,
                              banner=None, version_hint=None)

    text = _decode_banner(raw)
    # Trim to a reasonable size for readability/reporting
    trimmed = text[:512]
    version_hint = _extract_version(text)

    service_guess = port_result.service_guess
    if not service_guess:
        if text.upper().startswith("SSH-"):
            service_guess = "ssh"
        elif "HTTP/" in text[:16]:
            service_guess = "http"
        elif text.startswith("220"):
            service_guess = "ftp/smtp"

    return ServiceResult(port=port, protocol="tcp", service_guess=service_guess,
                          banner=trimmed, version_hint=version_hint)


def grab_banners(host: str, port_results: List[PortResult], timeout: float = 2.0,
                  concurrency: int = 25) -> List[ServiceResult]:
    """
    Grab banners for every open port in port_results.

    Reuses the port scan's results instead of re-discovering which ports
    are open, per the pipeline's "don't repeat work" principle.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    open_ports = open_ports_only(port_results)
    if not open_ports:
        logger.info("No open ports supplied to banner grabber for %s", host)
        return []

    logger.info("Grabbing banners for %d open port(s) on %s", len(open_ports), host)
    results: List[ServiceResult] = []
    with ThreadPoolExecutor(max_workers=min(concurrency, max(1, len(open_ports)))) as pool:
        futures = {pool.submit(grab_banner_for_port, host, pr, timeout): pr for pr in open_ports}
        for future in as_completed(futures):
            pr = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001
                logger.warning("Banner grab failed for %s:%d: %s", host, pr.port, exc)
                results.append(ServiceResult(port=pr.port, protocol="tcp",
                                              service_guess=pr.service_guess,
                                              banner=None, version_hint=None))

    results.sort(key=lambda r: r.port)
    return results
