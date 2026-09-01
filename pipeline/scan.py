"""
pipeline/scan.py

The full chained scan pipeline:

  Target -> Host Discovery -> Port Scan -> Banner Grab
         -> HTTP Header Analysis (if web ports found)
         -> OS Detection -> Vulnerability Assessment -> Report

Design principles applied here:
- Stages reuse prior results instead of re-discovering the same facts
  (e.g. the HTTP analyzer is only pointed at ports the port scanner
  already found open).
- Irrelevant stages are skipped with a clear reason recorded, not
  silently dropped.
- A failure in one stage is isolated: it's recorded in `errors` and
  the pipeline continues with whatever data it has.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from scanner.banner import ServiceResult, grab_banners
from scanner.headers import HTTPResult, analyze_headers
from scanner.host import HostResult, discover_hosts
from scanner.os_detect import OSResult, fingerprint_os
from scanner.ports import PortResult, scan_ports
from scanner.vulnerability import VulnerabilityFinding, assess
from utils.common import DEFAULT_TOP_PORTS

logger = logging.getLogger("kitsune.pipeline")

# Ports that indicate an HTTP(S)-speaking service worth handing to the
# header analyzer.
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}


@dataclass
class HostScanResult:
    """All results gathered for a single host during a full pipeline run."""
    host: str
    host_result: Optional[HostResult] = None
    port_results: List[PortResult] = field(default_factory=list)
    service_results: List[ServiceResult] = field(default_factory=list)
    http_result: Optional[HTTPResult] = None
    os_result: Optional[OSResult] = None
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    skipped_stages: List[str] = field(default_factory=list)
    stage_errors: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "host_discovery": self.host_result.to_dict() if self.host_result else None,
            "ports": [p.to_dict() for p in self.port_results],
            "services": [s.to_dict() for s in self.service_results],
            "http": self.http_result.to_dict() if self.http_result else None,
            "os_detection": self.os_result.to_dict() if self.os_result else None,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "skipped_stages": self.skipped_stages,
            "stage_errors": self.stage_errors,
        }


@dataclass
class ScanResult:
    """Top-level result of a full pipeline run, possibly across many hosts."""
    target: str
    started_at: str
    finished_at: Optional[str] = None
    hosts: List[HostScanResult] = field(default_factory=list)
    global_errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "hosts": [h.to_dict() for h in self.hosts],
            "global_errors": self.global_errors,
        }


def _run_stage(stage_name: str, host_scan: HostScanResult, func, *args, **kwargs):
    """
    Run a single pipeline stage with error isolation: on exception, record
    the error against this host and return None instead of propagating,
    so the rest of the pipeline can continue.
    """
    try:
        return func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - pipeline stages must never crash the run
        logger.warning("Stage '%s' failed for %s: %s", stage_name, host_scan.host, exc)
        host_scan.stage_errors[stage_name] = str(exc)
        return None


def run_full_scan(target: str, ports: Optional[List[int]] = None,
                   host_timeout: float = 1.5, port_timeout: float = 1.0,
                   banner_timeout: float = 2.0, http_timeout: float = 5.0,
                   concurrency: int = 100, max_hosts: int = 256,
                   skip_vuln: bool = False) -> ScanResult:
    """
    Execute the full Kitsune pipeline against a target (single host,
    hostname, or CIDR range) and return a ScanResult.
    """
    ports = ports or DEFAULT_TOP_PORTS
    started_at = datetime.now(timezone.utc).isoformat()
    scan_result = ScanResult(target=target, started_at=started_at)

    # --- Stage 1: Host Discovery -----------------------------------
    try:
        host_results = discover_hosts(target, timeout=host_timeout,
                                       concurrency=concurrency, max_hosts=max_hosts)
    except Exception as exc:  # noqa: BLE001
        logger.error("Host discovery failed for target '%s': %s", target, exc)
        scan_result.global_errors.append(f"Host discovery failed: {exc}")
        scan_result.finished_at = datetime.now(timezone.utc).isoformat()
        return scan_result

    active_hosts = [h for h in host_results if h.up]
    if not active_hosts:
        logger.warning("No active hosts found for target '%s'; stopping pipeline", target)
        scan_result.global_errors.append("No active hosts found; remaining stages skipped")
        # Still record the (all-down) host results for transparency.
        for h in host_results:
            hs = HostScanResult(host=h.ip, host_result=h)
            hs.skipped_stages = ["port-scan", "banner", "http-headers", "os-detect", "vuln-scan"]
            scan_result.hosts.append(hs)
        scan_result.finished_at = datetime.now(timezone.utc).isoformat()
        return scan_result

    for host_result in active_hosts:
        host_scan = HostScanResult(host=host_result.ip, host_result=host_result)
        scan_result.hosts.append(host_scan)

        # --- Stage 2: Port Scan --------------------------------
        port_results = _run_stage("port-scan", host_scan, scan_ports,
                                   host_result.ip, ports, port_timeout, concurrency)
        if port_results is None:
            host_scan.skipped_stages.extend(["banner", "http-headers", "os-detect", "vuln-scan"])
            continue
        host_scan.port_results = port_results

        open_ports = [p for p in port_results if p.state == "open"]
        if not open_ports:
            logger.info("No open ports on %s; skipping banner/HTTP/vuln stages", host_result.ip)
            host_scan.skipped_stages.extend(["banner", "http-headers", "vuln-scan"])
            # OS detection can still run on TTL alone.
            os_result = _run_stage("os-detect", host_scan, fingerprint_os,
                                    host_result.ttl, port_results, [])
            host_scan.os_result = os_result
            continue

        # --- Stage 3: Banner Grabbing ---------------------------
        service_results = _run_stage("banner", host_scan, grab_banners,
                                      host_result.ip, port_results, banner_timeout, concurrency)
        host_scan.service_results = service_results or []

        # --- Stage 4: HTTP Header Analysis (only if web port open) ---
        web_ports_open = [p.port for p in open_ports if p.port in WEB_PORTS]
        if web_ports_open:
            scheme = "https" if any(p in (443, 8443) for p in web_ports_open) else "http"
            url = f"{scheme}://{host_result.ip}:{web_ports_open[0]}"
            http_result = _run_stage("http-headers", host_scan, analyze_headers, url, http_timeout)
            host_scan.http_result = http_result
        else:
            host_scan.skipped_stages.append("http-headers")

        # --- Stage 5: OS Detection -------------------------------
        os_result = _run_stage("os-detect", host_scan, fingerprint_os,
                                host_result.ttl, port_results, host_scan.service_results)
        host_scan.os_result = os_result

        # --- Stage 6: Vulnerability Assessment --------------------
        if skip_vuln:
            host_scan.skipped_stages.append("vuln-scan")
        else:
            vulns = _run_stage("vuln-scan", host_scan, assess,
                                host_result.ip, port_results, host_scan.service_results,
                                host_scan.http_result, host_scan.os_result)
            host_scan.vulnerabilities = vulns or []

    scan_result.finished_at = datetime.now(timezone.utc).isoformat()
    return scan_result
