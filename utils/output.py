"""
utils/output.py

Centralized output handling. Scanner/pipeline modules never print or
write files directly -- they return structured dataclasses, and this
module is the only place that knows how to render them as text or
JSON. That keeps it easy to add more output formats later (CSV, HTML,
etc.) without touching scanner code.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict


def render_host_discovery_text(host_results) -> str:
    lines = ["Host Discovery", "-" * 40]
    for h in host_results:
        status = "UP" if h.up else "DOWN"
        extra = f" (via {h.method})" if h.up else ""
        lines.append(f"{h.ip:<20}{status}{extra}")
    return "\n".join(lines)


def render_port_scan_text(host: str, port_results) -> str:
    lines = [host, "-" * 40]
    for p in port_results:
        if p.state == "filtered":
            continue  # keep default output focused on actionable states
        svc = f"  {p.service_guess}" if p.service_guess else ""
        lines.append(f"{p.port}/{p.protocol:<6} {p.state.upper():<10}{svc}")
    if not any(p.state != "filtered" for p in port_results):
        lines.append("(no open or closed ports found; all probed ports were filtered)")
    return "\n".join(lines)


def render_banner_text(service_results) -> str:
    lines = []
    for s in service_results:
        lines.append(f"{s.port}/{s.protocol}")
        if s.banner:
            lines.append(f"  {s.banner.splitlines()[0]}")
            if s.version_hint:
                lines.append(f"  Version hint: {s.version_hint}")
        else:
            lines.append("  (no banner received)")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_http_text(http_result) -> str:
    if not http_result.reachable:
        return f"HTTP SECURITY ANALYSIS\n{'-' * 40}\nTarget unreachable: {http_result.error}"

    lines = ["HTTP SECURITY ANALYSIS", "-" * 40, f"URL: {http_result.url}",
              f"Status: {http_result.status_code}", ""]

    header_labels = {
        "Content-Security-Policy": "CSP",
        "Strict-Transport-Security": "HSTS",
        "X-Frame-Options": "X-Frame-Options",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy",
    }
    for header, label in header_labels.items():
        state = "PRESENT" if header in http_result.present_security_headers else "MISSING"
        lines.append(f"{label:<24}{state}")

    if http_result.server:
        lines.append("")
        lines.append(f"Server: {http_result.server}")

    if http_result.cookie_findings:
        lines.append("")
        lines.append("Cookie issues:")
        for finding in http_result.cookie_findings:
            lines.append(f"  - {finding}")

    if http_result.notes:
        lines.append("")
        for note in http_result.notes:
            lines.append(f"Note: {note}")

    return "\n".join(lines)


def render_os_text(os_result) -> str:
    lines = ["OS Detection", "-" * 40]
    lines.append(f"Likely OS: {os_result.os_guess}")
    lines.append(f"Confidence: {os_result.confidence}%")
    if os_result.status == "insufficient-data":
        lines.append("(insufficient data for a reliable guess)")
    if os_result.indicators:
        lines.append("")
        lines.append("Indicators:")
        for ind in os_result.indicators:
            lines.append(f"  - {ind}")
    return "\n".join(lines)


def render_vulnerabilities_text(findings) -> str:
    if not findings:
        return "Vulnerability Assessment\n" + "-" * 40 + "\nNo findings."

    lines = ["Vulnerability Assessment", "-" * 40]
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(findings, key=lambda x: severity_order.get(x.severity, 5)):
        lines.append(f"[{f.severity.upper()}] {f.title} ({f.confidence})")
        lines.append(f"  Target: {f.affected_target}")
        lines.append(f"  Evidence: {f.evidence}")
        lines.append(f"  {f.description}")
        lines.append(f"  Recommendation: {f.recommendation}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_full_scan_text(scan_result) -> str:
    lines = [f"Kitsune Scan Report - {scan_result.target}",
              f"Started:  {scan_result.started_at}",
              f"Finished: {scan_result.finished_at}",
              "=" * 50]

    if scan_result.global_errors:
        lines.append("")
        for err in scan_result.global_errors:
            lines.append(f"! {err}")

    for hs in scan_result.hosts:
        lines.append("")
        lines.append(f"### Host: {hs.host} ###")
        if hs.host_result:
            status = "UP" if hs.host_result.up else "DOWN"
            lines.append(f"Status: {status} (via {hs.host_result.method})")
        if not hs.host_result or not hs.host_result.up:
            continue

        if hs.port_results:
            lines.append("")
            lines.append(render_port_scan_text(hs.host, hs.port_results))

        if hs.service_results:
            lines.append("")
            lines.append("Services:")
            lines.append(render_banner_text(hs.service_results))

        if hs.http_result:
            lines.append("")
            lines.append(render_http_text(hs.http_result))

        if hs.os_result:
            lines.append("")
            lines.append(render_os_text(hs.os_result))

        lines.append("")
        lines.append(render_vulnerabilities_text(hs.vulnerabilities))

        if hs.skipped_stages:
            lines.append("")
            lines.append(f"Skipped stages: {', '.join(hs.skipped_stages)}")
        if hs.stage_errors:
            lines.append("Stage errors:")
            for stage, err in hs.stage_errors.items():
                lines.append(f"  - {stage}: {err}")

    return "\n".join(lines)


def to_json(data_object: Any) -> str:
    """Serialize any object exposing to_dict() (or a plain dict/list) to JSON."""
    if hasattr(data_object, "to_dict"):
        payload: Dict = data_object.to_dict()
    else:
        payload = data_object
    return json.dumps(payload, indent=2, default=str)


def save_json(data_object: Any, path: str = None, results_dir: str = "results") -> str:
    """
    Save a JSON rendering of data_object to disk. If `path` isn't given,
    auto-generates results/scan_<timestamp>.json and creates the results
    directory if needed. Returns the path written to.
    """
    if path is None:
        os.makedirs(results_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        path = os.path.join(results_dir, f"scan_{timestamp}.json")
    else:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        f.write(to_json(data_object))
    return path
