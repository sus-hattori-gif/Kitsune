#!/usr/bin/env python3
"""
Kitsune - lightweight, modular network & web security scanner.

Entry point / CLI dispatcher. This file only handles argument parsing
and wiring; all real logic lives in scanner/, pipeline/, and utils/.

Exit codes:
  0 - success
  1 - scan/runtime error
  2 - invalid arguments / input
  3 - no targets reachable
"""

from __future__ import annotations

import argparse
import sys

from scanner.banner import grab_banners
from scanner.headers import analyze_headers
from scanner.host import discover_hosts
from scanner.os_detect import fingerprint_os
from scanner.ports import scan_ports
from scanner.vulnerability import assess
from pipeline.scan import run_full_scan
from utils.common import KitsuneInputError, parse_port_range, parse_target
from utils.output import (
    render_banner_text,
    render_full_scan_text,
    render_host_discovery_text,
    render_http_text,
    render_os_text,
    render_port_scan_text,
    render_vulnerabilities_text,
    save_json,
    to_json,
)
from utils.common import setup_logging, DEFAULT_TOP_PORTS

BANNER = r"""

  _  _____ _____ ___ _   _ _  _ ___ 
 | |/ /_ _|_   _/ __| | | | \| | __|  |\__/|
 | ' < | |  | | \__ \ |_| | .` | _|   /     \
 |_|\_\___| |_| |___/\___/|_|\_|___| /_.~ ~,_\ security scanner 
                                        \@/    
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kitsune",
        description="Kitsune - lightweight, modular network & web security scanner.",
        epilog="Use only against systems you are authorized to test.",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0,
                         help="increase output verbosity (-v, -vv)")
    parser.add_argument("-q", "--quiet", action="store_true",
                         help="suppress non-error output")
    parser.add_argument("--json", action="store_true",
                         help="output results as JSON instead of text")
    parser.add_argument("--out", metavar="FILE",
                         help="write JSON results to this file (implies structured output)")
    parser.add_argument("--timeout", type=float, default=None,
                         help="override default per-probe timeout (seconds)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_scan = subparsers.add_parser("scan", help="run the full scan pipeline")
    p_scan.add_argument("target", help="IP, hostname, or CIDR range")
    p_scan.add_argument("--ports", help="port spec, e.g. '1-1000' or '22,80,443' "
                                          "(default: curated top-ports list)")
    p_scan.add_argument("--concurrency", type=int, default=100)
    p_scan.add_argument("--max-hosts", type=int, default=256,
                         help="safety cap on hosts expanded from a CIDR range")
    p_scan.add_argument("--skip-vuln", action="store_true", help="skip vulnerability assessment")

    p_host = subparsers.add_parser("host-scan", help="host discovery only")
    p_host.add_argument("target", help="IP, hostname, or CIDR range")
    p_host.add_argument("--concurrency", type=int, default=32)
    p_host.add_argument("--max-hosts", type=int, default=1024)

    p_port = subparsers.add_parser("port-scan", help="port scan only")
    p_port.add_argument("target", help="IP or hostname")
    p_port.add_argument("--ports", help="port spec, e.g. '1-1000' or '22,80,443'")
    p_port.add_argument("--concurrency", type=int, default=100)

    p_banner = subparsers.add_parser("banner", help="banner grab / service detection only")
    p_banner.add_argument("target", help="IP or hostname")
    p_banner.add_argument("--ports", help="port spec (default: curated top-ports list)")
    p_banner.add_argument("--concurrency", type=int, default=25)

    p_headers = subparsers.add_parser("headers", help="HTTP security header analysis only")
    p_headers.add_argument("target", help="URL or hostname (scheme optional, defaults to https)")

    p_os = subparsers.add_parser("os-detect", help="OS fingerprinting only")
    p_os.add_argument("target", help="IP or hostname")
    p_os.add_argument("--ports", help="port spec used to gather fingerprint signals")

    p_vuln = subparsers.add_parser("vuln-scan", help="vulnerability assessment only")
    p_vuln.add_argument("target", help="IP or hostname")
    p_vuln.add_argument("--ports", help="port spec used to gather assessment input")

    return parser


def _resolve_single_target_ip(target: str) -> str:
    parsed = parse_target(target, max_hosts=1)
    return parsed.hosts[0]


def cmd_scan(args, logger) -> int:
    ports = parse_port_range(args.ports) if args.ports else None
    kwargs = dict(ports=ports, concurrency=args.concurrency, max_hosts=args.max_hosts,
                  skip_vuln=args.skip_vuln)
    if args.timeout:
        kwargs.update(host_timeout=args.timeout, port_timeout=args.timeout,
                      banner_timeout=args.timeout, http_timeout=args.timeout)
    result = run_full_scan(args.target, **kwargs)

    if args.json or args.out:
        output = to_json(result)
        if args.out:
            path = save_json(result, path=args.out)
            if not args.quiet:
                print(f"Results written to {path}")
        else:
            print(output)
    else:
        print(render_full_scan_text(result))

    any_up = any(h.host_result and h.host_result.up for h in result.hosts)
    if not any_up:
        return 3
    return 0


def cmd_host_scan(args, logger) -> int:
    results = discover_hosts(args.target, timeout=args.timeout or 1.5,
                              concurrency=args.concurrency, max_hosts=args.max_hosts)
    if args.json or args.out:
        payload = [r.to_dict() for r in results]
        if args.out:
            path = save_json(payload, path=args.out)
            if not args.quiet:
                print(f"Results written to {path}")
        else:
            import json
            print(json.dumps(payload, indent=2))
    else:
        print(render_host_discovery_text(results))
    return 0 if any(r.up for r in results) else 3


def cmd_port_scan(args, logger) -> int:
    ip = _resolve_single_target_ip(args.target)
    ports = parse_port_range(args.ports) if args.ports else DEFAULT_TOP_PORTS
    results = scan_ports(ip, ports, timeout=args.timeout or 1.0, concurrency=args.concurrency)
    if args.json or args.out:
        payload = [r.to_dict() for r in results]
        if args.out:
            path = save_json(payload, path=args.out)
            if not args.quiet:
                print(f"Results written to {path}")
        else:
            import json
            print(json.dumps(payload, indent=2))
    else:
        print(render_port_scan_text(ip, results))
    return 0


def cmd_banner(args, logger) -> int:
    ip = _resolve_single_target_ip(args.target)
    ports = parse_port_range(args.ports) if args.ports else DEFAULT_TOP_PORTS
    port_results = scan_ports(ip, ports, timeout=args.timeout or 1.0, concurrency=args.concurrency)
    service_results = grab_banners(ip, port_results, timeout=args.timeout or 2.0,
                                    concurrency=args.concurrency)
    if args.json or args.out:
        payload = [s.to_dict() for s in service_results]
        if args.out:
            path = save_json(payload, path=args.out)
            if not args.quiet:
                print(f"Results written to {path}")
        else:
            import json
            print(json.dumps(payload, indent=2))
    else:
        print(render_banner_text(service_results) or "(no open ports / no banners retrieved)")
    return 0


def cmd_headers(args, logger) -> int:
    result = analyze_headers(args.target, timeout=args.timeout or 5.0)
    if args.json or args.out:
        if args.out:
            path = save_json(result, path=args.out)
            if not args.quiet:
                print(f"Results written to {path}")
        else:
            print(to_json(result))
    else:
        print(render_http_text(result))
    return 0 if result.reachable else 1


def cmd_os_detect(args, logger) -> int:
    ip = _resolve_single_target_ip(args.target)
    ports = parse_port_range(args.ports) if args.ports else DEFAULT_TOP_PORTS
    host_results = discover_hosts(ip, timeout=args.timeout or 1.5, max_hosts=1)
    ttl = host_results[0].ttl if host_results else None
    port_results = scan_ports(ip, ports, timeout=args.timeout or 1.0)
    service_results = grab_banners(ip, port_results, timeout=args.timeout or 2.0)
    result = fingerprint_os(ttl, port_results, service_results)
    if args.json or args.out:
        if args.out:
            path = save_json(result, path=args.out)
            if not args.quiet:
                print(f"Results written to {path}")
        else:
            print(to_json(result))
    else:
        print(render_os_text(result))
    return 0


def cmd_vuln_scan(args, logger) -> int:
    ip = _resolve_single_target_ip(args.target)
    ports = parse_port_range(args.ports) if args.ports else DEFAULT_TOP_PORTS
    port_results = scan_ports(ip, ports, timeout=args.timeout or 1.0)
    service_results = grab_banners(ip, port_results, timeout=args.timeout or 2.0)
    http_result = None
    if any(p.state == "open" and p.port in (80, 443, 8080, 8443) for p in port_results):
        web_port = next(p.port for p in port_results if p.state == "open" and p.port in (80, 443, 8080, 8443))
        scheme = "https" if web_port in (443, 8443) else "http"
        http_result = analyze_headers(f"{scheme}://{ip}:{web_port}", timeout=args.timeout or 5.0)
    findings = assess(ip, port_results, service_results, http_result)
    if args.json or args.out:
        payload = [f.to_dict() for f in findings]
        if args.out:
            path = save_json(payload, path=args.out)
            if not args.quiet:
                print(f"Results written to {path}")
        else:
            import json
            print(json.dumps(payload, indent=2))
    else:
        print(render_vulnerabilities_text(findings))
    return 0


COMMANDS = {
    "scan": cmd_scan,
    "host-scan": cmd_host_scan,
    "port-scan": cmd_port_scan,
    "banner": cmd_banner,
    "headers": cmd_headers,
    "os-detect": cmd_os_detect,
    "vuln-scan": cmd_vuln_scan,
}


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logger = setup_logging(verbosity=args.verbose, quiet=args.quiet)

    if not args.quiet and not args.json:
        print(BANNER)

    handler = COMMANDS.get(args.command)
    if handler is None:
        parser.print_help()
        return 2

    try:
        return handler(args, logger)
    except KitsuneInputError as exc:
        logger.error("Input error: %s", exc)
        return 2
    except KeyboardInterrupt:
        logger.error("Interrupted by user")
        return 1
    except Exception as exc:  # noqa: BLE001 - top-level safety net
        logger.error("Unexpected error: %s", exc)
        if args.verbose >= 2:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
