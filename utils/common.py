"""
utils/common.py

Shared, dependency-free helpers used across Kitsune:
- target parsing (single IP, hostname, CIDR)
- port range parsing
- logging setup
- small validation helpers

Keeping these in one place means every scanner module parses
targets and ports the exact same way.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import List, Optional


class KitsuneInputError(ValueError):
    """Raised when user-supplied input (target/ports/etc.) is invalid."""


@dataclass
class ParsedTarget:
    """Result of parsing a target string."""
    original: str
    is_network: bool
    hosts: List[str]          # resolved list of IP addresses to operate on
    hostname: Optional[str]   # original hostname, if the target was a name


def setup_logging(verbosity: int = 0, quiet: bool = False) -> logging.Logger:
    """
    Configure and return the root 'kitsune' logger.

    verbosity: 0 = warnings/errors only, 1 = info, 2+ = debug
    quiet: suppress everything except errors, overrides verbosity
    """
    logger = logging.getLogger("kitsune")
    logger.handlers.clear()

    if quiet:
        level = logging.ERROR
    elif verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    handler = logging.StreamHandler()
    fmt = "%(message)s" if level >= logging.INFO else "[%(levelname)s] %(name)s: %(message)s"
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> str:
    """Resolve a hostname to an IP address. Raises KitsuneInputError on failure."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        raise KitsuneInputError(f"Could not resolve hostname '{hostname}': {exc}") from exc


def parse_target(target: str, max_hosts: int = 1024) -> ParsedTarget:
    """
    Parse a target specification into a list of concrete IP addresses.

    Accepts:
      - a single IP address ("192.168.1.10")
      - a hostname ("example.com") -- resolved via DNS
      - a CIDR network ("192.168.1.0/24")

    max_hosts guards against accidentally expanding an enormous network
    (e.g. a /8) into millions of scan targets.
    """
    target = target.strip()
    if not target:
        raise KitsuneInputError("Empty target")

    # URL-like input: pull out just the host portion first, before any
    # CIDR/slash detection runs (otherwise a URL path looks like a CIDR).
    for prefix in ("http://", "https://"):
        if target.startswith(prefix):
            hostname = target[len(prefix):]
            hostname = hostname.split("/")[0].split(":")[0]
            if is_valid_ip(hostname):
                return ParsedTarget(original=target, is_network=False, hosts=[hostname], hostname=None)
            ip = resolve_hostname(hostname)
            return ParsedTarget(original=target, is_network=False, hosts=[ip], hostname=hostname)

    # CIDR network
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise KitsuneInputError(f"Invalid CIDR range '{target}': {exc}") from exc

        hosts = [str(ip) for ip in network.hosts()]
        # /31 and /32 have no usable .hosts(); fall back to network address itself
        if not hosts:
            hosts = [str(network.network_address)]

        if len(hosts) > max_hosts:
            raise KitsuneInputError(
                f"Network '{target}' expands to {len(hosts)} hosts, "
                f"which exceeds the safety limit of {max_hosts}. "
                f"Use a smaller range."
            )
        return ParsedTarget(original=target, is_network=True, hosts=hosts, hostname=None)

    # Single IP address
    if is_valid_ip(target):
        return ParsedTarget(original=target, is_network=False, hosts=[target], hostname=None)

    # Plain hostname (URL-scheme inputs are already handled above)
    hostname = target.split("/")[0].split(":")[0]
    ip = resolve_hostname(hostname)
    return ParsedTarget(original=target, is_network=False, hosts=[ip], hostname=hostname)


def parse_port_range(spec: str) -> List[int]:
    """
    Parse a port specification string into a sorted list of unique ports.

    Accepts comma-separated values and ranges, e.g.:
      "80"
      "22,80,443"
      "1-1024"
      "22,80,1000-2000,8443"
    """
    if not spec or not spec.strip():
        raise KitsuneInputError("Empty port specification")

    ports: set = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            parts = chunk.split("-")
            if len(parts) != 2:
                raise KitsuneInputError(f"Invalid port range '{chunk}'")
            try:
                start, end = int(parts[0]), int(parts[1])
            except ValueError as exc:
                raise KitsuneInputError(f"Invalid port range '{chunk}': {exc}") from exc
            if start > end:
                start, end = end, start
            _validate_port(start)
            _validate_port(end)
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError as exc:
                raise KitsuneInputError(f"Invalid port '{chunk}': {exc}") from exc
            _validate_port(port)
            ports.add(port)

    if not ports:
        raise KitsuneInputError(f"No valid ports found in '{spec}'")

    return sorted(ports)


def _validate_port(port: int) -> None:
    if not (0 < port <= 65535):
        raise KitsuneInputError(f"Port {port} is out of range (1-65535)")


# A small, well-known port -> service name map used as a fallback guess
# before banner grabbing runs. Not authoritative.
COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
}

DEFAULT_TOP_PORTS = sorted(COMMON_PORTS.keys())
