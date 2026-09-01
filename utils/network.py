"""
utils/network.py

Low-level, dependency-free network helpers shared by the scanner modules:
- TCP connect probing (used for both liveness and port scanning)
- a small retry/backoff wrapper
- best-effort TTL discovery via the system ping utility (no raw sockets
  or root privileges required)

Everything here is designed to fail soft: on timeout, refusal, or any
network error we return a structured "unknown/filtered" style result
instead of raising, so a single bad probe never crashes a scan.
"""

from __future__ import annotations

import logging
import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Callable, Optional, TypeVar

logger = logging.getLogger("kitsune.network")

T = TypeVar("T")


@dataclass
class ConnectResult:
    """Outcome of a single TCP connect attempt."""
    state: str            # "open", "closed", "filtered"
    rtt_ms: Optional[float]
    error: Optional[str] = None


def tcp_connect(host: str, port: int, timeout: float = 1.5) -> ConnectResult:
    """
    Attempt a TCP connect to host:port and classify the result.

    - "open": connection succeeded
    - "closed": connection actively refused (RST) -> host is up, port isn't listening
    - "filtered": timed out or unreachable -> likely dropped by a firewall/ACL,
      or the host itself is down. Callers combine this with host-discovery
      results to disambiguate.
    """
    start = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        rtt_ms = (time.monotonic() - start) * 1000
        if result == 0:
            return ConnectResult(state="open", rtt_ms=round(rtt_ms, 2))
        # ECONNREFUSED (61 on macOS/BSD, 111 on Linux) means actively closed
        if result in (61, 111):
            return ConnectResult(state="closed", rtt_ms=round(rtt_ms, 2))
        return ConnectResult(state="filtered", rtt_ms=round(rtt_ms, 2),
                              error=f"connect_ex returned {result}")
    except socket.timeout:
        return ConnectResult(state="filtered", rtt_ms=None, error="timeout")
    except OSError as exc:
        return ConnectResult(state="filtered", rtt_ms=None, error=str(exc))
    finally:
        try:
            sock.close()
        except OSError:
            pass


def read_banner(host: str, port: int, timeout: float = 2.0,
                 probe: Optional[bytes] = None, read_bytes: int = 1024) -> Optional[bytes]:
    """
    Connect to host:port, optionally send a probe payload, and read
    whatever the service sends back. Returns None on any failure
    (closed port, timeout, connection reset) rather than raising --
    plenty of services simply don't offer a banner, which is not an error.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if probe:
                try:
                    sock.sendall(probe)
                except OSError:
                    pass
            try:
                data = sock.recv(read_bytes)
                return data if data else None
            except socket.timeout:
                return None
    except (OSError, socket.timeout):
        return None


def retry(func: Callable[[], T], attempts: int = 2, backoff_seconds: float = 0.3) -> T:
    """
    Run func() up to `attempts` times, with linear backoff between
    attempts, returning the first result that doesn't raise. Re-raises
    the last exception if every attempt fails.
    """
    last_exc: Optional[Exception] = None
    for i in range(attempts):
        try:
            return func()
        except Exception as exc:  # noqa: BLE001 - intentionally broad, this is a generic retry wrapper
            last_exc = exc
            logger.debug("retry attempt %d/%d failed: %s", i + 1, attempts, exc)
            if i < attempts - 1:
                time.sleep(backoff_seconds * (i + 1))
    assert last_exc is not None
    raise last_exc


_PING_TTL_RE = re.compile(r"ttl[=\s](\d+)", re.IGNORECASE)
_PING_TIME_RE = re.compile(r"time[=<]([\d.]+)", re.IGNORECASE)


def ping_probe(host: str, timeout_seconds: float = 1.5) -> dict:
    """
    Best-effort liveness + TTL probe using the system 'ping' binary.

    This deliberately avoids raw sockets (which need root/CAP_NET_RAW)
    by shelling out to ping, which is present on essentially every
    Linux/macOS/Windows system and already has the needed privileges.

    Returns a dict: {"alive": bool, "ttl": Optional[int], "rtt_ms": Optional[float]}
    On any error (ping missing, host unreachable, permission issues) this
    returns alive=False rather than raising.
    """
    system = platform.system().lower()
    count_flag = ["-n", "1"] if system == "windows" else ["-c", "1"]
    timeout_flag: list
    if system == "windows":
        timeout_flag = ["-w", str(int(timeout_seconds * 1000))]
    elif system == "darwin":
        timeout_flag = ["-t", str(max(1, int(timeout_seconds)))]
    else:
        timeout_flag = ["-W", str(max(1, int(timeout_seconds)))]

    cmd = ["ping"] + count_flag + timeout_flag + [host]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 2,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("ping probe failed for %s: %s", host, exc)
        return {"alive": False, "ttl": None, "rtt_ms": None}

    output = proc.stdout or ""
    alive = proc.returncode == 0

    ttl_match = _PING_TTL_RE.search(output)
    ttl = int(ttl_match.group(1)) if ttl_match else None

    time_match = _PING_TIME_RE.search(output)
    rtt_ms = float(time_match.group(1)) if time_match else None

    return {"alive": alive, "ttl": ttl, "rtt_ms": rtt_ms}
