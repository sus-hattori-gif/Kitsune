"""
scanner/headers.py

HTTP(S) security header analysis. Uses only the standard library
(urllib + ssl + http.client) so Kitsune has no hard dependency on
`requests` for its core functionality.

Checks presence/absence of common security headers, inspects cookie
attributes, follows/records redirects, and captures whatever the
server exposes about itself (Server header, etc.) without ever
sending anything beyond a normal GET/HEAD request.
"""

from __future__ import annotations

import http.client
import logging
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("kitsune.headers")

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

INFO_HEADERS = ["Server", "Set-Cookie", "Location", "Cache-Control"]

MAX_REDIRECTS = 5


@dataclass
class HTTPResult:
    url: str
    reachable: bool
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    present_security_headers: List[str] = field(default_factory=list)
    missing_security_headers: List[str] = field(default_factory=list)
    server: Optional[str] = None
    cookie_findings: List[str] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    uses_https: bool = False
    tls_error: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "reachable": self.reachable,
            "status_code": self.status_code,
            "headers": self.headers,
            "present_security_headers": self.present_security_headers,
            "missing_security_headers": self.missing_security_headers,
            "server": self.server,
            "cookie_findings": self.cookie_findings,
            "redirect_chain": self.redirect_chain,
            "uses_https": self.uses_https,
            "tls_error": self.tls_error,
            "notes": self.notes,
            "error": self.error,
        }


def _normalize_url(target: str) -> str:
    """Ensure the target has a scheme; default to https."""
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _single_request(url: str, timeout: float) -> tuple:
    """
    Perform one HTTP GET using http.client (no auto-redirect-following),
    returning (status_code, headers_dict, location_or_None, tls_error_or_None).
    """
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    tls_error = None
    conn: http.client.HTTPConnection
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        try:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
            conn.request("GET", path, headers={
                "Host": host, "User-Agent": "Kitsune-Scanner/1.0",
                "Accept": "*/*", "Connection": "close",
            })
            response = conn.getresponse()
        except ssl.SSLError as exc:
            # Retry once without cert verification so we can still report
            # headers even for self-signed/misconfigured certs, but flag it.
            tls_error = str(exc)
            context_insecure = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context_insecure)
            conn.request("GET", path, headers={
                "Host": host, "User-Agent": "Kitsune-Scanner/1.0",
                "Accept": "*/*", "Connection": "close",
            })
            response = conn.getresponse()
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers={
            "Host": host, "User-Agent": "Kitsune-Scanner/1.0",
            "Accept": "*/*", "Connection": "close",
        })
        response = conn.getresponse()

    headers = {k: v for k, v in response.getheaders()}
    # response.msg.get_all() preserves *all* occurrences of repeated
    # headers (notably Set-Cookie), which the plain dict above collapses.
    set_cookie_values = response.msg.get_all("Set-Cookie") or []
    status = response.status
    location = headers.get("Location")
    try:
        conn.close()
    except Exception:  # noqa: BLE001
        pass

    return status, headers, location, tls_error, set_cookie_values


def _analyze_cookies(set_cookie_values: List[str]) -> List[str]:
    findings = []
    for cookie in set_cookie_values:
        name = cookie.split("=", 1)[0].strip()
        lower = cookie.lower()
        missing = []
        if "secure" not in lower:
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite" not in lower:
            missing.append("SameSite")
        if missing:
            findings.append(f"Cookie '{name}' missing: {', '.join(missing)}")
    return findings


def analyze_headers(target: str, timeout: float = 5.0,
                     follow_redirects: bool = True) -> HTTPResult:
    """
    Fetch `target` (URL or bare host) and analyze its HTTP security posture.

    Follows redirects up to MAX_REDIRECTS, recording the chain, and
    reports the final response's headers. Never raises -- connection,
    DNS, and TLS failures are captured in the result instead.
    """
    url = _normalize_url(target)
    original_url = url
    chain: List[str] = []
    tls_error_final = None

    set_cookie_values: List[str] = []
    for _ in range(MAX_REDIRECTS + 1):
        chain.append(url)
        try:
            status, headers, location, tls_error, set_cookie_values = _single_request(url, timeout)
        except (socket.timeout, ConnectionError) as exc:
            return HTTPResult(url=original_url, reachable=False,
                               redirect_chain=chain, error=f"Connection failed: {exc}")
        except socket.gaierror as exc:
            return HTTPResult(url=original_url, reachable=False,
                               redirect_chain=chain, error=f"DNS resolution failed: {exc}")
        except OSError as exc:
            return HTTPResult(url=original_url, reachable=False,
                               redirect_chain=chain, error=f"Network error: {exc}")
        except Exception as exc:  # noqa: BLE001
            return HTTPResult(url=original_url, reachable=False,
                               redirect_chain=chain, error=f"Unexpected error: {exc}")

        if tls_error:
            tls_error_final = tls_error

        if follow_redirects and status in (301, 302, 303, 307, 308) and location:
            next_url = location if location.startswith("http") else _join_relative(url, location)
            if next_url in chain:
                break  # redirect loop guard
            url = next_url
            continue
        break

    # Normalize header keys for case-insensitive comparisons but keep
    # original casing in the reported dict.
    lower_keys = {k.lower(): k for k in headers}

    present = [h for h in SECURITY_HEADERS if h.lower() in lower_keys]
    missing = [h for h in SECURITY_HEADERS if h.lower() not in lower_keys]

    server = headers.get(lower_keys.get("server", ""), None)
    cookie_findings = _analyze_cookies(set_cookie_values)

    notes: List[str] = []
    if tls_error_final:
        notes.append(f"TLS certificate issue encountered: {tls_error_final}")
    if status >= 500:
        notes.append("Server returned an error status; results may be incomplete")
    if len(chain) > 1:
        notes.append(f"Followed {len(chain) - 1} redirect(s)")

    result = HTTPResult(
        url=original_url,
        reachable=True,
        status_code=status,
        headers=dict(headers),
        present_security_headers=present,
        missing_security_headers=missing,
        server=server,
        cookie_findings=cookie_findings,
        redirect_chain=chain,
        uses_https=url.startswith("https://"),
        tls_error=tls_error_final,
        notes=notes,
    )
    return result


def _join_relative(base_url: str, location: str) -> str:
    from urllib.parse import urljoin
    return urljoin(base_url, location)
