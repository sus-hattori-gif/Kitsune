"""
Tests for scanner/host.py.

Mocks the ICMP ping probe (which needs the system 'ping' binary and
may behave differently across sandboxes) while exercising the real
TCP fallback path against a local listening socket.
"""

import socket
import threading
import unittest
from unittest.mock import patch

from scanner.host import discover_hosts, _tcp_fallback_check
from utils.network import ConnectResult


def _start_local_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    port = server.getsockname()[1]

    def accept_loop():
        while True:
            try:
                conn, _ = server.accept()
                conn.close()
            except OSError:
                break

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    return server, port


class TestTCPFallback(unittest.TestCase):
    def test_responsive_host_marked_up(self):
        with patch("scanner.host.FALLBACK_PROBE_PORTS", [_start_local_server()[1]]):
            result = _tcp_fallback_check("127.0.0.1", timeout=1.0)
            self.assertTrue(result.up)
            self.assertEqual(result.method, "tcp-fallback")

    def test_unresponsive_host_marked_down(self):
        # An unbound local port replies with an immediate refusal
        # ("closed"), which itself proves the host is up -- so to
        # simulate a genuinely unresponsive/filtered host we mock the
        # connect probe itself to always time out.
        with patch("scanner.host.tcp_connect") as mock_connect:
            mock_connect.return_value = ConnectResult(state="filtered", rtt_ms=None, error="timeout")
            result = _tcp_fallback_check("127.0.0.1", timeout=0.5)
            self.assertFalse(result.up)
            self.assertEqual(result.method, "none")


class TestDiscoverHosts(unittest.TestCase):
    @patch("scanner.host.ping_probe")
    def test_icmp_alive_reported(self, mock_ping):
        mock_ping.return_value = {"alive": True, "ttl": 64, "rtt_ms": 1.2}
        results = discover_hosts("127.0.0.1", timeout=1.0)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].up)
        self.assertEqual(results[0].method, "icmp")
        self.assertEqual(results[0].ttl, 64)

    @patch("scanner.host._tcp_fallback_check")
    @patch("scanner.host.ping_probe")
    def test_icmp_blocked_falls_back_to_tcp(self, mock_ping, mock_fallback):
        from scanner.host import HostResult
        mock_ping.return_value = {"alive": False, "ttl": None, "rtt_ms": None}
        mock_fallback.return_value = HostResult(ip="127.0.0.1", up=True, method="tcp-fallback")

        results = discover_hosts("127.0.0.1", timeout=1.0)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].up)
        self.assertEqual(results[0].method, "tcp-fallback")
        mock_fallback.assert_called()

    @patch("scanner.host.ping_probe")
    def test_results_include_every_requested_host(self, mock_ping):
        mock_ping.return_value = {"alive": False, "ttl": None, "rtt_ms": None}
        results = discover_hosts("192.168.50.0/30", timeout=0.3)
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
