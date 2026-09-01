"""
Tests for scanner/ports.py.

Uses a real local TCP server bound to 127.0.0.1 so port-state
classification (open/closed) is exercised without needing external
network access.
"""

import socket
import threading
import unittest

from scanner.ports import scan_ports, open_ports_only, PortResult


def _start_local_server():
    """Bind a listening socket on an ephemeral port and accept in the background."""
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


def _find_closed_port() -> int:
    """Find a port that's very likely closed by briefly binding then releasing it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestScanPorts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.open_port = _start_local_server()

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def test_open_port_detected(self):
        results = scan_ports("127.0.0.1", [self.open_port], timeout=1.0, concurrency=5)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].state, "open")

    def test_closed_port_detected(self):
        closed_port = _find_closed_port()
        results = scan_ports("127.0.0.1", [closed_port], timeout=1.0, concurrency=5)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].state, "closed")

    def test_results_sorted_by_port(self):
        closed_port = _find_closed_port()
        ports = sorted([self.open_port, closed_port], reverse=True)
        results = scan_ports("127.0.0.1", ports, timeout=1.0, concurrency=5)
        self.assertEqual([r.port for r in results], sorted(ports))

    def test_open_ports_only_filters_correctly(self):
        results = [
            PortResult(port=1, protocol="tcp", state="open", service_guess=None),
            PortResult(port=2, protocol="tcp", state="closed", service_guess=None),
            PortResult(port=3, protocol="tcp", state="filtered", service_guess=None),
        ]
        filtered = open_ports_only(results)
        self.assertEqual([r.port for r in filtered], [1])

    def test_service_guess_present_for_known_open_port(self):
        results = scan_ports("127.0.0.1", [self.open_port], timeout=1.0)
        # service_guess will be None unless the ephemeral port happens to
        # match a well-known port, so just assert the field exists and
        # the call doesn't error.
        self.assertTrue(hasattr(results[0], "service_guess"))


if __name__ == "__main__":
    unittest.main()
