"""
Tests for scanner/headers.py.

Spins up a local http.server instance with controlled response headers
so the security-header analysis logic can be verified deterministically.
"""

import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from scanner.headers import analyze_headers


class _SecureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Strict-Transport-Security", "max-age=63072000")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Server", "TestServer/1.0")
        self.send_header("Set-Cookie", "session=abc123; Secure; HttpOnly; SameSite=Strict")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):  # noqa: A002 - silence test server logging
        pass


class _InsecureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "OldServer/0.1")
        self.send_header("Set-Cookie", "session=abc123")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):  # noqa: A002
        pass


def _start_server(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


class TestAnalyzeHeadersSecure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.port = _start_server(_SecureHandler)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_all_security_headers_present(self):
        result = analyze_headers(f"http://127.0.0.1:{self.port}/", timeout=3.0)
        self.assertTrue(result.reachable)
        self.assertEqual(result.status_code, 200)
        self.assertIn("Content-Security-Policy", result.present_security_headers)
        self.assertIn("Strict-Transport-Security", result.present_security_headers)
        self.assertIn("X-Frame-Options", result.present_security_headers)

    def test_server_header_captured(self):
        result = analyze_headers(f"http://127.0.0.1:{self.port}/", timeout=3.0)
        self.assertEqual(result.server, "TestServer/1.0")

    def test_secure_cookie_has_no_findings(self):
        result = analyze_headers(f"http://127.0.0.1:{self.port}/", timeout=3.0)
        self.assertEqual(result.cookie_findings, [])


class TestAnalyzeHeadersInsecure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.port = _start_server(_InsecureHandler)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_missing_security_headers_detected(self):
        result = analyze_headers(f"http://127.0.0.1:{self.port}/", timeout=3.0)
        self.assertIn("Content-Security-Policy", result.missing_security_headers)
        self.assertIn("Strict-Transport-Security", result.missing_security_headers)

    def test_insecure_cookie_flagged(self):
        result = analyze_headers(f"http://127.0.0.1:{self.port}/", timeout=3.0)
        self.assertTrue(len(result.cookie_findings) >= 1)
        self.assertIn("Secure", result.cookie_findings[0])


class TestAnalyzeHeadersUnreachable(unittest.TestCase):
    def test_connection_refused_reported_gracefully(self):
        # Find a closed local port to connect to.
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        result = analyze_headers(f"http://127.0.0.1:{port}/", timeout=1.5)
        self.assertFalse(result.reachable)
        self.assertIsNotNone(result.error)


if __name__ == "__main__":
    unittest.main()
