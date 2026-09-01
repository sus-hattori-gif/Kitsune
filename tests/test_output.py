"""Tests for utils/output.py — JSON serialization and text rendering."""

import json
import os
import tempfile
import unittest

from scanner.host import HostResult
from scanner.ports import PortResult
from utils.output import (
    render_host_discovery_text,
    render_port_scan_text,
    save_json,
    to_json,
)


class TestJSONOutput(unittest.TestCase):
    def test_to_json_uses_to_dict(self):
        result = HostResult(ip="10.0.0.1", up=True, method="icmp", rtt_ms=1.5, ttl=64)
        payload = json.loads(to_json(result))
        self.assertEqual(payload["ip"], "10.0.0.1")
        self.assertTrue(payload["up"])

    def test_to_json_handles_plain_list(self):
        data = [{"a": 1}, {"b": 2}]
        payload = json.loads(to_json(data))
        self.assertEqual(payload, data)

    def test_save_json_writes_valid_file(self):
        result = PortResult(port=80, protocol="tcp", state="open", service_guess="http")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.json")
            written_path = save_json(result, path=path)
            self.assertEqual(written_path, path)
            with open(path) as f:
                payload = json.load(f)
            self.assertEqual(payload["port"], 80)

    def test_save_json_creates_default_results_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            try:
                os.chdir(tmp)
                result = PortResult(port=443, protocol="tcp", state="open", service_guess="https")
                path = save_json(result)
                self.assertTrue(os.path.exists(path))
                self.assertTrue(path.startswith("results" + os.sep))
            finally:
                os.chdir(cwd)


class TestTextOutput(unittest.TestCase):
    def test_render_host_discovery_text_shows_status(self):
        results = [
            HostResult(ip="10.0.0.1", up=True, method="icmp"),
            HostResult(ip="10.0.0.2", up=False, method="none"),
        ]
        text = render_host_discovery_text(results)
        self.assertIn("10.0.0.1", text)
        self.assertIn("UP", text)
        self.assertIn("DOWN", text)

    def test_render_port_scan_text_excludes_filtered_by_default(self):
        results = [
            PortResult(port=22, protocol="tcp", state="open", service_guess="ssh"),
            PortResult(port=25, protocol="tcp", state="filtered", service_guess=None),
        ]
        text = render_port_scan_text("10.0.0.1", results)
        self.assertIn("22/tcp", text)
        self.assertNotIn("25/tcp", text)


if __name__ == "__main__":
    unittest.main()
