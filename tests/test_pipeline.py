"""
Tests for pipeline/scan.py.

Uses unittest.mock to patch the underlying scanner functions so pipeline
*orchestration* (skip logic, result passing, error isolation) can be
verified without depending on real network conditions.
"""

import unittest
from unittest.mock import patch

from scanner.host import HostResult
from scanner.ports import PortResult
from pipeline import scan as pipeline_scan


def _host_up(ip="10.0.0.1", ttl=64):
    return [HostResult(ip=ip, up=True, method="icmp", rtt_ms=1.0, ttl=ttl)]


def _host_down(ip="10.0.0.1"):
    return [HostResult(ip=ip, up=False, method="none")]


class TestPipelineSkipLogic(unittest.TestCase):
    @patch("pipeline.scan.discover_hosts")
    def test_no_active_hosts_stops_pipeline(self, mock_discover):
        mock_discover.return_value = _host_down()
        result = pipeline_scan.run_full_scan("10.0.0.1")
        self.assertTrue(len(result.global_errors) > 0)
        self.assertEqual(len(result.hosts), 1)
        self.assertFalse(result.hosts[0].host_result.up)
        self.assertIn("vuln-scan", result.hosts[0].skipped_stages)

    @patch("pipeline.scan.assess")
    @patch("pipeline.scan.fingerprint_os")
    @patch("pipeline.scan.analyze_headers")
    @patch("pipeline.scan.grab_banners")
    @patch("pipeline.scan.scan_ports")
    @patch("pipeline.scan.discover_hosts")
    def test_no_open_ports_skips_banner_http_vuln(
        self, mock_discover, mock_ports, mock_banners, mock_headers, mock_os, mock_vuln
    ):
        mock_discover.return_value = _host_up()
        mock_ports.return_value = [
            PortResult(port=80, protocol="tcp", state="closed", service_guess=None)
        ]
        mock_os.return_value = None

        result = pipeline_scan.run_full_scan("10.0.0.1")

        host_scan = result.hosts[0]
        self.assertIn("banner", host_scan.skipped_stages)
        self.assertIn("http-headers", host_scan.skipped_stages)
        self.assertIn("vuln-scan", host_scan.skipped_stages)
        mock_banners.assert_not_called()
        mock_headers.assert_not_called()
        mock_vuln.assert_not_called()
        # OS detection should still be attempted using TTL alone
        mock_os.assert_called_once()

    @patch("pipeline.scan.assess")
    @patch("pipeline.scan.fingerprint_os")
    @patch("pipeline.scan.analyze_headers")
    @patch("pipeline.scan.grab_banners")
    @patch("pipeline.scan.scan_ports")
    @patch("pipeline.scan.discover_hosts")
    def test_non_web_open_port_skips_http_only(
        self, mock_discover, mock_ports, mock_banners, mock_headers, mock_os, mock_vuln
    ):
        mock_discover.return_value = _host_up()
        mock_ports.return_value = [
            PortResult(port=22, protocol="tcp", state="open", service_guess="ssh")
        ]
        mock_banners.return_value = []
        mock_os.return_value = None
        mock_vuln.return_value = []

        result = pipeline_scan.run_full_scan("10.0.0.1")

        host_scan = result.hosts[0]
        self.assertIn("http-headers", host_scan.skipped_stages)
        mock_headers.assert_not_called()
        mock_banners.assert_called_once()
        mock_vuln.assert_called_once()

    @patch("pipeline.scan.assess")
    @patch("pipeline.scan.fingerprint_os")
    @patch("pipeline.scan.analyze_headers")
    @patch("pipeline.scan.grab_banners")
    @patch("pipeline.scan.scan_ports")
    @patch("pipeline.scan.discover_hosts")
    def test_web_port_triggers_http_analysis(
        self, mock_discover, mock_ports, mock_banners, mock_headers, mock_os, mock_vuln
    ):
        mock_discover.return_value = _host_up()
        mock_ports.return_value = [
            PortResult(port=80, protocol="tcp", state="open", service_guess="http")
        ]
        mock_banners.return_value = []
        mock_os.return_value = None
        mock_vuln.return_value = []

        result = pipeline_scan.run_full_scan("10.0.0.1")

        host_scan = result.hosts[0]
        self.assertNotIn("http-headers", host_scan.skipped_stages)
        mock_headers.assert_called_once()


class TestPipelineErrorIsolation(unittest.TestCase):
    @patch("pipeline.scan.assess")
    @patch("pipeline.scan.fingerprint_os")
    @patch("pipeline.scan.grab_banners")
    @patch("pipeline.scan.scan_ports")
    @patch("pipeline.scan.discover_hosts")
    def test_banner_failure_does_not_stop_pipeline(
        self, mock_discover, mock_ports, mock_banners, mock_os, mock_vuln
    ):
        mock_discover.return_value = _host_up()
        mock_ports.return_value = [
            PortResult(port=22, protocol="tcp", state="open", service_guess="ssh")
        ]
        mock_banners.side_effect = RuntimeError("simulated banner failure")
        mock_os.return_value = None
        mock_vuln.return_value = []

        result = pipeline_scan.run_full_scan("10.0.0.1")

        host_scan = result.hosts[0]
        self.assertIn("banner", host_scan.stage_errors)
        self.assertIn("simulated banner failure", host_scan.stage_errors["banner"])
        # Pipeline should still have attempted later stages
        mock_os.assert_called_once()
        mock_vuln.assert_called_once()

    @patch("pipeline.scan.discover_hosts")
    def test_host_discovery_failure_produces_global_error(self, mock_discover):
        mock_discover.side_effect = RuntimeError("simulated discovery failure")
        result = pipeline_scan.run_full_scan("10.0.0.1")
        self.assertTrue(any("simulated discovery failure" in e for e in result.global_errors))
        self.assertEqual(result.hosts, [])


if __name__ == "__main__":
    unittest.main()
