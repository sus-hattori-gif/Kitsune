"""Tests for scanner/os_detect.py — pure logic, no network needed."""

import unittest

from scanner.banner import ServiceResult
from scanner.os_detect import fingerprint_os
from scanner.ports import PortResult


class TestFingerprintOS(unittest.TestCase):
    def test_no_signals_returns_insufficient_data(self):
        result = fingerprint_os(None, [], [])
        self.assertEqual(result.status, "insufficient-data")
        self.assertEqual(result.confidence, 0)

    def test_linux_ttl_biases_toward_linux(self):
        result = fingerprint_os(64, [], [])
        self.assertIn("Linux", result.os_guess)
        self.assertGreater(result.confidence, 0)

    def test_windows_ttl_biases_toward_windows(self):
        result = fingerprint_os(128, [], [])
        self.assertEqual(result.os_guess, "Windows")

    def test_windows_ports_increase_windows_confidence(self):
        ports = [
            PortResult(port=3389, protocol="tcp", state="open", service_guess="rdp"),
            PortResult(port=445, protocol="tcp", state="open", service_guess="microsoft-ds"),
        ]
        result = fingerprint_os(128, ports, [])
        self.assertEqual(result.os_guess, "Windows")
        self.assertGreater(result.confidence, 35)

    def test_confidence_never_exceeds_95(self):
        ports = [PortResult(port=3389, protocol="tcp", state="open", service_guess="rdp")] * 1
        services = [ServiceResult(port=22, protocol="tcp", service_guess="ssh",
                                   banner="Microsoft Windows SSH", version_hint="windows")]
        result = fingerprint_os(128, ports, services)
        self.assertLessEqual(result.confidence, 95)

    def test_banner_mentioning_ubuntu_influences_guess(self):
        services = [ServiceResult(port=22, protocol="tcp", service_guess="ssh",
                                   banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4",
                                   version_hint="OpenSSH_8.2p1 Ubuntu-4")]
        result = fingerprint_os(None, [], services)
        self.assertIn("Linux", result.os_guess)

    def test_closed_and_filtered_ports_are_ignored(self):
        ports = [
            PortResult(port=3389, protocol="tcp", state="closed", service_guess=None),
            PortResult(port=3389, protocol="tcp", state="filtered", service_guess=None),
        ]
        result = fingerprint_os(None, ports, [])
        self.assertEqual(result.status, "insufficient-data")


if __name__ == "__main__":
    unittest.main()
