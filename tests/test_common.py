"""Tests for utils/common.py: target parsing, CIDR handling, port parsing."""

import unittest

from utils.common import (
    KitsuneInputError,
    parse_port_range,
    parse_target,
)


class TestParseTarget(unittest.TestCase):
    def test_single_ip(self):
        result = parse_target("192.168.1.10")
        self.assertFalse(result.is_network)
        self.assertEqual(result.hosts, ["192.168.1.10"])

    def test_cidr_expands_to_hosts(self):
        result = parse_target("192.168.1.0/30")
        self.assertTrue(result.is_network)
        # A /30 has 2 usable host addresses
        self.assertEqual(len(result.hosts), 2)
        self.assertIn("192.168.1.1", result.hosts)
        self.assertIn("192.168.1.2", result.hosts)

    def test_cidr_slash_32_falls_back_to_network_address(self):
        result = parse_target("10.0.0.5/32")
        self.assertEqual(result.hosts, ["10.0.0.5"])

    def test_cidr_over_max_hosts_raises(self):
        with self.assertRaises(KitsuneInputError):
            parse_target("10.0.0.0/16", max_hosts=100)

    def test_empty_target_raises(self):
        with self.assertRaises(KitsuneInputError):
            parse_target("")

    def test_invalid_cidr_raises(self):
        with self.assertRaises(KitsuneInputError):
            parse_target("999.999.999.0/24")

    def test_url_like_hostname_is_stripped(self):
        # localhost always resolves, so this exercises the hostname path
        # without requiring external network access.
        result = parse_target("http://localhost/some/path")
        self.assertEqual(result.hostname, "localhost")
        self.assertEqual(len(result.hosts), 1)


class TestParsePortRange(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(parse_port_range("80"), [80])

    def test_comma_separated(self):
        self.assertEqual(parse_port_range("22,80,443"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(parse_port_range("1-5"), [1, 2, 3, 4, 5])

    def test_mixed_range_and_list(self):
        result = parse_port_range("22,80,1000-1002")
        self.assertEqual(result, [22, 80, 1000, 1001, 1002])

    def test_reversed_range_is_normalized(self):
        self.assertEqual(parse_port_range("5-1"), [1, 2, 3, 4, 5])

    def test_duplicate_ports_deduplicated(self):
        self.assertEqual(parse_port_range("80,80,80"), [80])

    def test_invalid_port_raises(self):
        with self.assertRaises(KitsuneInputError):
            parse_port_range("70000")

    def test_zero_port_raises(self):
        with self.assertRaises(KitsuneInputError):
            parse_port_range("0")

    def test_non_numeric_raises(self):
        with self.assertRaises(KitsuneInputError):
            parse_port_range("abc")

    def test_empty_spec_raises(self):
        with self.assertRaises(KitsuneInputError):
            parse_port_range("")


if __name__ == "__main__":
    unittest.main()
