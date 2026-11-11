# tests/test_investigator.py
# quick checks that the parsers reject bad lines and the detections fire
# run from the project folder with:  python -m unittest discover tests

import os
import sys
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parsers import parse_firewall_line, parse_auth_line
from analysis import SETTINGS, find_brute_force, find_success_after_failures


class TestParsers(unittest.TestCase):

    def test_good_firewall_line(self):
        e = parse_firewall_line("2026-10-12 08:00:00 BLOCKED src=203.0.113.55 dst=10.0.0.12 proto=TCP port=22 bytes=0")
        self.assertEqual(e["action"], "BLOCKED")
        self.assertEqual(e["port"], 22)

    def test_bad_firewall_lines(self):
        # these are the same kind of broken lines that are in the real dataset
        bad = [
            "2026-10-13 09:44:11 BLOCKED src= dst=10.0.0.8 proto=TCP port=22",
            "2026-10-15 12:00:00 UNKNOWN src=192.168.1.14 dst=10.0.0.9 proto=TCP port=9999 bytes=123",
            "2026-10-16 08:00:00 ALLOWED src=192.168.1.12 dst=10.0.0.8 proto=TCP port=notaport bytes=250",
            "2026-10-16 08:00:00 ALLOWED src=192.168.1.12 dst=10.0.0.8 proto=TCP port=70000 bytes=250",
            "MALFORMED LINE - missing timestamp and fields",
        ]
        for line in bad:
            with self.assertRaises(ValueError):
                parse_firewall_line(line)

    def test_bad_auth_lines(self):
        bad = [
            "2026-10-14 09:00:00 LOGIN_FAILED user= src=198.51.100.88 host=web01 method=password",
            "2026-10-16 11:30:00 UNKNOWN user=bob src=192.168.1.22 host=app01 method=password",
            "MALFORMED AUTH LINE",
        ]
        for line in bad:
            with self.assertRaises(ValueError):
                parse_auth_line(line)


def make_auth(minute, event, user="admin", ip="203.0.113.1"):
    # small helper to build fake auth events
    return {"time": datetime(2026, 10, 12, 9, 0) + timedelta(minutes=minute),
            "event": event, "user": user, "src": ip, "host": "vpn01", "method": "password"}


class TestDetections(unittest.TestCase):

    def test_brute_force_found(self):
        events = [make_auth(i, "LOGIN_FAILED") for i in range(12)]
        self.assertEqual(len(find_brute_force(events, SETTINGS)), 1)

    def test_slow_failures_not_brute_force(self):
        # 12 failures but spread over 12 hours, shouldn't count
        events = [make_auth(i * 60, "LOGIN_FAILED") for i in range(12)]
        self.assertEqual(find_brute_force(events, SETTINGS), [])

    def test_success_after_failures(self):
        events = [make_auth(i, "LOGIN_FAILED") for i in range(5)]
        events.append(make_auth(6, "LOGIN_SUCCESS"))
        result = find_success_after_failures(events, SETTINGS)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["fails_before"], 5)


if __name__ == "__main__":
    unittest.main()
