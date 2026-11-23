"""PC scan rules: Defender, firewall, listening ports, release-line matching (no network or database needed)."""
import unittest

from app import pcscan


class PcScanRules(unittest.TestCase):
    def test_defender_off_and_active_threat_are_flagged(self):
        found = pcscan.check_defender({"available": True, "antivirus_enabled": False, "real_time_protection": False,
                                       "signatures_updated": "2020-01-01T00:00:00Z", "quick_scan_end": None,
                                       "detections": [{"name": "Trojan:Win32/Test", "severity_id": 5, "active": True, "action_success": False}]})
        ids = {f["_id"]: f["severity"] for f in found}
        self.assertEqual(ids["PC-DEF-AV"], "critical")
        self.assertEqual(ids["PC-DEF-RTP"], "high")
        self.assertEqual(ids["PC-DEF-SIG"], "medium")
        self.assertEqual(ids["PC-DEF-THREAT-1"], "critical")

    def test_handled_detection_is_low(self):
        found = pcscan.check_defender({"available": True, "antivirus_enabled": True, "real_time_protection": True,
                                       "quick_scan_end": pcscan.utcnow().isoformat(), "tamper_protection": True,
                                       "detections": [{"name": "PUA:Win32/Presenoker", "severity_id": 1, "active": False, "action_success": True}]})
        self.assertEqual([(f["_id"], f["severity"]) for f in found], [("PC-DEF-THREAT-1", "low")])

    def test_firewall_public_off_is_high(self):
        self.assertEqual(pcscan.check_firewall([{"profile": "Public", "enabled": False}])[0]["severity"], "high")
        self.assertEqual(pcscan.check_firewall([{"profile": "Public", "enabled": True}]), [])

    def test_database_on_all_interfaces_grouped_per_process(self):
        found = pcscan.check_network([{"address": "::", "port": 3306, "process": "mysqld"},
                                      {"address": "::", "port": 33060, "process": "mysqld"},
                                      {"address": "127.0.0.1", "port": 27017, "process": "mongod"}], [], firewall_off=False)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["_id"], "PC-NET-MYSQLD")
        self.assertEqual(found[0]["evidence"]["ports"], [3306, 33060])
        self.assertEqual(found[0]["severity"], "low")

    def test_release_line_matching(self):
        cycles = [{"cycle": "3.1"}, {"cycle": "3.12"}, {"cycle": "157"}]
        self.assertEqual(pcscan.match_cycle("3.12.10", cycles)["cycle"], "3.12")
        self.assertEqual(pcscan.match_cycle("157.0.8103.79", cycles)["cycle"], "157")
        self.assertIsNone(pcscan.match_cycle("4.0", cycles))
        self.assertTrue(pcscan.vtuple("16.14") < pcscan.vtuple("16.16"))
        self.assertTrue(pcscan.is_past("2000-01-01"))
        self.assertFalse(pcscan.is_past(False))


if __name__ == "__main__":
    unittest.main()
