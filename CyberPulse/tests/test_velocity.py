"""
Unit Tests for 14-Day Attack Activity & Velocity Engine and REST Endpoints.
Verifies temporal timeline generation, exponential time-decay half-life mechanics,
trend classifications (surge, decay, steady, clean), and REST API endpoints.
"""
import unittest
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from modules.scorer import generate_attack_velocity, calculate_risk_score
from server import app
from modules.history import init_db


class TestAttackVelocity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_01_high_abuse_ip_surge(self):
        """Tests timeline generation for high abuse IP (surge / acute burst)."""
        vt_data = {"malicious": 16, "suspicious": 3, "harmless": 68, "undetected": 7}
        abuse_data = {
            "abuse_confidence_score": 100,
            "total_reports": 2841,
            "distinct_users": 394,
            "is_whitelisted": False,
            "last_reported_at": "2026-10-21T14:32:00+00:00"
        }
        otx_data = {"pulse_count": 42, "tags": ["tor", "c2", "bruteforce"]}

        res = generate_attack_velocity("185.220.101.5", "IPV4", vt_data, abuse_data, otx_data)

        self.assertEqual(res["ioc"], "185.220.101.5")
        self.assertEqual(res["ioc_type"], "IPV4")
        self.assertEqual(res["timeframe_days"], 14)
        self.assertEqual(len(res["daily_timeline"]), 14)
        self.assertEqual(res["trend_direction"], "surge")
        self.assertGreater(res["trend_percentage"], 0.0)
        self.assertIn("Active Surge", res["status_badge"])
        self.assertEqual(res["status_color"], "#ef4444")
        self.assertGreater(res["total_14d_events"], 0)
        self.assertGreater(res["peak_daily_events"], 0)
        self.assertTrue(bool(res["peak_date"]))
        self.assertAlmostEqual(res["decay_lambda"], 0.0495, places=3)
        self.assertEqual(res["half_life_days"], 14.0)
        self.assertIn("t_1/2 = 14.0d", res["half_life_text"])
        self.assertIn("surge", res["verdict"].lower())

    def test_02_decayed_ip_activity(self):
        """Tests timeline generation for decayed IP with large elapsed days."""
        vt_data = {"malicious": 12, "suspicious": 2}
        abuse_data = {"abuse_confidence_score": 85, "total_reports": 1200, "is_whitelisted": False}
        otx_data = {"pulse_count": 10}

        res = generate_attack_velocity(
            "185.220.101.5", "IPV4", vt_data, abuse_data, otx_data, days_elapsed=15.0
        )

        self.assertEqual(res["trend_direction"], "decay")
        self.assertLess(res["trend_percentage"], 0.0)
        self.assertIn("Decaying Activity", res["status_badge"])
        self.assertEqual(res["status_color"], "#f59e0b")
        self.assertGreater(res["total_14d_events"], 0)
        # Peak date should be earlier in the 14-day window
        self.assertIn("decaying", res["verdict"].lower())

    def test_03_clean_domain_zero_baseline(self):
        """Tests clean/benign asset returns zero hits across all 14 days."""
        vt_data = {"malicious": 0, "suspicious": 0, "harmless": 92}
        abuse_data = {"abuse_confidence_score": 0, "is_whitelisted": True, "total_reports": 0}
        otx_data = {"pulse_count": 0}

        res = generate_attack_velocity("google.com", "DOMAIN", vt_data, abuse_data, otx_data)

        self.assertEqual(res["trend_direction"], "clean")
        self.assertEqual(res["trend_percentage"], 0.0)
        self.assertEqual(res["status_badge"], "Clean Baseline")
        self.assertEqual(res["status_color"], "#10b981")
        self.assertEqual(res["total_14d_events"], 0)
        self.assertEqual(res["peak_daily_events"], 0)
        for entry in res["daily_timeline"]:
            self.assertEqual(entry["count"], 0)
        self.assertIn("clean", res["verdict"].lower())

    def test_04_file_hash_permanent_baseline(self):
        """Tests file hash maintains permanent baseline with lambda = 0.0."""
        hash_val = "44d88612fea8a8f36de82e1278abb02f"
        vt_data = {"malicious": 58, "suspicious": 0}
        otx_data = {"pulse_count": 18}

        res = generate_attack_velocity(hash_val, "MD5", vt_data, {}, otx_data)

        self.assertEqual(res["decay_lambda"], 0.0)
        self.assertIsNone(res["half_life_days"])
        self.assertIn("Permanent", res["half_life_text"])
        self.assertEqual(res["trend_direction"], "steady")
        self.assertEqual(res["status_badge"], "Stale / Permanent")
        self.assertEqual(res["status_color"], "#3b82f6")
        self.assertGreater(res["total_14d_events"], 0)
        for entry in res["daily_timeline"]:
            self.assertEqual(entry["decay_factor"], 1.0)
            self.assertGreater(entry["count"], 0)

    def test_05_unknown_or_empty_ioc(self):
        """Tests resilient handling of unknown IOC format."""
        res = generate_attack_velocity("invalid_ioc_format", "UNKNOWN")
        self.assertEqual(res["trend_direction"], "clean")
        self.assertEqual(res["total_14d_events"], 0)
        self.assertEqual(len(res["daily_timeline"]), 14)

    def test_06_api_scan_includes_velocity(self):
        """Verifies /api/scan response contains velocity payload."""
        response = self.client.post("/api/scan", json={"ioc": "185.220.101.5", "demo_mode": True})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("velocity", data)
        vel = data["velocity"]
        self.assertIn("daily_timeline", vel)
        self.assertEqual(len(vel["daily_timeline"]), 14)
        self.assertIn("status_badge", vel)
        self.assertIn("trend_direction", vel)

    def test_07_api_velocity_endpoint_get_and_post(self):
        """Tests standalone /api/velocity endpoint via GET and POST."""
        # GET request
        res_get = self.client.get("/api/velocity?ioc=185.220.101.5&demo_mode=true")
        self.assertEqual(res_get.status_code, 200)
        data_get = res_get.get_json()
        self.assertTrue(data_get.get("success"))
        self.assertIn("velocity", data_get)
        self.assertEqual(len(data_get["velocity"]["daily_timeline"]), 14)

        # POST request
        res_post = self.client.post("/api/velocity", json={"ioc": "google.com", "demo_mode": True})
        self.assertEqual(res_post.status_code, 200)
        data_post = res_post.get_json()
        self.assertTrue(data_post.get("success"))
        self.assertEqual(data_post["velocity"]["trend_direction"], "clean")

    def test_08_api_velocity_preresolved_telemetry(self):
        """Tests /api/velocity when telemetry payload is supplied directly."""
        payload = {
            "ioc": "185.220.101.5",
            "ioc_type": "IPV4",
            "vt": {"malicious": 20},
            "abuse": {"total_reports": 500, "abuse_confidence_score": 90},
            "otx": {"pulse_count": 5},
            "days_elapsed": 20.0
        }
        res = self.client.post("/api/velocity", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data["velocity"]["trend_direction"], "decay")

    def test_09_api_velocity_missing_ioc(self):
        """Tests /api/velocity validation with missing indicator."""
        res = self.client.post("/api/velocity", json={})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("success"))

    def test_10_lowercase_and_whitespace_ioc_type(self):
        """Tests that lowercase and whitespace-padded ioc_types are properly normalized."""
        vt_data = {"malicious": 14, "suspicious": 2}
        abuse_data = {"abuse_confidence_score": 88, "total_reports": 1400}
        
        # Lowercase "ipv4" must NOT be treated as a permanent file hash (decay_lambda must be > 0)
        res_ip = generate_attack_velocity("185.220.101.5", "  ipv4  ", vt_data, abuse_data)
        self.assertEqual(res_ip["ioc_type"], "IPV4")
        self.assertAlmostEqual(res_ip["decay_lambda"], 0.0495, places=3)
        self.assertEqual(res_ip["half_life_days"], 14.0)

        # Lowercase "domain"
        res_dom = generate_attack_velocity("evil-malware.com", "domain", vt_data)
        self.assertEqual(res_dom["ioc_type"], "DOMAIN")
        self.assertAlmostEqual(res_dom["decay_lambda"], 0.0116, places=3)
        self.assertEqual(res_dom["half_life_days"], 60.0)

    def test_11_string_and_invalid_days_elapsed(self):
        """Tests that string and malformed days_elapsed are parsed safely without exceptions."""
        vt_data = {"malicious": 10}
        # String float
        res1 = generate_attack_velocity("185.220.101.5", "IPV4", vt_data, days_elapsed="15.5")
        self.assertEqual(res1["trend_direction"], "decay")
        
        # Invalid string
        res2 = generate_attack_velocity("185.220.101.5", "IPV4", vt_data, days_elapsed="invalid_number")
        self.assertEqual(res2["trend_direction"], "surge")

    def test_12_api_velocity_preresolved_auto_detection(self):
        """Tests that /api/velocity auto-detects IOC type when omitted in pre-resolved telemetry."""
        payload = {
            "ioc": "185.220.101.5",
            "vt": {"malicious": 25}
        }
        res = self.client.post("/api/velocity", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data["ioc_type"], "IPV4")
        self.assertNotEqual(data["velocity"]["trend_direction"], "clean")
        self.assertGreater(data["velocity"]["total_14d_events"], 0)

    def test_13_api_velocity_defanged_ioc(self):
        """Tests /api/velocity properly refangs and resolves defanged indicators."""
        payload = {
            "ioc": "185[.]220[.]101[.]5",
            "vt": {"malicious": 15}
        }
        res = self.client.post("/api/velocity", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data["ioc"], "185.220.101.5")
        self.assertEqual(data["ioc_type"], "IPV4")

    def test_14_daily_timeline_surge_level_field(self):
        """Verifies that every timeline entry provides a valid surge_level."""
        vt_data = {"malicious": 20}
        res = generate_attack_velocity("185.220.101.5", "IPV4", vt_data)
        for entry in res["daily_timeline"]:
            self.assertIn("surge_level", entry)
            self.assertIn(entry["surge_level"], ["Critical Surge", "Elevated Surge", "Moderate", "Baseline", "Clean", "Steady", "No Activity"])

    def test_15_null_telemetry_resilience(self):
        """Verifies generate_attack_velocity handles None values in tags and malware without crashing."""
        otx_nulls = {"tags": None, "malware_families": None, "pulse_count": None}
        vt_nulls = {"malicious": None, "suspicious": None}
        abuse_nulls = {"abuse_confidence_score": None, "total_reports": None}
        res = generate_attack_velocity("185.220.101.5", "IPV4", vt_nulls, abuse_nulls, otx_nulls)
        self.assertIsInstance(res, dict)
        self.assertEqual(len(res["daily_timeline"]), 14)


if __name__ == "__main__":
    unittest.main()

