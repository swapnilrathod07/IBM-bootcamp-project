"""
Unit Tests for Telemetry API Modules and Fallback Handlers.
"""
import unittest
from modules.virustotal import query_virustotal
from modules.abuseipdb import query_abuseipdb
from modules.alienvault import query_alienvault
from modules.geolocation import query_geolocation


class TestTelemetryModules(unittest.TestCase):

    def test_virustotal_simulation_ip(self):
        res = query_virustotal("185.220.101.5", "IPV4", demo_mode=True)
        self.assertEqual(res["status"], "success")
        self.assertGreater(res["malicious"], 0)
        self.assertIn("CrowdStrike Falcon", res["vendors"])

    def test_virustotal_simulation_domain(self):
        res = query_virustotal("google.com", "DOMAIN", demo_mode=True)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["malicious"], 0)

    def test_abuseipdb_simulation_ip(self):
        res = query_abuseipdb("185.220.101.5", "IPV4", demo_mode=True)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["abuse_confidence_score"], 100)
        self.assertEqual(res["country_code"], "DE")

    def test_abuseipdb_non_ip(self):
        res = query_abuseipdb("google.com", "DOMAIN", demo_mode=True)
        self.assertEqual(res["status"], "not_applicable")

    def test_alienvault_simulation(self):
        res = query_alienvault("185.220.101.5", "IPV4", demo_mode=True)
        self.assertEqual(res["status"], "success")
        self.assertGreater(res["pulse_count"], 0)
        self.assertIn("tor", res["tags"])

    def test_geolocation_simulation(self):
        res = query_geolocation("185.220.101.5", "IPV4", demo_mode=True)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["country"], "Germany")
        self.assertAlmostEqual(res["lat"], 51.0504, places=2)

    def test_geolocation_non_ip(self):
        res = query_geolocation("google.com", "DOMAIN", demo_mode=True)
        self.assertEqual(res["status"], "not_applicable")


if __name__ == "__main__":
    unittest.main()
