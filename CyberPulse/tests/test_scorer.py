"""
Unit Tests for Unified Threat Risk Scorer.
"""
import unittest
from modules.scorer import calculate_risk_score


class TestRiskScorer(unittest.TestCase):

    def test_high_risk_ip_calculation(self):
        vt_data = {"malicious": 16, "suspicious": 3, "harmless": 60, "undetected": 5}
        abuse_data = {"abuse_confidence_score": 100, "is_whitelisted": False}
        otx_data = {"pulse_count": 25, "tags": ["tor", "c2", "cobalt-strike"], "malware_families": ["Cobalt Strike"]}

        res = calculate_risk_score("185.220.101.5", "IPV4", vt_data, abuse_data, otx_data)
        self.assertGreaterEqual(res["score"], 80)
        self.assertLessEqual(res["score"], 100)
        self.assertEqual(res["level"], "Malicious / Critical")
        self.assertEqual(res["color"], "#ef4444")
        self.assertGreater(len(res["actions"]), 0)

    def test_benign_whitelisted_ip(self):
        vt_data = {"malicious": 0, "suspicious": 0, "harmless": 88, "undetected": 2}
        abuse_data = {"abuse_confidence_score": 0, "is_whitelisted": True}
        otx_data = {"pulse_count": 1, "tags": ["dns", "benign"], "malware_families": []}

        res = calculate_risk_score("8.8.8.8", "IPV4", vt_data, abuse_data, otx_data)
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["level"], "Benign / Low Risk")
        self.assertEqual(res["color"], "#10b981")

    def test_moderate_suspicious_ip(self):
        vt_data = {"malicious": 2, "suspicious": 3, "harmless": 70, "undetected": 10}
        abuse_data = {"abuse_confidence_score": 40, "is_whitelisted": False}
        otx_data = {"pulse_count": 3, "tags": ["scanner"], "malware_families": []}

        res = calculate_risk_score("45.33.32.156", "IPV4", vt_data, abuse_data, otx_data)
        self.assertGreaterEqual(res["score"], 21)
        self.assertLessEqual(res["score"], 60)
        self.assertEqual(res["level"], "Suspicious / Moderate")
        self.assertEqual(res["color"], "#f59e0b")

    def test_malware_hash_non_ip_scoring(self):
        vt_data = {"malicious": 68, "suspicious": 0, "harmless": 0, "undetected": 2}
        abuse_data = {}  # Non-IP
        otx_data = {"pulse_count": 50, "tags": ["ransomware", "wannacry"], "malware_families": ["WannaCry"]}

        res = calculate_risk_score(
            "ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc",
            "SHA256", vt_data, abuse_data, otx_data
        )
        self.assertGreaterEqual(res["score"], 90)
        self.assertEqual(res["level"], "Malicious / Critical")

    def test_score_boundary_limits(self):
        # Even with extreme inputs, score must never exceed 100 or drop below 0
        vt_data = {"malicious": 999, "suspicious": 999}
        abuse_data = {"abuse_confidence_score": 500, "is_whitelisted": False}
        otx_data = {"pulse_count": 1000, "tags": ["c2"], "malware_families": ["Trojan"]}

        res = calculate_risk_score("1.2.3.4", "IPV4", vt_data, abuse_data, otx_data)
        self.assertEqual(res["score"], 100)

    def test_null_and_malformed_telemetry_resilience(self):
        # Explicit None values in telemetry dictionaries must never crash
        vt_data_nulls = {"malicious": None, "suspicious": None}
        abuse_data_nulls = {"abuse_confidence_score": None, "is_whitelisted": None}
        otx_data_nulls = {"pulse_count": None, "tags": None, "malware_families": None}
        geo_data_nulls = {"isp": None, "as_info": None}

        res = calculate_risk_score("1.2.3.4", "IPV4", vt_data_nulls, abuse_data_nulls, otx_data_nulls, geo_data=geo_data_nulls)
        self.assertIsInstance(res["score"], int)
        self.assertGreaterEqual(res["score"], 0)
        self.assertLessEqual(res["score"], 100)

        # String numeric values in telemetry dictionaries
        vt_data_str = {"malicious": "10", "suspicious": "2"}
        abuse_data_str = {"abuse_confidence_score": "80"}
        otx_data_str = {"pulse_count": "5"}
        res_str = calculate_risk_score("1.2.3.4", "IPV4", vt_data_str, abuse_data_str, otx_data_str)
        self.assertGreater(res_str["score"], 50)


if __name__ == "__main__":
    unittest.main()

