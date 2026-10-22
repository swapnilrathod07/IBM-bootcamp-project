"""
Unit tests for Time-Decay Half-Life, NRD Risk Modifier, and Cloud/CDN Suppression Engine.
"""
import unittest
from modules.scorer import calculate_risk_score


class TestDecayAndAccuracyEngine(unittest.TestCase):

    def test_ip_time_decay_half_life(self):
        vt_data = {"malicious": 10, "suspicious": 2}
        abuse_data = {"abuse_confidence_score": 80, "is_whitelisted": False}
        otx_data = {"pulse_count": 5, "tags": []}

        # 0 days elapsed (fresh report)
        score_fresh = calculate_risk_score("198.51.100.1", "IPV4", vt_data, abuse_data, otx_data, days_elapsed=0)
        
        # 14 days elapsed (exactly 1 half-life, raw score should decay to ~50%)
        score_14d = calculate_risk_score("198.51.100.1", "IPV4", vt_data, abuse_data, otx_data, days_elapsed=14)
        
        # 180 days elapsed (stale report, score should decay near zero)
        score_180d = calculate_risk_score("198.51.100.1", "IPV4", vt_data, abuse_data, otx_data, days_elapsed=180)

        self.assertGreater(score_fresh["score"], score_14d["score"])
        self.assertGreater(score_14d["score"], score_180d["score"])
        # Decay factor check
        self.assertAlmostEqual(score_14d["breakdown"]["decay_factor"], 0.5, delta=0.02)
        self.assertLess(score_180d["score"], 15)

    def test_file_hash_does_not_decay(self):
        vt_data = {"malicious": 45, "suspicious": 0}
        otx_data = {"pulse_count": 20, "tags": ["ransomware"], "malware_families": ["WannaCry"]}

        # Test hash with 0 days vs 365 days
        score_fresh = calculate_risk_score("ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc", "SHA256", vt_data, {}, otx_data, days_elapsed=0)
        score_365d = calculate_risk_score("ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc", "SHA256", vt_data, {}, otx_data, days_elapsed=365)

        self.assertEqual(score_fresh["score"], score_365d["score"])
        self.assertEqual(score_365d["breakdown"]["decay_factor"], 1.0)

    def test_domain_time_decay_60_days(self):
        vt_data = {"malicious": 10, "suspicious": 0}
        otx_data = {"pulse_count": 5, "tags": []}

        # Fresh domain
        fresh = calculate_risk_score("stale-malicious.com", "DOMAIN", vt_data, {}, otx_data, days_elapsed=0)
        # 60 days (half-life of domain)
        decayed_60d = calculate_risk_score("stale-malicious.com", "DOMAIN", vt_data, {}, otx_data, days_elapsed=60)

        self.assertAlmostEqual(decayed_60d["breakdown"]["decay_factor"], 0.5, delta=0.02)
        self.assertGreater(fresh["score"], decayed_60d["score"])

    def test_nrd_risk_modifier(self):
        vt_data = {"malicious": 2, "suspicious": 1}
        otx_data = {"pulse_count": 1, "tags": []}

        # Established domain (> 30 days)
        established = calculate_risk_score("test-domain.com", "DOMAIN", vt_data, {}, otx_data, domain_age_days=120)
        
        # Newly Registered Domain (< 30 days)
        nrd = calculate_risk_score("brand-new-phish.com", "DOMAIN", vt_data, {}, otx_data, domain_age_days=5)

        self.assertTrue(nrd["breakdown"].get("is_nrd"))
        self.assertEqual(nrd["breakdown"].get("nrd_boost"), 25.0)
        self.assertEqual(nrd["score"], established["score"] + 25)

    def test_cloud_cdn_suppression_advice(self):
        vt_data = {"malicious": 8, "as_owner": "Cloudflare, Inc."}
        abuse_data = {"abuse_confidence_score": 60, "isp": "Cloudflare Inc."}
        otx_data = {"pulse_count": 4, "tags": []}
        geo_data = {"isp": "Cloudflare, Inc.", "as_info": "AS13335 CLOUDFLARENET"}

        res = calculate_risk_score("104.21.45.12", "IPV4", vt_data, abuse_data, otx_data, geo_data=geo_data)

        self.assertTrue(res["shared_infrastructure"])
        self.assertTrue(res["breakdown"].get("shared_infrastructure"))
        self.assertTrue(any("ADVISORY: Multi-tenant CDN/Cloud IP detected" in a for a in res["actions"]))

    def test_parse_timestamp_formats(self):
        from modules.scorer import _parse_timestamp_to_days_ago
        # Epoch int
        self.assertIsNotNone(_parse_timestamp_to_days_ago(1600000000))
        # Epoch numeric string
        self.assertIsNotNone(_parse_timestamp_to_days_ago("1600000000"))
        # Clean ISO
        self.assertIsNotNone(_parse_timestamp_to_days_ago("2020-01-01T00:00:00Z"))
        # Invalid string falls back gracefully to None
        self.assertIsNone(_parse_timestamp_to_days_ago("not_a_date"))

    def test_decay_edge_cases(self):
        vt_data = {"malicious": 10, "suspicious": 2}
        abuse_data = {"abuse_confidence_score": 80, "is_whitelisted": False}
        otx_data = {"pulse_count": 5, "tags": []}

        # Negative delta_t clamped to 0.0
        res_neg = calculate_risk_score("198.51.100.1", "IPV4", vt_data, abuse_data, otx_data, days_elapsed=-15.0)
        self.assertEqual(res_neg["breakdown"]["days_elapsed"], 0.0)

        # String days_elapsed parsed safely
        res_str = calculate_risk_score("198.51.100.1", "IPV4", vt_data, abuse_data, otx_data, days_elapsed="14")
        self.assertAlmostEqual(res_str["breakdown"]["decay_factor"], 0.5, delta=0.02)

        # Non-numeric string falls back to 0.0
        res_inv_str = calculate_risk_score("198.51.100.1", "IPV4", vt_data, abuse_data, otx_data, days_elapsed="invalid")
        self.assertEqual(res_inv_str["breakdown"]["days_elapsed"], 0.0)

        # NaN falls back to 0.0
        res_nan = calculate_risk_score("198.51.100.1", "IPV4", vt_data, abuse_data, otx_data, days_elapsed=float('nan'))
        self.assertEqual(res_nan["breakdown"]["days_elapsed"], 0.0)

        # Infinity / massive delta_t decays to 0
        res_inf = calculate_risk_score("198.51.100.1", "IPV4", vt_data, abuse_data, otx_data, days_elapsed=float('inf'))
        self.assertEqual(res_inf["score"], 0)

    def test_nrd_string_params(self):
        vt_data = {"malicious": 2, "suspicious": 1}
        otx_data = {"pulse_count": 1, "tags": []}

        # is_nrd as string 'true'
        res_nrd_str = calculate_risk_score("brand-new-phish.com", "DOMAIN", vt_data, {}, otx_data, is_nrd="true")
        self.assertTrue(res_nrd_str["breakdown"].get("is_nrd"))
        self.assertEqual(res_nrd_str["breakdown"].get("nrd_boost"), 25.0)

        # domain_age_days as string '5'
        res_age_str = calculate_risk_score("brand-new-phish.com", "DOMAIN", vt_data, {}, otx_data, domain_age_days="5")
        self.assertTrue(res_age_str["breakdown"].get("is_nrd"))


if __name__ == "__main__":
    unittest.main()
