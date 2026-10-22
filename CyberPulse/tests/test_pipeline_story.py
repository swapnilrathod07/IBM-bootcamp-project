"""
Tests for Threat Stage Pipeline (5-stage kill chain) and 3-Step Attack Story Engine.
"""
import unittest
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import compute_threat_stages, compute_attack_story
from modules.attack_analyzer import ATTACK_VECTORS_CATALOG


class TestThreatPipelineAndStory(unittest.TestCase):
    def test_01_benign_asset_pipeline_and_story(self):
        """Tests that benign assets (e.g. 8.8.8.8, google.com) illuminate zero stages and produce clean story."""
        benign_att = ATTACK_VECTORS_CATALOG["benign"]
        
        # Google DNS 8.8.8.8
        stg_dns = compute_threat_stages(benign_att, {"score": 10}, "8.8.8.8", "IPV4", {"isp": "Google LLC"})
        self.assertEqual(stg_dns["active_stages"], [])
        self.assertIn("NO ACTIVE ATTACK PHASE", stg_dns["badge_text"])
        self.assertEqual(stg_dns["badge_color"], "#10b981")
        
        sty_dns = compute_attack_story(benign_att, {"score": 10}, "8.8.8.8", "IPV4", {"isp": "Google LLC"}, {}, {})
        self.assertTrue(sty_dns["is_benign"])
        self.assertEqual(sty_dns["who"]["entity"], "Google Public DNS Anycast Resolver")
        self.assertEqual(sty_dns["who"]["badge"], "VERIFIED BENIGN")
        self.assertEqual(sty_dns["attempt"]["entity"], "Standard Network Operations")
        self.assertEqual(sty_dns["impact"]["entity"], "Zero Exploitation Risk")

        # Google domain
        stg_dom = compute_threat_stages(benign_att, {"score": 5}, "google.com", "DOMAIN", {"isp": "Google LLC"})
        self.assertEqual(stg_dom["active_stages"], [])
        sty_dom = compute_attack_story(benign_att, {"score": 5}, "google.com", "DOMAIN", {"isp": "Google LLC"}, {}, {})
        self.assertTrue(sty_dom["is_benign"])
        self.assertEqual(sty_dom["who"]["entity"], "Google Global Cloud Infrastructure")

    def test_02_ransomware_pipeline_and_story(self):
        """Tests that ransomware IOCs illuminate Stage 5 (Actions/Impact) and map to known binary characteristics."""
        rw_att = ATTACK_VECTORS_CATALOG["ransomware"]
        ioc = "ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc"
        
        stg = compute_threat_stages(rw_att, {"score": 98}, ioc, "SHA256", {})
        self.assertEqual(stg["active_stages"], [5])
        self.assertIn("STAGE 5 ACTIVE", stg["badge_text"])
        self.assertIn("ACTIONS / IMPACT", stg["badge_text"])
        self.assertEqual(stg["badge_color"], "#ef4444")
        
        sty = compute_attack_story(rw_att, {"score": 98}, ioc, "SHA256", {}, {"malicious": 14}, {})
        self.assertFalse(sty["is_benign"])
        self.assertEqual(sty["who"]["entity"], "Known Ransomware Binary Signature")
        self.assertEqual(sty["who"]["badge"], "CONFIRMED MALWARE")
        self.assertEqual(sty["attempt"]["entity"], "Shadow Deletion & Rapid Encryption")
        self.assertEqual(sty["impact"]["entity"], "Enterprise Lockdown & Extortion")

    def test_03_phishing_pipeline_and_story(self):
        """Tests that phishing IOCs illuminate Stage 2 (Delivery) and map to credential theft story."""
        phish_att = ATTACK_VECTORS_CATALOG["phishing"]
        ioc = "secure-login-paypal-verify[.]com"
        
        stg = compute_threat_stages(phish_att, {"score": 88}, ioc, "DOMAIN", {})
        self.assertEqual(stg["active_stages"], [2])
        self.assertIn("STAGE 2 ACTIVE", stg["badge_text"])
        self.assertIn("INITIAL DELIVERY", stg["badge_text"])
        
        sty = compute_attack_story(phish_att, {"score": 88}, ioc, "DOMAIN", {}, {}, {})
        self.assertFalse(sty["is_benign"])
        self.assertEqual(sty["who"]["entity"], "Fraudulent Phishing Domain / Cloner")
        self.assertEqual(sty["attempt"]["entity"], "Harvesting Credentials & 2FA Cookies")
        self.assertEqual(sty["impact"]["entity"], "Cloud Tenant Compromise & BEC Fraud")

    def test_04_c2_beaconing_pipeline_and_story(self):
        """Tests that C2 beaconing illuminates Stage 4 (C2 Control)."""
        c2_att = ATTACK_VECTORS_CATALOG["c2_beaconing"]
        ioc = "http://malicious-c2-callback.org/beacon"
        
        stg = compute_threat_stages(c2_att, {"score": 95}, ioc, "URL", {})
        self.assertEqual(stg["active_stages"], [4])
        self.assertIn("STAGE 4 ACTIVE", stg["badge_text"])
        self.assertIn("C2 CONTROL", stg["badge_text"])
        
        sty = compute_attack_story(c2_att, {"score": 95}, ioc, "URL", {}, {}, {})
        self.assertFalse(sty["is_benign"])
        self.assertEqual(sty["who"]["entity"], "Command & Control (C2) Server Node")
        self.assertEqual(sty["attempt"]["entity"], "Covert Reverse Shell Callbacks")
        self.assertEqual(sty["impact"]["entity"], "Full Domain Dominance & Exfiltration")

    def test_05_tor_and_bruteforce_pipeline_and_story(self):
        """Tests that Tor exit nodes and brute force scanners illuminate Stages 1 & 3 (Recon & Exploitation)."""
        # Tor Exit Node
        bf_att = ATTACK_VECTORS_CATALOG["bruteforce"]
        tor_ioc = "185.220.101.5"
        geo = {"city": "Dresden", "country_code": "DE", "isp": "Zwiebelfreunde e.V."}
        
        stg_tor = compute_threat_stages(bf_att, {"score": 94}, tor_ioc, "IPV4", geo)
        self.assertEqual(stg_tor["active_stages"], [1, 3])
        self.assertIn("STAGES 1 & 3 ACTIVE", stg_tor["badge_text"])
        
        sty_tor = compute_attack_story(bf_att, {"score": 94}, tor_ioc, "IPV4", geo, {}, {})
        self.assertFalse(sty_tor["is_benign"])
        self.assertEqual(sty_tor["who"]["entity"], "Tor Anonymized Exit Node")
        self.assertEqual(sty_tor["attempt"]["entity"], "SSH & RDP Credential Spraying")
        self.assertEqual(sty_tor["impact"]["entity"], "Server Takeover & Lateral Pivot")

        # Non-Tor Scanner
        scanner_ioc = "45.33.32.156:8080"
        geo_scanner = {"isp": "Linode, LLC"}
        stg_scan = compute_threat_stages(bf_att, {"score": 85}, scanner_ioc, "IPV4", geo_scanner)
        self.assertEqual(stg_scan["active_stages"], [1, 3])
        sty_scan = compute_attack_story(bf_att, {"score": 85}, scanner_ioc, "IPV4", geo_scanner, {}, {})
        self.assertEqual(sty_scan["who"]["entity"], "Automated Botnet Scanner")

    def test_06_no_tor_false_positives_from_substrings(self):
        """Verifies that words like 'extortion', 'multi-factor', 'threat actor', 'monitored' do NOT falsely trigger Tor classification."""
        malicious_att = {
            "vector_id": "ransomware",
            "name": "Ransomware & Extortion",
            "summary": "Target exhibits threat actor behavioral indicators of double-extortion exfiltration operations and multi-factor bypass.",
            "hacker_objective": "Extort victim for service restoration."
        }
        ioc = "ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc"
        stg = compute_threat_stages(malicious_att, {"score": 95}, ioc, "SHA256", {"isp": "Actor Networks"})
        self.assertEqual(stg["active_stages"], [5], "Should be Stage 5 (Actions/Impact), NOT hijacked to Tor Recon/Exploit!")
        
        sty = compute_attack_story(malicious_att, {"score": 95}, ioc, "SHA256", {"isp": "Actor Networks"}, {}, {})
        self.assertEqual(sty["who"]["entity"], "Known Ransomware Binary Signature")

    def test_07_resilience_to_none_and_empty_inputs(self):
        """Tests that functions handle None, empty dicts, or missing fields without throwing unhandled exceptions."""
        stg = compute_threat_stages(None, None, "", "", None)
        self.assertIsInstance(stg, dict)
        self.assertIn("active_stages", stg)

        sty = compute_attack_story(None, None, None, None, None, None, None)
        self.assertIsInstance(sty, dict)
        self.assertIn("who", sty)
        self.assertIn("attempt", sty)
        self.assertIn("impact", sty)


if __name__ == "__main__":
    unittest.main()
