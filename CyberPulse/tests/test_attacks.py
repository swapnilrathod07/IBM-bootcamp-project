"""
Unit Tests for Attack Prediction Engine and Adversary Toolset Explorer.
Tests multi-source heuristics, MITRE ATT&CK TTP mapping, forensic artifacts,
containment playbooks, edge-case IOCs (benign, malformed, empty), and API endpoints.
"""
import unittest
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from modules.attack_analyzer import (
    analyze_attack_vector,
    get_adversary_tool,
    get_adversary_tool_catalog,
    get_attack_vector_catalog
)
from modules.report_gen import generate_json_report, generate_markdown_report, generate_pdf_report
from server import app


class TestAttackAnalyzer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_01_tool_catalog_and_lookup(self):
        """Verifies adversary tool catalog completeness and individual tool retrieval."""
        catalog = get_adversary_tool_catalog()
        self.assertGreaterEqual(len(catalog), 15)
        self.assertIn("mimikatz", catalog)
        self.assertIn("psexec", catalog)
        self.assertIn("evilginx2", catalog)
        self.assertIn("cobalt_strike", catalog)
        self.assertIn("sqlmap", catalog)

        # Lookup by ID
        mimi = get_adversary_tool("mimikatz")
        self.assertIsNotNone(mimi)
        self.assertEqual(mimi["name"], "Mimikatz")
        self.assertEqual(mimi["category"], "Credential Dumping")
        self.assertIn("LSASS", mimi["tactical_purpose"])
        self.assertIn("4688", mimi["forensic_artifacts"])
        self.assertIn("klist purge", mimi["containment_step"])

        # Unknown tool
        self.assertIsNone(get_adversary_tool("nonexistent_tool_xyz"))

    def test_02_vector_catalog(self):
        """Verifies attack vector definitions and taxonomy."""
        vectors = get_attack_vector_catalog()
        expected = ["ransomware", "bruteforce", "phishing", "c2_beaconing", "web_exploitation", "ddos_dos", "cryptomining", "reconnaissance", "benign"]
        for exp in expected:
            self.assertIn(exp, vectors)
            self.assertIn("icon", vectors[exp])
            self.assertIn("mitre_techniques", vectors[exp])
            self.assertIn("default_tools", vectors[exp])

    def test_03_ransomware_prediction(self):
        """Tests ransomware prediction on WannaCry-like hash telemetry."""
        ioc = "ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc"
        vt = {
            "malicious": 68,
            "suspicious": 0,
            "file_type": "Win32 EXE PE32",
            "tags": ["ransomware", "wannacry", "cryptor"],
            "vendors": {"Microsoft": "Ransom:Win32/WannaCrypt", "Kaspersky": "Ransom.Win32.Wanna.m"}
        }
        otx = {
            "pulse_count": 89,
            "tags": ["wannacry", "ransomware", "eternalblue"],
            "malware_families": ["WannaCry"]
        }
        res = analyze_attack_vector(ioc, "SHA256", vt_data=vt, otx_data=otx)
        self.assertEqual(res["vector_id"], "ransomware")
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertGreaterEqual(res["confidence"], 75)
        self.assertIn("T1486", [t["id"] for t in res["mitre_techniques"]])
        tool_ids = [t["id"] for t in res["adversary_tools"]]
        self.assertIn("mimikatz", tool_ids)
        self.assertIn("vssadmin", tool_ids)

    def test_04_phishing_prediction(self):
        """Tests phishing prediction on fraudulent domain telemetry."""
        ioc = "secure-login-paypal-verify.com"
        vt = {
            "malicious": 32,
            "suspicious": 5,
            "categories": {"Forcepoint": "Phishing and Other Scams"},
            "tags": ["phishing", "paypal"],
            "vendors": {"CrowdStrike": "Malicious / Phishing", "Kaspersky": "Trojan-Spy.HTML.Paypal"}
        }
        otx = {
            "pulse_count": 18,
            "tags": ["phishing", "credential-harvesting"]
        }
        res = analyze_attack_vector(ioc, "DOMAIN", vt_data=vt, otx_data=otx, domain_age_days=12)
        self.assertEqual(res["vector_id"], "phishing")
        self.assertIn("T1566.002", [t["id"] for t in res["mitre_techniques"]])
        tool_ids = [t["id"] for t in res["adversary_tools"]]
        self.assertIn("evilginx2", tool_ids)

    def test_05_c2_beaconing_prediction(self):
        """Tests C2 beaconing detection on dropper URL."""
        ioc = "http://bad-c2-update.org/payload.exe"
        vt = {
            "malicious": 42,
            "suspicious": 6,
            "tags": ["c2", "cobalt-strike", "beacon", "dropper"],
            "vendors": {"Kaspersky": "Malicious / C2 Binary URL"}
        }
        otx = {
            "pulse_count": 30,
            "tags": ["cobalt-strike", "c2"],
            "malware_families": ["Cobalt Strike"]
        }
        res = analyze_attack_vector(ioc, "URL", vt_data=vt, otx_data=otx)
        self.assertEqual(res["vector_id"], "c2_beaconing")
        self.assertIn("T1071.001", [t["id"] for t in res["mitre_techniques"]])
        tool_ids = [t["id"] for t in res["adversary_tools"]]
        self.assertIn("cobalt_strike", tool_ids)

    def test_06_bruteforce_or_recon_prediction(self):
        """Tests brute force prediction on abusive scanner/Tor node."""
        ioc = "185.220.101.5:22"
        abuse = {
            "abuse_confidence_score": 100,
            "total_reports": 2841,
            "usage_type": "Data Center / Tor Exit Node"
        }
        otx = {
            "pulse_count": 42,
            "tags": ["tor", "proxy", "bruteforce"]
        }
        res = analyze_attack_vector(ioc, "IPV4", abuse_data=abuse, otx_data=otx)
        self.assertEqual(res["vector_id"], "bruteforce")
        tool_ids = [t["id"] for t in res["adversary_tools"]]
        self.assertIn("thc_hydra", tool_ids)

    def test_07_benign_asset_prediction(self):
        """Tests benign infrastructure prediction on Google DNS 8.8.8.8."""
        ioc = "8.8.8.8"
        vt = {"malicious": 0, "suspicious": 0, "harmless": 88}
        abuse = {"abuse_confidence_score": 0, "is_whitelisted": True}
        otx = {"pulse_count": 1, "tags": ["dns", "benign"]}
        res = analyze_attack_vector(ioc, "IPV4", vt_data=vt, abuse_data=abuse, otx_data=otx)
        self.assertEqual(res["vector_id"], "benign")
        self.assertEqual(res["severity"], "LOW")
        self.assertGreaterEqual(res["confidence"], 80)

    def test_08_unknown_or_malformed_ioc(self):
        """Tests graceful fallback when given malformed, empty, or unknown IOC."""
        res_empty = analyze_attack_vector("", "UNKNOWN")
        self.assertEqual(res_empty["vector_id"], "unclassified")
        self.assertEqual(res_empty["confidence"], 0)

        res_none = analyze_attack_vector(None, "UNKNOWN")
        self.assertEqual(res_none["vector_id"], "unclassified")

    def test_09_api_attacks_tool_endpoint(self):
        """Tests GET /api/attacks?tool=<id>."""
        res = self.client.get("/api/attacks?tool=psexec")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["tool"]["name"], "PsExec")
        self.assertIn("PSEXESVC", data["tool"]["forensic_artifacts"])

        # 404 on missing tool
        res_404 = self.client.get("/api/attacks?tool=bogus_tool")
        self.assertEqual(res_404.status_code, 404)

    def test_10_api_attacks_catalog_endpoint(self):
        """Tests GET /api/attacks?catalog=true."""
        res = self.client.get("/api/attacks?catalog=true")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("vectors", data)
        self.assertIn("tools", data)

    def test_11_api_attacks_scan_endpoint(self):
        """Tests GET and POST /api/attacks with IOC indicator."""
        # GET query param
        res = self.client.get("/api/attacks?ioc=185.220.101.5&demo_mode=true")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("attacks", data)
        self.assertIn("vector_id", data["attacks"])

        # POST body
        res_post = self.client.post("/api/attacks", json={"ioc": "secure-login-paypal-verify[.]com", "demo_mode": True})
        self.assertEqual(res_post.status_code, 200)
        data_post = res_post.get_json()
        self.assertEqual(data_post["attacks"]["vector_id"], "phishing")

        # Missing IOC
        res_err = self.client.post("/api/attacks", json={})
        self.assertEqual(res_err.status_code, 400)

    def test_12_api_scan_includes_attacks(self):
        """Tests that standard /api/scan endpoint contains 'attacks' payload."""
        res = self.client.post("/api/scan", json={"ioc": "185.220.101.5", "demo_mode": True})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("attacks", data)
        self.assertIn("adversary_tools", data["attacks"])
        self.assertIn("mitre_techniques", data["attacks"])

    def test_13_reports_include_attacks(self):
        """Tests that JSON, Markdown, and PDF reports incorporate attack predictions."""
        ioc = "185.220.101.5"
        risk = {"score": 95, "level": "Malicious", "summary": "Tor exit node threat", "actions": ["Block IP"]}
        vt = {"malicious": 16, "suspicious": 3, "harmless": 68}
        abuse = {"abuse_confidence_score": 100, "total_reports": 2800}
        otx = {"pulse_count": 42, "tags": ["tor", "c2"]}
        geo = {"status": "success", "city": "Dresden", "country": "Germany"}

        # JSON
        json_rep = generate_json_report(ioc, "IPV4", risk, vt, abuse, otx, geo)
        parsed = json.loads(json_rep)
        self.assertIn("attack_prediction", parsed)
        self.assertIn("vector_id", parsed["attack_prediction"])

        # Markdown
        md_rep = generate_markdown_report(ioc, "IPV4", risk, vt, abuse, otx, geo)
        self.assertIn("Predicted Attack Vector & Adversary Toolset", md_rep)
        self.assertIn("MITRE ATT&CK TTP Mapping", md_rep)

        # PDF
        pdf_bytes = generate_pdf_report(ioc, "IPV4", risk, vt, abuse, otx, geo)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 200)

    def test_14_abuseipdb_categories_influence(self):
        """Tests that AbuseIPDB category numbers accurately drive attack vector prediction."""
        ioc = "192.168.1.100"
        # Category 18 = Brute Force, 22 = SSH
        abuse_bf = {"abuse_confidence_score": 60, "categories": [18, 22]}
        res_bf = analyze_attack_vector(ioc, "IPV4", abuse_data=abuse_bf)
        self.assertEqual(res_bf["vector_id"], "bruteforce")

        # Category 4 = DDoS Attack
        abuse_ddos = {"abuse_confidence_score": 70, "reports": [{"categories": [4, 23]}]}
        res_ddos = analyze_attack_vector(ioc, "IPV4", abuse_data=abuse_ddos)
        self.assertEqual(res_ddos["vector_id"], "ddos_dos")

        # Category 21 = Web App Attack
        abuse_web = {"abuse_confidence_score": 50, "categories": [21]}
        res_web = analyze_attack_vector(ioc, "IPV4", abuse_data=abuse_web)
        self.assertEqual(res_web["vector_id"], "web_exploitation")

    def test_15_ports_telemetry_influence(self):
        """Tests that port parameters and detected ports heavily weight specific attack vectors."""
        ioc = "10.0.0.5"
        # Port 3333 -> Stratum Mining
        res_mining = analyze_attack_vector(ioc, "IPV4", ports=[3333])
        self.assertEqual(res_mining["vector_id"], "cryptomining")

        # Port 3389 -> RDP Brute Force
        res_rdp = analyze_attack_vector(f"{ioc}:3389", "IPV4")
        self.assertEqual(res_rdp["vector_id"], "bruteforce")

        # Port 8080 with suspicious traffic -> Web Exploitation
        res_web = analyze_attack_vector(ioc, "IPV4", vt_data={"malicious": 5, "ports": [8080]})
        self.assertEqual(res_web["vector_id"], "web_exploitation")

    def test_16_domain_age_and_nrd_influence(self):
        """Tests that Newly Registered Domain (NRD) and young domain age boost phishing and C2."""
        ioc = "account-verification-suspicious-alert.com"
        vt = {"malicious": 8, "suspicious": 2}
        res_nrd = analyze_attack_vector(ioc, "DOMAIN", vt_data=vt, domain_age_days=4, is_nrd=True)
        self.assertEqual(res_nrd["vector_id"], "phishing")
        self.assertGreaterEqual(res_nrd["confidence"], 75)

    def test_17_malformed_telemetry_resilience(self):
        """Verifies engine resiliency against non-string tags, dict tags, and None values."""
        ioc = "malformed-test-asset.net"
        vt = {
            "tags": [12345, None, {"nested": "value"}],
            "vendors": 9999,  # Non-dict vendors
            "categories": [None, 42]
        }
        otx = {
            "tags": None,
            "malware_families": [None, True]
        }
        res = analyze_attack_vector(ioc, "DOMAIN", vt_data=vt, otx_data=otx)
        self.assertIsNotNone(res)
        self.assertIn("vector_id", res)
        self.assertIn("confidence", res)

    def test_18_all_thirty_tools_integrity(self):
        """Verifies that all 30 adversary tools in the catalog are fully populated with required fields."""
        catalog = get_adversary_tool_catalog()
        self.assertEqual(len(catalog), 30)
        required_fields = ["id", "name", "category", "primary_vector", "tactical_purpose", "forensic_artifacts", "containment_step"]
        for tool_id, tool_data in catalog.items():
            for field in required_fields:
                self.assertIn(field, tool_data, f"Tool '{tool_id}' missing '{field}'")
                self.assertTrue(len(str(tool_data[field])) > 0, f"Tool '{tool_id}' field '{field}' is empty")

    def test_19_reports_with_ports_and_domain_age(self):
        """Tests that reports accept domain_age_days, ports, and is_nrd parameters without regression."""
        ioc = "stratum-pool.minexmr.com"
        risk = {"score": 85, "level": "Malicious", "summary": "Cryptomining domain", "actions": ["Block domain"]}
        json_rep = generate_json_report(ioc, "DOMAIN", risk, {}, {}, {}, {}, domain_age_days=10, ports=[3333], is_nrd=True)
        parsed = json.loads(json_rep)
        self.assertEqual(parsed["attack_prediction"]["vector_id"], "cryptomining")

        pdf_bytes = generate_pdf_report(ioc, "DOMAIN", risk, {}, {}, {}, {}, domain_age_days=10, ports=[3333], is_nrd=True)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 200)

    def test_20_api_attacks_with_ports_and_nrd(self):
        """Tests /api/attacks endpoint with ports and is_nrd parameters."""
        res = self.client.post("/api/attacks", json={
            "ioc": "crypto-mining-worker.org",
            "ports": [3333],
            "demo_mode": True
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["attacks"]["vector_id"], "cryptomining")

    def test_21_null_telemetry_resilience(self):
        """Verifies analyze_attack_vector handles None values across all telemetry sources without crashing."""
        abuse_nulls = {"reports": None, "categories": None, "abuse_confidence_score": None, "total_reports": None}
        vt_nulls = {"malicious": None, "suspicious": None, "tags": None, "vendors": None, "categories": None}
        otx_nulls = {"pulse_count": None, "tags": None, "malware_families": None}
        res = analyze_attack_vector("185.220.101.5", "IPV4", vt_data=vt_nulls, abuse_data=abuse_nulls, otx_data=otx_nulls)
        self.assertIsInstance(res, dict)
        self.assertIn("vector_id", res)
        self.assertIn("confidence", res)


if __name__ == "__main__":
    unittest.main()

