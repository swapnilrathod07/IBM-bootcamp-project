"""
Comprehensive Unit & Integration Tests for Internal & RFC 1918 / Loopback Asset Protection.
Verifies loopback URLs, loopback IPs, localhost domain, private RFC 1918 subnets,
attack analyzer classification, graph generator mapping, web security developer advisory,
and ensures public malicious threats remain scored critically.
"""
import unittest
from modules.detector import detect_ioc_type
from modules.mock_data import generate_mock_telemetry
from modules.scorer import calculate_risk_score, generate_attack_velocity
from modules.attack_analyzer import analyze_attack_vector
from modules.graph_gen import generate_threat_graph
from modules.web_security import audit_website_security
from modules.rule_gen import generate_firewall_commands
from server import app


class TestInternalAndLoopbackAssets(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()

    def test_01_loopback_url_detection(self):
        """Verifies http://127.0.0.1:5000/ and http://localhost:8080/ are detected as private loopback URLs."""
        res_ip_url = detect_ioc_type("http://127.0.0.1:5000/")
        self.assertTrue(res_ip_url["valid"])
        self.assertEqual(res_ip_url["type"], "URL")
        self.assertTrue(res_ip_url["is_private"])
        self.assertTrue(res_ip_url["is_loopback"])

        res_lh_url = detect_ioc_type("http://localhost:8080/api/v1")
        self.assertTrue(res_lh_url["valid"])
        self.assertEqual(res_lh_url["type"], "URL")
        self.assertTrue(res_lh_url["is_private"])
        self.assertTrue(res_lh_url["is_loopback"])

        res_no_scheme = detect_ioc_type("127.0.0.1:3000/dashboard")
        self.assertTrue(res_no_scheme["valid"])
        self.assertEqual(res_no_scheme["type"], "URL")
        self.assertTrue(res_no_scheme["is_private"])
        self.assertTrue(res_no_scheme["is_loopback"])

    def test_02_loopback_ip_and_domain_detection(self):
        """Verifies 127.0.0.1, 127.0.0.1:5000, localhost, and ::1 return loopback and private True."""
        res_ip = detect_ioc_type("127.0.0.1")
        self.assertTrue(res_ip["valid"])
        self.assertEqual(res_ip["type"], "IPV4")
        self.assertTrue(res_ip["is_private"])
        self.assertTrue(res_ip["is_loopback"])

        res_ip_port = detect_ioc_type("127.0.0.1:5000")
        self.assertTrue(res_ip_port["valid"])
        self.assertEqual(res_ip_port["type"], "IPV4")
        self.assertTrue(res_ip_port["is_private"])
        self.assertTrue(res_ip_port["is_loopback"])

        res_dom = detect_ioc_type("localhost")
        self.assertTrue(res_dom["valid"])
        self.assertEqual(res_dom["type"], "DOMAIN")
        self.assertTrue(res_dom["is_private"])
        self.assertTrue(res_dom["is_loopback"])

        res_dom_port = detect_ioc_type("localhost:8080")
        self.assertTrue(res_dom_port["valid"])
        self.assertEqual(res_dom_port["type"], "DOMAIN")
        self.assertTrue(res_dom_port["is_private"])
        self.assertTrue(res_dom_port["is_loopback"])

        res_v6 = detect_ioc_type("::1")
        self.assertTrue(res_v6["valid"])
        self.assertEqual(res_v6["type"], "IPV6")
        self.assertTrue(res_v6["is_private"])
        self.assertTrue(res_v6["is_loopback"])

    def test_03_rfc1918_private_ips_and_urls(self):
        """Verifies 192.168.1.1, 10.0.0.1, 172.16.0.1 are private but NOT loopback."""
        for ip in ("192.168.1.1", "10.0.0.1", "172.16.0.1", "192.168.0.254"):
            res = detect_ioc_type(ip)
            self.assertTrue(res["valid"])
            self.assertEqual(res["type"], "IPV4")
            self.assertTrue(res["is_private"])
            self.assertFalse(res["is_loopback"])

        res_priv_url = detect_ioc_type("http://192.168.1.1/admin")
        self.assertTrue(res_priv_url["valid"])
        self.assertEqual(res_priv_url["type"], "URL")
        self.assertTrue(res_priv_url["is_private"])
        self.assertFalse(res_priv_url["is_loopback"])

    def test_04_mock_data_telemetry_clean(self):
        """Verifies mock telemetry generator suppresses false alarms for internal and loopback assets."""
        for target in ("http://127.0.0.1:5000/", "127.0.0.1", "localhost", "192.168.1.1"):
            mock = generate_mock_telemetry(target, "URL" if "http" in target else ("DOMAIN" if target == "localhost" else "IPV4"))
            self.assertEqual(mock["virustotal"]["malicious"], 0)
            self.assertEqual(mock["virustotal"]["suspicious"], 0)
            self.assertEqual(mock["abuseipdb"]["abuse_confidence_score"], 0)
            self.assertEqual(mock["alienvault"]["pulse_count"], 0)
            self.assertEqual(len(mock["alienvault"]["malware_families"]), 0)
            self.assertIn("Local Loopback", mock["geolocation"]["isp"])

    def test_05_risk_score_zero_for_internal_assets(self):
        """Verifies calculate_risk_score returns 0 and Benign / Internal Asset without self-blocking actions."""
        mock = generate_mock_telemetry("127.0.0.1", "IPV4")
        risk = calculate_risk_score(
            "127.0.0.1", "IPV4",
            mock["virustotal"], mock["abuseipdb"], mock["alienvault"],
            geo_data=mock["geolocation"],
            is_private=True, is_loopback=True
        )
        self.assertEqual(risk["score"], 0)
        self.assertEqual(risk["level"], "Benign / Internal Asset")
        self.assertEqual(risk["color"], "#10b981")
        self.assertTrue(risk["is_internal"])
        self.assertTrue(risk["is_loopback"])
        # Ensure no self-blocking DROP rule is suggested
        for act in risk["actions"]:
            self.assertNotIn("DROP", act.upper())

        # Test URL loopback auto-detection without explicit flags
        url_mock = generate_mock_telemetry("http://127.0.0.1:5000/", "URL")
        risk_url = calculate_risk_score("http://127.0.0.1:5000/", "URL", url_mock["virustotal"], url_mock["abuseipdb"], url_mock["alienvault"])
        self.assertEqual(risk_url["score"], 0)
        self.assertEqual(risk_url["level"], "Benign / Internal Asset")
        self.assertTrue(risk_url["is_internal"])

    def test_06_attack_analyzer_internal_classification(self):
        """Verifies attack analyzer classifies internal assets as internal_asset instead of malware/botnet."""
        mock = generate_mock_telemetry("http://127.0.0.1:5000/", "URL")
        risk = calculate_risk_score("http://127.0.0.1:5000/", "URL", mock["virustotal"], mock["abuseipdb"], mock["alienvault"], is_private=True, is_loopback=True)
        attacks = analyze_attack_vector("http://127.0.0.1:5000/", "URL", mock["virustotal"], mock["abuseipdb"], mock["alienvault"], risk_data=risk)
        self.assertEqual(attacks["vector_id"], "internal_asset")
        self.assertEqual(attacks["icon"], "🏠")
        self.assertEqual(attacks["severity"], "INFO")
        self.assertIn("Internal Asset", attacks["name"])
        self.assertEqual(len(attacks["adversary_tools"]), 0)

    def test_07_threat_graph_internal_mapping(self):
        """Verifies threat relationship graph connects internal assets to loopback/private nodes without malware families."""
        mock = generate_mock_telemetry("127.0.0.1", "IPV4")
        risk = calculate_risk_score("127.0.0.1", "IPV4", mock["virustotal"], mock["abuseipdb"], mock["alienvault"], is_private=True, is_loopback=True)
        graph = generate_threat_graph("127.0.0.1", "IPV4", mock["virustotal"], mock["abuseipdb"], mock["alienvault"], mock["geolocation"], risk_data=risk)
        self.assertEqual(graph["summary"]["actors_found"], [])
        self.assertEqual(graph["summary"]["malware_found"], [])
        self.assertEqual(graph["summary"]["reputation"], "clean")

        node_groups = {n["group"] for n in graph["nodes"]}
        self.assertIn("internal", node_groups)
        self.assertNotIn("malware", node_groups)
        self.assertNotIn("actor", node_groups)

    def test_08_web_security_localhost_developer_advisory(self):
        """Verifies audit_website_security provides developer advisory for localhost development server."""
        for target in ("http://127.0.0.1:5000/", "http://localhost:8080/"):
            res = audit_website_security(target, demo_mode=True)
            self.assertEqual(res["status"], "success")
            self.assertTrue(res["is_localhost"])
            self.assertIn("Local Development Server Detected", res["advisory"])
            self.assertTrue(any("Nginx/Cloudflare" in r for r in res["recommendations"]))

    def test_09_public_malicious_threats_unaffected(self):
        """Verifies public threats (Tor exit node 185.220.101.5, WannaCry hash) continue to score as critical threats."""
        res_tor = detect_ioc_type("185.220.101.5")
        self.assertFalse(res_tor["is_private"])
        self.assertFalse(res_tor["is_loopback"])

        mock_tor = generate_mock_telemetry("185.220.101.5", "IPV4")
        risk_tor = calculate_risk_score("185.220.101.5", "IPV4", mock_tor["virustotal"], mock_tor["abuseipdb"], mock_tor["alienvault"], geo_data=mock_tor["geolocation"])
        self.assertGreaterEqual(risk_tor["score"], 70)
        self.assertEqual(risk_tor["level"], "Malicious / Critical")

        attacks_tor = analyze_attack_vector("185.220.101.5", "IPV4", mock_tor["virustotal"], mock_tor["abuseipdb"], mock_tor["alienvault"], geo_data=mock_tor["geolocation"], risk_data=risk_tor)
        self.assertIn(attacks_tor["vector_id"], ("bruteforce", "c2_beaconing", "reconnaissance"))

        # WannaCry hash
        wc_hash = "ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc"
        res_wc = detect_ioc_type(wc_hash)
        self.assertFalse(res_wc["is_private"])
        self.assertFalse(res_wc["is_loopback"])

    def test_10_api_scan_internal_loopback_integration(self):
        """Tests end-to-end /api/scan endpoint with http://127.0.0.1:5000/."""
        response = self.client.post("/api/scan", json={"ioc": "http://127.0.0.1:5000/", "demo_mode": True})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["risk"]["score"], 0)
        self.assertEqual(data["risk"]["level"], "Benign / Internal Asset")
        self.assertTrue(data["detection"]["is_loopback"])
        self.assertTrue(data["detection"]["is_private"])
        self.assertEqual(data["attacks"]["vector_id"], "internal_asset")
        self.assertIn("Local Development Server Detected", str(data["web_security"]["recommendations"]))

    def test_11_loopback_firewall_suppression(self):
        """Verifies generate_firewall_commands suppresses DROP rules on loopback 127.0.0.1 and ::1."""
        for loop_ip in ("127.0.0.1", "127.0.0.2", "::1"):
            fw = generate_firewall_commands(loop_ip)
            self.assertIn("powershell", fw)
            self.assertIn("iptables", fw)
            self.assertIn("cisco_acl", fw)
            # Crucial: Must NEVER contain -j DROP or -Action Block
            self.assertNotIn("-j DROP", fw["iptables"])
            self.assertNotIn("-Action Block", fw["powershell"])
            self.assertNotIn("deny ip any host", fw["cisco_acl"])
            # Must recommend safe local port inspection
            self.assertIn("netstat -tulnp", fw["iptables"])
            self.assertIn("Get-NetTCPConnection", fw["powershell"])

    def test_12_unspecified_local_host_0_0_0_0(self):
        """Verifies 0.0.0.0 and http://0.0.0.0:8000/ are detected and scored as benign internal infrastructure."""
        res_url = detect_ioc_type("http://0.0.0.0:8000/")
        self.assertTrue(res_url["valid"])
        self.assertEqual(res_url["type"], "URL")
        self.assertTrue(res_url["is_private"])

        scan_resp = self.client.post("/api/scan", json={"ioc": "http://0.0.0.0:8000/", "demo_mode": True})
        self.assertEqual(scan_resp.status_code, 200)
        sdata = scan_resp.get_json()
        self.assertEqual(sdata["risk"]["score"], 0)
        self.assertEqual(sdata["risk"]["level"], "Benign / Internal Asset")

        # Plain 0.0.0.0
        res_ip = detect_ioc_type("0.0.0.0")
        self.assertTrue(res_ip["valid"])
        self.assertEqual(res_ip["type"], "IPV4")
        self.assertTrue(res_ip["is_private"])

    def test_13_schemeless_urls_resilience(self):
        """Verifies schemeless URLs (127.0.0.1/dashboard, 192.168.1.1/admin, localhost/app) resolve internal asset status."""
        for schemeless in ("127.0.0.1/dashboard", "192.168.1.1/admin", "localhost/app"):
            det = detect_ioc_type(schemeless)
            self.assertTrue(det["valid"])
            self.assertEqual(det["type"], "URL")
            self.assertTrue(det["is_private"])

            mock = generate_mock_telemetry(schemeless, "URL")
            risk = calculate_risk_score(schemeless, "URL", mock["virustotal"], mock["abuseipdb"], mock["alienvault"])
            self.assertEqual(risk["score"], 0)
            self.assertEqual(risk["level"], "Benign / Internal Asset")
            self.assertTrue(risk["is_internal"])

            attacks = analyze_attack_vector(schemeless, "URL", mock["virustotal"], mock["abuseipdb"], mock["alienvault"], risk_data=risk)
            self.assertEqual(attacks["vector_id"], "internal_asset")

            graph = generate_threat_graph(schemeless, "URL", mock["virustotal"], mock["abuseipdb"], mock["alienvault"], mock["geolocation"], risk_data=risk)
            self.assertEqual(graph["summary"]["reputation"], "clean")


if __name__ == "__main__":
    unittest.main()
