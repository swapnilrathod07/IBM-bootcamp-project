"""
Unit Tests for CyberPulse Flask REST API and Web Endpoints.
Verifies server health, IOC detection, multi-source telemetry scanning, bulk triage,
audit history persistence, single-item CRUD, and report generation streams.
"""
import unittest
import json
import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from server import app
from modules.history import init_db


class TestCyberPulseAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_01_healthcheck(self):
        """Tests /api/health endpoint status."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data.get("status"), "online")
        self.assertIn("CYBERPULSE", data.get("app"))

    def test_02_config(self):
        """Tests /api/config endpoint returns system metadata."""
        response = self.client.get("/api/config")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("version", data)
        self.assertIn("integrations", data)

    def test_03_index_route(self):
        """Tests / route serves HTML frontend."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CYBERPULSE", response.data)
        self.assertIn(b"text/html", response.content_type.encode())

    def test_04_detect_endpoint(self):
        """Tests /api/detect endpoint with IPv4, IPv6, defanged URL, and hashes."""
        # IPv4
        res = self.client.post("/api/detect", json={"ioc": "1.1.1.1"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["detection"]["valid"])
        self.assertEqual(data["detection"]["type"], "IPV4")

        # IPv6
        res_v6 = self.client.post("/api/detect", json={"ioc": "2001:db8::1"})
        self.assertEqual(res_v6.status_code, 200)
        self.assertEqual(res_v6.get_json()["detection"]["type"], "IPV6")

        # Defanged Domain
        res2 = self.client.post("/api/detect", json={"ioc": "hxxps[://]evil[.]com"})
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()
        self.assertTrue(data2["detection"]["valid"])
        self.assertTrue(data2["detection"]["is_defanged"])

        # SHA-256
        res3 = self.client.post("/api/detect", json={"ioc": "ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc"})
        self.assertEqual(res3.status_code, 200)
        data3 = res3.get_json()
        self.assertEqual(data3["detection"]["type"], "SHA256")

        # GET request to /api/detect
        res_get = self.client.get("/api/detect?ioc=8.8.8.8")
        self.assertEqual(res_get.status_code, 200)
        self.assertEqual(res_get.get_json()["detection"]["type"], "IPV4")

    def test_05_scan_tor_ip_demo(self):
        """Tests /api/scan with Tor exit node sample in demo mode."""
        payload = {
            "ioc": "185.220.101.5",
            "demo_mode": True
        }
        response = self.client.post("/api/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        self.assertTrue(data["success"])
        self.assertEqual(data["ioc"], "185.220.101.5")
        self.assertGreaterEqual(data["risk"]["score"], 61)
        self.assertEqual(data["risk"]["level"], "Malicious / Critical")
        self.assertGreater(data["vt"]["malicious"], 0)
        self.assertEqual(data["abuse"]["abuse_confidence_score"], 100)
        self.assertGreater(data["otx"]["pulse_count"], 0)
        self.assertEqual(data["geo"]["country"], "Germany")

    def test_05b_scan_via_get_and_form(self):
        """Tests /api/scan with GET query params and form-encoded data."""
        # GET query param
        res_get = self.client.get("/api/scan?ioc=8.8.8.8&demo_mode=true")
        self.assertEqual(res_get.status_code, 200)
        self.assertEqual(res_get.get_json()["ioc"], "8.8.8.8")

        # Form data
        res_form = self.client.post("/api/scan", data={"ioc": "8.8.8.8", "demo_mode": "true"})
        self.assertEqual(res_form.status_code, 200)
        self.assertEqual(res_form.get_json()["ioc"], "8.8.8.8")

    def test_06_scan_invalid_ioc(self):
        """Tests /api/scan with invalid IOC format."""
        response = self.client.post("/api/scan", json={"ioc": "invalid_ioc_format!@#"})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Invalid", data["error"])

    def test_07_scan_missing_body(self):
        """Tests /api/scan with missing parameter."""
        response = self.client.post("/api/scan", json={})
        self.assertEqual(response.status_code, 400)

    def test_08_bulk_scan(self):
        """Tests /api/bulk batch scanner endpoint with list."""
        payload = {
            "iocs": ["185.220.101.5", "8.8.8.8", "google.com"],
            "demo_mode": True
        }
        response = self.client.post("/api/bulk", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["count"], 3)
        self.assertEqual(len(data["results"]), 3)

        scores = [r["risk_score"] for r in data["results"]]
        self.assertIn(100, scores)  # 185.220.101.5
        self.assertIn(0, scores)    # 8.8.8.8 or google.com

    def test_08b_bulk_scan_delimiters_and_headers(self):
        """Tests /api/bulk with delimiters (pipes, semicolons, tabs, newlines) and CSV header."""
        csv_payload = {
            "iocs": "IOC\n\"185.220.101.5\"; 8.8.8.8 | google.com\ted01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc",
            "demo_mode": "true"
        }
        response = self.client.post("/api/bulk", json=csv_payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["count"], 4)
        iocs = [r["ioc"] for r in data["results"]]
        self.assertNotIn("IOC", iocs)
        self.assertIn("185.220.101.5", iocs)
        self.assertIn("8.8.8.8", iocs)

    def test_09_history_and_stats(self):
        """Tests /api/history and /api/stats retrieval."""
        stats_res = self.client.get("/api/stats")
        self.assertEqual(stats_res.status_code, 200)
        stats_data = stats_res.get_json()
        self.assertTrue(stats_data["success"])
        self.assertIn("total_scans", stats_data["stats"])

        hist_res = self.client.get("/api/history?limit=10")
        self.assertEqual(hist_res.status_code, 200)
        hist_data = hist_res.get_json()
        self.assertTrue(hist_data["success"])
        self.assertGreater(len(hist_data["history"]), 0)

    def test_09b_history_item_get_delete_and_404(self):
        """Tests /api/history/<id> retrieval, deletion, and 404 responses."""
        # Create record
        scan_res = self.client.post("/api/scan", json={"ioc": "8.8.4.4", "demo_mode": True})
        inv_id = scan_res.get_json()["id"]

        # GET by ID
        get_res = self.client.get(f"/api/history/{inv_id}")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.get_json()["investigation"]["id"], inv_id)

        # DELETE by ID
        del_res = self.client.delete(f"/api/history/{inv_id}")
        self.assertEqual(del_res.status_code, 200)
        self.assertTrue(del_res.get_json()["success"])

        # GET non-existent
        get_404 = self.client.get(f"/api/history/{inv_id}")
        self.assertEqual(get_404.status_code, 404)

        # DELETE non-existent
        del_404 = self.client.delete(f"/api/history/{inv_id}")
        self.assertEqual(del_404.status_code, 404)

    def test_09c_clear_history(self):
        """Tests DELETE /api/history endpoint to clear all records."""
        # Insert a scan to be sure history has something
        self.client.post("/api/scan", json={"ioc": "1.1.1.1", "demo_mode": True})

        clear_res = self.client.delete("/api/history")
        self.assertEqual(clear_res.status_code, 200)
        self.assertTrue(clear_res.get_json()["success"])

        # History should now be empty
        hist_res = self.client.get("/api/history")
        self.assertEqual(hist_res.get_json()["count"], 0)

    def test_10_export_endpoints_post(self):
        """Tests PDF, JSON, and Markdown export endpoints via POST."""
        payload = {
            "ioc": "185.220.101.5",
            "demo_mode": True
        }

        # JSON
        json_res = self.client.post("/api/export/json", json=payload)
        self.assertEqual(json_res.status_code, 200)
        self.assertIn("application/json", json_res.content_type)
        self.assertIn(b"SOC Threat Intelligence Dossier", json_res.data)

        # Markdown
        md_res = self.client.post("/api/export/markdown", json=payload)
        self.assertEqual(md_res.status_code, 200)
        self.assertIn("text/markdown", md_res.content_type)
        self.assertIn(b"CyberPulse", md_res.data)

        # PDF
        pdf_res = self.client.post("/api/export/pdf", json=payload)
        self.assertEqual(pdf_res.status_code, 200)
        self.assertIn("application/pdf", pdf_res.content_type)
        self.assertGreater(len(pdf_res.data), 100)

    def test_10b_export_endpoints_get(self):
        """Tests PDF, JSON, and Markdown export endpoints via GET."""
        # JSON via GET
        json_res = self.client.get("/api/export/json?ioc=8.8.8.8&demo_mode=true")
        self.assertEqual(json_res.status_code, 200)
        self.assertIn("application/json", json_res.content_type)

        # Markdown via GET
        md_res = self.client.get("/api/export/markdown?ioc=8.8.8.8&demo_mode=true")
        self.assertEqual(md_res.status_code, 200)
        self.assertIn("text/markdown", md_res.content_type)

        # PDF via GET
        pdf_res = self.client.get("/api/export/pdf?ioc=8.8.8.8&demo_mode=true")
        self.assertEqual(pdf_res.status_code, 200)
        self.assertIn("application/pdf", pdf_res.content_type)

    def test_11_cors_headers_and_options(self):
        """Tests CORS headers on all endpoints and OPTIONS preflight requests."""
        endpoints = [
            "/api/scan", "/api/detect", "/api/bulk",
            "/api/history", "/api/export/pdf",
            "/api/export/json", "/api/export/markdown",
            "/api/rules", "/api/graph", "/api/export/stix",
            "/api/webhook/dispatch"
        ]
        for ep in endpoints:
            opt = self.client.options(ep)
            self.assertEqual(opt.status_code, 204, f"OPTIONS failed on {ep}")
            self.assertEqual(opt.headers.get("Access-Control-Allow-Origin"), "*")
            self.assertIn("OPTIONS", opt.headers.get("Access-Control-Allow-Methods", ""))

    def test_12_rules_endpoint(self):
        """Tests /api/rules endpoint returns YARA, Sigma, and firewall rules."""
        # Test IP
        res = self.client.get("/api/rules?ioc=185.220.101.5&demo_mode=true")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("rules", data)
        self.assertIn("yara", data["rules"])
        self.assertIn("sigma", data["rules"])
        self.assertIn("firewall", data["rules"])
        self.assertIn("New-NetFirewallRule", data["rules"]["firewall"]["powershell"])

        # Test Hash
        res_hash = self.client.post("/api/rules", json={
            "ioc": "ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc",
            "demo_mode": True
        })
        self.assertEqual(res_hash.status_code, 200)
        data_hash = res_hash.get_json()
        self.assertTrue(data_hash["success"])
        self.assertIn("rule CyberPulse_", data_hash["rules"]["yara"])

    def test_13_graph_endpoint(self):
        """Tests /api/graph endpoint returns relationship nodes and edges."""
        res = self.client.get("/api/graph?ioc=185.220.101.5&demo_mode=true")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("graph", data)
        self.assertIn("nodes", data["graph"])
        self.assertIn("edges", data["graph"])
        self.assertGreaterEqual(len(data["graph"]["nodes"]), 2)

    def test_14_export_stix_endpoint(self):
        """Tests /api/export/stix endpoint generates valid OASIS STIX 2.1 bundle."""
        res = self.client.get("/api/export/stix?ioc=185.220.101.5&demo_mode=true")
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/json", res.content_type)
        data = res.get_json()
        self.assertEqual(data.get("type"), "bundle")
        self.assertTrue(data.get("id", "").startswith("bundle--"))

    def test_15_webhook_dispatch_endpoint(self):
        """Tests /api/webhook/dispatch endpoint in simulated dry-run mode."""
        payload = {
            "webhook_url": "https://discord.com/api/webhooks/simulation/test",
            "ioc": "185.220.101.5",
            "dry_run": True,
            "demo_mode": True
        }
        res = self.client.post("/api/webhook/dispatch", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data.get("simulated"))
        self.assertEqual(data.get("platform"), "discord")

    def test_16_scan_with_decay_and_nrd(self):
        """Tests /api/scan endpoint honoring days_elapsed and is_nrd parameters."""
        # 1. IP with decay
        res_fresh = self.client.post("/api/scan", json={"ioc": "185.220.101.5", "demo_mode": True, "days_elapsed": 0})
        res_stale = self.client.post("/api/scan", json={"ioc": "185.220.101.5", "demo_mode": True, "days_elapsed": 60})
        self.assertEqual(res_fresh.status_code, 200)
        self.assertEqual(res_stale.status_code, 200)
        score_fresh = res_fresh.get_json()["risk"]["score"]
        score_stale = res_stale.get_json()["risk"]["score"]
        self.assertGreater(score_fresh, score_stale)

        # 2. Domain with NRD modifier
        res_domain = self.client.post("/api/scan", json={"ioc": "suspicious-test.com", "demo_mode": True, "is_nrd": True})
        self.assertEqual(res_domain.status_code, 200)
        data_dom = res_domain.get_json()
        self.assertTrue(data_dom["risk"]["breakdown"].get("is_nrd"))

    def test_17_api_json_error_handlers(self):
        """Tests that API routes return valid JSON on 404 and 405 errors."""
        # 404 error
        res_404 = self.client.get("/api/nonexistent-endpoint")
        self.assertEqual(res_404.status_code, 404)
        self.assertTrue(res_404.is_json)
        self.assertFalse(res_404.get_json()["success"])
        self.assertEqual(res_404.get_json()["status_code"], 404)

        # 405 error
        res_405 = self.client.get("/api/bulk")
        self.assertEqual(res_405.status_code, 405)
        self.assertTrue(res_405.is_json)
        self.assertFalse(res_405.get_json()["success"])
        self.assertEqual(res_405.get_json()["status_code"], 405)

    def test_18_oversized_input_guard(self):
        """Tests that oversized indicators (> 4096 characters) are rejected cleanly."""
        oversized = "a" * 5000
        res = self.client.post("/api/scan", json={"ioc": oversized})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertIn("exceeds maximum allowed length", data["error"])

    def test_19_webhook_scheme_validation(self):
        """Tests that non-HTTP/HTTPS webhook URLs are rejected with a clear error."""
        res = self.client.post("/api/webhook/dispatch", json={
            "webhook_url": "ftp://malicious-server/hook",
            "ioc": "1.1.1.1"
        })
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Invalid webhook URL scheme", data["error"])

    def test_20_merged_query_and_json_params(self):
        """Tests that query parameters in URL merge with JSON body."""
        res = self.client.post("/api/scan?demo_mode=true", json={"ioc": "8.8.8.8"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["ioc"], "8.8.8.8")

    def test_21_bulk_accepts_ioc_key(self):
        """Tests that /api/bulk accepts 'ioc' key as string or list in addition to 'iocs'."""
        # Single IOC as string
        res_str = self.client.post("/api/bulk", json={"ioc": "8.8.8.8", "demo_mode": True})
        self.assertEqual(res_str.status_code, 200)
        data_str = res_str.get_json()
        self.assertTrue(data_str["success"])
        self.assertEqual(data_str["count"], 1)

        # List under 'ioc' key
        res_list = self.client.post("/api/bulk", json={"ioc": ["8.8.8.8", "1.1.1.1"], "demo_mode": True})
        self.assertEqual(res_list.status_code, 200)
        data_list = res_list.get_json()
        self.assertTrue(data_list["success"])
        self.assertEqual(data_list["count"], 2)

    def test_22_export_auto_deduces_ioc_type(self):
        """Tests that export and rule endpoints deduce ioc_type when omitted in explicit telemetry."""
        payload = {
            "ioc": "1.1.1.1",
            "risk": {"score": 10, "level": "Benign / Low Risk"}
        }
        res_rules = self.client.post("/api/rules", json=payload)
        self.assertEqual(res_rules.status_code, 200)
        data = res_rules.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["ioc_type"], "IPV4")


if __name__ == "__main__":
    unittest.main()

