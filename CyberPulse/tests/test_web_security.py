"""
Unit and Integration Tests for Website Security Posture & SSL/Headers Health Engine.
Tests SSL inspection, OWASP defensive headers checklist, score and letter grade computation,
non-web indicator handling, reporting integration, and REST API endpoints.
"""
import unittest
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from modules.web_security import (
    audit_website_security,
    _calculate_grade,
    _compute_hardening_score,
    _build_checklist_from_headers,
    _generate_server_configs,
    extract_target_host
)
from modules.report_gen import generate_json_report, generate_markdown_report, generate_pdf_report
from server import app


class TestWebSecurity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_01_demo_presets_grades(self):
        """Verifies high-fidelity demo mode presets for google.com, test phishing, and c2 domains."""
        # 1. Clean reputable domain: google.com -> Grade A+
        g_res = audit_website_security("google.com", demo_mode=True)
        self.assertEqual(g_res["status"], "success")
        self.assertEqual(g_res["grade"], "A+")
        self.assertGreaterEqual(g_res["score"], 90)
        self.assertTrue(g_res["ssl"]["valid"])
        self.assertEqual(g_res["ssl"]["protocol"], "TLSv1.3")
        self.assertTrue(g_res["redirect"]["enforced"])
        self.assertIn("Google Trust Services", g_res["ssl"]["issuer"])

        # 2. Phishing test domain: secure-login-paypal-verify.com -> Grade D
        p_res = audit_website_security("secure-login-paypal-verify.com", demo_mode=True)
        self.assertEqual(p_res["status"], "success")
        self.assertEqual(p_res["grade"], "D")
        self.assertEqual(p_res["server_banner"]["status"], "FAIL")
        self.assertTrue(p_res["server_banner"]["leaked"])
        self.assertIn("Apache", p_res["server_banner"]["value"])

        # 3. Malicious C2 URL: http://bad-c2-update.org/payload.exe -> Grade F
        c2_res = audit_website_security("http://bad-c2-update.org/payload.exe", demo_mode=True)
        self.assertEqual(c2_res["status"], "success")
        self.assertEqual(c2_res["grade"], "F")
        self.assertFalse(c2_res["ssl"]["valid"])
        self.assertTrue(c2_res["ssl"]["expired"])
        self.assertFalse(c2_res["redirect"]["enforced"])

    def test_02_generic_demo_domain(self):
        """Verifies deterministic high-fidelity simulation for unlisted domains in demo mode."""
        res1 = audit_website_security("corp-enterprise-portal.net", demo_mode=True)
        res2 = audit_website_security("corp-enterprise-portal.net", demo_mode=True)
        self.assertEqual(res1["status"], "success")
        self.assertEqual(res1["score"], res2["score"])
        self.assertEqual(res1["grade"], res2["grade"])
        self.assertTrue(res1["ssl"]["valid"])
        self.assertIn(res1["grade"], ["A+", "A", "B", "C"])

    def test_03_non_web_indicators_graceful_not_applicable(self):
        """Verifies non-web indicators (IP addresses, hashes) gracefully return not_applicable."""
        # IPv4
        ip_res = audit_website_security("185.220.101.5", demo_mode=True)
        self.assertEqual(ip_res["status"], "not_applicable")
        self.assertEqual(ip_res["grade"], "N/A")
        self.assertIsNone(ip_res["score"])
        self.assertIn("only applicable to web domains and URLs", ip_res["message"])

        # IPv6
        ip6_res = audit_website_security("2001:4860:4860::8888", demo_mode=True)
        self.assertEqual(ip6_res["status"], "not_applicable")

        # MD5, SHA1, SHA256 Hashes
        sha_res = audit_website_security("ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc", demo_mode=True)
        self.assertEqual(sha_res["status"], "not_applicable")

    def test_04_empty_or_malformed_inputs(self):
        """Verifies resilience against empty, whitespace-only, or None indicators."""
        self.assertEqual(audit_website_security("")["status"], "not_applicable")
        self.assertEqual(audit_website_security("   ")["status"], "not_applicable")
        self.assertEqual(audit_website_security(None)["status"], "not_applicable")

    def test_05_target_host_extraction(self):
        """Verifies clean extraction of hostnames and ports from various URL formats."""
        host, port = extract_target_host("example.com")
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)

        host, port = extract_target_host("https://secure.bank.org:8443/login?q=1")
        self.assertEqual(host, "secure.bank.org")
        self.assertEqual(port, 8443)

        host, port = extract_target_host("http://insecure-site.com/test")
        self.assertEqual(host, "insecure-site.com")
        self.assertEqual(port, 443)

    def test_06_header_checklist_evaluator(self):
        """Verifies OWASP security header compliance checklist grading."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        }
        banner = {"status": "PASS", "value": "Masked", "leaked": False, "details": "Safe"}
        checklist = _build_checklist_from_headers(headers, banner)
        self.assertEqual(len(checklist), 7)

        # Check that HSTS, CSP, XFO, XCTO, Referrer all pass
        hdr_map = {item["header"]: item for item in checklist}
        self.assertTrue(hdr_map["Strict-Transport-Security"]["passed"])
        self.assertTrue(hdr_map["Content-Security-Policy"]["passed"])
        self.assertTrue(hdr_map["X-Frame-Options"]["passed"])
        self.assertTrue(hdr_map["X-Content-Type-Options"]["passed"])
        self.assertTrue(hdr_map["Referrer-Policy"]["passed"])

    def test_07_hardening_score_and_grade_scale(self):
        """Verifies letter grade boundaries (A+, A, B, C, D, F)."""
        self.assertEqual(_calculate_grade(100)[0], "A+")
        self.assertEqual(_calculate_grade(92)[0], "A+")
        self.assertEqual(_calculate_grade(85)[0], "A")
        self.assertEqual(_calculate_grade(75)[0], "B")
        self.assertEqual(_calculate_grade(60)[0], "C")
        self.assertEqual(_calculate_grade(48)[0], "D")
        self.assertEqual(_calculate_grade(20)[0], "F")
        self.assertEqual(_calculate_grade(0)[0], "F")
        self.assertEqual(_calculate_grade(-10)[0], "F")

    def test_08_server_configs_generator(self):
        """Verifies generation of Apache and Nginx hardening configuration snippets."""
        checklist = [
            {"header": "Strict-Transport-Security", "passed": False},
            {"header": "X-Frame-Options", "passed": False},
            {"header": "X-Content-Type-Options", "passed": True}
        ]
        configs = _generate_server_configs(checklist)
        self.assertIn("add_header Strict-Transport-Security", configs["nginx"])
        self.assertIn("add_header X-Frame-Options", configs["nginx"])
        self.assertIn("Header always set Strict-Transport-Security", configs["apache"])
        self.assertIn("ServerTokens Prod", configs["apache"])

    def test_09_api_web_security_endpoint(self):
        """Tests GET and POST /api/web-security standalone audit endpoint."""
        # 1. GET with target and demo_mode
        resp = self.client.get("/api/web-security?target=google.com&demo_mode=true")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["web_security"]["grade"], "A+")

        # 2. POST with JSON body
        resp = self.client.post("/api/web-security", json={"target": "secure-login-paypal-verify.com", "demo_mode": True})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["web_security"]["grade"], "D")

        # 3. Missing target returns 400
        resp = self.client.get("/api/web-security")
        self.assertEqual(resp.status_code, 400)

    def test_10_api_scan_includes_web_security(self):
        """Verifies standard /api/scan endpoint contains web_security payload."""
        # Domain scan
        resp = self.client.get("/api/scan?ioc=google.com&demo_mode=true")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("web_security", data)
        self.assertEqual(data["web_security"]["status"], "success")
        self.assertEqual(data["web_security"]["grade"], "A+")

        # IP scan
        resp_ip = self.client.get("/api/scan?ioc=8.8.8.8&demo_mode=true")
        self.assertEqual(resp_ip.status_code, 200)
        data_ip = resp_ip.get_json()
        self.assertIn("web_security", data_ip)
        self.assertEqual(data_ip["web_security"]["status"], "not_applicable")

    def test_11_reports_incorporate_web_security(self):
        """Verifies JSON, Markdown, and PDF investigation reports cleanly incorporate website security audits."""
        # 1. JSON Report
        json_str = generate_json_report("google.com", "DOMAIN", {"score": 10, "level": "Low", "summary": "Clean", "actions": []}, {}, {}, {}, {})
        json_obj = json.loads(json_str)
        self.assertIn("website_security_posture", json_obj)
        self.assertEqual(json_obj["website_security_posture"]["grade"], "A+")

        # 2. Markdown Report
        md_str = generate_markdown_report("google.com", "DOMAIN", {"score": 10, "level": "Low", "summary": "Clean", "actions": []}, {}, {}, {}, {})
        self.assertIn("Website Security Posture & SSL Health", md_str)
        self.assertIn("Hardening Grade:", md_str)

        # 3. PDF Report
        pdf_bytes = generate_pdf_report("google.com", "DOMAIN", {"score": 10, "level": "Low", "summary": "Clean", "actions": []}, {}, {}, {}, {})
        self.assertIsInstance(pdf_bytes, (bytes, bytearray))
        self.assertGreater(len(pdf_bytes), 1000)

    def test_12_defanged_domains_and_urls(self):
        """Verifies resilience against defanged domain and URL indicators without parser crashes."""
        # Defanged domain
        d_res = audit_website_security("google[.]com", demo_mode=True)
        self.assertEqual(d_res["status"], "success")
        self.assertEqual(d_res["grade"], "A+")
        self.assertEqual(d_res["hostname"], "google.com")

        # Defanged URL with hxxps and bracketed scheme
        u_res = audit_website_security("hxxps[://]google[.]com/login", demo_mode=True)
        self.assertEqual(u_res["status"], "success")
        self.assertEqual(u_res["grade"], "A+")

        # REST API endpoint with defanged input
        api_res = self.client.get("/api/web-security?target=google[.]com&demo_mode=true")
        self.assertEqual(api_res.status_code, 200)
        api_data = api_res.get_json()
        self.assertTrue(api_data["success"])
        self.assertEqual(api_data["web_security"]["grade"], "A+")

    def test_13_malformed_empty_host_urls(self):
        """Verifies that URLs missing a valid destination hostname return not_applicable gracefully."""
        for malformed in ["https://", "http://", "http://:8080", "https:///path"]:
            res = audit_website_security(malformed, demo_mode=True)
            self.assertEqual(res["status"], "not_applicable", f"Failed on: {malformed}")
            self.assertTrue("missing" in res["message"].lower() or "applicable" in res["message"].lower())

    def test_14_export_endpoints_preserve_web_security(self):
        """Verifies on-the-fly export endpoints (PDF and JSON) properly evaluate and include web security."""
        # PDF GET with domain
        resp_pdf = self.client.get("/api/export/pdf?ioc=google.com&demo_mode=true")
        self.assertEqual(resp_pdf.status_code, 200)
        self.assertEqual(resp_pdf.mimetype, "application/pdf")
        self.assertGreater(len(resp_pdf.data), 2000)

        # JSON GET with domain
        resp_json = self.client.get("/api/export/json?ioc=google.com&demo_mode=true")
        self.assertEqual(resp_json.status_code, 200)
        dossier = resp_json.get_json()
        self.assertIn("website_security_posture", dossier)
        self.assertEqual(dossier["website_security_posture"]["grade"], "A+")

    def test_15_live_ssl_time_parser_resilience(self):
        """Verifies openSSL notAfter certificate expiration timestamp parsing."""
        import ssl
        from datetime import datetime, timezone
        # Standard OpenSSL timestamp format
        sample_ts = "Dec 31 23:59:59 2030 GMT"
        secs = ssl.cert_time_to_seconds(sample_ts)
        self.assertGreater(secs, 1900000000)
        dt = datetime.fromtimestamp(secs, tz=timezone.utc)
        self.assertEqual(dt.year, 2030)
        self.assertEqual(dt.month, 12)
        self.assertEqual(dt.day, 31)

    def test_16_idn_domain_web_security(self):
        """Verifies that IDN domains (e.g. münchen.de) cleanly audit in demo mode."""
        res = audit_website_security("münchen.de", demo_mode=True)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["hostname"], "xn--mnchen-3ya.de")
        self.assertIsNotNone(res["score"])
        self.assertIn(res["grade"], ["A+", "A", "B", "C", "D", "F"])


if __name__ == "__main__":
    unittest.main()

