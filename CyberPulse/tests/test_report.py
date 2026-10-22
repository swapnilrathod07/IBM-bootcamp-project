"""
Unit Tests for Report Generation (JSON, Markdown, PDF) and SQLite History.
"""
import unittest
import json
from modules.report_gen import generate_json_report, generate_markdown_report, generate_pdf_report
from modules.history import save_investigation, get_history, get_history_stats, clear_history


class TestReportAndHistory(unittest.TestCase):

    def setUp(self):
        self.ioc = "185.220.101.5"
        self.ioc_type = "IPV4"
        self.risk_data = {
            "score": 95,
            "level": "Malicious / Critical",
            "summary": "Confirmed high threat IP.",
            "actions": ["Block on firewall", "Isolate host"]
        }
        self.vt_data = {"malicious": 16, "suspicious": 3, "harmless": 68, "reputation": -35}
        self.abuse_data = {"abuse_confidence_score": 100, "total_reports": 2800, "isp": "Tor Relay"}
        self.otx_data = {"pulse_count": 40, "tags": ["tor", "c2"]}
        self.geo_data = {"status": "success", "city": "Dresden", "country": "Germany", "lat": 51.05, "lon": 13.73}

    def test_json_report_generation(self):
        json_str = generate_json_report(
            self.ioc, self.ioc_type, self.risk_data,
            self.vt_data, self.abuse_data, self.otx_data, self.geo_data
        )
        parsed = json.loads(json_str)
        self.assertEqual(parsed["metadata"]["target_indicator"], self.ioc)
        self.assertEqual(parsed["unified_risk_assessment"]["score"], 95)
        self.assertEqual(parsed["telemetry_sources"]["abuseipdb"]["abuse_confidence_score"], 100)

    def test_markdown_report_generation(self):
        md_str = generate_markdown_report(
            self.ioc, self.ioc_type, self.risk_data,
            self.vt_data, self.abuse_data, self.otx_data, self.geo_data
        )
        self.assertIn("SOC Threat Intelligence Report", md_str)
        self.assertIn("95/100", md_str)
        self.assertIn("Block on firewall", md_str)

    def test_pdf_report_generation(self):
        pdf_bytes = generate_pdf_report(
            self.ioc, self.ioc_type, self.risk_data,
            self.vt_data, self.abuse_data, self.otx_data, self.geo_data
        )
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 100)

    def test_pdf_report_with_special_xml_characters(self):
        # Must not raise ValueError: paraparser: syntax error
        pdf_bytes = generate_pdf_report(
            "http://malicious.com/test?user=admin&token=xyz<script>alert('xss')</script>",
            "URL",
            {"score": 88, "level": "Malicious", "summary": "C&C Server & Payload > 50KB", "actions": ["Block & Isolate <immediate>"]},
            {"malicious": 12, "suspicious": 2, "harmless": 40, "reputation": -50, "vendors": {"Vendor & Partner": "Malicious <trojan>"}},
            {"abuse_confidence_score": "N/A", "total_reports": 0, "isp": "Bad & Evil ISP"},
            {"pulse_count": 5, "tags": ["tag&1", "<c2>"]},
            {"status": "not_applicable"}
        )
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 500)

    def test_sqlite_history_lifecycle(self):
        clear_history()
        stats_empty = get_history_stats()
        self.assertEqual(stats_empty["total_scans"], 0)

        # Save record
        row_id = save_investigation(
            ioc="185.220.101.5",
            ioc_type="IPV4",
            risk_score=95,
            risk_level="Malicious / Critical",
            vt_malicious=16,
            abuse_score=100,
            country="Germany",
            analyst_notes="Test log"
        )
        self.assertGreater(row_id, 0)

        # Retrieve by id
        from modules.history import get_investigation_by_id, delete_investigation
        record = get_investigation_by_id(row_id)
        self.assertIsNotNone(record)
        self.assertEqual(record["ioc"], "185.220.101.5")

        # Delete by id
        deleted = delete_investigation(row_id)
        self.assertTrue(deleted)
        self.assertIsNone(get_investigation_by_id(row_id))

        # Clean up
        clear_history()


if __name__ == "__main__":
    unittest.main()
