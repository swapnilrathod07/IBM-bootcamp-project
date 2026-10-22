"""
Unit tests for Threat Relationship Graph Generation module.
Verifies node and edge synthesis, actor/malware attribution, and infrastructure mapping.
"""
import unittest
from modules.graph_gen import generate_threat_graph, _sanitize_node_id, _normalize_malware_name


class TestThreatGraphGen(unittest.TestCase):
    def test_graph_ip_indicator(self):
        vt_data = {"status": "success", "malicious": 16, "as_owner": "Zwiebelfreunde e.V."}
        abuse_data = {"status": "success", "isp": "Zwiebelfreunde e.V."}
        otx_data = {
            "status": "success",
            "pulses": [
                {"name": "Cobalt Strike C2 Relay via Anonymization Nodes", "author": "Mandiant SOC", "tags": ["cobalt-strike", "c2", "apt29"]}
            ],
            "malware_families": ["Cobalt Strike"]
        }
        geo_data = {
            "status": "success",
            "country": "Germany",
            "city": "Dresden",
            "as_info": "AS200651 Zwiebelfreunde e.V."
        }
        graph = generate_threat_graph("185.220.101.5", "IPV4", vt_data, abuse_data, otx_data, geo_data)

        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertGreaterEqual(len(graph["nodes"]), 4)
        self.assertGreaterEqual(len(graph["edges"]), 3)

        # Check central node
        node_groups = {n["group"] for n in graph["nodes"]}
        self.assertIn("ioc", node_groups)
        self.assertIn("malware", node_groups)
        self.assertIn("geolocation", node_groups)
        self.assertIn("asn", node_groups)

    def test_graph_wannacry_hash(self):
        hash_val = "ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc"
        vt_data = {
            "file_type": "Win32 EXE (PE32 executable)"
        }
        otx_data = {
            "pulses": [
                {"name": "Lazarus Group Campaign Indicators", "tags": ["lazarus", "apt38"]}
            ],
            "malware_families": ["WannaCry"]
        }
        graph = generate_threat_graph(hash_val, "SHA256", vt_data=vt_data, otx_data=otx_data)
        
        node_groups = {n["group"] for n in graph["nodes"]}
        self.assertIn("ioc", node_groups)
        self.assertIn("malware", node_groups)
        self.assertIn("actor", node_groups)
        self.assertIn("file_type", node_groups)

    def test_graph_empty_telemetry(self):
        graph = generate_threat_graph("example.com", "DOMAIN")
        self.assertEqual(len(graph["nodes"]), 1)
        self.assertEqual(graph["nodes"][0]["group"], "ioc")
        self.assertEqual(len(graph["edges"]), 0)

    def test_graph_vt_vendor_harvesting(self):
        vt_data = {
            "vendors": {
                "Kaspersky": "Trojan.WannaCry.Gen",
                "CrowdStrike": "Malicious / Lazarus"
            }
        }
        graph = generate_threat_graph("d41d8cd98f00b204e9800998ecf8427e", "MD5", vt_data=vt_data)
        node_groups = {n["group"] for n in graph["nodes"]}
        self.assertIn("malware", node_groups)
        self.assertIn("actor", node_groups)

    def test_graph_clean_reputation_fallback(self):
        """Verifies clean reputation fallback node when telemetry is benign and has no malware/actors."""
        vt_data = {"status": "success", "malicious": 0, "as_owner": "Cloudflare, Inc."}
        abuse_data = {"status": "success", "abuse_confidence_score": 0}
        geo_data = {"country": "United States", "as_info": "AS13335 Cloudflare"}
        risk_data = {"score": 0, "level": "BENIGN"}

        graph = generate_threat_graph("1.1.1.1", "IPV4", vt_data, abuse_data, geo_data=geo_data, risk_data=risk_data)
        node_groups = {n["group"] for n in graph["nodes"]}

        self.assertIn("ioc", node_groups)
        self.assertIn("clean", node_groups)
        self.assertIn("geolocation", node_groups)
        self.assertIn("asn", node_groups)
        self.assertNotIn("malware", node_groups)
        self.assertNotIn("actor", node_groups)

        # Check clean node attributes
        clean_node = next(n for n in graph["nodes"] if n["group"] == "clean")
        self.assertEqual(clean_node["label"], "Clean Reputation")
        self.assertEqual(clean_node["shape"], "box")
        self.assertEqual(clean_node["color"], "#10b981")
        self.assertEqual(graph["summary"]["reputation"], "clean")

    def test_graph_unattributed_threat_fallback(self):
        """Verifies unattributed threat node when malicious detections exist but actor/family is unknown."""
        vt_data = {"status": "success", "malicious": 8}
        abuse_data = {"status": "success", "abuse_score": 45}
        risk_data = {"score": 65, "level": "SUSPICIOUS"}

        graph = generate_threat_graph("unknown-bad.org", "DOMAIN", vt_data=vt_data, abuse_data=abuse_data, risk_data=risk_data)
        node_groups = {n["group"] for n in graph["nodes"]}

        self.assertIn("ioc", node_groups)
        self.assertIn("status", node_groups)
        self.assertNotIn("clean", node_groups)

        status_node = next(n for n in graph["nodes"] if n["group"] == "status")
        self.assertEqual(status_node["label"], "Unattributed Threat")
        self.assertEqual(status_node["shape"], "box")
        self.assertEqual(status_node["color"], "#f59e0b")
        self.assertEqual(graph["summary"]["reputation"], "suspicious")

    def test_graph_malware_deduplication(self):
        """Verifies malware names with hyphens/spaces normalize and deduplicate cleanly."""
        otx_data = {
            "malware_families": ["Cobalt Strike"],
            "pulses": [
                {"tags": ["cobalt-strike", "cobalt strike", "mirai"]}
            ]
        }
        graph = generate_threat_graph("test.org", "DOMAIN", otx_data=otx_data)
        malware_nodes = [n for n in graph["nodes"] if n["group"] == "malware"]
        malware_labels = [n["label"] for n in malware_nodes]

        self.assertEqual(len(malware_nodes), 2)  # Only "Cobalt Strike" and "Mirai"
        self.assertIn("Malware: Cobalt Strike", malware_labels)
        self.assertIn("Malware: Mirai", malware_labels)

    def test_graph_node_id_sanitization(self):
        """Tests that unusual IOC characters (URLs, colons, slashes, query params) are safely sanitized."""
        url = "https://malicious.evil-corp.com:8443/login?user=admin&token=xyz#hash"
        sanitized = _sanitize_node_id(url)
        self.assertNotIn("/", sanitized)
        self.assertNotIn(":", sanitized)
        self.assertNotIn("?", sanitized)
        self.assertNotIn("&", sanitized)
        self.assertNotIn("#", sanitized)

        graph = generate_threat_graph(url, "URL")
        self.assertEqual(len(graph["nodes"]), 1)
        self.assertTrue(graph["nodes"][0]["id"].startswith("ioc_"))

    def test_graph_edge_schema_and_contrast(self):
        """Verifies edge attributes include arrows, middle font alignment, stroke contrast, and dash styling."""
        vt_data = {"malicious": 10, "country": "Japan"}
        otx_data = {"pulses": [{"name": "Sample Pulse", "tags": ["apt28"]}]}
        geo_data = {"country": "Japan"}

        graph = generate_threat_graph("192.0.2.1", "IPV4", vt_data=vt_data, otx_data=otx_data, geo_data=geo_data)
        for edge in graph["edges"]:
            self.assertIn("from", edge)
            self.assertIn("to", edge)
            self.assertIn("label", edge)
            self.assertIn("arrows", edge)
            self.assertIn("font", edge)
            self.assertEqual(edge["font"]["strokeColor"], "#070a13")
            self.assertGreaterEqual(edge["font"]["strokeWidth"], 2)

    def test_graph_actor_normalization(self):
        """Verifies APT-29 and APT29 normalize and deduplicate cleanly into one actor node."""
        otx_data = {
            "threat_actors": ["APT-29"],
            "pulses": [
                {"adversary": "APT29", "tags": ["apt-29", "APT29"]}
            ]
        }
        graph = generate_threat_graph("evil-apt.org", "DOMAIN", otx_data=otx_data)
        actor_nodes = [n for n in graph["nodes"] if n["group"] == "actor"]
        self.assertEqual(len(actor_nodes), 1)
        self.assertEqual(actor_nodes[0]["label"], "Actor: APT29")

    def test_graph_string_numeric_scores(self):
        """Verifies string-encoded scores (e.g. from JSON/query params) do not crash numeric comparison."""
        vt_data = {"malicious": "0"}
        abuse_data = {"abuse_score": "0"}
        risk_data = {"score": "15", "level": "BENIGN"}

        graph = generate_threat_graph("1.1.1.1", "IPV4", vt_data=vt_data, abuse_data=abuse_data, risk_data=risk_data)
        node_groups = {n["group"] for n in graph["nodes"]}
        self.assertIn("clean", node_groups)
        self.assertEqual(graph["summary"]["reputation"], "clean")

    def test_graph_malformed_telemetry(self):
        """Tests resiliency against malformed telemetry (strings instead of lists or dicts)."""
        otx_data = {
            "malware_families": "Cobalt Strike",  # string instead of list
            "threat_actors": "FIN7",             # string instead of list
            "pulses": "Single Malicious Pulse"    # string instead of list of dicts
        }
        graph = generate_threat_graph("8.8.8.8", "IPV4", otx_data=otx_data)
        self.assertGreaterEqual(len(graph["nodes"]), 3)
        node_groups = {n["group"] for n in graph["nodes"]}
        self.assertIn("malware", node_groups)
        self.assertIn("actor", node_groups)

    def test_graph_empty_ioc(self):
        """Tests that empty or None IOC safely generates a valid fallback central node."""
        graph1 = generate_threat_graph("", "")
        self.assertEqual(len(graph1["nodes"]), 1)
        self.assertIn("ioc", {n["group"] for n in graph1["nodes"]})

        graph2 = generate_threat_graph(None, "UNKNOWN")
        self.assertEqual(len(graph2["nodes"]), 1)
        self.assertIn("ioc", {n["group"] for n in graph2["nodes"]})

    def test_graph_edge_integrity(self):
        """Verifies no dangling edges (both source and target exist) and no self-referential edges."""
        vt_data = {"malicious": 5, "country": "US", "file_type": "PE32"}
        otx_data = {
            "pulses": [{"name": "P1", "tags": ["wannacry", "apt38"]}],
            "malware_families": ["WannaCry"]
        }
        geo_data = {"country": "US", "as_info": "AS15169 Google LLC", "isp": "Google"}
        graph = generate_threat_graph("192.0.2.1", "IPV4", vt_data, {}, otx_data, geo_data)

        node_ids = {n["id"] for n in graph["nodes"]}
        for edge in graph["edges"]:
            self.assertIn(edge["from"], node_ids, f"Edge source {edge['from']} does not exist in nodes")
            self.assertIn(edge["to"], node_ids, f"Edge target {edge['to']} does not exist in nodes")
            self.assertNotEqual(edge["from"], edge["to"], "Edge cannot be self-referential")


if __name__ == "__main__":
    unittest.main()

