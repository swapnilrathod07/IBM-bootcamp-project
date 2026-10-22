"""
Unit tests for STIX 2.1 Threat Intelligence Bundle Generation.
"""
import unittest
import json
from modules.stix_gen import generate_stix_bundle, generate_stix_json


class TestSTIX21Gen(unittest.TestCase):

    def test_stix_bundle_structure(self):
        bundle = generate_stix_bundle(
            ioc="185.220.101.5",
            ioc_type="IPV4",
            risk_data={"score": 88, "level": "Malicious / Critical"},
            otx_data={
                "malware_families": ["Cobalt Strike"],
                "pulses": [{"tags": ["apt29"]}]
            }
        )
        self.assertEqual(bundle["type"], "bundle")
        self.assertTrue(bundle["id"].startswith("bundle--"))
        self.assertIn("objects", bundle)
        self.assertGreaterEqual(len(bundle["objects"]), 4)

        types = [o["type"] for o in bundle["objects"]]
        self.assertIn("identity", types)
        self.assertIn("indicator", types)
        self.assertIn("malware", types)
        self.assertIn("threat-actor", types)
        self.assertIn("relationship", types)

        indicator_obj = next(o for o in bundle["objects"] if o["type"] == "indicator")
        self.assertEqual(indicator_obj["spec_version"], "2.1")
        self.assertEqual(indicator_obj["pattern"], "[ipv4-addr:value = '185.220.101.5']")
        self.assertEqual(indicator_obj["confidence"], 88)

    def test_stix_patterns_for_various_types(self):
        types_map = {
            "IPV6": ("2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"),
            "DOMAIN": ("malicious.com", "[domain-name:value = 'malicious.com']"),
            "URL": ("http://c2.org/a.exe", "[url:value = 'http://c2.org/a.exe']"),
            "SHA256": ("ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc", "[file:hashes.'SHA-256' = 'ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc']"),
            "MD5": ("44d88612fea8a8f36de82e1278abb02f", "[file:hashes.MD5 = '44d88612fea8a8f36de82e1278abb02f']"),
            "SHA1": ("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", "[file:hashes.'SHA-1' = '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12']")
        }
        for ioc_t, (val, expected_pattern) in types_map.items():
            bundle = generate_stix_bundle(val, ioc_t)
            ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
            self.assertEqual(ind["pattern"], expected_pattern)

    def test_stix_json_serialization(self):
        json_str = generate_stix_json("8.8.8.8", "IPV4", {"score": 0, "level": "Benign"})
        parsed = json.loads(json_str)
        self.assertEqual(parsed["type"], "bundle")
        self.assertTrue(parsed["id"].startswith("bundle--"))

    def test_stix_generic_hash_and_relationship_semantics(self):
        # Generic HASH type
        bundle_hash = generate_stix_bundle("44d88612fea8a8f36de82e1278abb02f", "HASH")
        ind = next(o for o in bundle_hash["objects"] if o["type"] == "indicator")
        self.assertIn("file:hashes.MD5", ind["pattern"])

        # When indicator links directly to threat-actor (no malware), relationship is 'indicates'
        bundle_actor = generate_stix_bundle(
            "1.2.3.4", "IPV4",
            otx_data={"pulses": [{"tags": ["apt29"]}]}
        )
        actor_rel = next(
            (o for o in bundle_actor["objects"] if o["type"] == "relationship" and o.get("target_ref", "").startswith("threat-actor--")),
            None
        )
        self.assertIsNotNone(actor_rel)
        self.assertEqual(actor_rel["relationship_type"], "indicates")


if __name__ == "__main__":
    unittest.main()
