"""
Unit tests for the Defensive Rule Generator module.
Verifies YARA, Sigma YAML, and Firewall command syntax and structure.
"""
import unittest
from modules.rule_gen import (
    generate_yara_rule,
    generate_sigma_rule,
    generate_firewall_commands,
    generate_all_defensive_rules
)


class TestDefensiveRuleGen(unittest.TestCase):
    def test_yara_rule_generation_hash(self):
        sample_hash = "ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc"
        telemetry = {
            "otx": {"malware_families": ["WannaCry", "Lazarus"]},
            "risk": {"level": "Malicious / Critical", "score": 98}
        }
        rule = generate_yara_rule(sample_hash, "SHA256", telemetry)
        
        self.assertIn("rule CyberPulse_", rule)
        self.assertIn("meta:", rule)
        self.assertIn("strings:", rule)
        self.assertIn("condition:", rule)
        self.assertIn(sample_hash, rule)
        self.assertIn("WannaCry", rule)
        self.assertIn("TLP:AMBER", rule)

    def test_yara_rule_generation_domain(self):
        sample_domain = "malicious-c2-domain.com"
        rule = generate_yara_rule(sample_domain, "DOMAIN")
        self.assertIn(sample_domain, rule)
        self.assertIn("condition:", rule)

    def test_sigma_rule_generation_domain(self):
        sample_domain = "evil-phishing.org"
        sigma = generate_sigma_rule(sample_domain, "DOMAIN", {"risk": {"score": 85}})
        
        self.assertIn("title: CyberPulse Detection - evil-phishing.org", sigma)
        self.assertIn("category: dns", sigma)
        self.assertIn("query: 'evil-phishing.org'", sigma)
        self.assertIn("level: high", sigma)
        self.assertIn("attack.command_and_control", sigma)

    def test_sigma_rule_generation_ip(self):
        sample_ip = "185.220.101.5"
        sigma = generate_sigma_rule(sample_ip, "IPV4", {"risk": {"score": 95}})
        self.assertIn("DestinationIp: '185.220.101.5'", sigma)
        self.assertIn("category: firewall", sigma)
        self.assertIn("level: critical", sigma)

    def test_firewall_commands_generation(self):
        ip = "185.220.101.5"
        fw = generate_firewall_commands(ip)
        
        self.assertIn("powershell", fw)
        self.assertIn("iptables", fw)
        self.assertIn("cisco_acl", fw)
        
        self.assertIn("New-NetFirewallRule", fw["powershell"])
        self.assertIn("-RemoteAddress \"185.220.101.5\"", fw["powershell"])
        self.assertIn("iptables -A OUTPUT -d 185.220.101.5 -j DROP", fw["iptables"])
        self.assertIn("access-list 100 deny ip any host 185.220.101.5", fw["cisco_acl"])

    def test_generate_all_defensive_rules(self):
        res = generate_all_defensive_rules("185.220.101.5", "IPV4")
        self.assertIsNotNone(res["firewall"])
        self.assertTrue(res["yara"].startswith("rule "))
        self.assertIn("DestinationIp", res["sigma"])

        res_hash = generate_all_defensive_rules("44d88612fea8a8f36de82e1278abb02f", "MD5")
        self.assertIsNone(res_hash["firewall"])
        self.assertIn("Hashes.MD5", res_hash["sigma"])

    def test_yara_rule_empty_families_no_generic_string(self):
        sample_hash = "ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc"
        rule = generate_yara_rule(sample_hash, "SHA256", {})
        # Strings section should only contain hash_ref, never Generic Suspicious Indicator
        self.assertNotIn('$tag_context = "Generic Suspicious Indicator"', rule)
        self.assertIn("$hash_ref =", rule)

    def test_sigma_rule_generic_hash_and_yaml_safety(self):
        import yaml
        sample_hash = "44d88612fea8a8f36de82e1278abb02f"  # MD5 (32 hex)
        sigma = generate_sigma_rule(sample_hash, "HASH", {"risk": {"score": 90}})
        self.assertIn("Hashes.MD5", sigma)
        self.assertIn("process_creation", sigma)

        # Indicator with colon and spaces should parse cleanly in YAML
        tricky_ioc = "malicious-c2: 8080/path"
        tricky_sigma = generate_sigma_rule(tricky_ioc, "URL")
        parsed = yaml.safe_load(tricky_sigma)
        self.assertIn("title", parsed)
        self.assertIn("detection", parsed)

    def test_firewall_commands_ipv6(self):
        ipv6 = "2001:db8::8a2e:370:7334"
        fw = generate_firewall_commands(ipv6)
        self.assertIn("ip6tables", fw["iptables"])
        self.assertIn("ipv6 access-list", fw["cisco_acl"])
        self.assertIn("New-NetFirewallRule", fw["powershell"])


if __name__ == "__main__":
    unittest.main()
