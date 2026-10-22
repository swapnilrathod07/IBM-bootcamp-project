"""
Unit Tests for IOC Detection, Defanging, and Refanging Engine.
"""
import unittest
from modules.detector import detect_ioc_type, defang_ioc, refang_ioc


class TestIOCDetector(unittest.TestCase):

    def test_refang_and_defang_url(self):
        defanged = "hxxps[://]malicious-site[.]com/payload.bin"
        refanged = refang_ioc(defanged)
        self.assertEqual(refanged, "https://malicious-site.com/payload.bin")

        re_defanged = defang_ioc(refanged)
        self.assertIn("hxxps://", re_defanged)
        self.assertIn("[.]", re_defanged)

    def test_refang_defanged_ip(self):
        defanged_ip = "185[.]220[.]101[.]5"
        self.assertEqual(refang_ioc(defanged_ip), "185.220.101.5")

        dot_ip = "10(dot)0(dot)0(dot)1"
        self.assertEqual(refang_ioc(dot_ip), "10.0.0.1")

    def test_ipv4_detection_public(self):
        res = detect_ioc_type("185.220.101.5")
        self.assertTrue(res["valid"])
        self.assertEqual(res["type"], "IPV4")
        self.assertFalse(res["is_private"])
        self.assertEqual(res["normalized"], "185.220.101.5")

    def test_ipv4_detection_private(self):
        res = detect_ioc_type("192.168.1.1")
        self.assertTrue(res["valid"])
        self.assertEqual(res["type"], "IPV4")
        self.assertTrue(res["is_private"])

    def test_ipv4_invalid_octets(self):
        res = detect_ioc_type("999.999.999.999")
        self.assertFalse(res["valid"])
        self.assertEqual(res["type"], "UNKNOWN")

    def test_ipv6_detection(self):
        res = detect_ioc_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        self.assertTrue(res["valid"])
        self.assertEqual(res["type"], "IPV6")

    def test_md5_hash_detection(self):
        md5_sample = "44d88612fea8a8f36de82e1278abb02f"
        res = detect_ioc_type(md5_sample)
        self.assertTrue(res["valid"])
        self.assertEqual(res["type"], "MD5")
        self.assertEqual(res["normalized"], md5_sample.lower())

    def test_sha1_hash_detection(self):
        sha1_sample = "3395856ce81f2b7382dee72602f798b642f14140"
        res = detect_ioc_type(sha1_sample)
        self.assertTrue(res["valid"])
        self.assertEqual(res["type"], "SHA1")

    def test_sha256_hash_detection(self):
        sha256_sample = "ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc"
        res = detect_ioc_type(sha256_sample)
        self.assertTrue(res["valid"])
        self.assertEqual(res["type"], "SHA256")
        self.assertEqual(res["normalized"], sha256_sample)

    def test_domain_detection(self):
        res = detect_ioc_type("google.com")
        self.assertTrue(res["valid"])
        self.assertEqual(res["type"], "DOMAIN")
        self.assertEqual(res["normalized"], "google.com")

        subdomain_res = detect_ioc_type("sub.domain.threat.co.uk")
        self.assertTrue(subdomain_res["valid"])
        self.assertEqual(subdomain_res["type"], "DOMAIN")

    def test_defanged_domain_detection(self):
        res = detect_ioc_type("bad-c2[.]org")
        self.assertTrue(res["valid"])
        self.assertTrue(res["is_defanged"])
        self.assertEqual(res["normalized"], "bad-c2.org")

    def test_url_detection(self):
        res = detect_ioc_type("https://evil-domain.com/login?user=admin")
        self.assertTrue(res["valid"])
        self.assertEqual(res["type"], "URL")

    def test_empty_and_garbage_input(self):
        res_empty = detect_ioc_type("")
        self.assertFalse(res_empty["valid"])

        res_none = detect_ioc_type(None)
        self.assertFalse(res_none["valid"])

        res_garbage = detect_ioc_type("not an indicator @@@ !!")
        self.assertFalse(res_garbage["valid"])

    def test_ipv4_with_port(self):
        res = detect_ioc_type("185.220.101.5:9001")
        self.assertTrue(res["valid"])
        self.assertEqual(res["type"], "IPV4")
        self.assertEqual(res["normalized"], "185.220.101.5")
        self.assertEqual(res.get("port"), 9001)

    def test_cidr_detection(self):
        res_host = detect_ioc_type("8.8.8.8/32")
        self.assertTrue(res_host["valid"])
        self.assertEqual(res_host["type"], "IPV4")
        self.assertEqual(res_host["normalized"], "8.8.8.8")

        res_subnet = detect_ioc_type("192.168.1.0/24")
        self.assertTrue(res_subnet["valid"])
        self.assertEqual(res_subnet["type"], "IPV4")
        self.assertEqual(res_subnet["normalized"], "192.168.1.0")

    def test_domain_and_url_with_ports(self):
        res_dom = detect_ioc_type("evil.com:8080")
        self.assertTrue(res_dom["valid"])
        self.assertEqual(res_dom["type"], "DOMAIN")
        self.assertEqual(res_dom["normalized"], "evil.com")

        res_url = detect_ioc_type("evil.com:8080/payload.exe")
        self.assertTrue(res_url["valid"])
        self.assertEqual(res_url["type"], "URL")
        self.assertEqual(res_url["normalized"], "http://evil.com:8080/payload.exe")

        res_ip_url = detect_ioc_type("185.220.101.5:8080/c2")
        self.assertTrue(res_ip_url["valid"])
        self.assertEqual(res_ip_url["type"], "URL")
        self.assertEqual(res_ip_url["normalized"], "http://185.220.101.5:8080/c2")

    def test_ipv6_bracketed(self):
        res = detect_ioc_type("[2001:db8::1]")
        self.assertTrue(res["valid"])
        self.assertEqual(res["type"], "IPV6")
        self.assertEqual(res["normalized"], "2001:db8::1")

        res_port = detect_ioc_type("[2001:db8::1]:8443")
        self.assertTrue(res_port["valid"])
        self.assertEqual(res_port["type"], "IPV6")
        self.assertEqual(res_port["normalized"], "2001:db8::1")

    def test_nested_brackets_and_idempotent_defang(self):
        nested = "192[[.]]168[[.]]1[[.]]1"
        res = detect_ioc_type(nested)
        self.assertTrue(res["valid"])
        self.assertEqual(res["normalized"], "192.168.1.1")

        url_defanged = "hxxp[s]://evil[.]com"
        res_url = detect_ioc_type(url_defanged)
        self.assertTrue(res_url["valid"])
        self.assertEqual(res_url["type"], "URL")
        self.assertEqual(res_url["normalized"], "https://evil.com")

        # Idempotence
        d1 = defang_ioc("https://evil.com")
        d2 = defang_ioc(d1)
        self.assertEqual(d1, d2)
        self.assertEqual(d2, "hxxps://evil[.]com")

    def test_unconventional_schemes_and_brackets(self):
        # meow and meows refanging
        r_meow = detect_ioc_type("meow://evil.com/malware")
        self.assertTrue(r_meow["valid"])
        self.assertEqual(r_meow["type"], "URL")
        self.assertEqual(r_meow["normalized"], "http://evil.com/malware")

        r_meows = detect_ioc_type("meows[:]//evil.com/malware")
        self.assertTrue(r_meows["valid"])
        self.assertEqual(r_meows["type"], "URL")
        self.assertEqual(r_meows["normalized"], "https://evil.com/malware")

        # hxxp[:]// and https[://]
        r_hxxp = detect_ioc_type("hxxp[:]//bad.org/c2")
        self.assertTrue(r_hxxp["valid"])
        self.assertEqual(r_hxxp["normalized"], "http://bad.org/c2")

        r_bracket_scheme = detect_ioc_type("https[://]secure-login.com")
        self.assertTrue(r_bracket_scheme["valid"])
        self.assertEqual(r_bracket_scheme["normalized"], "https://secure-login.com")

    def test_ipv4_leading_zeros_and_hex(self):
        # Leading zeroes
        res_zero = detect_ioc_type("192.168.01.1")
        self.assertTrue(res_zero["valid"])
        self.assertEqual(res_zero["type"], "IPV4")
        self.assertEqual(res_zero["normalized"], "192.168.1.1")

        res_zero2 = detect_ioc_type("010.000.000.001")
        self.assertTrue(res_zero2["valid"])
        self.assertEqual(res_zero2["normalized"], "10.0.0.1")

        # Hex octets
        res_hex = detect_ioc_type("0x7f.0.0.1")
        self.assertTrue(res_hex["valid"])
        self.assertEqual(res_hex["normalized"], "127.0.0.1")

        res_hex_full = detect_ioc_type("0x7F.0x00.0x00.0x01")
        self.assertTrue(res_hex_full["valid"])
        self.assertEqual(res_hex_full["normalized"], "127.0.0.1")

    def test_ipv6_exploded_and_zone_ids(self):
        # Exploded IPv6 normalization to canonical RFC 5952
        exploded = "2001:0db8:0000:0000:0000:0000:0000:0001"
        res = detect_ioc_type(exploded)
        self.assertTrue(res["valid"])
        self.assertEqual(res["type"], "IPV6")
        self.assertEqual(res["normalized"], "2001:db8::1")

        # Zone ID handling
        zone_ip = "fe80::1%eth0"
        res_zone = detect_ioc_type(zone_ip)
        self.assertTrue(res_zone["valid"])
        self.assertEqual(res_zone["type"], "IPV6")
        self.assertEqual(res_zone["normalized"], "fe80::1")
        self.assertIn("zone ID '%eth0'", res_zone["notes"])

    def test_ipv6_cidr_block(self):
        res = detect_ioc_type("2001:db8::/32")
        self.assertTrue(res["valid"])
        self.assertEqual(res["type"], "IPV6")
        self.assertEqual(res["normalized"], "2001:db8::")
        self.assertIn("/32", res["notes"])

    def test_hash_whitespace_and_invalid_length(self):
        # Whitespace-spaced hash
        spaced_hash = "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855"
        res = detect_ioc_type(spaced_hash)
        self.assertTrue(res["valid"])
        self.assertEqual(res["type"], "SHA256")
        self.assertEqual(res["normalized"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        # Invalid length hash diagnostic
        inv_hash = "a" * 31
        res_inv = detect_ioc_type(inv_hash)
        self.assertFalse(res_inv["valid"])
        self.assertEqual(res_inv["type"], "UNKNOWN")
        self.assertIn("Invalid cryptographic hash length (31 hex characters)", res_inv["notes"])

    def test_idn_punycode_domains(self):
        # Unicode IDN domain
        res_idn = detect_ioc_type("münchen.de")
        self.assertTrue(res_idn["valid"])
        self.assertEqual(res_idn["type"], "DOMAIN")
        self.assertEqual(res_idn["normalized"], "xn--mnchen-3ya.de")

        # Already Punycode
        res_puny = detect_ioc_type("xn--mnchen-3ya.de")
        self.assertTrue(res_puny["valid"])
        self.assertEqual(res_puny["type"], "DOMAIN")
        self.assertEqual(res_puny["normalized"], "xn--mnchen-3ya.de")

    def test_url_with_ipv6_host(self):
        res_url = detect_ioc_type("http://[2001:db8::1]:8080/payload.bin")
        self.assertTrue(res_url["valid"])
        self.assertEqual(res_url["type"], "URL")

    def test_bracketed_scheme_refanging_no_bracket_leak(self):
        # Verify no trailing ']' leak in hxxp[://], meow[://], http[://]
        res_hxxp = detect_ioc_type("hxxp[://]bad[.]com")
        self.assertTrue(res_hxxp["valid"])
        self.assertEqual(res_hxxp["type"], "URL")
        self.assertEqual(res_hxxp["normalized"], "http://bad.com")

        res_meow = detect_ioc_type("meow[://]bad[.]com")
        self.assertTrue(res_meow["valid"])
        self.assertEqual(res_meow["type"], "URL")
        self.assertEqual(res_meow["normalized"], "http://bad.com")

        res_http = detect_ioc_type("http[://]bad[.]com")
        self.assertTrue(res_http["valid"])
        self.assertEqual(res_http["type"], "URL")
        self.assertEqual(res_http["normalized"], "http://bad.com")

    def test_idn_urls_and_ports(self):
        # IDN URL with scheme and path
        res_url = detect_ioc_type("http://münchen.de/path")
        self.assertTrue(res_url["valid"])
        self.assertEqual(res_url["type"], "URL")
        self.assertEqual(res_url["normalized"], "http://xn--mnchen-3ya.de/path")

        # IDN HTTPS
        res_https = detect_ioc_type("https://münchen.de")
        self.assertTrue(res_https["valid"])
        self.assertEqual(res_https["type"], "URL")
        self.assertEqual(res_https["normalized"], "https://xn--mnchen-3ya.de")

        # IDN Domain with Port
        res_port = detect_ioc_type("münchen.de:8080")
        self.assertTrue(res_port["valid"])
        self.assertEqual(res_port["type"], "DOMAIN")
        self.assertEqual(res_port["normalized"], "xn--mnchen-3ya.de")
        self.assertEqual(res_port.get("port"), 8080)

        # IDN URL without scheme
        res_noscheme = detect_ioc_type("münchen.de/path")
        self.assertTrue(res_noscheme["valid"])
        self.assertEqual(res_noscheme["type"], "URL")
        self.assertEqual(res_noscheme["normalized"], "http://xn--mnchen-3ya.de/path")

    def test_ipv6_bracketed_with_path_as_url(self):
        # [2001:db8::1]/path is a URL, not bare IPv6
        res_path = detect_ioc_type("[2001:db8::1]/path")
        self.assertTrue(res_path["valid"])
        self.assertEqual(res_path["type"], "URL")
        self.assertEqual(res_path["normalized"], "http://[2001:db8::1]/path")

        # [2001:db8::1]:8080/path
        res_port_path = detect_ioc_type("[2001:db8::1]:8080/path")
        self.assertTrue(res_port_path["valid"])
        self.assertEqual(res_port_path["type"], "URL")
        self.assertEqual(res_port_path["normalized"], "http://[2001:db8::1]:8080/path")

    def test_hash_prefixes_and_broad_invalid_lengths(self):
        # MD5 with prefix
        res_md5_pfx = detect_ioc_type("md5: 5d41402abc4b2a76b9719d911017c592")
        self.assertTrue(res_md5_pfx["valid"])
        self.assertEqual(res_md5_pfx["type"], "MD5")
        self.assertEqual(res_md5_pfx["normalized"], "5d41402abc4b2a76b9719d911017c592")

        # SHA256 with prefix
        res_sha_pfx = detect_ioc_type("sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertTrue(res_sha_pfx["valid"])
        self.assertEqual(res_sha_pfx["type"], "SHA256")

        # Truncated 30-char hex
        res_30 = detect_ioc_type("a" * 30)
        self.assertFalse(res_30["valid"])
        self.assertIn("Invalid cryptographic hash length (30 hex characters)", res_30["notes"])


if __name__ == "__main__":
    unittest.main()

