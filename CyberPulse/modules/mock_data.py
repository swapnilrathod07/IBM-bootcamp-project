"""
High-Fidelity Mock Threat Telemetry Fixtures and Dynamic Generator for Demo / Simulation Mode.
Provides realistic threat intelligence data out of the box without requiring API keys.
"""
import hashlib
import ipaddress
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple


def is_rfc1918_or_internal_ip(ip_obj) -> bool:
    """Checks if IP is RFC 1918 private, RFC 6598 CGNAT, RFC 3927 link-local, RFC 1122 unspecified, or RFC 4193 ULA."""
    if isinstance(ip_obj, ipaddress.IPv4Address):
        if ip_obj.is_unspecified:
            return True
        octets = ip_obj.exploded.split(".")
        o0, o1 = int(octets[0]), int(octets[1])
        if o0 == 10:
            return True
        if o0 == 172 and 16 <= o1 <= 31:
            return True
        if o0 == 192 and o1 == 168:
            return True
        if o0 == 169 and o1 == 254:
            return True
        if o0 == 100 and 64 <= o1 <= 127:
            return True
        return False
    elif isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.is_unspecified:
            return True
        return ip_obj.is_private and not ip_obj.is_multicast and not ip_obj.is_loopback
    return False


def _is_internal_asset(ioc: str, ioc_type: str = "") -> Tuple[bool, bool]:
    """Returns (is_internal, is_loopback) for a given indicator."""
    if not ioc:
        return False, False
    clean = str(ioc).strip().lower()
    host = clean
    if "://" in clean:
        try:
            host = urllib.parse.urlsplit(clean).hostname or clean
        except Exception:
            host = clean.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    else:
        if "/" in clean:
            clean = clean.split("/", 1)[0]
        if ":" in clean and clean.count(":") == 1:
            host = clean.split(":", 1)[0]
        else:
            host = clean

    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "::") or host.endswith(".localhost"):
        return True, host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")
    if host.endswith((".local", ".internal", ".lan", ".home", ".corp")) or host in ("localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        return True, host in ("localhost.localdomain", "ip6-localhost", "ip6-loopback")

    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or str(ip).startswith("127."):
            return True, True
        if is_rfc1918_or_internal_ip(ip):
            return True, False
    except ValueError:
        pass
    return False, False



# Known Pre-Engineered SOC Samples for Instant Testing
MOCK_DATABASE = {
    # 1. Tor Exit Node / High Abuse IP
    "185.220.101.5": {
        "ioc_type": "IPV4",
        "virustotal": {
            "status": "success",
            "malicious": 16,
            "suspicious": 3,
            "harmless": 68,
            "undetected": 7,
            "reputation": -35,
            "as_owner": "Zwiebelfreunde e.V.",
            "country": "DE",
            "vendors": {
                "CrowdStrike Falcon": "Malicious / Tor Exit Node",
                "Kaspersky": "Malicious / Suspicious Network",
                "Sophos": "Malicious / Anonymous Proxy",
                "Microsoft": "Clean / Harmless",
                "BitDefender": "Malicious / Threat Actor Infrastructure",
                "Fortinet": "Malicious / Proxy",
                "Cisco Talos": "Suspicious / High Volume Scanner",
                "Mandiant": "Malicious / Tor Relay",
            }
        },
        "abuseipdb": {
            "status": "success",
            "abuse_confidence_score": 100,
            "total_reports": 2841,
            "distinct_users": 394,
            "country_code": "DE",
            "country_name": "Germany",
            "isp": "Zwiebelfreunde e.V.",
            "domain": "torservers.net",
            "usage_type": "Data Center / Web Hosting / Transit",
            "is_whitelisted": False,
            "last_reported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        },
        "alienvault": {
            "status": "success",
            "pulse_count": 42,
            "pulses": [
                {"name": "Active Tor Exit Relays - Worldwide Feed", "author": "AlienVault OTX Labs", "tags": ["tor", "proxy", "anonymizer"]},
                {"name": "Cobalt Strike C2 Relay via Anonymization Nodes", "author": "Mandiant SOC", "tags": ["cobalt-strike", "c2", "apt"]},
                {"name": "Credential Stuffing Source IP Cluster", "author": "Unit42", "tags": ["bruteforce", "credential-stuffing"]}
            ],
            "tags": ["tor", "proxy", "anonymizer", "cobalt-strike", "c2", "bruteforce"],
            "malware_families": ["Cobalt Strike", "Mirai Botnet"]
        },
        "geolocation": {
            "status": "success",
            "country": "Germany",
            "country_code": "DE",
            "region": "SN",
            "region_name": "Saxony",
            "city": "Dresden",
            "zip": "01067",
            "lat": 51.0504,
            "lon": 13.7373,
            "timezone": "Europe/Berlin",
            "isp": "Zwiebelfreunde e.V.",
            "org": "Tor Exit Relay Network",
            "as_info": "AS200651 Zwiebelfreunde e.V."
        }
    },

    # 2. Benign Google Public DNS IP
    "8.8.8.8": {
        "ioc_type": "IPV4",
        "virustotal": {
            "status": "success",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 88,
            "undetected": 5,
            "reputation": 120,
            "as_owner": "Google LLC",
            "country": "US",
            "vendors": {
                "CrowdStrike Falcon": "Clean",
                "Kaspersky": "Clean",
                "Sophos": "Clean",
                "Microsoft": "Clean",
                "BitDefender": "Clean",
                "Fortinet": "Clean",
                "Cisco Talos": "Clean",
                "Mandiant": "Clean",
            }
        },
        "abuseipdb": {
            "status": "success",
            "abuse_confidence_score": 0,
            "total_reports": 12,
            "distinct_users": 4,
            "country_code": "US",
            "country_name": "United States",
            "isp": "Google LLC",
            "domain": "google.com",
            "usage_type": "Commercial / Public Anycast DNS",
            "is_whitelisted": True,
            "last_reported_at": "2026-10-18T09:12:00+00:00"
        },
        "alienvault": {
            "status": "success",
            "pulse_count": 2,
            "pulses": [
                {"name": "Public Anycast DNS Resolvers Whitelist", "author": "OTX Community", "tags": ["dns", "whitelist", "benign"]}
            ],
            "tags": ["dns", "google", "resolver"],
            "malware_families": []
        },
        "geolocation": {
            "status": "success",
            "country": "United States",
            "country_code": "US",
            "region": "VA",
            "region_name": "Virginia",
            "city": "Ashburn",
            "zip": "20149",
            "lat": 39.0438,
            "lon": -77.4874,
            "timezone": "America/New_York",
            "isp": "Google LLC",
            "org": "Google Public DNS",
            "as_info": "AS15169 Google LLC"
        }
    },

    # 3. Suspicious Reconnaissance / Port Scanner IP
    "45.33.32.156": {
        "ioc_type": "IPV4",
        "virustotal": {
            "status": "success",
            "malicious": 3,
            "suspicious": 4,
            "harmless": 72,
            "undetected": 15,
            "reputation": -8,
            "as_owner": "Linode, LLC",
            "country": "US",
            "vendors": {
                "CrowdStrike Falcon": "Clean",
                "Kaspersky": "Suspicious / Network Scanner",
                "Sophos": "Clean",
                "Microsoft": "Clean",
                "BitDefender": "Suspicious / Port Sweep",
                "Fortinet": "Malicious / Scanner",
                "Cisco Talos": "Suspicious / Masscan Activity",
                "Mandiant": "Clean",
            }
        },
        "abuseipdb": {
            "status": "success",
            "abuse_confidence_score": 48,
            "total_reports": 89,
            "distinct_users": 23,
            "country_code": "US",
            "country_name": "United States",
            "isp": "Linode, LLC",
            "domain": "scanme.nmap.org",
            "usage_type": "Data Center / Cloud Hosting",
            "is_whitelisted": False,
            "last_reported_at": "2026-10-21T08:15:00+00:00"
        },
        "alienvault": {
            "status": "success",
            "pulse_count": 6,
            "pulses": [
                {"name": "Nmap Authorized Testing & Scanning Server", "author": "Security Research", "tags": ["scanner", "nmap", "recon"]},
                {"name": "Automated Port Sweep Telemetry", "author": "OTX Community", "tags": ["recon", "portscan"]}
            ],
            "tags": ["recon", "nmap", "scanner"],
            "malware_families": []
        },
        "geolocation": {
            "status": "success",
            "country": "United States",
            "country_code": "US",
            "region": "NJ",
            "region_name": "New Jersey",
            "city": "Newark",
            "zip": "07102",
            "lat": 40.7357,
            "lon": -74.1724,
            "timezone": "America/New_York",
            "isp": "Linode, LLC",
            "org": "Akamai Cloud / Linode",
            "as_info": "AS63949 Akamai Connected Cloud"
        }
    },

    # 4. WannaCry Ransomware Sample SHA-256
    "ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc": {
        "ioc_type": "SHA256",
        "virustotal": {
            "status": "success",
            "malicious": 68,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 4,
            "reputation": -98,
            "file_type": "Win32 EXE (PE32 executable)",
            "file_size": 3514368,
            "magic_header": "PE32 executable (GUI) Intel 80386, for MS Windows",
            "vendors": {
                "CrowdStrike Falcon": "Win/malicious_confidence_100% (D)",
                "Kaspersky": "Ransom.Win32.Wanna.m",
                "Sophos": "Troj/Wanna-G",
                "Microsoft": "Ransom:Win32/WannaCrypt",
                "BitDefender": "Gen:Variant.Ransom.WannaCryptor.1",
                "Fortinet": "W32/WannaCryptor.A!tr",
                "Cisco Talos": "W32.WannaCry.Ransomware",
                "Mandiant": "UNC757 / WannaCry Decryptor Component",
            }
        },
        "abuseipdb": {"status": "not_applicable"},
        "alienvault": {
            "status": "success",
            "pulse_count": 89,
            "pulses": [
                {"name": "WannaCry Global Ransomware Outbreak (EternalBlue)", "author": "US-CERT", "tags": ["wannacry", "eternalblue", "ms17-010"]},
                {"name": "Lazarus Group Campaign Indicators", "author": "CISA Alert", "tags": ["lazarus", "apt38", "north-korea"]},
                {"name": "Killswitch Domain & Dropper Binaries", "author": "MalwareTech", "tags": ["killswitch", "ransomware"]}
            ],
            "tags": ["wannacry", "eternalblue", "ms17-010", "ransomware", "lazarus", "apt38"],
            "malware_families": ["WannaCry", "WanaCrypt0r", "Lazarus"]
        },
        "geolocation": {"status": "not_applicable"}
    },

    # 5. Benign Domain: google.com
    "google.com": {
        "ioc_type": "DOMAIN",
        "virustotal": {
            "status": "success",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 92,
            "undetected": 2,
            "reputation": 450,
            "categories": {"Forcepoint": "Search Engines", "Sophos": "Search Engines", "OpenDNS": "Search Engines"},
            "vendors": {
                "CrowdStrike Falcon": "Clean",
                "Kaspersky": "Clean",
                "Sophos": "Clean",
                "Microsoft": "Clean",
                "BitDefender": "Clean",
                "Google Safebrowsing": "Clean",
            }
        },
        "abuseipdb": {"status": "not_applicable"},
        "alienvault": {
            "status": "success",
            "pulse_count": 1,
            "pulses": [
                {"name": "Top 1M Umbrella Benign Domain Feed", "author": "Cisco Umbrella", "tags": ["benign", "alexa-top-1m"]}
            ],
            "tags": ["search", "google", "benign"],
            "malware_families": []
        },
        "geolocation": {"status": "not_applicable"}
    },

    # 6. Malicious Phishing Domain
    "secure-login-paypal-verify.com": {
        "ioc_type": "DOMAIN",
        "virustotal": {
            "status": "success",
            "malicious": 32,
            "suspicious": 5,
            "harmless": 12,
            "undetected": 38,
            "reputation": -58,
            "categories": {"Forcepoint": "Phishing and Other Scams", "Sophos": "Malicious Sites"},
            "vendors": {
                "CrowdStrike Falcon": "Malicious / Phishing",
                "Kaspersky": "HEUR:Trojan-Spy.HTML.Paypal.a",
                "Sophos": "Malicious / Credential Harvester",
                "Microsoft": "Phish:HTML/PaypalPhish",
                "BitDefender": "Phishing.Gen",
                "Google Safebrowsing": "Phishing Site Warning",
            }
        },
        "abuseipdb": {"status": "not_applicable"},
        "alienvault": {
            "status": "success",
            "pulse_count": 18,
            "pulses": [
                {"name": "Financially Motivated PayPal Credential Harvesting Kit", "author": "PhishLabs Intel", "tags": ["paypal", "phishing", "scam"]},
                {"name": "Spoofed Brand Identity Campaign Q3", "author": "OTX Threat Hunter", "tags": ["brand-abuse", "typosquatting"]}
            ],
            "tags": ["phishing", "paypal", "credential-harvesting", "spoofing"],
            "malware_families": ["GenericPhishKit"]
        },
        "geolocation": {"status": "not_applicable"}
    },

    # 7. Malicious C2 Dropper URL
    "http://bad-c2-update.org/payload.exe": {
        "ioc_type": "URL",
        "virustotal": {
            "status": "success",
            "malicious": 42,
            "suspicious": 6,
            "harmless": 8,
            "undetected": 30,
            "reputation": -75,
            "categories": {"Forcepoint": "Malicious Web Sites", "Sophos": "Malware Repository"},
            "vendors": {
                "CrowdStrike Falcon": "Malicious / Dropper Distribution",
                "Kaspersky": "Malicious / C2 Binary URL",
                "Sophos": "Troj/Dropper-BC",
                "Microsoft": "Exploit:Win32/C2Dropper",
                "BitDefender": "Trojan.GenericKD.Payload",
                "Google Safebrowsing": "Malware Distribution Point",
            }
        },
        "abuseipdb": {"status": "not_applicable"},
        "alienvault": {
            "status": "success",
            "pulse_count": 25,
            "pulses": [
                {"name": "Emotet / TrickBot Secondary Stage Payload URL", "author": "Cryptolaemus Intel", "tags": ["emotet", "trickbot", "c2-payload"]},
                {"name": "Compromised CMS Host Distributing Binaries", "author": "AlienVault OTX", "tags": ["compromised-cms", "dropper"]}
            ],
            "tags": ["emotet", "dropper", "c2", "trickbot"],
            "malware_families": ["Emotet", "TrickBot"]
        },
        "geolocation": {"status": "not_applicable"}
    }
}


def generate_mock_telemetry(ioc: str, ioc_type: str) -> Dict[str, Any]:
    """
    Generates a deterministic and realistic mock telemetry payload for any IOC
    when running in Demo Mode or when API keys are not supplied.
    """
    normalized = ioc.strip().lower()

    # If exact match exists in pre-configured database
    if normalized in MOCK_DATABASE:
        return MOCK_DATABASE[normalized]

    # Suppress false alarms for internal / RFC 1918 / loopback indicators
    is_internal, is_loop = _is_internal_asset(normalized, ioc_type)
    if is_internal:
        geo_city = "Local Loopback" if is_loop else "Private Subnet"
        return {
            "ioc_type": ioc_type,
            "virustotal": {
                "status": "success",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 88,
                "undetected": 5,
                "reputation": 100,
                "vendors": {
                    "CrowdStrike Falcon": "Clean / Internal Network Asset",
                    "Kaspersky": "Clean / Internal Network Asset",
                    "Sophos": "Clean / Harmless Localhost",
                    "Microsoft": "Clean / Internal Network Asset",
                    "BitDefender": "Clean / Private Subnet",
                    "Cisco Talos": "Clean / Internal Asset",
                    "Mandiant": "Clean / Non-Routable Asset"
                }
            },
            "abuseipdb": {
                "status": "success" if ioc_type in ("IPV4", "IPV6") else "not_applicable",
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "distinct_users": 0,
                "country_code": "LOCAL",
                "country_name": "Internal Network",
                "isp": "Local Loopback / Private Subnet",
                "domain": "localhost" if is_loop else "local",
                "usage_type": "Loopback / RFC 1918 Private Subnet",
                "is_whitelisted": True,
                "last_reported_at": None
            },
            "alienvault": {
                "status": "success",
                "pulse_count": 0,
                "pulses": [],
                "tags": ["internal-network", "rfc1918", "loopback", "non-routable"],
                "malware_families": []
            },
            "geolocation": {
                "status": "internal",
                "country": "Internal Network",
                "country_code": "LOCAL",
                "region": "Localhost" if is_loop else "LAN",
                "region_name": "Internal Subnet",
                "city": geo_city,
                "zip": "00000",
                "lat": 0.0,
                "lon": 0.0,
                "timezone": "UTC",
                "isp": "Local Loopback / Private Subnet",
                "org": "Internal Network Infrastructure",
                "as_info": "RFC 1918 / Non-Routable"
            }
        }


    # Deterministic generation using SHA256 of the input
    h = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    int_seed = int(h[:8], 16)

    # Heuristic: Check if string has suspicious keywords
    suspicious_keywords = ["bad", "malware", "phish", "trojan", "c2", "ransom", "attack", "hack", "evil", "stealer", "dropper"]
    is_suspicious_by_name = any(k in normalized for k in suspicious_keywords)

    if is_suspicious_by_name:
        malicious_count = 25 + (int_seed % 35)
        suspicious_count = 3 + (int_seed % 5)
        abuse_score = 75 + (int_seed % 25)
        pulse_count = 12 + (int_seed % 20)
        reputation = -40 - (int_seed % 50)
        tags = ["threat-actor", "malicious-activity", "c2-traffic", "credential-abuse"]
        families = ["Trojan.Generic", "Stealer.Agent"]
    else:
        # Pseudo-random classification: 70% benign, 20% moderate, 10% high
        score_mod = int_seed % 100
        if score_mod < 70:
            malicious_count = 0
            suspicious_count = 0
            abuse_score = 0
            pulse_count = int_seed % 2
            reputation = 50 + (int_seed % 50)
            tags = ["benign", "verified-asset"]
            families = []
        elif score_mod < 90:
            malicious_count = 2 + (int_seed % 4)
            suspicious_count = 3 + (int_seed % 3)
            abuse_score = 30 + (int_seed % 25)
            pulse_count = 3 + (int_seed % 5)
            reputation = -5 - (int_seed % 15)
            tags = ["suspicious-activity", "low-reputation"]
            families = ["Adware.Generic"]
        else:
            malicious_count = 20 + (int_seed % 25)
            suspicious_count = 4 + (int_seed % 4)
            abuse_score = 80 + (int_seed % 20)
            pulse_count = 10 + (int_seed % 15)
            reputation = -50 - (int_seed % 40)
            tags = ["botnet", "command-and-control"]
            families = ["Mirai.Variant"]

    vt_vendors = {
        "CrowdStrike Falcon": "Malicious" if malicious_count > 15 else ("Suspicious" if malicious_count > 0 else "Clean"),
        "Kaspersky": "Malicious" if malicious_count > 10 else "Clean",
        "Sophos": "Malicious" if malicious_count > 5 else "Clean",
        "Microsoft": "Malicious" if malicious_count > 20 else "Clean",
        "BitDefender": "Malicious" if malicious_count > 12 else "Clean",
        "Cisco Talos": "Suspicious" if suspicious_count > 2 else "Clean",
        "Mandiant": "Malicious" if malicious_count > 18 else "Clean",
    }

    # Geolocation for IPs
    geo_data = {"status": "not_applicable"}
    if ioc_type in ("IPV4", "IPV6"):
        countries = [
            ("United States", "US", 37.751, -122.419, "San Francisco", "Cloudflare, Inc."),
            ("Germany", "DE", 52.520, 13.405, "Berlin", "Hetzner Online GmbH"),
            ("Netherlands", "NL", 52.370, 4.895, "Amsterdam", "DigitalOcean, LLC"),
            ("Singapore", "SG", 1.352, 103.820, "Singapore", "Amazon.com, Inc."),
            ("United Kingdom", "GB", 51.507, -0.127, "London", "British Telecom")
        ]
        selected_geo = countries[int_seed % len(countries)]
        geo_data = {
            "status": "success",
            "country": selected_geo[0],
            "country_code": selected_geo[1],
            "region": "State",
            "region_name": selected_geo[4],
            "city": selected_geo[4],
            "zip": "00000",
            "lat": selected_geo[2],
            "lon": selected_geo[3],
            "timezone": "UTC",
            "isp": selected_geo[5],
            "org": selected_geo[5],
            "as_info": f"AS{10000 + (int_seed % 50000)} {selected_geo[5]}"
        }

    return {
        "ioc_type": ioc_type,
        "virustotal": {
            "status": "success",
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "harmless": 70,
            "undetected": 10,
            "reputation": reputation,
            "vendors": vt_vendors
        },
        "abuseipdb": {
            "status": "success" if ioc_type in ("IPV4", "IPV6") else "not_applicable",
            "abuse_confidence_score": abuse_score if ioc_type in ("IPV4", "IPV6") else 0,
            "total_reports": (abuse_score * 12) if ioc_type in ("IPV4", "IPV6") else 0,
            "distinct_users": (abuse_score * 3) if ioc_type in ("IPV4", "IPV6") else 0,
            "country_code": geo_data.get("country_code", "US"),
            "country_name": geo_data.get("country", "Unknown"),
            "isp": geo_data.get("isp", "Unknown ISP"),
            "domain": "network.net",
            "usage_type": "Commercial / Hosting",
            "is_whitelisted": False,
            "last_reported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        },
        "alienvault": {
            "status": "success",
            "pulse_count": pulse_count,
            "pulses": [
                {"name": f"Automated Intelligence Cluster #{int_seed % 999}", "author": "OTX Hunter", "tags": tags[:2]}
            ] if pulse_count > 0 else [],
            "tags": tags,
            "malware_families": families
        },
        "geolocation": geo_data
    }
