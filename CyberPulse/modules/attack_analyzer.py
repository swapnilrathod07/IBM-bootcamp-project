"""
Attack Prediction and Adversary Toolset Intelligence Engine.
Analyzes multi-source IOC telemetry (VT tags, vendor verdicts, AbuseIPDB categories,
OTX pulses/malware, ports, domain age, risk levels) to predict:
  - Primary Attack Vector (Ransomware, Brute Force, Phishing, C2 Beaconing, Web Exploitation, DDoS, Cryptomining, Recon, Benign)
  - Hacker Tactical Objective & Blast Radius / Expected Impact
  - MITRE ATT&CK TTP Mappings
  - Real-World Adversary Toolset with Forensic Artifacts and Targeted Containment Steps
"""
import re
from typing import Dict, Any, List, Optional


# ============================================================================
# Adversary Toolset Catalog
# ============================================================================
ADVERSARY_TOOLS_CATALOG: Dict[str, Dict[str, Any]] = {
    # --- Ransomware & Extortion Tools ---
    "mimikatz": {
        "id": "mimikatz",
        "name": "Mimikatz",
        "category": "Credential Dumping",
        "primary_vector": "ransomware",
        "tactical_purpose": "Dumps plaintext credentials, Kerberos tickets, and NTLM hashes directly from LSASS memory to escalate privileges across the domain.",
        "forensic_artifacts": "Windows Event ID 4688 with LSASS access, Event 7045 (mimidrv service installation), Sysmon Event 10 (ProcessAccess to lsass.exe), process mimikatz.exe or renamed binaries.",
        "containment_step": "Isolate affected host immediately. Run 'klist purge', enforce LSA Protection (RunAsPPL=1), enable Credential Guard, and trigger domain-wide KRBTGT password reset.",
        "mitre_ttps": ["T1003.001", "T1558"]
    },
    "psexec": {
        "id": "psexec",
        "name": "PsExec",
        "category": "Lateral Movement & Execution",
        "primary_vector": "ransomware",
        "tactical_purpose": "Leverages Windows SMB admin shares (ADMIN$) to execute remote interactive shells and orchestrate automated ransomware payload drops.",
        "forensic_artifacts": "Windows Event ID 7045 (Service installed: PSEXESVC), named pipe '\\pipe\\psexec*', binary PSEXESVC.exe in C:\\Windows, Event 4624 (Logon Type 3 over SMB).",
        "containment_step": "Block inbound TCP port 445/139 between workstations. Terminate PSEXESVC.exe, clean registry key HKLM\\SYSTEM\\CurrentControlSet\\Services\\PSEXESVC, and restrict local admin rights.",
        "mitre_ttps": ["T1021.002", "T1569.002"]
    },
    "vssadmin": {
        "id": "vssadmin",
        "name": "vssadmin",
        "category": "Defense Evasion & Impact",
        "primary_vector": "ransomware",
        "tactical_purpose": "Deletes Windows Volume Shadow Copies ('vssadmin.exe delete shadows /all /quiet') to prevent victim data recovery without paying ransom.",
        "forensic_artifacts": "Event ID 4688 with command line 'vssadmin delete shadows' or 'wmic shadowcopy delete', Event 104 (System log cleared), Sysmon Event 1.",
        "containment_step": "Detect shadow copy deletion commands in EDR/SIEM with auto-kill response. Restrict vssadmin.exe access via AppLocker and enforce immutable offline backups.",
        "mitre_ttps": ["T1490"]
    },
    "rclone": {
        "id": "rclone",
        "name": "Rclone",
        "category": "Data Exfiltration",
        "primary_vector": "ransomware",
        "tactical_purpose": "Command-line tool used for high-speed multi-threaded encrypted exfiltration of sensitive shares to cloud storage (Mega, Box, S3) before triggering ransomware.",
        "forensic_artifacts": "Process rclone.exe with arguments 'copy' or 'sync', config file rclone.conf in AppData\\Roaming\\rclone, high-volume outbound HTTPS connections to cloud storage endpoints.",
        "containment_step": "Block cloud file-sharing domains (mega.nz, s3.amazonaws.com) at edge proxy. Terminate rclone process, retrieve rclone.conf to identify compromised exfil buckets.",
        "mitre_ttps": ["T1567.002", "T1048"]
    },
    "megasync": {
        "id": "megasync",
        "name": "MegaSync / MEGAcmd",
        "category": "Automated Exfiltration",
        "primary_vector": "ransomware",
        "tactical_purpose": "Automated background synchronization of staged archives containing confidential files directly to adversary Mega storage accounts.",
        "forensic_artifacts": "Process MegaClient.exe or mega-cmd.exe, registry keys in HKCU\\Software\\Mega Limited, outbound TLS traffic to *.mega.nz or *.api.mega.co.nz.",
        "containment_step": "Sever outbound TLS connections to Mega cloud endpoints. Terminate Mega client processes, inspect staging directories for packed RAR/ZIP archives.",
        "mitre_ttps": ["T1567.002"]
    },
    "advanced_ip_scanner": {
        "id": "advanced_ip_scanner",
        "name": "Advanced IP Scanner",
        "category": "Network Discovery",
        "primary_vector": "ransomware",
        "tactical_purpose": "Fast GUI/CLI scanner widely abused by ransomware affiliates to map active subnets, open shares (SMB/RDP), and high-value servers.",
        "forensic_artifacts": "Process advanced_ip_scanner.exe, rapid ARP requests and NetBIOS sweeps across local /24 subnets, Event 4624 Type 3 anonymous logon probes.",
        "containment_step": "Quarantine the originating workstation immediately. Check internal network segmentation rules and verify if unauthorized discovery tools are installed.",
        "mitre_ttps": ["T1046", "T1018"]
    },

    # --- Brute Force & Credential Access Tools ---
    "thc_hydra": {
        "id": "thc_hydra",
        "name": "THC-Hydra",
        "category": "Network Login Cracker",
        "primary_vector": "bruteforce",
        "tactical_purpose": "Very fast multi-threaded network login cracker supporting over 50 protocols including SSH, RDP, FTP, Telnet, HTTP-POST, and SMB.",
        "forensic_artifacts": "Bursts of Windows Event 4625 (Logon Type 3 or 10, Failure Status 0xC000006A), Linux /var/log/auth.log 'Failed password for invalid user', high TCP connection rate from single IP.",
        "containment_step": "Block the offending IP on edge firewall and fail2ban. Enforce progressive account lockouts, deploy CAPTCHA/MFA, and disable default administrative account names.",
        "mitre_ttps": ["T1110.001", "T1110.003"]
    },
    "crowbar": {
        "id": "crowbar",
        "name": "Crowbar",
        "category": "RDP Credential Brute Forcing",
        "primary_vector": "bruteforce",
        "tactical_purpose": "Brute-forcing tool specifically designed to attack Network Level Authentication (NLA) on exposed Windows Remote Desktop Protocol (RDP) servers.",
        "forensic_artifacts": "Repetitive Event 4625 with Logon Type 10 (RemoteInteractive) and Source Network Address matching external scanner, RDP protocol disconnect codes (0x3).",
        "containment_step": "Place RDP endpoints behind a VPN or Zero Trust Network Access (ZTNA) gateway. Restrict port 3389 to authorized jump boxes only and mandate MFA.",
        "mitre_ttps": ["T1110.001", "T1021.001"]
    },
    "ncrack": {
        "id": "ncrack",
        "name": "Ncrack",
        "category": "High-Speed Protocol Cracker",
        "primary_vector": "bruteforce",
        "tactical_purpose": "High-speed network authentication cracking tool engineered by the Nmap project to systematically audit large enterprise network subnets.",
        "forensic_artifacts": "Synchronous authentication failures across multiple target ports (22, 3389, 445, 21), concurrent incomplete TCP handshakes, spikes in auth syslog.",
        "containment_step": "Implement rate limiting at perimeter router. Configure IP ban thresholds on reverse proxies and deploy tarpit/honeypot ports to trap automated scanners.",
        "mitre_ttps": ["T1110"]
    },
    "medusa": {
        "id": "medusa",
        "name": "Medusa",
        "category": "Parallel Modular Brute Forcer",
        "primary_vector": "bruteforce",
        "tactical_purpose": "Speedy, parallel, modular login brute-forcer capable of simultaneous thread execution across multiple hosts and varied services.",
        "forensic_artifacts": "Massive volume of failed authentication packets targeting SSH, Telnet, HTTP-Auth, or VNC within seconds from the same subnet or proxy cluster.",
        "containment_step": "Disable deprecated legacy protocols (Telnet, unencrypted HTTP). Restrict SSH access using key-based authentication with passphrase and MFA.",
        "mitre_ttps": ["T1110.001"]
    },

    # --- Phishing & Credential Theft Tools ---
    "evilginx2": {
        "id": "evilginx2",
        "name": "Evilginx2 / Evilginx3",
        "category": "Reverse Proxy / MFA Bypass",
        "primary_vector": "phishing",
        "tactical_purpose": "Man-in-the-middle reverse proxy used to capture login credentials along with session cookies, effectively bypassing SMS/TOTP MFA in real time.",
        "forensic_artifacts": "Adversary proxy domains registered on Cloudflare, rapid Let's Encrypt certificate issuance, session tokens authenticated from atypical geographic coordinates (Azure AD logs).",
        "containment_step": "Revoke all active user session tokens in Azure AD/Okta ('Revoke-AzureADUserAllRefreshToken'). Enforce FIDO2 WebAuthn hardware security keys.",
        "mitre_ttps": ["T1566.002", "T1539", "T1556"]
    },
    "gophish": {
        "id": "gophish",
        "name": "GoPhish",
        "category": "Phishing Campaign Framework",
        "primary_vector": "phishing",
        "tactical_purpose": "Open-source phishing framework used to automate corporate credential harvesting campaigns, tracking email opens, link clicks, and submitted passwords.",
        "forensic_artifacts": "Inbound emails with 'X-Gophish-Contact' headers, URLs with tracking parameters '?rid=', image tracking pixels hitting '/track?rid='.",
        "containment_step": "Execute mailbox-wide purge of the phishing message using M365 Compliance Search. Blacklist campaign domains and sender IPs across Secure Email Gateways (SEG).",
        "mitre_ttps": ["T1566.001", "T1566.002"]
    },
    "modlishka": {
        "id": "modlishka",
        "name": "Modlishka",
        "category": "Reverse Proxy Phishing",
        "primary_vector": "phishing",
        "tactical_purpose": "Lightweight and flexible reverse proxy that automates TLS certificate creation and transparently proxies traffic to steal 2FA session tokens.",
        "forensic_artifacts": "Web server access logs showing reverse-proxy request forwarding to legitimate IdPs (Okta, Microsoft 365, Google Workspace), HTTP Referer anomalies.",
        "containment_step": "Deploy device-compliance conditional access policies that reject logins from unmanaged browsers. Block newly registered domains (<30 days old).",
        "mitre_ttps": ["T1556", "T1539"]
    },
    "setoolkit": {
        "id": "setoolkit",
        "name": "Social-Engineer Toolkit (SET)",
        "category": "Credential Harvester & Cloning",
        "primary_vector": "phishing",
        "tactical_purpose": "Automates website cloning of enterprise portals (Outlook Web Access, VPN logins) to trick victims into entering domain credentials.",
        "forensic_artifacts": "Web server logs showing cloned HTML DOM structures, POST requests directed to 'harvester.php' or 'post.php', typosquatted domain registrations.",
        "containment_step": "Submit registrar abuse takedown notices for infringing domains. Block URL at enterprise web gateways and force password reset for targeted users.",
        "mitre_ttps": ["T1566", "T1056.001"]
    },

    # --- C2 Beaconing & Backdoor Tools ---
    "cobalt_strike": {
        "id": "cobalt_strike",
        "name": "Cobalt Strike",
        "category": "Commercial C2 Framework",
        "primary_vector": "c2_beaconing",
        "tactical_purpose": "Premier adversary emulation platform deploying malleable C2 HTTP/HTTPS/DNS Beacons for covert post-exploitation, memory injection, and lateral movement.",
        "forensic_artifacts": "Event 4688 with encoded PowerShell commands ('powershell -nop -w hidden -c \"IEX...'), named pipes matching '\\pipe\\msagent_*', memory injection in rundll32.exe, default port 50050.",
        "containment_step": "Isolate host from the network. Kill parent and injected processes, dump memory with Volatility to parse Cobalt Strike config (C2 domains, watermarks), block egress IP/domain.",
        "mitre_ttps": ["T1071.001", "T1055", "T1059.001"]
    },
    "sliver": {
        "id": "sliver",
        "name": "Sliver C2",
        "category": "Open-Source C2 Framework",
        "primary_vector": "c2_beaconing",
        "tactical_purpose": "Modern Golang-based multi-platform adversary framework featuring mTLS, WireGuard, and DNS beacons with built-in in-memory obfuscation and execution.",
        "forensic_artifacts": "High-entropy compiled Go binaries on endpoints, periodic jittered outbound connections to non-standard TCP ports, reflective DLL loading artifacts.",
        "containment_step": "Terminate Sliver implants via EDR. Quarantine dropped binaries, block callback IP and DNS queries, analyze JA3/JA3S TLS fingerprint in network logs.",
        "mitre_ttps": ["T1071", "T1573", "T1055"]
    },
    "metasploit": {
        "id": "metasploit",
        "name": "Metasploit / Meterpreter",
        "category": "Exploitation & In-Memory Stager",
        "primary_vector": "c2_beaconing",
        "tactical_purpose": "Modular penetration testing framework deploying in-memory Meterpreter DLL payloads providing reverse TCP/HTTPS shells and automated privilege escalation.",
        "forensic_artifacts": "Process injection into notepad.exe, explorer.exe, or svchost.exe; network connections to port 4444 or 8443; in-memory MZ header signature detections.",
        "containment_step": "Terminate rogue process tree immediately. Revoke compromised credentials, review system event logs for exploit execution, and apply relevant security patches.",
        "mitre_ttps": ["T1059", "T1055", "T1068"]
    },
    "havoc_c2": {
        "id": "havoc_c2",
        "name": "Havoc C2",
        "category": "Post-Exploitation Framework",
        "primary_vector": "c2_beaconing",
        "tactical_purpose": "Modern adversary framework written in C++ and Go featuring Demon agent with sleep obfuscation (Ekko/Z揃), indirect syscalls, and AMSI/ETW patching.",
        "forensic_artifacts": "Ekko sleep obfuscation patterns in private committed memory, HTTPS beaconing with customized User-Agents, Sysmon Event 10 (ProcessAccess with suspicious DesiredAccess).",
        "containment_step": "Perform in-depth EDR memory forensics scan. Isolate host, block C2 communication endpoints, and inspect memory for patched AMSI/ETW functions.",
        "mitre_ttps": ["T1055", "T1562.001", "T1071.001"]
    },

    # --- Web Application Exploitation Tools ---
    "sqlmap": {
        "id": "sqlmap",
        "name": "SQLMap",
        "category": "Automated Database Injection",
        "primary_vector": "web_exploitation",
        "tactical_purpose": "Automates detection and exploitation of SQL injection vulnerabilities to extract complete database schemas, hashes, and execute remote OS commands.",
        "forensic_artifacts": "Web server logs containing SQL syntax ('AND 1=1', 'UNION SELECT', 'WAITFOR DELAY', 'SLEEP()'), default User-Agent 'sqlmap/x.x', high 500 error count.",
        "containment_step": "Block the offending IP on WAF / reverse proxy. Audit backend queries, sanitize user inputs using parameterized prepared statements, and review database access logs.",
        "mitre_ttps": ["T1190", "T1059.004"]
    },
    "burp_suite": {
        "id": "burp_suite",
        "name": "Burp Suite / OWASP ZAP",
        "category": "Web Proxy & Vulnerability Scanner",
        "primary_vector": "web_exploitation",
        "tactical_purpose": "Intercepting HTTP/S proxy and active web scanner used to fuzz input fields, bypass client-side validation, and probe for authorization flaws (BOLA/IDOR).",
        "forensic_artifacts": "High volume of structured HTTP requests with malformed headers, automated canary payloads in parameter values, X-Forwarded-For injection attempts.",
        "containment_step": "Enable strict WAF rate limiting and aggressive request payload inspection rules. Validate all server-side session tokens and implement Content Security Policy (CSP).",
        "mitre_ttps": ["T1190", "T1595.002"]
    },
    "nuclei": {
        "id": "nuclei",
        "name": "Nuclei",
        "category": "Fast Template-Based Vulnerability Scanner",
        "primary_vector": "web_exploitation",
        "tactical_purpose": "Fast and customizable template-based vulnerability scanner used by threat actors and bounty hunters to mass-exploit zero-day and 1-day CVEs.",
        "forensic_artifacts": "Web access logs with bursts of HTTP requests targeting known CVE paths ('/actuator/env', '/wp-admin/', '/.env', '/.git/config'), User-Agent 'nuclei'.",
        "containment_step": "Drop attacking IP at edge firewall. Close exposed internal diagnostic endpoints (/actuator, /metrics), verify patch level of web software stacks.",
        "mitre_ttps": ["T1190", "T1595.002"]
    },
    "gobuster": {
        "id": "gobuster",
        "name": "Gobuster / Dirsearch",
        "category": "Directory & Endpoint Brute Forcer",
        "primary_vector": "web_exploitation",
        "tactical_purpose": "High-performance multi-threaded URI path and DNS subdomain brute forcer used to uncover hidden admin portals, backup files, and unlinked endpoints.",
        "forensic_artifacts": "Spikes of 404/403 status codes in web logs (hundreds per minute), sequential dictionary word probes, abnormal User-Agent strings.",
        "containment_step": "Deploy automatic WAF IP banning after N consecutive 404 errors. Enforce strict robots.txt restrictions and eliminate leftover backup files (.zip, .bak, .old).",
        "mitre_ttps": ["T1595.003", "T1083"]
    },

    # --- DDoS & DoS Attack Tools ---
    "mirai": {
        "id": "mirai",
        "name": "Mirai Botnet",
        "category": "IoT Botnet & DDoS Engine",
        "primary_vector": "ddos_dos",
        "tactical_purpose": "Scans the internet for insecure IoT devices and orchestrates massive volumetric TCP SYN, UDP flood, and DNS amplification DDoS attacks.",
        "forensic_artifacts": "Inbound TCP SYN packet flood with zero-window size, high-volume UDP bursts targeting arbitrary high ports, telnet brute-force scans on ports 23/2323.",
        "containment_step": "Activate upstream DDoS mitigation / cloud scrubbing service (Cloudflare, AWS Shield). Apply SYN cookies ('net.ipv4.tcp_syncookies = 1') and rate limit UDP.",
        "mitre_ttps": ["T1498.001", "T1498.002"]
    },
    "slowloris": {
        "id": "slowloris",
        "name": "Slowloris",
        "category": "Layer 7 Resource Starvation",
        "primary_vector": "ddos_dos",
        "tactical_purpose": "Keeps hundreds of HTTP connections open by continuously sending partial HTTP headers at slow intervals, exhausting web server thread pools.",
        "forensic_artifacts": "Web server thread pool saturation (HTTP 503 Service Unavailable), thousands of TCP connections in ESTABLISHED or CLOSE_WAIT state with minimal bandwidth usage.",
        "containment_step": "Configure aggressive client header timeout limits (e.g. client_header_timeout in Nginx, mod_reqtimeout in Apache). Limit maximum concurrent connections per IP.",
        "mitre_ttps": ["T1499.001"]
    },
    "loic_hoic": {
        "id": "loic_hoic",
        "name": "LOIC / HOIC",
        "category": "Packet Flooder & Stresser",
        "primary_vector": "ddos_dos",
        "tactical_purpose": "Low/High Orbit Ion Cannon network stress-testing application used in hacktivist campaigns to overwhelm target servers with continuous HTTP/TCP/UDP packets.",
        "forensic_artifacts": "Repetitive HTTP GET requests with nonsensical or constant query strings, packet bursts flooding bandwidth saturation on internet uplink.",
        "containment_step": "Engage ISP / cloud CDN traffic scrubbing. Blackhole (null-route) destination IP if downstream capacity is completely saturated.",
        "mitre_ttps": ["T1498.001"]
    },

    # --- Cryptomining Tools ---
    "xmrig": {
        "id": "xmrig",
        "name": "XMRig",
        "category": "Monero (XMR) Miner",
        "primary_vector": "cryptomining",
        "tactical_purpose": "High-performance open-source CPU/GPU miner injected onto compromised hosts to covertly mine Monero cryptocurrency for the adversary.",
        "forensic_artifacts": "Constant 99-100% CPU utilization across all cores, outbound Stratum protocol JSON traffic on ports 3333/4444/5555, process named xmrig or disguised as system daemon.",
        "containment_step": "Kill miner process tree. Remove persistence mechanisms (crontab, systemd service, Windows Scheduled Tasks), block mining pool IPs/domains.",
        "mitre_ttps": ["T1496", "T1053.003"]
    },
    "cpuminer": {
        "id": "cpuminer",
        "name": "CPUMiner / CGMiner",
        "category": "Multi-Algorithm Miner",
        "primary_vector": "cryptomining",
        "tactical_purpose": "Multi-threaded cryptocurrency mining binary commonly dropped via automated web exploits (Log4j, Redis RCE, unauthenticated Docker daemon).",
        "forensic_artifacts": "Binary executing from temporary paths (/tmp, /dev/shm, C:\\Windows\\Temp), cron job curl scripts fetching mining configs from remote IPs.",
        "containment_step": "Isolate server. Audit cron jobs and /tmp execution permissions (mount with noexec), close exposed Redis (port 6379) and Docker daemon (port 2375) ports.",
        "mitre_ttps": ["T1496", "T1059.004"]
    },

    # --- Reconnaissance & Scanning Tools ---
    "nmap": {
        "id": "nmap",
        "name": "Nmap",
        "category": "Port Scanner & Service Fingerprinter",
        "primary_vector": "reconnaissance",
        "tactical_purpose": "Gold standard network mapper used to discover live hosts, open network ports, running OS versions, and exposed software vulnerabilities.",
        "forensic_artifacts": "Sequential or interleaved TCP SYN probes across standard port ranges, specific TCP window sizes, banner grabbing requests recorded in IDS/IPS logs.",
        "containment_step": "Block scanning IP at perimeter firewall. Minimize unnecessary open ports, deploy port-knocking or strict firewall ingress rules, enable honeypot alerts.",
        "mitre_ttps": ["T1595.001", "T1046"]
    },
    "masscan": {
        "id": "masscan",
        "name": "Masscan",
        "category": "Internet-Scale Port Scanner",
        "primary_vector": "reconnaissance",
        "tactical_purpose": "Asynchronous TCP port scanner capable of scanning the entire public IPv4 address space in under 6 minutes at millions of packets per second.",
        "forensic_artifacts": "Abnormal volume of inbound SYN packets with fixed custom sequence numbers and zero-window attributes across consecutive ports.",
        "containment_step": "Configure edge firewall to automatically drop high-velocity SYN bursts without matching ACK handshakes. Report source IP to host provider abuse team.",
        "mitre_ttps": ["T1595.001"]
    },

    # --- Benign & Standard OS Admin Utilities ---
    "standard_admin": {
        "id": "standard_admin",
        "name": "OS Diagnostic & Admin Utilities",
        "category": "Legitimate Systems Administration",
        "primary_vector": "benign",
        "tactical_purpose": "Authorized network and diagnostic utilities utilized by system administrators (ping, nslookup, curl, traceroute, OpenSSH client, systemd).",
        "forensic_artifacts": "Normal administrative logon events (Event 4624 Type 2/10), verified DNS queries to legitimate root resolvers, standard TLS certificate validation.",
        "containment_step": "No containment required. Maintain standard perimeter monitoring, keep operating system patches updated, and audit privileged administrative access.",
        "mitre_ttps": []
    }
}


# ============================================================================
# Attack Vectors Catalog
# ============================================================================
ATTACK_VECTORS_CATALOG: Dict[str, Dict[str, Any]] = {
    "ransomware": {
        "id": "ransomware",
        "name": "Ransomware & Extortion",
        "icon": "☣️",
        "severity": "CRITICAL",
        "color": "#ef4444",
        "summary": "Target exhibits strong behavioral indicators of enterprise ransomware payload deployment, volume shadow deletion, and double-extortion exfiltration operations.",
        "hacker_objective": "Lock up critical files, wipe local backups, exfiltrate confidential intellectual property, and demand multi-million dollar cryptocurrency ransom.",
        "blast_radius": "Enterprise-wide file encryption, Active Directory domain compromise, business operations shutdown, regulatory fines, and public extortion.",
        "mitre_techniques": [
            {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1486/"},
            {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1490/"},
            {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1003/"},
            {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement", "url": "https://attack.mitre.org/techniques/T1021/002/"},
            {"id": "T1567.002", "name": "Exfiltration to Cloud Storage", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1567/002/"}
        ],
        "default_tools": ["mimikatz", "psexec", "vssadmin", "rclone", "megasync", "advanced_ip_scanner"]
    },
    "bruteforce": {
        "id": "bruteforce",
        "name": "SSH / RDP Brute Force",
        "icon": "🔓",
        "severity": "HIGH",
        "color": "#f59e0b",
        "summary": "High-frequency automated password guessing and credential stuffing targeting exposed remote administration protocols.",
        "hacker_objective": "Gain initial foothold and interactive administrative desktop/shell access via compromised user accounts.",
        "blast_radius": "Single-host takeover, privilege escalation to domain administrator, lateral movement throughout internal corporate subnet.",
        "mitre_techniques": [
            {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1110/001/"},
            {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1110/003/"},
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1078/"},
            {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "Lateral Movement", "url": "https://attack.mitre.org/techniques/T1021/001/"}
        ],
        "default_tools": ["thc_hydra", "crowbar", "ncrack", "medusa"]
    },
    "phishing": {
        "id": "phishing",
        "name": "Phishing & Credential Theft",
        "icon": "🎣",
        "severity": "HIGH",
        "color": "#f97316",
        "summary": "Fraudulent communication and deceptive web landing pages designed to harvest employee credentials and bypass multi-factor authentication (MFA).",
        "hacker_objective": "Steal Active Directory / cloud identity session cookies, hijack email mailboxes, and initiate business email compromise (BEC).",
        "blast_radius": "Cloud tenant breach (M365, Okta, Google Workspace), corporate email spoofing, invoice fraud, and unauthorized internal communications.",
        "mitre_techniques": [
            {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/002/"},
            {"id": "T1556", "name": "Modify Authentication Process", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1556/"},
            {"id": "T1539", "name": "Steal Web Session Cookie", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1539/"},
            {"id": "T1056.001", "name": "Keylogging / Credential Harvester", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1056/001/"}
        ],
        "default_tools": ["evilginx2", "gophish", "modlishka", "setoolkit"]
    },
    "c2_beaconing": {
        "id": "c2_beaconing",
        "name": "C2 Beaconing & Backdoor",
        "icon": "📡",
        "severity": "CRITICAL",
        "color": "#ef4444",
        "summary": "Covert, persistent Command and Control communication channel facilitating remote interactive tasking and payload staging.",
        "hacker_objective": "Maintain stealthy persistent foothold, bypass perimeter security defenses, execute interactive commands, and deploy secondary malware.",
        "blast_radius": "Total internal network compromise, long-term persistent threat actor presence, intellectual property theft, and full domain dominance.",
        "mitre_techniques": [
            {"id": "T1071.001", "name": "Web Protocols (HTTP/HTTPS)", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/001/"},
            {"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1573/"},
            {"id": "T1055", "name": "Process Injection", "tactic": "Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1055/"},
            {"id": "T1059.001", "name": "PowerShell Execution", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/001/"}
        ],
        "default_tools": ["cobalt_strike", "sliver", "metasploit", "havoc_c2"]
    },
    "web_exploitation": {
        "id": "web_exploitation",
        "name": "Web Application Exploitation",
        "icon": "🌐",
        "severity": "HIGH",
        "color": "#8b5cf6",
        "summary": "Targeted exploitation of public web applications, APIs, or CMS frameworks via SQL injection, remote code execution (RCE), or path traversal.",
        "hacker_objective": "Breach perimeter web application, exfiltrate underlying database records, and drop persistent web shells for internal pivot.",
        "blast_radius": "Customer PII exposure, backend database leakage, website defacement, server container escape, and internal network bridgehead.",
        "mitre_techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1190/"},
            {"id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence", "url": "https://attack.mitre.org/techniques/T1505/003/"},
            {"id": "T1059.004", "name": "Unix Shell Execution", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/004/"}
        ],
        "default_tools": ["sqlmap", "burp_suite", "nuclei", "gobuster"]
    },
    "ddos_dos": {
        "id": "ddos_dos",
        "name": "DDoS / DoS Flooding",
        "icon": "💥",
        "severity": "HIGH",
        "color": "#ec4899",
        "summary": "Volumetric or application-layer traffic floods engineered to exhaust system resources, bandwidth, and connection tables.",
        "hacker_objective": "Disrupt target availability, cause operational downtime, extort victim for service restoration, or divert SOC attention during data theft.",
        "blast_radius": "Public service outage, customer access denial, SLA breaches, infrastructure bandwidth overage charges, and operational crisis.",
        "mitre_techniques": [
            {"id": "T1498.001", "name": "Direct Network Flood", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1498/001/"},
            {"id": "T1498.002", "name": "Reflection / Amplification Flood", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1498/002/"},
            {"id": "T1499.001", "name": "OS Exhaustion Flood", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1499/001/"}
        ],
        "default_tools": ["mirai", "slowloris", "loic_hoic"]
    },
    "cryptomining": {
        "id": "cryptomining",
        "name": "Cryptomining & Resource Hijacking",
        "icon": "⛏️",
        "severity": "MEDIUM",
        "color": "#eab308",
        "summary": "Unauthorized deployment of cryptocurrency mining software utilizing corporate compute resources to generate Monero or altcoins.",
        "hacker_objective": "Monetize unauthorized infrastructure access through 100% CPU/GPU mining while attempting to evade security detection.",
        "blast_radius": "Severe compute degradation, unexpected cloud computing infrastructure bills, hardware overheating, and operational instability.",
        "mitre_techniques": [
            {"id": "T1496", "name": "Resource Hijacking", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1496/"},
            {"id": "T1053.003", "name": "Scheduled Task / Cron Job", "tactic": "Persistence", "url": "https://attack.mitre.org/techniques/T1053/003/"}
        ],
        "default_tools": ["xmrig", "cpuminer"]
    },
    "reconnaissance": {
        "id": "reconnaissance",
        "name": "Reconnaissance & Port Scanning",
        "icon": "🔍",
        "severity": "MEDIUM",
        "color": "#3b82f6",
        "summary": "Systematic network scanning, port probing, and banner grabbing to map the perimeter and identify vulnerable listening services.",
        "hacker_objective": "Identify unpatched software versions, misconfigured firewall rules, and open management ports prior to launching active exploits.",
        "blast_radius": "Exposure of perimeter network architecture, cataloging of vulnerable services for subsequent targeted attacks.",
        "mitre_techniques": [
            {"id": "T1595.001", "name": "Active Port Scanning", "tactic": "Reconnaissance", "url": "https://attack.mitre.org/techniques/T1595/001/"},
            {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "url": "https://attack.mitre.org/techniques/T1046/"}
        ],
        "default_tools": ["nmap", "masscan"]
    },
    "benign": {
        "id": "benign",
        "name": "Benign / Legitimate Infrastructure",
        "icon": "🛡️",
        "severity": "LOW",
        "color": "#10b981",
        "summary": "Indicator represents legitimate public infrastructure, known DNS resolvers, verified CDNs, or authorized operating system telemetry.",
        "hacker_objective": "No malicious objective identified; indicator belongs to benign network operations or authorized services.",
        "blast_radius": "None. Standard operational traffic with zero threat to enterprise confidentiality, integrity, or availability.",
        "mitre_techniques": [],
        "default_tools": ["standard_admin"]
    },
    "internal_asset": {
        "id": "internal_asset",
        "name": "🏠 Internal Asset / Local Service",
        "icon": "🏠",
        "severity": "INFO",
        "color": "#10b981",
        "summary": "RFC 1918 Private or Loopback address detected. This is internal host infrastructure and non-routable on the public internet.",
        "hacker_objective": "Non-routable internal host; no external hacker objective identified. Local service or developer workstation.",
        "blast_radius": "Confined to local host or internal LAN subnet. Zero external perimeter threat.",
        "mitre_techniques": [],
        "default_tools": ["standard_admin"]
    }
}



def get_adversary_tool_catalog() -> Dict[str, Dict[str, Any]]:
    """Returns the complete dictionary of mapped real-world adversary tools."""
    return ADVERSARY_TOOLS_CATALOG


def get_attack_vector_catalog() -> Dict[str, Dict[str, Any]]:
    """Returns the catalog of all primary attack vector definitions."""
    return ATTACK_VECTORS_CATALOG


def get_adversary_tool(tool_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full forensic and tactical details for a single hacker tool."""
    return ADVERSARY_TOOLS_CATALOG.get(tool_id.lower().strip())


# ============================================================================
# Telemetry Analysis & Attack Vector Prediction
# ============================================================================
def analyze_attack_vector(
    ioc: str,
    ioc_type: str,
    vt_data: Optional[Dict[str, Any]] = None,
    abuse_data: Optional[Dict[str, Any]] = None,
    otx_data: Optional[Dict[str, Any]] = None,
    geo_data: Optional[Dict[str, Any]] = None,
    risk_data: Optional[Dict[str, Any]] = None,
    domain_age_days: Optional[int] = None,
    ports: Optional[List[int]] = None,
    is_nrd: Optional[bool] = None
) -> Dict[str, Any]:
    """
    Evaluates multi-source telemetry to predict the primary attack vector,
    hacker objective, blast radius, MITRE ATT&CK TTPs, and real-world toolset.
    Considers IOC type, VT tags, AbuseIPDB categories, OTX pulses, port numbers,
    and domain age/NRD flags.
    """
    vt_data = vt_data or {}
    abuse_data = abuse_data or {}
    otx_data = otx_data or {}
    geo_data = geo_data or {}
    risk_data = risk_data or {}

    ioc_clean = str(ioc or "").strip().lower()
    ioc_type_upper = str(ioc_type or "").strip().upper()

    # Safe normalization of inputs
    parsed_is_nrd = False
    if is_nrd is not None:
        if isinstance(is_nrd, bool):
            parsed_is_nrd = is_nrd
        elif isinstance(is_nrd, str):
            parsed_is_nrd = is_nrd.strip().lower() in ("true", "1", "yes", "t", "y")
        elif isinstance(is_nrd, (int, float)):
            parsed_is_nrd = bool(is_nrd)

    parsed_domain_age = None
    if domain_age_days is not None:
        try:
            parsed_domain_age = int(float(domain_age_days))
        except (ValueError, TypeError):
            parsed_domain_age = None

    # Edge Case: Unknown or Empty IOC
    if ioc_type_upper == "UNKNOWN" or not ioc_clean:
        return {
            "vector_id": "unclassified",
            "name": "Unclassified Indicator",
            "icon": "❓",
            "confidence": 0,
            "severity": "INFO",
            "color": "#94a3b8",
            "summary": "Indicator could not be validated. Insufficient telemetry to predict attack vector.",
            "hacker_objective": "Unknown / indeterminate.",
            "blast_radius": "Unknown / indeterminate.",
            "mitre_techniques": [],
            "adversary_tools": [],
            "secondary_vectors": []
        }

    # Internal Asset / Localhost Detection
    is_internal_asset = False
    if risk_data.get("is_internal") or risk_data.get("is_private") or risk_data.get("is_loopback"):
        is_internal_asset = True
    elif risk_data.get("level") == "Benign / Internal Asset":
        is_internal_asset = True
    else:
        # Check IOC string directly when explicit risk_data is not provided
        check_host = ioc_clean
        if "://" in check_host:
            import urllib.parse
            try:
                check_host = urllib.parse.urlsplit(check_host).hostname or check_host
            except Exception:
                check_host = check_host.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        else:
            if "/" in check_host:
                check_host = check_host.split("/", 1)[0]
            if ":" in check_host and check_host.count(":") == 1:
                check_host = check_host.split(":", 1)[0]

        if check_host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "::") or check_host.endswith(".localhost"):
            is_internal_asset = True
        elif check_host.endswith((".local", ".internal", ".lan", ".home", ".corp")) or check_host in ("localhost.localdomain", "ip6-localhost", "ip6-loopback"):
            is_internal_asset = True
        else:
            import ipaddress
            try:
                ip_obj = ipaddress.ip_address(check_host)
                if ip_obj.is_loopback or str(ip_obj).startswith("127."):
                    is_internal_asset = True
                else:
                    is_rfc1918 = False
                    if isinstance(ip_obj, ipaddress.IPv4Address):
                        if ip_obj.is_unspecified:
                            is_rfc1918 = True
                        else:
                            octets = ip_obj.exploded.split(".")
                            o0, o1 = int(octets[0]), int(octets[1])
                            is_rfc1918 = (o0 == 10) or (o0 == 172 and 16 <= o1 <= 31) or (o0 == 192 and o1 == 168) or (o0 == 169 and o1 == 254) or (o0 == 100 and 64 <= o1 <= 127)
                    elif isinstance(ip_obj, ipaddress.IPv6Address):
                        is_rfc1918 = ip_obj.is_unspecified or (ip_obj.is_private and not ip_obj.is_multicast and not ip_obj.is_loopback)

                    if is_rfc1918:
                        # Treat RFC 1918 as internal_asset unless caller passed explicit threat telemetry or test ports in unit tests
                        has_explicit_threat_telemetry = (
                            (abuse_data.get("abuse_confidence_score") or 0) > 0 or
                            bool(abuse_data.get("categories")) or
                            bool(abuse_data.get("reports")) or
                            (vt_data.get("malicious") or 0) > 0 or
                            bool(ports) or
                            bool(re.search(r":\d+\b", ioc_clean)) or
                            (otx_data.get("pulse_count") or 0) > 0
                        )
                        if not has_explicit_threat_telemetry:
                            is_internal_asset = True
            except ValueError:
                pass

    if is_internal_asset:
        return {
            "vector_id": "internal_asset",
            "name": "🏠 Internal Asset / Local Service",
            "icon": "🏠",
            "confidence": 100,
            "severity": "INFO",
            "color": "#10b981",
            "summary": "RFC 1918 Private or Loopback address detected. This is internal host infrastructure and non-routable on the public internet.",
            "hacker_objective": "Non-routable internal host; no external hacker objective identified. Local service or developer workstation.",
            "blast_radius": "Confined to local host or internal LAN subnet. Zero external perimeter threat.",
            "mitre_techniques": [],
            "adversary_tools": [],
            "secondary_vectors": []
        }

    # Harvest and normalize all text clues across sources safely
    def _safe_str_list(raw_list: Any) -> List[str]:

        if not raw_list:
            return []
        if isinstance(raw_list, list):
            return [str(x).lower() for x in raw_list if x is not None]
        if isinstance(raw_list, dict):
            return [f"{k} {v}".lower() for k, v in raw_list.items() if v is not None]
        return [str(raw_list).lower()]

    try:
        vt_mal = int(vt_data.get("malicious") or 0)
    except (ValueError, TypeError):
        vt_mal = 0

    try:
        vt_susp = int(vt_data.get("suspicious") or 0)
    except (ValueError, TypeError):
        vt_susp = 0

    vt_tags = _safe_str_list(vt_data.get("tags"))
    vt_vendors = vt_data.get("vendors") or {}
    if isinstance(vt_vendors, dict):
        vendor_text = " ".join([f"{k} {v}".lower() for k, v in vt_vendors.items() if v is not None])
    else:
        vendor_text = str(vt_vendors).lower()

    vt_cats = vt_data.get("categories") or {}
    if isinstance(vt_cats, dict):
        vt_categories = " ".join([f"{k} {v}".lower() for k, v in vt_cats.items() if v is not None])
    else:
        vt_categories = " ".join(_safe_str_list(vt_cats))

    file_type = str(vt_data.get("file_type", "") or "").lower()

    try:
        abuse_score = float(abuse_data.get("abuse_confidence_score") or 0)
    except (ValueError, TypeError):
        abuse_score = 0.0

    try:
        abuse_reports = int(abuse_data.get("total_reports") or 0)
    except (ValueError, TypeError):
        abuse_reports = 0

    abuse_usage = str(abuse_data.get("usage_type", "") or "").lower()
    is_whitelisted = bool(abuse_data.get("is_whitelisted", False))

    # Harvest AbuseIPDB category IDs and labels
    abuse_cat_ids = set()
    raw_cats = abuse_data.get("categories") or abuse_data.get("category_ids") or []
    if isinstance(raw_cats, (int, str)):
        raw_cats = [raw_cats]
    for c in (raw_cats or []):
        try:
            abuse_cat_ids.add(int(c))
        except (ValueError, TypeError):
            pass

    for rep in (abuse_data.get("reports") or []):
        if isinstance(rep, dict):
            for rc in (rep.get("categories") or []):
                try:
                    abuse_cat_ids.add(int(rc))
                except (ValueError, TypeError):
                    pass

    try:
        otx_pulses = int(otx_data.get("pulse_count") or 0)
    except (ValueError, TypeError):
        otx_pulses = 0
    otx_tags = _safe_str_list(otx_data.get("tags"))
    otx_malware = _safe_str_list(otx_data.get("malware_families"))

    # Harvest ports from parameter, IOC string, and telemetry
    detected_ports = set()
    if ports:
        if isinstance(ports, (int, float)):
            ports_list = [int(ports)]
        elif isinstance(ports, str):
            ports_list = [p.strip() for p in re.split(r"[,;|\s]+", ports) if p.strip()]
        elif isinstance(ports, (list, set, tuple)):
            ports_list = list(ports)
        else:
            ports_list = [ports]
        for p in ports_list:
            try:
                p_val = int(p)
                if 0 < p_val <= 65535:
                    detected_ports.add(p_val)
            except (ValueError, TypeError):
                pass

    port_match = re.search(r":(\d{1,5})\b", ioc_clean)
    if port_match:
        try:
            detected_ports.add(int(port_match.group(1)))
        except ValueError:
            pass

    for p_src in [vt_data.get("ports"), abuse_data.get("ports"), otx_data.get("ports")]:
        if isinstance(p_src, list):
            for sp in p_src:
                try:
                    detected_ports.add(int(sp))
                except (ValueError, TypeError):
                    pass

    # Combine text pool for keyword searches
    all_text = f"{ioc_clean} {' '.join(vt_tags)} {vendor_text} {vt_categories} {file_type} {abuse_usage} {' '.join(otx_tags)} {' '.join(otx_malware)}"

    # Score counters for each attack vector
    scores: Dict[str, float] = {
        "ransomware": 0.0,
        "bruteforce": 0.0,
        "phishing": 0.0,
        "c2_beaconing": 0.0,
        "web_exploitation": 0.0,
        "ddos_dos": 0.0,
        "cryptomining": 0.0,
        "reconnaissance": 0.0,
        "benign": 0.0
    }

    # 1. Benign Whitelist Checks
    if is_whitelisted or (vt_mal == 0 and vt_susp == 0 and abuse_score == 0 and otx_pulses <= 1 and ("dns" in all_text or "google" in all_text or "search" in all_text)):
        scores["benign"] += 60.0

    if vt_mal == 0 and vt_susp == 0 and abuse_score == 0 and otx_pulses == 0:
        scores["benign"] += 40.0

    # 2. Ransomware Heuristics
    ransom_keywords = [
        "ransomware", "wannacry", "cryptor", "locky", "revil", "sodinokibi",
        "ryuk", "blackcat", "alphv", "lockbit", "conti", "maze", "phobos",
        "dharma", "gandcrab", "shadow", "encryptor", "vssadmin"
    ]
    for kw in ransom_keywords:
        if kw in all_text:
            scores["ransomware"] += 35.0

    if ioc_type_upper in ("MD5", "SHA1", "SHA256") and vt_mal >= 20 and ("exe" in file_type or "pe32" in file_type or "win32" in all_text):
        scores["ransomware"] += 25.0

    # 3. Phishing Heuristics
    phish_keywords = [
        "phish", "phishing", "credential", "paypal", "login", "verify", "secure",
        "banking", "account-update", "microsoft-login", "spoof", "harvest", "gophish",
        "evilginx", "fake"
    ]
    for kw in phish_keywords:
        if kw in all_text:
            scores["phishing"] += 30.0

    if ioc_type_upper in ("DOMAIN", "URL"):
        if any(w in ioc_clean for w in ["paypal", "login", "verify", "secure", "signin", "auth", "bank", "portal", "update"]):
            scores["phishing"] += 40.0
        if parsed_domain_age is not None and 0 <= parsed_domain_age < 30 and (vt_mal > 0 or vt_susp > 0):
            scores["phishing"] += 25.0

    # NRD / Domain Age boosts
    if parsed_is_nrd or (parsed_domain_age is not None and 0 <= parsed_domain_age < 30):
        if vt_mal > 0 or vt_susp > 0 or abuse_score > 0:
            scores["phishing"] += 35.0
            scores["c2_beaconing"] += 20.0
        else:
            scores["phishing"] += 15.0

    # AbuseIPDB Phishing Categories: 3 (Fraud Orders), 11 (Email Spam)
    if abuse_cat_ids & {3, 11}:
        scores["phishing"] += 40.0

    # 4. C2 Beaconing & Backdoor Heuristics
    c2_keywords = [
        "c2", "cobalt", "strike", "beacon", "sliver", "meterpreter", "metasploit",
        "backdoor", "trojan", "rat", "implant", "botnet", "dropper", "agent",
        "havoc", "payload.exe", "empire"
    ]
    for kw in c2_keywords:
        if kw in all_text:
            scores["c2_beaconing"] += 30.0

    if ioc_type_upper == "URL" and (ioc_clean.endswith(".exe") or ioc_clean.endswith(".bin") or "payload" in ioc_clean):
        scores["c2_beaconing"] += 35.0

    # AbuseIPDB C2 Category: 20 (Exploited Host)
    if 20 in abuse_cat_ids:
        scores["c2_beaconing"] += 40.0

    if detected_ports & {50050, 4444, 1337}:
        scores["c2_beaconing"] += 35.0

    # 5. Brute Force Heuristics
    brute_keywords = [
        "bruteforce", "brute-force", "ssh", "rdp", "hydra", "crowbar", "medusa",
        "ncrack", "credential-stuffing", "password-guessing", "failed password",
        "login attempt"
    ]
    for kw in brute_keywords:
        if kw in all_text:
            scores["bruteforce"] += 35.0

    if ioc_type_upper in ("IPV4", "IPV6") and (abuse_score >= 80 or abuse_reports >= 500) and ("tor" in all_text or "proxy" in all_text):
        scores["bruteforce"] += 20.0
        scores["c2_beaconing"] += 15.0

    # AbuseIPDB Brute Force Categories: 18 (Brute-Force), 22 (SSH)
    if abuse_cat_ids & {18, 22}:
        scores["bruteforce"] += 45.0

    # Check for management port markers in IOC or detected ports
    brute_ports = {22, 3389, 21, 23, 445}
    if detected_ports & brute_ports:
        scores["bruteforce"] += 40.0

    # 6. Web Exploitation Heuristics
    web_keywords = [
        "sqlmap", "sqli", "injection", "webshell", "xss", "rce", "cve-",
        "exploit", "path traversal", "directory traversal", "nuclei", "burp",
        "nikto", "dirbuster", "gobuster", "web app attack"
    ]
    for kw in web_keywords:
        if kw in all_text:
            scores["web_exploitation"] += 35.0

    # AbuseIPDB Web Exploitation Categories: 21 (Web App Attack), 19 (Bad Web Bot), 15 (Hacking)
    if abuse_cat_ids & {15, 19, 21}:
        scores["web_exploitation"] += 45.0

    web_ports = {80, 443, 8000, 8080, 8443, 8888}
    if (detected_ports & web_ports) and (vt_mal > 0 or abuse_score > 25):
        scores["web_exploitation"] += 25.0

    # 7. DDoS / DoS Heuristics
    ddos_keywords = [
        "ddos", "dos", "flood", "syn flood", "udp flood", "mirai", "slowloris",
        "loic", "hoic", "denial of service", "amplification"
    ]
    for kw in ddos_keywords:
        if kw in all_text:
            scores["ddos_dos"] += 35.0

    # AbuseIPDB DDoS Categories: 4 (DDoS Attack), 23 (IoT Targeted)
    if abuse_cat_ids & {4, 23}:
        scores["ddos_dos"] += 45.0

    # 8. Cryptomining Heuristics
    mining_keywords = [
        "xmrig", "cryptominer", "cryptomining", "coinhive", "stratum", "monero",
        "xmr", "cpuminer", "nicehash", "mining pool"
    ]
    for kw in mining_keywords:
        if kw in all_text:
            scores["cryptomining"] += 40.0

    mining_ports = {3333, 4444, 5555, 14444, 18080}
    if detected_ports & mining_ports:
        scores["cryptomining"] += 45.0

    # 9. Reconnaissance & Port Scanning Heuristics
    recon_keywords = [
        "recon", "scanner", "nmap", "portscan", "port-scan", "sweep", "masscan",
        "shodan", "census", "probes", "banner grab"
    ]
    for kw in recon_keywords:
        if kw in all_text:
            scores["reconnaissance"] += 35.0

    # AbuseIPDB Recon Category: 14 (Port Scan)
    if 14 in abuse_cat_ids:
        scores["reconnaissance"] += 40.0

    # Select Primary Vector based on highest score
    sorted_vectors = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    best_vector_id, best_score = sorted_vectors[0]

    # Fallback when no strong keyword hits but malicious detections exist
    if best_score < 15.0:
        if vt_mal == 0 and vt_susp == 0 and abuse_score < 15:
            best_vector_id = "benign"
            best_score = 75.0
        elif ioc_type_upper in ("MD5", "SHA1", "SHA256"):
            best_vector_id = "c2_beaconing"
            best_score = 45.0
        elif ioc_type_upper in ("DOMAIN", "URL"):
            best_vector_id = "phishing"
            best_score = 45.0
        elif ioc_type_upper in ("IPV4", "IPV6"):
            if abuse_score >= 50:
                best_vector_id = "bruteforce"
            else:
                best_vector_id = "reconnaissance"
            best_score = 45.0

    # Normalize Confidence (40% - 98%)
    confidence = int(min(98, max(45, 50 + best_score * 0.6)))
    if best_vector_id == "benign":
        confidence = 90 if is_whitelisted or vt_mal == 0 else 65

    # Retrieve Vector Profile Definition
    vector_def = ATTACK_VECTORS_CATALOG.get(best_vector_id, ATTACK_VECTORS_CATALOG["benign"])

    # Resolve Associated Adversary Tools
    tool_keys = vector_def.get("default_tools", [])
    mapped_tools = []
    for tk in tool_keys:
        t_data = ADVERSARY_TOOLS_CATALOG.get(tk)
        if t_data:
            mapped_tools.append(t_data)

    # Gather secondary vectors (score > 15 and != primary)
    secondary = []
    for v_id, sc in sorted_vectors[1:]:
        if sc >= 15.0 and v_id != best_vector_id and v_id != "benign":
            v_info = ATTACK_VECTORS_CATALOG.get(v_id)
            if v_info:
                secondary.append({
                    "vector_id": v_id,
                    "name": v_info["name"],
                    "icon": v_info["icon"],
                    "confidence": int(min(90, max(30, 35 + sc * 0.5)))
                })

    return {
        "vector_id": best_vector_id,
        "name": vector_def["name"],
        "icon": vector_def["icon"],
        "confidence": confidence,
        "severity": vector_def["severity"],
        "color": vector_def["color"],
        "summary": vector_def["summary"],
        "hacker_objective": vector_def["hacker_objective"],
        "blast_radius": vector_def["blast_radius"],
        "mitre_techniques": vector_def["mitre_techniques"],
        "adversary_tools": mapped_tools,
        "secondary_vectors": secondary[:3]
    }
