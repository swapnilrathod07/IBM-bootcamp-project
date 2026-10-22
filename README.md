# 🛡️ CyberPulse — Threat Intelligence & IOC Analysis Platform
> **IBM Bootcamp Capstone Project Portfolio**  
> *Autonomous Multi-Source SOC Cyber Threat Intelligence Engine & IOC Analyzer*

---

## 📌 Project Overview
**CyberPulse** is an enterprise-grade Cyber Threat Intelligence (CTI) and Security Operations Center (SOC) Command Center developed for the IBM Bootcamp Project. It automates indicator triage (IPs, Domains, URLs, Hashes), predicts adversary attack vectors, visualizes threat infrastructure ontologies, and generates 1-click containment rules (YARA, Sigma, Firewall).

```text
IBM-bootcamp-project/
├── CyberPulse/                  # 🛡️ Core Threat Intelligence Application
│   ├── modules/                 # Security telemetry, scoring, detection & analysis engines
│   │   ├── detector.py          # Multi-format IOC classifier & defanging engine
│   │   ├── scorer.py            # 0-100 risk scoring with exponential time-decay half-life
│   │   ├── attack_analyzer.py   # 9-vector adversary predictor with MITRE ATT&CK mapping
│   │   ├── web_security.py      # SSL/TLS inspection & OWASP defensive headers audit
│   │   ├── rule_gen.py          # 1-click YARA, Sigma YAML & PowerShell/iptables block rules
│   │   ├── graph_gen.py         # Vis.js force-directed threat relationship graph generator
│   │   ├── stix_gen.py          # OASIS STIX 2.1 JSON threat intelligence standard generator
│   │   ├── webhook.py           # SOC alert dispatcher (Discord, Slack, MS Teams)
│   │   ├── history.py           # SQLite audit trail (investigations.db)
│   │   └── mock_data.py         # Deterministic demo fixtures & simulation engine
│   ├── templates/               # SOC Cyber Command Center HTML Interface
│   │   └── index.html           # High-performance glassmorphic UI with CSS Grid
│   ├── tests/                   # Automated unit test suite (187 test cases)
│   ├── server.py                # Flask REST API backend server
│   ├── app.py                   # Streamlit Analytics Dashboard
│   ├── requirements.txt         # Project dependencies
│   └── investigations.db        # Persistent SQLite investigation database
│
├── run.py                       # 🚀 Master 1-Click Root Launcher
├── requirements.txt             # Root dependency manifest
└── README.md                    # Project documentation
```

---

## ⚡ Quick Start (How to Run)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch Cyber Command Center (Web UI)
```bash
python run.py
```
Open **`http://127.0.0.1:5000`** in your browser.

### 3. Launch Streamlit Analytics Dashboard (Alternative UI)
```bash
python run.py --streamlit
```
Open **`http://localhost:8501`** in your browser.

### 4. Run Automated Test Suite
```bash
python run.py --test
```
*(Runs 187 comprehensive unit tests with 100% pass rate).*

---

## 🌟 Key Capabilities & Features

### 1. 🎯 SOC Analyst Lab Interface
- **Unified Executive Triage Island**: 1-row triage summary presenting Score, Status Badge, Indicator, Geolocation, Velocity, and 1-Click Containment.
- **75% Text De-Cluttering**: Clean typography, high-contrast micro-chips, and zero formula fluff.

### 2. 📈 14-Day Attack Activity & Velocity Wave Line Chart
- Smooth SVG vector spline curve mapping incident velocity over 14 days.
- **Dynamic Danger Threshold Line** (`Threshold: 100 hits`) and peak burst milestone markers.
- Visualizes the backend exponential time-decay half-life algorithm ($S(t) = S_0 \cdot e^{-\lambda \Delta t}$).

### 3. 🌳 Interactive Horizontal Attack Tree & Kill Chain Stepper
- 5-stage cyber kill chain progress tracker (`Recon` ➔ `Delivery` ➔ `Exploitation` ➔ `C2 Control` ➔ `Impact`).
- Left-to-right adversary hierarchy mapping indicators directly to real hacker tools (`Mimikatz`, `THC-Hydra`, `Cobalt Strike`).

### 4. 🏠 RFC 1918 & Localhost Protection Engine
- Native zero-download loopback and private subnet detection (`127.0.0.1`, `localhost`, `192.168.x.x`, `10.x.x.x`).
- Accurate `0 / 100 (Safe Internal Asset)` score without fake public botnet false positives.
- Suppresses destructive firewall drop commands on loopback addresses to prevent self-blocking.

### 5. 🕸️ Deep Forensics & Watermark-Free Geolocation
- **Interactive Threat Relationship Graph**: Force-directed ontology (Vis.js) linking Target IOC $\leftrightarrow$ Malware $\leftrightarrow$ Threat Actors $\leftrightarrow$ Infrastructure.
- **Esri World Dark Gray Canvas Map**: Clean, high-contrast dark geolocation map with zero watermarks.

### 6. 🛡️ 1-Click Defensive Containment & Exports
- **Firewall & Detection Rules**: PowerShell `New-NetFirewallRule`, Linux `iptables`, Cisco ACL, YARA (`.yar`), and Sigma YAML.
- **Export Standards**: OASIS STIX 2.1 JSON bundle, Executive PDF dossier, Markdown summary.
- **SOC Webhooks**: Instant alert dispatching to Discord, Slack, and Microsoft Teams.

---

## 🧪 Automated Testing & Verification
The platform includes **187 automated unit tests** spanning 15 specialized suites:
- `test_detector.py`: Multi-format regex IOC detector & RFC 1918 classification
- `test_scorer.py`: Threat risk scoring and time-decay half-life engine
- `test_internal_assets.py`: Loopback, RFC 1918, and firewall safety tests
- `test_velocity.py`: 14-day attack velocity timeline and threshold scaling
- `test_rules.py`: Defensive YARA, Sigma, and firewall rule generation
- `test_graph.py`: Vis.js graph ontology generation and node deduplication
- `test_web_security.py`: SSL/TLS inspection and OWASP defensive headers checklist
- `test_api.py`: Flask REST API endpoints and error boundaries

```bash
>> Ran 187 tests in 0.484s
>> OK (Total Tests Run: 187, Errors: 0, Failures: 0)
>> ALL TESTS PASSED SUCCESSFULLY! <<
```

---

## 👥 Authors & Acknowledgments
- Developed by **Swapnil** as a capstone project for the **IBM Bootcamp**.
- Designed to empower SOC Tier 1/2 analysts and incident responders with rapid, high-confidence threat triage.

---

## 📜 License
This project is licensed under the [MIT License](LICENSE) — see the [LICENSE](LICENSE) file for details.
Copyright (c) 2026 Swapnil (CyberPulse Project). All rights reserved.
