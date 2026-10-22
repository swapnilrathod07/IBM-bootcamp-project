"""
CYBERPULSE // SOC Threat Intelligence & IOC Scanner Dashboard.
Modern Streamlit Application with Multi-Source Telemetry, Unified Risk Scoring, and Report Generation.
"""
import streamlit as st
import pandas as pd
import json
import io
import time
import re
from datetime import datetime

# Set Streamlit Page Configuration (Must be first Streamlit command)
st.set_page_config(
    page_title="CyberPulse SOC Threat Intel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Import internal modules
from config import (
    APP_TITLE, APP_SUBTITLE, APP_VERSION, SOC_COLORS,
    get_env_api_keys, is_default_demo_mode
)
from modules.detector import detect_ioc_type, defang_ioc, refang_ioc, IOC_TYPES
from modules.virustotal import query_virustotal
from modules.abuseipdb import query_abuseipdb
from modules.alienvault import query_alienvault
from modules.geolocation import query_geolocation
from modules.scorer import calculate_risk_score, generate_attack_velocity
from modules.history import (
    save_investigation, get_history, get_history_stats,
    clear_history, get_investigation_by_id, delete_investigation
)
from modules.report_gen import generate_json_report, generate_markdown_report, generate_pdf_report
from modules.rule_gen import generate_all_defensive_rules, generate_yara_rule, generate_sigma_rule, generate_firewall_commands
from modules.graph_gen import generate_threat_graph
from modules.stix_gen import generate_stix_json
from modules.webhook import dispatch_webhook_alert
from modules.attack_analyzer import analyze_attack_vector, get_adversary_tool, get_attack_vector_catalog
from modules.web_security import audit_website_security
import streamlit.components.v1 as components

# Attempt Plotly for Gauge Visualization
try:
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False


# =====================================================================
# SOC-Grade Custom CSS Styling
# =====================================================================
def apply_custom_styles():
    st.markdown("""
    <style>
    /* Dark SOC Command Center Theme */
    .stApp {
        background-color: #0b0f19;
        color: #f3f4f6;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Top Header Bar */
    .soc-header {
        background: linear-gradient(135deg, #111827 0%, #1e1b4b 100%);
        border: 1px solid #1f2937;
        border-radius: 12px;
        padding: 20px 26px;
        margin-bottom: 22px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .soc-header h1 {
        color: #00f0ff;
        font-size: 26px;
        font-weight: 800;
        letter-spacing: 1.5px;
        margin: 0;
        text-transform: uppercase;
    }
    .soc-header p {
        color: #94a3b8;
        font-size: 13px;
        margin-top: 6px;
        margin-bottom: 0;
    }

    /* Metric Cards */
    .soc-card {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 16px;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .soc-card:hover {
        border-color: #3b82f6;
        transform: translateY(-2px);
    }
    .soc-card-label {
        color: #9ca3af;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .soc-card-value {
        color: #f9fafb;
        font-size: 22px;
        font-weight: 700;
        margin-top: 4px;
        font-family: 'JetBrains Mono', 'Fira Code', monospace;
    }
    
    /* Risk Badges */
    .badge-low {
        display: inline-block;
        background-color: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid #10b981;
        border-radius: 6px;
        padding: 4px 10px;
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .badge-medium {
        display: inline-block;
        background-color: rgba(245, 158, 11, 0.15);
        color: #f59e0b;
        border: 1px solid #f59e0b;
        border-radius: 6px;
        padding: 4px 10px;
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .badge-high {
        display: inline-block;
        background-color: rgba(239, 68, 68, 0.15);
        color: #ef4444;
        border: 1px solid #ef4444;
        border-radius: 6px;
        padding: 4px 10px;
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    /* Indicator Type Pill */
    .type-pill {
        display: inline-block;
        background-color: rgba(59, 130, 246, 0.15);
        color: #60a5fa;
        border: 1px solid #3b82f6;
        border-radius: 4px;
        padding: 3px 8px;
        font-size: 11px;
        font-weight: 600;
        font-family: monospace;
    }

    /* Monospace Code Callouts */
    .mono-text {
        font-family: 'JetBrains Mono', 'Consolas', monospace;
        color: #38bdf8;
    }
    
    /* Streamlit Tab Customization */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #1f2937;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #111827;
        border-radius: 6px 6px 0 0;
        color: #94a3b8;
        padding: 10px 18px;
        border: 1px solid #1f2937;
        border-bottom: none;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1e293b !important;
        color: #00f0ff !important;
        border-color: #3b82f6 !important;
    }
    </style>
    """, unsafe_allow_html=True)


# =====================================================================
# State Management Initialization
# =====================================================================
if "ioc_input" not in st.session_state:
    st.session_state.ioc_input = "185.220.101.5"  # Default sample Tor node

if "last_investigation" not in st.session_state:
    st.session_state.last_investigation = None

if "trigger_scan" not in st.session_state:
    st.session_state.trigger_scan = True

if "bulk_results" not in st.session_state:
    st.session_state.bulk_results = None


# =====================================================================
# Sidebar: Settings, API Keys, Demo Mode & Quick Samples
# =====================================================================
def render_sidebar():
    with st.sidebar:
        st.markdown("### 🛡️ SOC ENGINE CONFIG")
        st.caption(f"CyberPulse Core {APP_VERSION}")

        # Demo / Simulation Mode Toggle
        env_demo = is_default_demo_mode()
        demo_mode = st.toggle(
            "⚡ Demo / Simulation Mode",
            value=env_demo,
            help="When active, realistic threat telemetry is simulated for instant testing without requiring external API keys."
        )

        st.markdown("---")
        st.markdown("#### 🔑 Threat API Integrations")
        
        env_keys = get_env_api_keys()
        
        # VirusTotal Key
        vt_key = st.text_input(
            "VirusTotal v3 API Key",
            value=env_keys.get("virustotal", ""),
            type="password",
            help="Free key from virustotal.com/gui/join-us"
        )
        if vt_key:
            st.caption("🟢 VT Key Configured (Live API)")
        else:
            st.caption("🟡 No VT Key (Simulation Fallback)")

        # AbuseIPDB Key
        abuse_key = st.text_input(
            "AbuseIPDB v2 API Key",
            value=env_keys.get("abuseipdb", ""),
            type="password",
            help="Free key from abuseipdb.com/register"
        )
        if abuse_key:
            st.caption("🟢 AbuseIPDB Configured (Live API)")
        else:
            st.caption("🟡 No AbuseIPDB Key (Simulation Fallback)")

        # AlienVault OTX Key
        otx_key = st.text_input(
            "AlienVault OTX Key",
            value=env_keys.get("alienvault", ""),
            type="password",
            help="Community key from otx.alienvault.com/api"
        )
        if otx_key:
            st.caption("🟢 OTX Configured (Live API)")
        else:
            st.caption("🟡 No OTX Key (Simulation Fallback)")

        st.markdown("---")
        st.markdown("#### 🎯 Quick Test Samples")
        st.caption("Click to load pre-engineered SOC test indicators:")

        col_s1, col_s2 = st.columns(2)
        with col_s1:
            if st.button("🚨 Tor Exit Node", use_container_width=True):
                st.session_state.ioc_input = "185.220.101.5"
                st.session_state.trigger_scan = True
                st.rerun()
            if st.button("🦠 WannaCry Hash", use_container_width=True):
                st.session_state.ioc_input = "ed01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc"
                st.session_state.trigger_scan = True
                st.rerun()
            if st.button("🎣 Phish Domain", use_container_width=True):
                st.session_state.ioc_input = "secure-login-paypal-verify[.]com"
                st.session_state.trigger_scan = True
                st.rerun()

        with col_s2:
            if st.button("🟢 Google DNS", use_container_width=True):
                st.session_state.ioc_input = "8.8.8.8"
                st.session_state.trigger_scan = True
                st.rerun()
            if st.button("🌐 Google.com", use_container_width=True):
                st.session_state.ioc_input = "google.com"
                st.session_state.trigger_scan = True
                st.rerun()
            if st.button("⚠️ Scanner IP", use_container_width=True):
                st.session_state.ioc_input = "45.33.32.156:8080"
                st.session_state.trigger_scan = True
                st.rerun()

        st.markdown("---")
        # History Quick Stats in Sidebar
        stats = get_history_stats()
        st.markdown("#### 📊 Triage Audit Stats")
        st.markdown(f"- Total Scans: **{stats['total_scans']}**")
        st.markdown(f"- Critical Threats: <font color='#ef4444'><b>{stats['critical_threats']}</b></font>", unsafe_allow_html=True)
        st.markdown(f"- Suspicious Items: <font color='#f59e0b'><b>{stats['suspicious_indicators']}</b></font>", unsafe_allow_html=True)
        st.markdown(f"- Benign Assets: <font color='#10b981'><b>{stats['benign_assets']}</b></font>", unsafe_allow_html=True)

        return {
            "demo_mode": demo_mode,
            "vt_key": vt_key.strip(),
            "abuse_key": abuse_key.strip(),
            "otx_key": otx_key.strip()
        }


# =====================================================================
# Plotly Threat Score Gauge
# =====================================================================
def render_risk_gauge(score: int, level: str, color_hex: str):
    """Draws an interactive Threat Risk Gauge using Plotly."""
    if not PLOTLY_AVAILABLE:
        st.metric(label="Unified Risk Score", value=f"{score}/100", delta=level)
        return

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "<b>UNIFIED RISK INDEX</b>", 'font': {'size': 14, 'color': '#94a3b8'}},
        number={'suffix': "/100", 'font': {'size': 36, 'color': color_hex, 'family': 'JetBrains Mono'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#475569"},
            'bar': {'color': color_hex, 'thickness': 0.3},
            'bgcolor': "#1e293b",
            'borderwidth': 1,
            'bordercolor': "#334155",
            'steps': [
                {'range': [0, 20], 'color': 'rgba(16, 185, 129, 0.15)'},
                {'range': [20, 60], 'color': 'rgba(245, 158, 11, 0.15)'},
                {'range': [60, 100], 'color': 'rgba(239, 68, 68, 0.2)'}
            ],
            'threshold': {
                'line': {'color': color_hex, 'width': 4},
                'thickness': 0.75,
                'value': score
            }
        }
    ))

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=220,
        margin=dict(l=15, r=15, t=30, b=10)
    )
    st.plotly_chart(fig, use_container_width=True)


# =====================================================================
# Threat Stage Pipeline & 3-Step Attack Story Engine
# =====================================================================
def compute_threat_stages(attacks: dict, risk: dict, ioc: str, ioc_type: str, geo_data: dict) -> dict:
    attacks = attacks or {}
    risk = risk or {}
    geo_data = geo_data or {}
    risk_score = risk.get("score", 0) if isinstance(risk, dict) else 0
    vector_id = (attacks.get("vector_id") or attacks.get("id") or "").lower()
    name = (attacks.get("name") or "").lower()
    ioc_lower = (ioc or "").lower()
    ioc_type_upper = (ioc_type or "").upper()
    isp = (geo_data.get("isp") or "").lower()
    summary = (attacks.get("summary") or "").lower()

    is_hash = ioc_type_upper in ("SHA256", "MD5", "SHA1") or bool(re.match(r'^[a-f0-9]{32,64}$', ioc_lower))
    is_domain_or_url = ioc_type_upper in ("DOMAIN", "URL") or ".com" in ioc_lower or "http" in ioc_lower

    is_tor = not is_hash and not is_domain_or_url and (
        "185.220.101.5" in ioc_lower
        or "zwiebelfreunde" in isp
        or bool(re.search(r'\btor\b', isp))
        or bool(re.search(r'\btor\s+(?:exit|relay|node|proxy|network)\b', summary))
    )
    is_nrd = bool(attacks.get("is_nrd"))

    # 1. Benign assets
    if risk_score <= 20 or vector_id == "benign" or "benign" in name:
        return {
            "active_stages": [],
            "badge_text": "🟢 NO ACTIVE ATTACK PHASE",
            "badge_color": "#10b981",
            "badge_bg": "rgba(16, 185, 129, 0.15)",
            "badge_border": "#10b981",
            "desc": "Asset verified clean or whitelisted infrastructure. Zero active cyber kill chain stages observed."
        }

    # 2. Ransomware / Malware Execution -> Stage 5 (Actions / Impact)
    if vector_id in ("ransomware", "cryptomining", "ddos_dos") or "ransom" in name or "miner" in name or "dos" in name or "impact" in name or (is_hash and risk_score > 60):
        return {
            "active_stages": [5],
            "badge_text": "STAGE 5 ACTIVE (ACTIONS / IMPACT)",
            "badge_color": "#ef4444",
            "badge_bg": "rgba(239, 68, 68, 0.15)",
            "badge_border": "#ef4444",
            "desc": "Adversary has reached impact phase: file encryption, volumetric resource denial, or data extortion."
        }

    # 3. C2 / Dropper -> Stage 4 (C2 Control)
    if vector_id == "c2_beaconing" or "c2" in name or "beacon" in name or "backdoor" in name or "dropper" in name:
        return {
            "active_stages": [4],
            "badge_text": "STAGE 4 ACTIVE (C2 CONTROL)",
            "badge_color": "#ef4444",
            "badge_bg": "rgba(239, 68, 68, 0.15)",
            "badge_border": "#ef4444",
            "desc": "Active command-and-control beaconing, interactive tasking, or secondary payload staging detected."
        }

    # 4. Phishing / NRD -> Stage 2 (Delivery)
    if vector_id == "phishing" or "phish" in name or is_nrd:
        return {
            "active_stages": [2],
            "badge_text": "STAGE 2 ACTIVE (INITIAL DELIVERY)",
            "badge_color": "#f97316",
            "badge_bg": "rgba(249, 115, 22, 0.15)",
            "badge_border": "#f97316",
            "desc": "Adversary is staging deceptive communication or cloned web portals to deliver phishing lure payloads."
        }

    # 5. Web Exploitation -> Stage 3 (Exploitation)
    if vector_id == "web_exploitation" or "web" in name or "exploit" in name:
        return {
            "active_stages": [3],
            "badge_text": "STAGE 3 ACTIVE (EXPLOITATION)",
            "badge_color": "#8b5cf6",
            "badge_bg": "rgba(139, 92, 246, 0.15)",
            "badge_border": "#8b5cf6",
            "desc": "Active exploitation of perimeter application vulnerabilities (SQLi, RCE, directory traversal)."
        }

    # 6. Tor Exit / Brute-Force / Port Scan -> Stages 1 & 3 (Recon / Exploitation)
    if is_tor or vector_id in ("bruteforce", "reconnaissance") or "brute" in name or "recon" in name or "port scan" in name:
        return {
            "active_stages": [1, 3],
            "badge_text": "STAGES 1 & 3 ACTIVE (RECON & EXPLOITATION)",
            "badge_color": "#f59e0b",
            "badge_bg": "rgba(245, 158, 11, 0.15)",
            "badge_border": "#f59e0b",
            "desc": "Adversary is conducting automated scanning, network reconnaissance, and remote credential brute-force attempts."
        }

    # 7. Severity fallback
    if risk_score > 75:
        return {
            "active_stages": [4, 5],
            "badge_text": "STAGES 4 & 5 ACTIVE (C2 & IMPACT)",
            "badge_color": "#ef4444",
            "badge_bg": "rgba(239, 68, 68, 0.15)",
            "badge_border": "#ef4444",
            "desc": "Critical threat activity detected across advanced operational stages."
        }
    elif risk_score > 40:
        return {
            "active_stages": [3],
            "badge_text": "STAGE 3 ACTIVE (EXPLOITATION)",
            "badge_color": "#f59e0b",
            "badge_bg": "rgba(245, 158, 11, 0.15)",
            "badge_border": "#f59e0b",
            "desc": "Active perimeter probing and exploitation observed."
        }
    else:
        return {
            "active_stages": [1],
            "badge_text": "STAGE 1 ACTIVE (DISCOVERY/RECON)",
            "badge_color": "#3b82f6",
            "badge_bg": "rgba(59, 130, 246, 0.15)",
            "badge_border": "#3b82f6",
            "desc": "Early-stage adversary reconnaissance and probe scanning."
        }


def compute_attack_story(attacks: dict, risk: dict, ioc: str, ioc_type: str, geo_data: dict, vt_data: dict, abuse_data: dict) -> dict:
    attacks = attacks or {}
    risk = risk or {}
    geo_data = geo_data or {}
    vt_data = vt_data or {}
    abuse_data = abuse_data or {}
    risk_score = risk.get("score", 0) if isinstance(risk, dict) else 0
    vector_id = (attacks.get("vector_id") or attacks.get("id") or "").lower()
    name = attacks.get("name") or "Adversary Activity"
    ioc_lower = (ioc or "").lower()
    ioc_type_upper = (ioc_type or "").upper()
    isp = (geo_data.get("isp") or "").lower()
    summary = (attacks.get("summary") or "").lower()

    is_hash = ioc_type_upper in ("SHA256", "MD5", "SHA1") or bool(re.match(r'^[a-f0-9]{32,64}$', ioc_lower))
    is_domain_or_url = ioc_type_upper in ("DOMAIN", "URL") or ".com" in ioc_lower or "http" in ioc_lower

    is_tor = not is_hash and not is_domain_or_url and (
        "185.220.101.5" in ioc_lower
        or "zwiebelfreunde" in isp
        or bool(re.search(r'\btor\b', isp))
        or bool(re.search(r'\btor\s+(?:exit|relay|node|proxy|network)\b', summary))
    )

    is_internal = (
        risk.get("is_internal")
        or vector_id == "internal_asset"
        or "internal" in name.lower()
        or "internal" in str(risk.get("level", "")).lower()
        or ioc_lower in ("localhost", "127.0.0.1", "::1")
        or "127.0.0.1" in ioc_lower
        or "localhost" in ioc_lower
        or ioc_lower.startswith("192.168.")
        or ioc_lower.startswith("10.")
    )

    if is_internal:
        return {
            "is_benign": True,
            "is_internal": True,
            "who": {
                "title": "1. INTERNAL ASSET",
                "badge": "🏠 LOCALHOST / INTERNAL",
                "badge_color": "#10b981",
                "entity": "Internal Loopback / RFC 1918 Private Asset",
                "detail": "Non-routable internal host infrastructure. Public threat feeds hold zero malicious telemetry.",
                "footer": "INTERNAL 🏠"
            },
            "attempt": {
                "title": "2. OBSERVED ACTIVITY",
                "badge": "LOCAL SERVICE",
                "badge_color": "#10b981",
                "entity": "Local Development / Internal Subnet",
                "detail": "Service bound to local interface. Standard software development or internal LAN communication.",
                "footer": "LOCAL 🏠"
            },
            "impact": {
                "title": "3. RISK TO ENTERPRISE",
                "badge": "SAFE INTERNAL",
                "badge_color": "#10b981",
                "entity": "Zero External Attack Risk",
                "detail": "Do NOT apply perimeter firewall block (blocking 127.0.0.1 disrupts local host networking). Audit local ports.",
                "footer": "SAFE 🛡️"
            }
        }

    # 1. Benign assets
    if risk_score <= 20 or vector_id == "benign" or "benign" in name.lower():
        is_google_dns = "8.8.8.8" in ioc_lower or "8[.]8[.]8[.]8" in ioc_lower

        who_entity = "Google Public DNS Anycast Resolver" if is_google_dns else ("Google Global Cloud Infrastructure" if ("google.com" in ioc_lower or "google[.]com" in ioc_lower) else "Verified Legitimate Host")
        return {
            "is_benign": True,
            "who": {
                "title": "1. VERIFIED ASSET",
                "badge": "VERIFIED BENIGN",
                "badge_color": "#10b981",
                "entity": who_entity,
                "detail": "Authenticated public infrastructure with 0 malicious reports across 70+ threat feeds.",
                "footer": "VERIFIED ➔"
            },
            "attempt": {
                "title": "2. OBSERVED ACTIVITY",
                "badge": "NORMAL TRAFFIC",
                "badge_color": "#10b981",
                "entity": "Standard Network Operations",
                "detail": "Standard DNS resolution, CDN caching, or authorized operating system telemetry.",
                "footer": "NORMAL ➔"
            },
            "impact": {
                "title": "3. RISK TO ENTERPRISE",
                "badge": "CLEAN REPUTATION",
                "badge_color": "#10b981",
                "entity": "Zero Exploitation Risk",
                "detail": "No defensive containment or firewall blocking needed. Whitelisted for normal operations.",
                "footer": "SAFE 🛡️"
            }
        }

    # 2. Ransomware & Known Malware Binary
    if vector_id == "ransomware" or "ransom" in name.lower() or (is_hash and risk_score > 60):
        vt_mal = vt_data.get("malicious", 14) if isinstance(vt_data, dict) else 14
        return {
            "is_benign": False,
            "who": {
                "title": "1. WHO IS ATTACKING?",
                "badge": "CONFIRMED MALWARE",
                "badge_color": "#ef4444",
                "entity": "Known Ransomware Binary Signature",
                "detail": f"Malicious cryptographic binary flagged by {vt_mal}+ commercial antivirus engines with destructive payload characteristics.",
                "footer": "CAUSE ➔"
            },
            "attempt": {
                "title": "2. WHAT ARE THEY ATTEMPTING?",
                "badge": "DATA EXTORTION",
                "badge_color": "#ef4444",
                "entity": "Shadow Deletion & Rapid Encryption",
                "detail": "Deletes Windows Volume Shadow Copies ('vssadmin delete shadows'), dumps LSASS credentials, and spreads via SMB shares.",
                "footer": "ACTION ➔"
            },
            "impact": {
                "title": "3. WHAT IS THE RISK/IMPACT?",
                "badge": "CRITICAL BLAST RADIUS",
                "badge_color": "#ef4444",
                "entity": "Enterprise Lockdown & Extortion",
                "detail": "Irreversible encryption of corporate network shares, operational shutdown, and multi-million dollar double-extortion leak.",
                "footer": "IMPACT 💥"
            }
        }

    # 3. Phishing & Cloned Domain
    if vector_id == "phishing" or "phish" in name.lower() or (ioc_type_upper == "DOMAIN" and risk_score > 50):
        return {
            "is_benign": False,
            "who": {
                "title": "1. WHO IS ATTACKING?",
                "badge": "CLONED INFRASTRUCTURE",
                "badge_color": "#f97316",
                "entity": "Fraudulent Phishing Domain / Cloner",
                "detail": "Deceptive typosquatting host engineered to masquerade as trusted corporate login portal.",
                "footer": "CAUSE ➔"
            },
            "attempt": {
                "title": "2. WHAT ARE THEY ATTEMPTING?",
                "badge": "CREDENTIAL THEFT",
                "badge_color": "#f59e0b",
                "entity": "Harvesting Credentials & 2FA Cookies",
                "detail": "Intercepting corporate credentials and session cookies via reverse proxy to bypass MFA security controls.",
                "footer": "ACTION ➔"
            },
            "impact": {
                "title": "3. WHAT IS THE RISK/IMPACT?",
                "badge": "HIGH IDENTITY RISK",
                "badge_color": "#ef4444",
                "entity": "Cloud Tenant Compromise & BEC Fraud",
                "detail": "Direct access to corporate mailboxes (M365/Okta), invoice fraud, and unauthorized internal communications.",
                "footer": "IMPACT 💥"
            }
        }

    # 4. C2 Beaconing / Dropper
    if vector_id == "c2_beaconing" or "c2" in name.lower() or "beacon" in name.lower() or (ioc_type_upper == "URL" and risk_score > 50):
        return {
            "is_benign": False,
            "who": {
                "title": "1. WHO IS ATTACKING?",
                "badge": "C2 INFRASTRUCTURE",
                "badge_color": "#ef4444",
                "entity": "Command & Control (C2) Server Node",
                "detail": "Active adversary command server coordinating infected endpoints with beaconing frameworks (Cobalt Strike / Sliver).",
                "footer": "CAUSE ➔"
            },
            "attempt": {
                "title": "2. WHAT ARE THEY ATTEMPTING?",
                "badge": "REMOTE PERSISTENCE",
                "badge_color": "#ef4444",
                "entity": "Covert Reverse Shell Callbacks",
                "detail": "Maintaining encrypted beacon channels to receive operator tasks, stage secondary payloads, and evade perimeter monitoring.",
                "footer": "ACTION ➔"
            },
            "impact": {
                "title": "3. WHAT IS THE RISK/IMPACT?",
                "badge": "CRITICAL COMPROMISE",
                "badge_color": "#ef4444",
                "entity": "Full Domain Dominance & Exfiltration",
                "detail": "Unrestricted adversary control inside corporate boundaries, covert data exfiltration, and persistent lateral foothold.",
                "footer": "IMPACT 💥"
            }
        }

    # 5. Tor Exit Node / Brute Force / Port Scan
    if is_tor or vector_id in ("bruteforce", "reconnaissance") or "brute" in name.lower() or "recon" in name.lower() or "port scan" in name.lower():
        geo_city = geo_data.get("city", "Dresden") if isinstance(geo_data, dict) else "Dresden"
        geo_cc = geo_data.get("country_code", "DE") if isinstance(geo_data, dict) else "DE"
        who_ent = "Tor Anonymized Exit Node" if is_tor else "Automated Botnet Scanner"
        who_det = f"Traffic routes through Tor relay network ({geo_city}, {geo_cc}) masking the true threat actor identity." if is_tor else f"External scanner originating from {geo_data.get('as_info') or geo_data.get('isp') or 'remote network'} probing external ports."
        return {
            "is_benign": False,
            "who": {
                "title": "1. WHO IS ATTACKING?",
                "badge": "ANONYMIZED PROXY" if is_tor else "HOSTILE SCANNER",
                "badge_color": "#ef4444",
                "entity": who_ent,
                "detail": who_det,
                "footer": "CAUSE ➔"
            },
            "attempt": {
                "title": "2. WHAT ARE THEY ATTEMPTING?",
                "badge": "BRUTE-FORCE & RECON",
                "badge_color": "#f59e0b",
                "entity": "SSH & RDP Credential Spraying",
                "detail": "High-frequency dictionary password guessing against remote administration ports (TCP 22, 3389, 8080) to gain interactive access.",
                "footer": "ACTION ➔"
            },
            "impact": {
                "title": "3. WHAT IS THE RISK/IMPACT?",
                "badge": "HIGH OPERATIONAL RISK",
                "badge_color": "#ef4444",
                "entity": "Server Takeover & Lateral Pivot",
                "detail": "Successful credential breach enables root/administrator access, internal network reconnaissance, and secondary malware deployment.",
                "footer": "IMPACT 💥"
            }
        }

    # 6. Generic Fallback
    return {
        "is_benign": False,
        "who": {
            "title": "1. WHO IS ATTACKING?",
            "badge": "ACTIVE THREAT",
            "badge_color": "#ef4444",
            "entity": name,
            "detail": attacks.get("summary", "Threat actor exhibiting hostile infrastructure signatures across global telemetry."),
            "footer": "CAUSE ➔"
        },
        "attempt": {
            "title": "2. WHAT ARE THEY ATTEMPTING?",
            "badge": "EXPLOITATION",
            "badge_color": "#f59e0b",
            "entity": attacks.get("hacker_objective", "Perimeter exploitation and unauthorized access."),
            "detail": "Exploiting network or application vulnerabilities to breach defenses.",
            "footer": "ACTION ➔"
        },
        "impact": {
            "title": "3. WHAT IS THE RISK/IMPACT?",
            "badge": "ELEVATED RISK",
            "badge_color": "#ef4444",
            "entity": attacks.get("blast_radius", "Potential host compromise and data loss."),
            "detail": "Operational risk requiring immediate firewall blocking and security analyst review.",
            "footer": "IMPACT 💥"
        }
    }


def render_threat_pipeline_and_story(attacks: dict, risk: dict, ioc: str, ioc_type: str, geo_data: dict, vt_data: dict, abuse_data: dict):
    """Renders the sleek Threat Stage Pipeline and 3-Step Attack Story cards for SOC analysts."""
    stages_info = compute_threat_stages(attacks, risk, ioc, ioc_type, geo_data)
    story_info = compute_attack_story(attacks, risk, ioc, ioc_type, geo_data, vt_data, abuse_data)
    active_stages = stages_info["active_stages"]

    stage_defs = [
        {"num": 1, "name": "1. Discovery / Recon", "tag": "Recon", "sub": "Port Scan & Banners", "icon": "🔍"},
        {"num": 2, "name": "2. Initial Delivery", "tag": "Delivery", "sub": "Phishing & Clones", "icon": "🎣"},
        {"num": 3, "name": "3. Exploitation", "tag": "Exploit", "sub": "Cred Spray & CVEs", "icon": "⚡"},
        {"num": 4, "name": "4. C2 Control", "tag": "C2", "sub": "Beaconing & Shells", "icon": "📡"},
        {"num": 5, "name": "5. Actions / Impact", "tag": "Impact", "sub": "Data Wipe & Extortion", "icon": "💥"},
    ]

    steps_html = []
    for s in stage_defs:
        s_num = s["num"]
        is_active = s_num in active_stages
        arrow_badge = '<span style="color: #475569; font-size: 11px; margin-left: auto;">➔</span>' if s_num < 5 else ''

        if is_active:
            if s_num in (1, 3):
                border_color = "rgba(245, 158, 11, 0.85)"
                bg_style = "background: linear-gradient(180deg, rgba(245, 158, 11, 0.18) 0%, #0c1222 100%);"
                glow = "box-shadow: 0 0 16px -2px rgba(245, 158, 11, 0.35);"
                badge_bg = "background: #f59e0b; color: #000;"
                tag_style = "background: rgba(245, 158, 11, 0.2); color: #fcd34d; border: 1px solid #f59e0b;"
                status_html = '<span style="color: #fbbf24; font-weight: 700;">● ACTIVE</span>'
            elif s_num == 2:
                border_color = "rgba(249, 115, 22, 0.85)"
                bg_style = "background: linear-gradient(180deg, rgba(249, 115, 22, 0.18) 0%, #0c1222 100%);"
                glow = "box-shadow: 0 0 16px -2px rgba(249, 115, 22, 0.35);"
                badge_bg = "background: #f97316; color: #000;"
                tag_style = "background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid #f97316;"
                status_html = '<span style="color: #fb923c; font-weight: 700;">● ACTIVE</span>'
            else:
                border_color = "rgba(239, 68, 68, 0.85)"
                bg_style = "background: linear-gradient(180deg, rgba(239, 68, 68, 0.18) 0%, #0c1222 100%);"
                glow = "box-shadow: 0 0 16px -2px rgba(239, 68, 68, 0.35);"
                badge_bg = "background: #ef4444; color: #fff;"
                tag_style = "background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid #ef4444;"
                status_html = '<span style="color: #f87171; font-weight: 700;">● ACTIVE</span>'
            title_color = "#ffffff"
            sub_color = "#cbd5e1"
        else:
            border_color = "#1e293b"
            bg_style = "background: #0f172a;"
            glow = ""
            badge_bg = "background: #1e293b; color: #64748b; border: 1px solid #334155;"
            tag_style = "background: rgba(15, 23, 42, 0.6); color: #64748b; border: 1px solid #1e293b;"
            status_text = "Clean" if not active_stages else "Standby"
            status_color = "#10b981" if not active_stages else "#475569"
            status_html = f'<span style="color: {status_color}; font-weight: 500;">{status_text}</span>'
            title_color = "#94a3b8"
            sub_color = "#64748b"

        step_card = f"""
        <div style="{bg_style} border: 1px solid {border_color}; border-radius: 10px; padding: 10px 12px; {glow} display: flex; flex-direction: column; justify-content: space-between; min-height: 94px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span style="{badge_bg} width: 20px; height: 20px; border-radius: 9999px; display: inline-flex; align-items: center; justify-content: center; font-size: 10.5px; font-weight: 800; font-family: monospace;">{s_num}</span>
                <div style="display: flex; align-items: center; gap: 5px;">
                    <span style="{tag_style} font-size: 9px; font-family: monospace; font-weight: 700; padding: 1px 6px; border-radius: 4px; text-transform: uppercase;">{s['tag']}</span>
                    {arrow_badge}
                </div>
            </div>
            <div>
                <div style="font-size: 11.5px; font-weight: 700; color: {title_color}; font-family: monospace;">{s['name']}</div>
                <div style="font-size: 9.5px; color: {sub_color}; margin-top: 1px;">{s['sub']}</div>
            </div>
            <div style="margin-top: 8px; padding-top: 5px; border-top: 1px solid rgba(255,255,255,0.06); font-size: 9.5px; font-family: monospace; display: flex; justify-content: space-between; align-items: center;">
                {status_html}
                <span style="font-size: 11px;">{s['icon']}</span>
            </div>
        </div>
        """
        steps_html.append(step_card)

    steps_grid = f"""
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 8px; margin-top: 10px;">
        {''.join(steps_html)}
    </div>
    """

    pipeline_component = f"""
    <div style="background-color: #0c1222; border: 1px solid #1e293b; border-radius: 12px; padding: 14px 18px; margin-bottom: 14px; box-shadow: 0 4px 20px rgba(0,0,0,0.35);">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 8px; flex-wrap: wrap; gap: 8px;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="width: 8px; height: 8px; border-radius: 50%; background-color: {stages_info['badge_color']}; display: inline-block;"></span>
                <span style="font-size: 11px; font-weight: 800; font-family: monospace; color: #cbd5e1; letter-spacing: 1px; text-transform: uppercase;">
                    KILL CHAIN PIPELINE // MITRE ATT&CK EXECUTION FLOW
                </span>
            </div>
            <div>
                <span style="background: {stages_info['badge_bg']}; color: {stages_info['badge_color']}; border: 1px solid {stages_info['badge_border']}; padding: 2px 10px; border-radius: 9999px; font-size: 10.5px; font-weight: 700; font-family: monospace;">
                    {stages_info['badge_text']}
                </span>
            </div>
        </div>
        {steps_grid}
        <div style="margin-top: 12px; padding-top: 10px; border-top: 1px solid #1e293b; font-size: 11.5px; color: #94a3b8; font-family: monospace; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 6px;">
            <div><span style="color: #00f0ff; margin-right: 6px;">⚡</span>{stages_info['desc']}</div>
            <span style="color: #475569; font-size: 10px;">CYBER KILL CHAIN MAPPING</span>
        </div>
    </div>
    """
    st.markdown(pipeline_component, unsafe_allow_html=True)

    # 3-Step Attack Story Infographic
    story_who = story_info["who"]
    story_attempt = story_info["attempt"]
    story_impact = story_info["impact"]
    is_benign = story_info.get("is_benign", False)

    card_border = "rgba(16, 185, 129, 0.4)" if is_benign else "#1e293b"
    mode_badge_text = "CLEAN INFRASTRUCTURE // VERIFIED ASSET" if is_benign else "SOC PLAIN-ENGLISH TRANSLATION"
    mode_badge_color = "#10b981" if is_benign else "#94a3b8"
    mode_badge_bg = "rgba(16, 185, 129, 0.12)" if is_benign else "#111827"

    who_icon = "🛡️" if is_benign else "👤"
    attempt_icon = "🟢" if is_benign else "🎯"
    impact_icon = "✅" if is_benign else "💥"
    impact_footer_color = "#10b981" if is_benign else "#ef4444"
    impact_footer_label = "ENTERPRISE POSTURE" if is_benign else "BLAST RADIUS"

    story_component = f"""
    <div style="background-color: #0c1222; border: 1px solid #1e293b; border-radius: 12px; padding: 16px 20px; margin-bottom: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.35);">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 10px; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 14px;">📖</span>
                <span style="font-size: 11px; font-weight: 800; font-family: monospace; color: #cbd5e1; letter-spacing: 1px; text-transform: uppercase;">
                    ATTACK STORY IN 3 STEPS // CAUSE ➔ ACTION ➔ IMPACT
                </span>
            </div>
            <div>
                <span style="background: {mode_badge_bg}; color: {mode_badge_color}; border: 1px solid {card_border}; padding: 3px 10px; border-radius: 6px; font-size: 10.5px; font-family: monospace; font-weight: 600;">
                    {mode_badge_text}
                </span>
            </div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px;">
            <!-- Step 1: Who is Attacking? -->
            <div style="background-color: #111827; border: 1px solid {card_border}; border-radius: 10px; padding: 16px; display: flex; flex-direction: column; justify-content: space-between;">
                <div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="font-size: 11px; font-family: monospace; font-weight: 700; color: #94a3b8; text-transform: uppercase;">
                            {who_icon} {story_who['title']}
                        </span>
                        <span style="background: {'rgba(16, 185, 129, 0.15)' if is_benign else 'rgba(239, 68, 68, 0.15)'}; color: {story_who['badge_color']}; border: 1px solid {story_who['badge_color']}; padding: 2px 6px; border-radius: 4px; font-size: 9px; font-family: monospace; font-weight: 800;">
                            {story_who['badge']}
                        </span>
                    </div>
                    <div style="font-size: 15px; font-weight: 800; color: #f8fafc; font-family: monospace; margin-bottom: 6px;">
                        {story_who['entity']}
                    </div>
                    <div style="font-size: 12px; color: #cbd5e1; line-height: 1.5;">
                        {story_who['detail']}
                    </div>
                </div>
                <div style="margin-top: 14px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.06); font-size: 10px; font-family: monospace; color: #64748b; display: flex; justify-content: space-between;">
                    <span>ADVERSARY ORIGIN</span>
                    <span style="color: {'#10b981' if is_benign else '#00f0ff'}; font-weight: 700;">{story_who['footer']}</span>
                </div>
            </div>

            <!-- Step 2: What are they Attempting? -->
            <div style="background-color: #111827; border: 1px solid {card_border}; border-radius: 10px; padding: 16px; display: flex; flex-direction: column; justify-content: space-between;">
                <div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="font-size: 11px; font-family: monospace; font-weight: 700; color: #94a3b8; text-transform: uppercase;">
                            {attempt_icon} {story_attempt['title']}
                        </span>
                        <span style="background: {'rgba(16, 185, 129, 0.15)' if is_benign else 'rgba(245, 158, 11, 0.15)'}; color: {story_attempt['badge_color']}; border: 1px solid {story_attempt['badge_color']}; padding: 2px 6px; border-radius: 4px; font-size: 9px; font-family: monospace; font-weight: 800;">
                            {story_attempt['badge']}
                        </span>
                    </div>
                    <div style="font-size: 15px; font-weight: 800; color: #f8fafc; font-family: monospace; margin-bottom: 6px;">
                        {story_attempt['entity']}
                    </div>
                    <div style="font-size: 12px; color: #cbd5e1; line-height: 1.5;">
                        {story_attempt['detail']}
                    </div>
                </div>
                <div style="margin-top: 14px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.06); font-size: 10px; font-family: monospace; color: #64748b; display: flex; justify-content: space-between;">
                    <span>TACTICAL BEHAVIOR</span>
                    <span style="color: {'#10b981' if is_benign else '#f59e0b'}; font-weight: 700;">{story_attempt['footer']}</span>
                </div>
            </div>

            <!-- Step 3: What is the Risk/Impact? -->
            <div style="background-color: #111827; border: 1px solid {card_border}; border-radius: 10px; padding: 16px; display: flex; flex-direction: column; justify-content: space-between;">
                <div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="font-size: 11px; font-family: monospace; font-weight: 700; color: #94a3b8; text-transform: uppercase;">
                            {impact_icon} {story_impact['title']}
                        </span>
                        <span style="background: {'rgba(16, 185, 129, 0.15)' if is_benign else 'rgba(239, 68, 68, 0.15)'}; color: {story_impact['badge_color']}; border: 1px solid {story_impact['badge_color']}; padding: 2px 6px; border-radius: 4px; font-size: 9px; font-family: monospace; font-weight: 800;">
                            {story_impact['badge']}
                        </span>
                    </div>
                    <div style="font-size: 15px; font-weight: 800; color: #f8fafc; font-family: monospace; margin-bottom: 6px;">
                        {story_impact['entity']}
                    </div>
                    <div style="font-size: 12px; color: #cbd5e1; line-height: 1.5;">
                        {story_impact['detail']}
                    </div>
                </div>
                <div style="margin-top: 14px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.06); font-size: 10px; font-family: monospace; color: #64748b; display: flex; justify-content: space-between;">
                    <span>{impact_footer_label}</span>
                    <span style="color: {impact_footer_color}; font-weight: 700;">{story_impact['footer']}</span>
                </div>
            </div>
        </div>
    </div>
    """
    st.markdown(story_component, unsafe_allow_html=True)



# =====================================================================
# Tab 1: Single IOC Investigation Engine
# =====================================================================
def render_single_investigation(config: dict):
    st.markdown("### 🔍 Live Indicator Investigation & Threat Analysis")
    
    # Input field with Auto-Detection bound to session state
    if "pending_ioc_input" in st.session_state:
        st.session_state.ioc_input = st.session_state.pop("pending_ioc_input")

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        user_input = st.text_input(
            "Enter IP, Hash, Domain, or URL (Defanged formats like hxxps[://] and 1[.]1[.]1[.]1 supported):",
            key="ioc_input",
            placeholder="e.g. 185.220.101.5 or ed01ebf8342f1ab0... or malicious-domain[.]com"
        )
    with col_btn:
        st.write("")
        st.write("")
        scan_clicked = st.button("🚀 Analyze IOC", type="primary", use_container_width=True)

    # Perform Detection
    detection = detect_ioc_type(user_input)

    # Display Indicator Type Badge
    col_badge1, col_badge2, col_badge3 = st.columns([2, 2, 3])
    with col_badge1:
        st.markdown(f"**Detected Type:** <span class='type-pill'>{detection['type_label']}</span>", unsafe_allow_html=True)
    with col_badge2:
        if detection["is_defanged"]:
            st.markdown("🛡️ **Defanged Input Detected** &bull; Refanged for API analysis")
        else:
            st.markdown("🟢 **Standard Format**")
    with col_badge3:
        st.caption(f"_{detection['notes']}_")

    if not detection["valid"]:
        st.warning("⚠️ Please provide a valid IPv4, IPv6, MD5, SHA-1, SHA-256, Domain, or URL to begin threat scanning.")
        return

    target_ioc = detection["normalized"]

    # Determine if we should perform a fresh scan:
    should_scan = (
        scan_clicked
        or st.session_state.trigger_scan
        or st.session_state.last_investigation is None
        or st.session_state.last_investigation.get("ioc") != target_ioc
    )

    if should_scan:
        with st.spinner(f"Querying threat intelligence engines for {target_ioc}..."):
            # 1. VirusTotal
            vt_data = query_virustotal(
                target_ioc, detection["type"],
                api_key=config["vt_key"],
                demo_mode=config["demo_mode"]
            )

            # 2. AbuseIPDB
            abuse_data = query_abuseipdb(
                target_ioc, detection["type"],
                api_key=config["abuse_key"],
                demo_mode=config["demo_mode"]
            )

            # 3. AlienVault OTX
            otx_data = query_alienvault(
                target_ioc, detection["type"],
                api_key=config["otx_key"],
                demo_mode=config["demo_mode"]
            )

            # 4. Geolocation
            geo_data = query_geolocation(
                target_ioc, detection["type"],
                demo_mode=config["demo_mode"]
            )

            # 5. Risk Scorer
            risk = calculate_risk_score(
                target_ioc, detection["type"],
                vt_data, abuse_data, otx_data,
                geo_data=geo_data,
                is_private=detection.get("is_private"),
                is_loopback=detection.get("is_loopback")
            )


            # 6. Attack Prediction & Adversary Toolset Engine
            attacks = analyze_attack_vector(
                target_ioc, detection["type"],
                vt_data=vt_data,
                abuse_data=abuse_data,
                otx_data=otx_data,
                geo_data=geo_data,
                risk_data=risk
            )

            # 7. Website Security Posture & SSL Health
            web_security = audit_website_security(target_ioc, demo_mode=config["demo_mode"])

            # 8. 14-Day Attack Activity & Velocity Engine
            velocity = generate_attack_velocity(
                target_ioc, detection["type"],
                vt_data=vt_data,
                abuse_data=abuse_data,
                otx_data=otx_data
            )

            # Save to SQLite history exactly once per new scan
            country_name = geo_data.get("country", "N/A") if geo_data.get("status") == "success" else "N/A"
            save_investigation(
                ioc=target_ioc,
                ioc_type=detection["type"],
                risk_score=risk["score"],
                risk_level=risk["level"],
                vt_malicious=vt_data.get("malicious", 0),
                abuse_score=abuse_data.get("abuse_confidence_score", 0),
                country=country_name,
                analyst_notes=risk["summary"]
            )

            # Cache in session state
            st.session_state.last_investigation = {
                "ioc": target_ioc,
                "detection": detection,
                "risk": risk,
                "attacks": attacks,
                "web_security": web_security,
                "velocity": velocity,
                "vt": vt_data,
                "abuse": abuse_data,
                "otx": otx_data,
                "geo": geo_data
            }
            st.session_state.trigger_scan = False

    # Retrieve cached investigation
    inv = st.session_state.last_investigation
    if not inv or inv.get("ioc") != target_ioc:
        return

    risk = inv["risk"]
    vt_data = inv["vt"]
    abuse_data = inv["abuse"]
    otx_data = inv["otx"]
    geo_data = inv["geo"]
    velocity_data = inv.get("velocity") or generate_attack_velocity(target_ioc, detection["type"], vt_data=vt_data, abuse_data=abuse_data, otx_data=otx_data)

    # =================================================================
    # Presentation: Executive Triage Dashboard
    # =================================================================
    st.markdown("---")
    
    attacks = inv.get("attacks") or analyze_attack_vector(
        target_ioc, detection["type"], vt_data, abuse_data, otx_data, geo_data, risk,
        domain_age_days=st.session_state.get("domain_age_days"),
        is_nrd=st.session_state.get("is_nrd")
    )
    web_security = inv.get("web_security") or audit_website_security(
        target_ioc, demo_mode=config.get("demo_mode", False)
    )

    # Modal Dialog Handlers for Adversary Intelligence
    if hasattr(st, "dialog"):
        @st.dialog("⚔️ Adversary Tool Forensic Telemetry & Containment", width="large")
        def show_adversary_tool_dialog(t_data: dict):
            st.markdown(f"### {t_data.get('name', 'Adversary Tool')} &bull; `{t_data.get('category', 'Category')}`")
            st.caption(f"Mapped Campaign Vector: {t_data.get('primary_vector', 'Adversary TTPs')}")
            
            st.markdown("##### 🎯 Hacker's Tactical Purpose")
            st.info(t_data.get('tactical_purpose', 'N/A'))
            
            st.markdown("##### 🔍 SOC Forensic Artifacts (Windows Event IDs & Log Indicators)")
            st.code(t_data.get('forensic_artifacts', 'N/A'), language="powershell")
            
            st.markdown("##### 🛡️ Targeted SOC Containment Step")
            st.success(t_data.get('containment_step', 'N/A'))
            
            if t_data.get('mitre_ttps'):
                st.markdown("**MITRE ATT&CK TTPs:** " + ", ".join([f"`{ttp}`" for ttp in t_data['mitre_ttps']]))

        @st.dialog("🛡️ Adversary Campaign & Attack Vector Playbook", width="large")
        def show_attack_vector_dialog(v_data: dict):
            st.markdown(f"### {v_data.get('icon', '⚔️')} {v_data.get('name', 'Attack Vector')}")
            st.markdown(f"**Severity:** `{v_data.get('severity', 'UNKNOWN')}` &bull; **Confidence:** `{v_data.get('confidence', 0)}%`")
            st.markdown(v_data.get('summary', ''))
            
            c_obj, c_blast = st.columns(2)
            with c_obj:
                st.markdown("**🎯 Hacker Tactical Objective:**")
                st.info(v_data.get('hacker_objective', 'N/A'))
            with c_blast:
                st.markdown("**💥 Expected Blast Radius:**")
                st.warning(v_data.get('blast_radius', 'N/A'))
                
            st.markdown("#### ⚔️ Associated Adversary Tools & Containment")
            for at in v_data.get('adversary_tools', []):
                with st.expander(f"🔧 {at.get('name')} ({at.get('category')})", expanded=False):
                    st.markdown(f"**Tactical Purpose:** {at.get('tactical_purpose')}")
                    st.markdown("**Forensic Artifacts:**")
                    st.code(at.get('forensic_artifacts'), language="powershell")
                    st.markdown("**Targeted Containment:**")
                    st.success(at.get('containment_step'))
    else:
        def show_adversary_tool_dialog(t_data: dict):
            st.info(f"{t_data.get('name')} ({t_data.get('category')}): {t_data.get('containment_step')}")
        def show_attack_vector_dialog(v_data: dict):
            st.info(f"{v_data.get('name')}: {v_data.get('summary')}")

    # 1. Compact Non-Scrolling Executive Header (2-Column SOC Layout)
    is_internal = (
        risk.get("is_internal")
        or detection.get("is_private")
        or detection.get("is_loopback")
        or "internal" in str(risk.get("level", "")).lower()
        or target_ioc in ("localhost", "127.0.0.1", "::1")
        or "127.0.0.1" in target_ioc
        or "localhost" in target_ioc
        or target_ioc.startswith("192.168.")
        or target_ioc.startswith("10.")
    )

    if is_internal:
        verdict_status_text = "🏠 LOCALHOST / INTERNAL — NON-ROUTABLE ASSET"
        verdict_badge_class = "badge-low"
        soc_action_text = "INTERNAL ASSET / LOCALHOST"
        soc_action_color = "#10b981"
        posture_text = "Internal RFC 1918 / Loopback Asset &bull; Non-routable on perimeter threat feeds. Do NOT block."
    elif risk["score"] <= 20:
        verdict_status_text = "🟢 BENIGN / VERIFIED REPUTATION — NO THREAT DETECTED"
        verdict_badge_class = "badge-low"
        soc_action_text = "INFORMATIONAL / BENIGN"
        soc_action_color = "#10b981"
        posture_text = "Asset verified benign / whitelisted &bull; No active containment necessary."
    elif risk["score"] <= 60:
        verdict_status_text = "🟡 SUSPICIOUS ASSET — MONITOR INTERNAL TRAFFIC"
        verdict_badge_class = "badge-medium"
        soc_action_text = "MONITORING RECOMMENDED"
        soc_action_color = "#f59e0b"
        posture_text = "Suspicious activity observed &bull; Monitor internal telemetry and egress traffic."
    else:
        verdict_status_text = "🔴 CRITICAL THREAT — IMMEDIATE CONTAINMENT RECOMMENDED"
        verdict_badge_class = "badge-high"
        soc_action_text = "SOC ACTION REQUIRED"
        soc_action_color = "#ef4444"
        posture_text = "Immediate containment required &bull; Enforce automated perimeter blocking."

    # 1. Unified Executive Triage Island (Full-Width SOC Lab Command Bar)
    story_info = compute_attack_story(attacks, risk, target_ioc, detection["type"], geo_data, vt_data, abuse_data)
    is_benign = story_info.get("is_benign", False)
    who_ent = story_info["who"]["entity"]
    cc = geo_data.get("country_code", "DE") if isinstance(geo_data, dict) else "DE"
    flag_map = {"DE": "🇩🇪", "US": "🇺🇸", "CN": "🇨🇳", "RU": "🇷🇺", "NL": "🇳🇱", "FR": "🇫🇷", "GB": "🇬🇧"}
    flag_icon = flag_map.get(cc, "🌐")
    cc_flag = f"{flag_icon} {geo_data.get('country', cc) if isinstance(geo_data, dict) else cc}"
    isp_name = geo_data.get("isp", "Network Host") if isinstance(geo_data, dict) else "Network Host"
    asn_code = geo_data.get("as_info", "") if isinstance(geo_data, dict) else ""

    if is_internal:
        rec_action = "🏠 Internal Asset (No Block)"
    elif is_benign:
        rec_action = "Whitelist Asset & Allow Egress"
    elif detection["type"] in ("IPV4", "IPV6"):
        rec_action = "Block Perimeter IP"
    elif detection["type"] in ("DOMAIN", "URL"):
        rec_action = "Sinkhole Domain & Flush DNS"
    elif any(h in detection["type"] for h in ("SHA", "MD5")):
        rec_action = "Quarantine Binary & Kill Process"
    else:
        rec_action = "Enforce Perimeter Containment"

    # Velocity Pill data
    trend_pct = velocity_data.get("trend_percentage", 0.0)
    trend_dir = velocity_data.get("trend_direction", "steady")
    decay_label = "14d Decay" if velocity_data.get("half_life_days") == 14.0 else ("60d Decay" if velocity_data.get("half_life_days") == 60.0 else "Permanent")
    
    if trend_dir == "surge":
        vel_border = "rgba(244, 63, 94, 0.45)"
        vel_color = "#f43f5e"
        vel_text = f"🔥 +{trend_pct:.1f}% Active Surge"
    elif trend_dir == "decay":
        vel_border = "rgba(245, 158, 11, 0.45)"
        vel_color = "#f59e0b"
        vel_text = f"📉 {trend_pct:.1f}% Decaying"
    elif trend_dir == "clean":
        vel_border = "rgba(16, 185, 129, 0.45)"
        vel_color = "#10b981"
        vel_text = "🛡️ Clean Baseline"
    else:
        vel_border = "rgba(0, 240, 255, 0.4)"
        vel_color = "#00f0ff"
        vel_text = f"⚓ {trend_pct:.1f}% Steady"

    # Executive Island HTML Component
    island_html = f"""
    <div style="background: rgba(14, 20, 36, 0.95); border: 1px solid rgba(0, 240, 255, 0.25); border-radius: 16px; padding: 16px 20px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); margin-bottom: 14px;">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
            <!-- 1. Score & Level -->
            <div style="display: flex; align-items: center; gap: 14px;">
                <div style="background: #0b0f19; border: 2px solid {risk['color']}; border-radius: 12px; width: 68px; height: 56px; display: flex; flex-direction: column; align-items: center; justify-content: center; box-shadow: 0 0 16px {risk['color']}33;">
                    <span style="font-size: 22px; font-weight: 900; font-family: monospace; color: {risk['color']}; line-height: 1;">{risk['score']}</span>
                    <span style="font-size: 9px; color: #94a3b8; font-family: monospace; font-weight: 700; text-transform: uppercase;">/ 100</span>
                </div>
                <div>
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span style="background: {risk['color']}22; color: {risk['color']}; border: 1px solid {risk['color']}; padding: 2px 10px; border-radius: 9999px; font-size: 11px; font-weight: 800; font-family: monospace; text-transform: uppercase;">
                            {risk['level']}
                        </span>
                        <span style="background: rgba(0, 240, 255, 0.1); color: #00f0ff; border: 1px solid rgba(0, 240, 255, 0.3); padding: 2px 6px; border-radius: 4px; font-size: 10px; font-family: monospace;">AI 0-100</span>
                    </div>
                    <div style="font-size: 10px; color: #64748b; font-family: monospace; margin-top: 4px;">TLP:CLEAR &bull; SOC RISK INDEX</div>
                </div>
            </div>

            <!-- 2. Target Indicator, Geolocation & ISP -->
            <div style="flex: 1; min-width: 260px; padding: 0 12px; border-left: 1px solid rgba(255,255,255,0.08); border-right: 1px solid rgba(255,255,255,0.08);">
                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                    <span style="font-size: 16px; font-weight: 800; font-family: monospace; color: #f8fafc; letter-spacing: 0.5px;">{target_ioc}</span>
                    <span style="background: rgba(0, 240, 255, 0.12); color: #00f0ff; border: 1px solid rgba(0, 240, 255, 0.3); padding: 1px 6px; border-radius: 4px; font-size: 10px; font-family: monospace; font-weight: 700;">{detection['type']}</span>
                    <span style="background: {'rgba(16, 185, 129, 0.15)' if (is_internal or is_benign) else 'rgba(239, 68, 68, 0.15)'}; color: {'#10b981' if (is_internal or is_benign) else '#ef4444'}; border: 1px solid {'#10b981' if (is_internal or is_benign) else '#ef4444'}; padding: 1px 6px; border-radius: 4px; font-size: 10px; font-family: monospace; font-weight: 700;">{'🏠 LOCALHOST / INTERNAL' if is_internal else ('VERIFIED BENIGN' if is_benign else 'HIGH SEVERITY')}</span>
                </div>
                <div style="font-size: 11.5px; font-family: monospace; color: #cbd5e1; margin-top: 4px; display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
                    <span style="color: #f1f5f9; font-weight: 700;">{who_ent}</span>
                    <span style="color: #64748b;">•</span>
                    <span style="color: #38bdf8;">{cc_flag}</span>
                    <span style="color: #64748b;">•</span>
                    <span style="color: #94a3b8;">{isp_name} {f'({asn_code})' if asn_code else ''}</span>
                </div>
            </div>

            <!-- 3. Velocity Pill -->
            <div style="background: #0f172a; border: 1px solid {vel_border}; border-radius: 10px; padding: 6px 12px; font-family: monospace; font-size: 11.5px; display: flex; align-items: center; gap: 6px; box-shadow: inset 0 1px 3px rgba(0,0,0,0.5);">
                <span style="color: {vel_color}; font-weight: 800;">{vel_text}</span>
                <span style="color: #64748b;">•</span>
                <span style="color: #94a3b8; font-size: 10.5px;">{decay_label}</span>
            </div>
        </div>
    </div>
    """
    st.markdown(island_html, unsafe_allow_html=True)

    # 1-Click Action Bar & Deep Inspection Drawer
    col_act, col_drawer_note = st.columns([1.5, 3])
    with col_act:
        if st.button(f"🛡️ {rec_action}", key="island_enforce_action_btn", use_container_width=True):
            st.session_state["active_containment_tab"] = True
            if is_internal:
                cmd_copied = f"# {target_ioc} is an internal/loopback asset (RFC 1918 / RFC 1122). Perimeter blocking suppressed.\n# Inspect local listening ports:\nnetstat -tulnp | grep 127.0.0.1"
                toast_msg = f"🏠 Internal asset {target_ioc} verified. Perimeter block suppressed."
            elif is_benign:
                cmd_copied = f"# Whitelist {target_ioc} - Verified Benign Asset (No blocking rule required)"
                toast_msg = f"✅ Whitelist notation for {target_ioc} copied!"
            elif detection["type"] in ("IPV4", "IPV6"):
                cmd_copied = f"iptables -A INPUT -s {target_ioc} -j DROP # Auto Perimeter Containment Rule"
                toast_msg = f"🛡️ Perimeter Block rule for {target_ioc} copied! Containment engaged."
            elif detection["type"] in ("DOMAIN", "URL"):
                cmd_copied = f"0.0.0.0 {target_ioc} # Auto DNS Sinkhole Containment Rule"
                toast_msg = f"🛡️ DNS Sinkhole rule for {target_ioc} copied! Containment engaged."
            elif any(h in detection["type"] for h in ("SHA", "MD5")):
                short_h = target_ioc[:8] if len(target_ioc) > 8 else target_ioc
                cmd_copied = f"chmod 000 /bin/{short_h}* 2>/dev/null; pkill -9 -f {short_h} # Auto Binary Quarantine"
                toast_msg = f"🛡️ Binary Quarantine command for {short_h}... copied! Containment engaged."
            else:
                cmd_copied = f"iptables -A INPUT -s {target_ioc} -j DROP # Auto Containment Rule"
                toast_msg = f"🛡️ Containment rule for {target_ioc} copied! Containment engaged."
            st.session_state["last_containment_rule"] = cmd_copied
            st.toast(toast_msg, icon="🛡️")


    if st.session_state.get("active_containment_tab"):
        active_rule = st.session_state.get("last_containment_rule", f"iptables -A INPUT -s {target_ioc} -j DROP")
        st.success(
            f"🛡️ **Active Containment Action Engaged**: `{active_rule}` "
            f"*(Rule active & available in Tab 3 Defense & Containment)*"
        )

    with st.expander("🔬 Deep Telemetry & Tactical Guidance Drawer (AV Flagging, Abuse History, MITRE, Mitigation Steps)", expanded=False):
        # 4 Mini-Metrics Grid
        kpi_c1, kpi_c2, kpi_c3, kpi_c4 = st.columns(4)
        with kpi_c1:
            vt_m = vt_data.get("malicious", 0)
            vt_s = vt_data.get("suspicious", 0)
            total_vt = vt_m + vt_s + vt_data.get('harmless', 0) + vt_data.get('undetected', 0) or 70
            st.metric("Antivirus (VT v3)", f"{vt_m} / {total_vt}", f"Susp: {vt_s} • Clean: {vt_data.get('harmless', 0)}", delta_color="inverse" if vt_m > 0 else "normal")
        with kpi_c2:
            abuse_score = abuse_data.get("abuse_confidence_score", "N/A")
            abuse_val_str = f"{abuse_score}%" if isinstance(abuse_score, (int, float)) else "N/A"
            st.metric("Abuse History", abuse_val_str, f"Rpts: {abuse_data.get('total_reports', 0)} • CC: {abuse_data.get('country_code', 'N/A')}", delta_color="inverse" if isinstance(abuse_score, int) and abuse_score >= 50 else "normal")
        with kpi_c3:
            attack_name = attacks.get("name", "Unclassified Vector")
            attack_icon = attacks.get("icon", "⚔️")
            st.metric("Primary Threat", f"{attack_icon} {attack_name}", f"{attacks.get('severity', 'UNKNOWN')} • {attacks.get('confidence', 0)}% Conf")
        with kpi_c4:
            geo_location = f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country_code', '??')}" if geo_data.get("status") == "success" else "N/A (Non-IP)"
            st.metric("Origin (Geo/BGP)", geo_location, isp_name)

        st.markdown(f"**⚡ Executive Situational Awareness:** {risk['summary']}")
        st.markdown(f"**🛡️ Recommended Tactical Posture:** {posture_text}")
        if risk.get("actions"):
            st.markdown("**Prioritized Containment Steps:**")
            for a_idx, a_step in enumerate(risk["actions"], 1):
                st.markdown(f"**[{a_idx}]** {a_step}")

    # 2. Consolidate into 3 Clean Workflow Super-Tabs
    st.markdown("---")
    tab_overview, tab_forensics, tab_containment = st.tabs([
        "🎯 Threat & Attack Flow",
        "🔬 Deep Forensics & Map",
        "🛡️ Defense & Containment"
    ])

    # TAB 1: Threat & Attack Flow
    with tab_overview:
        # Threat Stage Pipeline & 3-Step Attack Story Infographic
        render_threat_pipeline_and_story(
            attacks, risk, target_ioc, detection["type"],
            geo_data, vt_data, abuse_data
        )

        # 14-Day Attack Activity & Velocity Line Chart
        col_hdr, col_tf = st.columns([3, 1])
        with col_hdr:
            st.markdown("#### 📈 14-Day Attack Activity & Velocity Line Chart")
            st.caption("14-Day Temporal Event Distribution • Surge Velocity Tracking")
        with col_tf:
            tf_choice = st.radio("Timeframe", ["14 Days", "7 Days"], horizontal=True, label_visibility="collapsed", key="velocity_tf_choice")

        full_timeline = velocity_data.get("daily_timeline", [])
        slice_count = 7 if tf_choice == "7 Days" else 14
        timeline = full_timeline[-slice_count:] if full_timeline else []
        total_hits = sum(x.get("count", 0) for x in timeline)
        peak_entry = max(timeline, key=lambda x: x.get("count", 0)) if timeline else {"count": 0, "date": "N/A"}

        # 4 Mini-Metric Columns
        v_col1, v_col2, v_col3, v_col4 = st.columns(4)

        with v_col1:
            trend_val = velocity_data.get("trend_percentage", 0.0)
            trend_dir = velocity_data.get("trend_direction", "steady")
            badge = velocity_data.get("status_badge", "Normal")
            st.metric(
                label="Trend Velocity (48h)",
                value=f"{trend_val:+.1f}%" if trend_dir != "clean" else "0.0%",
                delta=badge
            )

        with v_col2:
            st.metric(
                label=f"Total {slice_count}D Hits",
                value=f"{total_hits:,}",
                delta=f"{slice_count}-Day Observation"
            )

        with v_col3:
            st.metric(
                label="Peak Daily Burst",
                value=f"{peak_entry.get('count', 0):,}",
                delta=f"Date: {peak_entry.get('date', 'N/A')}"
            )

        with v_col4:
            hl_days = velocity_data.get("half_life_days")
            if hl_days:
                hl_display = f"{hl_days:.0f}d Half-Life"
                hl_sub = "Active Decay"
            elif velocity_data.get("trend_direction") == "clean":
                hl_display = "N/A (Clean)"
                hl_sub = "Baseline"
            else:
                hl_display = "Permanent"
                hl_sub = "Static Signature"
            st.metric(
                label="Persistence Decay",
                value=hl_display,
                delta=hl_sub
            )

        if timeline and PLOTLY_AVAILABLE:
            df_velocity = pd.DataFrame(timeline)

            trend_dir = velocity_data.get("trend_direction", "steady")
            if trend_dir == "surge":
                line_color = "#f43f5e"
                fill_color = "rgba(244, 63, 94, 0.15)"
            elif trend_dir == "decay":
                line_color = "#f59e0b"
                fill_color = "rgba(245, 158, 11, 0.15)"
            elif trend_dir == "clean":
                line_color = "#10b981"
                fill_color = "rgba(16, 185, 129, 0.12)"
            else:
                line_color = "#00f0ff"
                fill_color = "rgba(0, 240, 255, 0.15)"

            custom_vals = [[p.get("decay_factor", 1.0), p.get("surge_level", "Baseline")] for p in timeline]

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=df_velocity["date"],
                y=df_velocity["count"],
                mode="lines+markers",
                name="Daily Hits",
                line=dict(color=line_color, width=3, shape="spline"),
                marker=dict(size=6, color="#0b0f19", line=dict(color=line_color, width=2)),
                fill="tozeroy",
                fillcolor=fill_color,
                customdata=custom_vals,
                hovertemplate="<b>%{x}</b><br>Daily Events: <b>%{y:,} hits</b><br>Surge Level: <b>%{customdata[1]}</b><extra></extra>"
            ))

            # Danger threshold dashed line
            max_daily = max([p.get("count", 0) for p in timeline], default=0)
            if max_daily >= 60:
                fig.add_hline(
                    y=100,
                    line_dash="dash",
                    line_color="rgba(244, 63, 94, 0.75)",
                    annotation_text="Threshold: 100 hits",
                    annotation_position="top right",
                    annotation_font_size=10,
                    annotation_font_color="#f43f5e"
                )

            fig.update_layout(
                paper_bgcolor="#0E1424",
                plot_bgcolor="#0E1424",
                margin=dict(l=40, r=20, t=20, b=30),
                height=260,
                xaxis=dict(
                    showgrid=True,
                    gridcolor="#1e293b",
                    gridwidth=1,
                    color="#94a3b8",
                    tickfont=dict(family="JetBrains Mono, monospace", size=10)
                ),
                yaxis=dict(
                    showgrid=True,
                    gridcolor="#1e293b",
                    gridwidth=1,
                    color="#94a3b8",
                    tickfont=dict(family="JetBrains Mono, monospace", size=10)
                ),
                hovermode="x unified",
                showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)
        elif timeline:
            df_velocity = pd.DataFrame(timeline).set_index("date")
            st.line_chart(df_velocity["count"], height=240)

        verdict = velocity_data.get("verdict", "Baseline telemetry normal.")
        st.info(f"💡 **SOC Velocity Assessment:** {verdict}")
        st.markdown("---")

        st.markdown("#### 🎯 Predicted Attack Vector & Adversary Campaign")
        st.markdown(f"""
        <div class="soc-card" style="border-left: 4px solid {attacks.get('color', '#ef4444')}; margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 22px;">{attacks.get('icon', '⚔️')}</span>
                    <span style="font-size: 16px; font-weight: 800; color: #f8fafc;">{attacks.get('name', 'Unclassified')}</span>
                    <span style="background: rgba(239, 68, 68, 0.2); color: {attacks.get('color', '#ef4444')}; border: 1px solid {attacks.get('color', '#ef4444')}; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;">
                        {attacks.get('severity', 'UNKNOWN')}
                    </span>
                    <span style="background: rgba(6, 182, 212, 0.15); color: #06b6d4; border: 1px solid #0891b2; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">
                        {attacks.get('confidence', 0)}% Confidence
                    </span>
                </div>
            </div>
            <p style="font-size: 13px; color: #cbd5e1; margin-bottom: 12px; line-height: 1.5;">
                {attacks.get('summary', '')}
            </p>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 10px;">
                <div style="background: #0f172a; padding: 10px 14px; border-radius: 8px; border: 1px solid #1e293b;">
                    <div style="font-size: 11px; font-weight: 700; color: #f59e0b; text-transform: uppercase;">🎯 Hacker Tactical Objective</div>
                    <div style="font-size: 12px; color: #e2e8f0; margin-top: 4px; font-family: monospace;">{attacks.get('hacker_objective', 'N/A')}</div>
                </div>
                <div style="background: #0f172a; padding: 10px 14px; border-radius: 8px; border: 1px solid #1e293b;">
                    <div style="font-size: 11px; font-weight: 700; color: #ef4444; text-transform: uppercase;">💥 Expected Blast Radius</div>
                    <div style="font-size: 12px; color: #e2e8f0; margin-top: 4px; font-family: monospace;">{attacks.get('blast_radius', 'N/A')}</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if st.button(f"🛡️ Open Interactive Vector Playbook: {attacks.get('name')}", key="open_vector_modal_btn", use_container_width=True):
            show_attack_vector_dialog(attacks)

        # MITRE ATT&CK Mapping
        ttps = attacks.get("mitre_techniques", [])
        if ttps:
            st.markdown("##### 🛡️ MITRE ATT&CK® TTP Mapping")
            ttp_cols = st.columns(len(ttps[:4]) or 1)
            for i, ttp in enumerate(ttps[:4]):
                with ttp_cols[i % len(ttp_cols)]:
                    st.markdown(f"""
                    <div style="background: #0f172a; border: 1px solid #1e293b; padding: 8px 12px; border-radius: 6px; font-family: monospace;">
                        <a href="{ttp.get('url', '#')}" target="_blank" style="color: #38bdf8; text-decoration: none; font-weight: 700;">{ttp.get('id')}</a><br>
                        <span style="font-size: 11px; color: #94a3b8;">{ttp.get('name')}</span><br>
                        <span style="font-size: 10px; color: #64748b;">({ttp.get('tactic', 'Tactic')})</span>
                    </div>
                    """, unsafe_allow_html=True)

        # =============================================================
        # Interactive Hierarchical Attack Tree (Left-to-Right Adversary Flow)
        # =============================================================
        st.markdown("##### ⚡ Interactive Horizontal Attack Tree (Adversary Flow)")
        st.caption("Explore hierarchical attack paths: [Level 1: Target Indicator] ➔ [Level 2: Attack Vectors] ➔ [Level 3: Weaponized Tools] ➔ [Level 4: Forensics & Containment]")

        # Prepare Level 2 Vector Branches
        primary_vec_id = attacks.get("vector_id", "ransomware")
        vector_catalog = get_attack_vector_catalog()
        
        branch_options = [primary_vec_id]
        branch_labels = {primary_vec_id: f"★ PRIMARY: {attacks.get('icon', '☣️')} {attacks.get('name', 'Primary Vector')}"}
        
        # Name-to-ID fallback lookup for secondary vectors
        vector_name_lookup = {
            "ransomware": "ransomware", "ransomware & extortion": "ransomware",
            "bruteforce": "bruteforce", "ssh / rdp brute force": "bruteforce", "brute force": "bruteforce",
            "phishing": "phishing", "phishing & credential theft": "phishing",
            "c2_beaconing": "c2_beaconing", "c2 beaconing & backdoor": "c2_beaconing", "c2 beaconing": "c2_beaconing",
            "web_exploitation": "web_exploitation", "web application exploitation": "web_exploitation", "web exploitation": "web_exploitation",
            "ddos_dos": "ddos_dos", "ddos / dos flooding": "ddos_dos", "ddos": "ddos_dos",
            "cryptomining": "cryptomining", "cryptomining & resource hijacking": "cryptomining",
            "reconnaissance": "reconnaissance", "reconnaissance & port scanning": "reconnaissance", "recon": "reconnaissance",
            "benign": "benign", "benign / legitimate infrastructure": "benign"
        }
        for sv in attacks.get("secondary_vectors", []):
            sv_id = sv.get("vector_id") or vector_name_lookup.get(str(sv.get("name", "")).lower().strip())
            if sv_id and sv_id not in branch_options and sv_id in vector_catalog:
                branch_options.append(sv_id)
                branch_labels[sv_id] = f"{sv.get('icon', '⚔️')} {sv.get('name')}"

        # Ensure at least 2 branches exist for comparative tree exploration
        if len(branch_options) < 2:
            for fallback_key in ["bruteforce", "c2_beaconing", "reconnaissance"]:
                if fallback_key not in branch_options and fallback_key in vector_catalog:
                    fb_def = vector_catalog[fallback_key]
                    branch_options.append(fallback_key)
                    branch_labels[fallback_key] = f"{fb_def.get('icon', '⚔️')} {fb_def.get('name')}"
                    if len(branch_options) >= 3:
                        break

        # Level 2 Attack Vector Branch Selector
        col_tree_sel, col_tree_meta = st.columns([3, 1])
        with col_tree_sel:
            selected_vector_id = st.radio(
                "Branch (Level 2 Attack Vector):",
                options=branch_options,
                format_func=lambda x: branch_labels.get(x, x),
                horizontal=True,
                key="streamlit_tree_vector_radio"
            )
        with col_tree_meta:
            st.metric(
                label="Active Vector",
                value=attacks.get("name") if selected_vector_id == primary_vec_id else vector_catalog.get(selected_vector_id, {}).get("name", "Vector"),
                delta="Primary Intent" if selected_vector_id == primary_vec_id else "Alt Vector"
            )

        if not selected_vector_id:
            selected_vector_id = primary_vec_id

        # Resolve Level 3 Tools for the Selected Vector Branch
        if selected_vector_id == primary_vec_id and attacks.get("adversary_tools"):
            tool_objs = attacks.get("adversary_tools", [])
        else:
            v_def = vector_catalog.get(selected_vector_id, {})
            tool_keys = v_def.get("default_tools", ["mimikatz"])
            tool_objs = [get_adversary_tool(k) for k in tool_keys if get_adversary_tool(k)]
        
        if not tool_objs:
            tool_objs = [get_adversary_tool("mimikatz")]

        # Render Visual Cyber Attack Tree Horizontal Diagram
        defanged_target = defang_ioc(target_ioc)
        curr_vec_name = attacks.get("name") if selected_vector_id == primary_vec_id else vector_catalog.get(selected_vector_id, {}).get("name", "Vector")
        curr_vec_icon = attacks.get("icon", "⚔️") if selected_vector_id == primary_vec_id else vector_catalog.get(selected_vector_id, {}).get("icon", "⚔️")
        
        tools_html_chips = "".join([
            f"<div style='background: #0f172a; border: 1px solid #38bdf8; color: #f8fafc; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-family: monospace; font-weight: 700; white-space: nowrap;'>🧰 {t.get('name')} <span style='color: #94a3b8; font-size: 10px;'>({t.get('category')})</span></div>"
            for t in tool_objs[:4]
        ])

        st.markdown(f"""
        <div style="background: radial-gradient(circle at 10% 20%, rgba(14, 20, 36, 0.95) 0%, rgba(8, 12, 22, 0.98) 100%); border: 1px solid #1e293b; border-radius: 12px; padding: 14px 18px; margin-bottom: 16px; overflow-x: auto;">
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 16px; min-width: 680px;">
                <!-- Level 1 Root Node -->
                <div style="background: #0c1222; border: 1.5px solid #00f0ff; box-shadow: 0 0 12px rgba(0, 240, 255, 0.2); border-radius: 8px; padding: 8px 12px; width: 190px;">
                    <div style="font-size: 9px; color: #00f0ff; font-weight: 800; text-transform: uppercase; font-family: monospace;">Level 1 &bull; Target IOC</div>
                    <div style="font-size: 12px; font-weight: 800; color: #ffffff; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{defanged_target}</div>
                    <div style="font-size: 10px; color: #94a3b8; font-family: monospace; margin-top: 2px;">{detection.get('type', 'IOC')} &bull; <span style="color: {risk.get('color', '#ef4444')}; font-weight: 700;">{risk.get('level')}</span></div>
                </div>

                <!-- Connector Line L1 -> L2 -->
                <div style="flex: 1; height: 2px; background: linear-gradient(90deg, #00f0ff, #f43f5e); position: relative;">
                    <div style="position: absolute; right: 0; top: -3px; width: 8px; height: 8px; border-radius: 50%; background: #f43f5e;"></div>
                </div>

                <!-- Level 2 Branch Node -->
                <div style="background: #111a30; border: 1.5px solid #f43f5e; box-shadow: 0 0 12px rgba(244, 63, 94, 0.25); border-radius: 8px; padding: 8px 12px; width: 220px;">
                    <div style="font-size: 9px; color: #f43f5e; font-weight: 800; text-transform: uppercase; font-family: monospace;">Level 2 &bull; Active Branch</div>
                    <div style="font-size: 12px; font-weight: 800; color: #ffffff; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{curr_vec_icon} {curr_vec_name}</div>
                    <div style="font-size: 10px; color: #cbd5e1; font-family: monospace; margin-top: 2px;">{len(tool_objs)} Weaponized Tools Mapped</div>
                </div>

                <!-- Connector Line L2 -> L3 -->
                <div style="flex: 1; height: 2px; background: linear-gradient(90deg, #f43f5e, #38bdf8); position: relative;">
                    <div style="position: absolute; right: 0; top: -3px; width: 8px; height: 8px; border-radius: 50%; background: #38bdf8;"></div>
                </div>

                <!-- Level 3 Leaf Nodes Summary -->
                <div style="display: flex; flex-direction: column; gap: 4px; min-width: 220px;">
                    <div style="font-size: 9px; color: #38bdf8; font-weight: 800; text-transform: uppercase; font-family: monospace;">Level 3 &bull; Tool Leaves</div>
                    <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                        {tools_html_chips}
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Level 3 Leaf Selector
        tool_options = [t.get("id") for t in tool_objs]
        tool_labels = {t.get("id"): f"🧰 {t.get('name')} — {t.get('category')}" for t in tool_objs}
        
        selected_tool_id = st.radio(
            "Select Weaponized Tool Leaf Node (Level 3):",
            options=tool_options,
            format_func=lambda x: tool_labels.get(x, x),
            horizontal=True,
            key=f"streamlit_tree_tool_radio_{selected_vector_id}"
        )

        selected_tool = next((t for t in tool_objs if t.get("id") == selected_tool_id), tool_objs[0])

        # Level 4: Forensics & Containment Inspector Card
        st.markdown(f"##### 🔬 Level 4 &bull; Forensics & Containment Inspector: **{selected_tool.get('name')}**")
        
        c_insp_info, c_insp_modal = st.columns([3, 1])
        with c_insp_info:
            active_branch_label = attacks.get("name") if selected_vector_id == primary_vec_id else vector_catalog.get(selected_vector_id, {}).get("name", selected_tool.get("primary_vector"))
            st.markdown(f"**Tool Category:** `{selected_tool.get('category')}` &bull; **Active Branch:** `{active_branch_label}`")
            st.markdown(f"**Hacker Tactical Purpose:** {selected_tool.get('tactical_purpose')}")
        with c_insp_modal:
            if st.button("🔍 Modal Playbook", key=f"insp_modal_btn_{selected_tool.get('id')}", use_container_width=True):
                show_adversary_tool_dialog(selected_tool)

        col_art, col_cont = st.columns(2)
        with col_art:
            st.markdown("**🔍 SOC Forensic Artifacts (Windows Event IDs & Log Indicators):**")
            st.code(selected_tool.get("forensic_artifacts", "No forensic artifacts recorded."), language="powershell")
        with col_cont:
            st.markdown("**🛡️ Targeted Containment Step:**")
            st.code(selected_tool.get("containment_step", "No containment step recorded."), language="powershell")

        # Threat Tags & Malware Families
        tags = otx_data.get("tags", [])
        malware_fams = otx_data.get("malware_families", [])
        if tags or malware_fams:
            st.markdown("##### 🏷️ Threat Actor Tags & Associated Campaigns")
            if malware_fams:
                st.markdown(f"**Malware Families:** " + " ".join([f"`{mf}`" for mf in malware_fams]))
            if tags:
                tag_badges = " ".join([f"<span class='type-pill'>#{t}</span>" for t in tags[:12]])
                st.markdown(f"**Campaign Tags:** {tag_badges}", unsafe_allow_html=True)

    # TAB 2: Deep Forensics & Map
    with tab_forensics:
        st.markdown("#### 🕸️ Interactive Threat Relationship Graph")
        with st.container():
            graph_data = generate_threat_graph(target_ioc, detection["type"], vt_data, abuse_data, otx_data, geo_data, risk_data=risk)
            nodes_json = json.dumps(graph_data.get("nodes", [])).replace("</", "<\\/")
            edges_json = json.dumps(graph_data.get("edges", [])).replace("</", "<\\/")
            graph_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="utf-8">
              <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
              <style>
                * {{ box-sizing: border-box; }}
                body {{
                  margin: 0;
                  padding: 0;
                  background-color: #070a13;
                  color: #e2e8f0;
                  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                  overflow: hidden;
                }}
                .graph-toolbar {{
                  display: flex;
                  justify-content: space-between;
                  align-items: center;
                  padding: 8px 12px;
                  background: #0f172a;
                  border: 1px solid #1e293b;
                  border-bottom: none;
                  border-radius: 8px 8px 0 0;
                  font-size: 11px;
                  flex-wrap: wrap;
                  gap: 8px;
                }}
                .graph-toolbar .legend {{
                  display: flex;
                  gap: 6px;
                  flex-wrap: wrap;
                  align-items: center;
                }}
                .badge {{
                  padding: 2px 6px;
                  border-radius: 4px;
                  font-family: monospace;
                  font-size: 10px;
                }}
                .b-ioc {{ background: rgba(0, 240, 255, 0.15); color: #00f0ff; border: 1px solid rgba(0, 240, 255, 0.4); }}
                .b-mal {{ background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }}
                .b-act {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
                .b-asn {{ background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }}
                .b-geo {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }}
                .b-pulse {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
                .b-status {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }}
                .btn-group {{
                  display: flex;
                  gap: 4px;
                  margin-left: auto;
                }}
                .btn {{
                  background: #1e293b;
                  border: 1px solid #334155;
                  color: #cbd5e1;
                  padding: 3px 8px;
                  border-radius: 4px;
                  cursor: pointer;
                  font-size: 11px;
                  transition: all 0.15s ease;
                }}
                .btn:hover {{
                  background: #334155;
                  color: #f8fafc;
                }}
                #network {{
                  width: 100%;
                  height: 380px;
                  background: #070a13;
                  border: 1px solid #1e293b;
                  position: relative;
                }}
                #inspector {{
                  padding: 6px 12px;
                  background: #0b1120;
                  border: 1px solid #1e293b;
                  border-top: none;
                  border-radius: 0 0 8px 8px;
                  font-size: 11px;
                  font-family: monospace;
                  color: #94a3b8;
                  min-height: 28px;
                  display: flex;
                  align-items: center;
                  overflow-x: auto;
                }}
                #inspector strong {{ color: #00f0ff; }}
              </style>
            </head>
            <body>
              <div class="graph-toolbar">
                <div class="legend">
                  <span class="badge b-ioc">★ Target IOC</span>
                  <span class="badge b-mal">⬡ Malware</span>
                  <span class="badge b-act">◆ Threat Actor</span>
                  <span class="badge b-asn">■ ASN / Host</span>
                  <span class="badge b-geo">● Geolocation</span>
                  <span class="badge b-pulse">▲ Pulse</span>
                  <span class="badge b-status">🛡️ Status</span>
                </div>
                <div class="btn-group">
                  <button class="btn" onclick="network.moveTo({{ scale: network.getScale() * 1.25 }})">+</button>
                  <button class="btn" onclick="network.moveTo({{ scale: network.getScale() * 0.8 }})">-</button>
                  <button class="btn" onclick="network.fit({{ animation: {{ duration: 500, easingFunction: 'easeInOutQuad' }} }})">↺ Center</button>
                  <button class="btn" id="btn-phys" onclick="togglePhysics()">⏸ Physics</button>
                </div>
              </div>
              <div id="network"></div>
              <div id="inspector">Click any node or relationship link to inspect threat intelligence telemetry</div>

              <script>
                function escapeHtml(str) {{
                  if (!str) return '';
                  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
                }}

                let physicsEnabled = true;
                let network = null;
                const nodes = new vis.DataSet({nodes_json});
                const edges = new vis.DataSet({edges_json});
                const container = document.getElementById('network');
                const inspector = document.getElementById('inspector');

                const options = {{
                  physics: {{
                    barnesHut: {{
                      gravitationalConstant: -4000,
                      centralGravity: 0.15,
                      springLength: 160,
                      springConstant: 0.04,
                      damping: 0.09
                    }},
                    repulsion: {{
                      nodeDistance: 175,
                      centralGravity: 0.15,
                      springLength: 160,
                      springConstant: 0.04,
                      damping: 0.09
                    }},
                    stabilization: {{ iterations: 120 }}
                  }},
                  interaction: {{
                    hover: true,
                    tooltipDelay: 100,
                    zoomView: true,
                    dragView: true
                  }},
                  nodes: {{
                    borderWidth: 2,
                    shadow: {{ enabled: true, color: 'rgba(0, 240, 255, 0.25)', size: 8, x: 0, y: 0 }},
                    font: {{
                      color: '#ffffff',
                      face: 'Inter, -apple-system, sans-serif',
                      size: 12,
                      strokeWidth: 2,
                      strokeColor: '#070a13'
                    }}
                  }},
                  edges: {{
                    width: 1.5,
                    smooth: {{ type: 'continuous' }},
                    arrows: {{ to: {{ enabled: true, scaleFactor: 0.8 }} }},
                    font: {{
                      color: '#94a3b8',
                      face: 'Inter, -apple-system, sans-serif',
                      size: 10,
                      align: 'middle',
                      strokeWidth: 0,
                      background: '#070a13'
                    }}
                  }},
                  groups: {{
                    ioc: {{ shape: "star", size: 35 }},
                    actor: {{ shape: "diamond", size: 28 }},
                    malware: {{ shape: "hexagon", size: 26 }},
                    geolocation: {{ shape: "dot", size: 20 }},
                    asn: {{ shape: "square", size: 22 }},
                    isp: {{ shape: "box", size: 18 }},
                    pulse: {{ shape: "triangle", size: 18 }},
                    file_type: {{ shape: "ellipse", size: 18 }},
                    clean: {{ shape: "box", size: 22 }},
                    status: {{ shape: "box", size: 22 }}
                  }}
                }};

                network = new vis.Network(container, {{ nodes: nodes, edges: edges }}, options);

                network.once('stabilizationIterationsDone', function() {{
                  network.fit({{ animation: {{ duration: 500, easingFunction: 'easeInOutQuad' }} }});
                }});

                network.on('click', function(params) {{
                  if (params.nodes.length > 0) {{
                    const n = nodes.get(params.nodes[0]);
                    if (n) {{
                      const grp = escapeHtml((n.group || '').toUpperCase());
                      const rawLbl = escapeHtml(n.label || '');
                      const rawTit = escapeHtml(n.title || '');
                      const cleanVal = rawLbl.replace(/^(Actor|Malware|Location|ASN|ISP|Pulse|Format):\\s*/i, '').trim();
                      let cleanTit = rawTit.replace(/^(Threat Actor Group|Threat Actor|Malware Family|Malware|Host Physical Geolocation|Host Location|Autonomous System|Internet Service Provider \\/ Host|Internet Service Provider|AlienVault Pulse|File Classification|Target Indicator|Reputation):\\s*/i, '').trim();
                      const normVal = cleanVal.toLowerCase().replace(/[\\[\\]\\(\\)\\s]/g, '');
                      const normTit = cleanTit.toLowerCase().replace(/[\\[\\]\\(\\)\\s]/g, '');
                      const normLbl = rawLbl.toLowerCase().replace(/[\\[\\]\\(\\)\\s]/g, '');

                      if (!cleanTit || normTit === normVal || normTit === normLbl) {{
                        inspector.innerHTML = `<strong>Selected Node:</strong> [${{grp}}] ${{cleanVal || rawLbl}}`;
                      }} else {{
                        let extra = cleanTit;
                        const refangedVal = cleanVal.replace(/\\[\\.\\]/g, '.').replace(/hxxp/gi, 'http');
                        [cleanVal, refangedVal].forEach(function(v) {{
                          if (v && extra.includes(v)) extra = extra.replace(v, '').trim();
                        }});
                        extra = extra.replace(/^[•–\\-\\s:()]+|[•–\\-\\s:()]+$/g, '');

                        if (extra && extra.toLowerCase() !== normVal) {{
                          inspector.innerHTML = `<strong>Selected Node:</strong> [${{grp}}] ${{cleanVal || rawLbl}} &bull; ${{extra}}`;
                        }} else {{
                          inspector.innerHTML = `<strong>Selected Node:</strong> [${{grp}}] ${{cleanVal || rawLbl}}`;
                        }}
                      }}
                    }}
                  }} else if (params.edges.length > 0) {{
                    const e = edges.get(params.edges[0]);
                    if (e) {{
                      const src = nodes.get(e.from);
                      const tgt = nodes.get(e.to);
                      const sLabel = escapeHtml(src ? src.label : e.from);
                      const tLabel = escapeHtml(tgt ? tgt.label : e.to);
                      const relLabel = escapeHtml(e.label || 'connected');
                      inspector.innerHTML = `<strong>Selected Relationship:</strong> ${{sLabel}} &rarr; ${{tLabel}} [${{relLabel}}]`;
                    }}
                  }}
                }});

                network.on('hoverNode', function() {{ container.style.cursor = 'pointer'; }});
                network.on('blurNode', function() {{ container.style.cursor = 'default'; }});
                network.on('hoverEdge', function() {{ container.style.cursor = 'pointer'; }});
                network.on('blurEdge', function() {{ container.style.cursor = 'default'; }});

                function togglePhysics() {{
                  physicsEnabled = !physicsEnabled;
                  network.setOptions({{ physics: {{ enabled: physicsEnabled }} }});
                  const btn = document.getElementById('btn-phys');
                  btn.innerText = physicsEnabled ? '⏸ Physics' : '▶ Physics';
                }}
              </script>
            </body>
            </html>
            """
            components.html(graph_html, height=480)
            col_g1, col_g2, col_g3 = st.columns(3)
            with col_g1:
                st.caption(f"Nodes: **{len(graph_data.get('nodes', []))}** | Edges: **{len(graph_data.get('edges', []))}**")
            with col_g2:
                actors = graph_data.get("summary", {}).get("actors_found", [])
                st.caption(f"Threat Actors: **{', '.join(actors) if actors else 'None'}**")
            with col_g3:
                malware = graph_data.get("summary", {}).get("malware_found", [])
                st.caption(f"Malware Families: **{', '.join(malware) if malware else 'None'}**")

        st.markdown('---')
        st.markdown('#### 🗺️ Physical Origin & Network Map')
        st.markdown("#### 🗺️ Physical Location & ASN Routing Map")
        if geo_data.get("status") == "success" and "lat" in geo_data and "lon" in geo_data and (geo_data["lat"] != 0.0 or geo_data["lon"] != 0.0):
            lat = geo_data["lat"]
            lon = geo_data["lon"]
            map_df = pd.DataFrame([{"lat": lat, "lon": lon}])
            col_map, col_as = st.columns([2, 1])
            with col_map:
                st.map(map_df, zoom=3)
            with col_as:
                st.markdown(f"""
                <div class="soc-card">
                    <div class="soc-card-label">Network Infrastructure</div>
                    <p style="margin-top: 8px; font-size: 13px;">
                        <b>ISP:</b> {geo_data.get('isp', 'Unknown')}<br>
                        <b>ASN:</b> {geo_data.get('as_info', 'Unknown')}<br>
                        <b>Timezone:</b> {geo_data.get('timezone', 'UTC')}<br>
                        <b>Coordinates:</b> {lat}, {lon}
                    </p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("🌐 **Non-IP Asset Telemetry:** Physical origin maps and BGP Autonomous System routing are specifically applicable to IPv4 and IPv6 assets. This indicator is investigated via global file reputation, domain infrastructure, and vendor telemetry.")

        st.markdown("---")
        st.markdown("#### 🔬 Multi-Source Antivirus Vendor Detection Matrix")
        vendors = vt_data.get("vendors", {})
        if vendors:
            tier1_keywords = [
                "microsoft", "crowdstrike", "sentinelone", "sophos", "palo alto", "paloaltonetworks",
                "symantec", "broadcom", "trendmicro", "trend micro", "kaspersky", "bitdefender",
                "carbonblack", "carbon black", "trellix", "mcafee", "fortinet", "cisco", "eset", "withsecure"
            ]
            
            vendor_records = []
            tier1_total = 0
            tier1_flagged = 0
            for v_name, v_verdict in vendors.items():
                v_lower = str(v_verdict).lower()
                status_tag = "🔴 Malicious" if "malicious" in v_lower else ("🟡 Suspicious" if "suspicious" in v_lower else "🟢 Clean")
                is_tier1 = any(k in v_name.lower() for k in tier1_keywords)
                if is_tier1:
                    tier1_total += 1
                    if "malicious" in v_lower or "suspicious" in v_lower:
                        tier1_flagged += 1
                
                vendor_records.append({
                    "Security Vendor": f"⭐ {v_name} (Tier-1 EDR)" if is_tier1 else v_name,
                    "Threat Classification": str(v_verdict),
                    "Status": status_tag,
                    "is_tier1": is_tier1
                })
            
            if tier1_total > 0:
                tier1_color = "#ef4444" if tier1_flagged > 0 else "#10b981"
                st.markdown(f"""
                <div style="background-color: #0c1222; border: 1px solid #1e293b; border-radius: 8px; padding: 10px 16px; margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="font-weight: 700; color: #f59e0b; font-size: 12px; font-family: monospace;">⭐ TIER-1 EDR CONSENSUS:</span>
                        <span style="font-weight: 800; color: {tier1_color}; font-size: 13px; font-family: monospace; margin-left: 8px;">{tier1_flagged} / {tier1_total} Engines Flagged</span>
                    </div>
                    <span style="font-size: 11px; color: #94a3b8;">CrowdStrike, Defender, SentinelOne, Sophos, Palo Alto, etc.</span>
                </div>
                """, unsafe_allow_html=True)
            
            col_vf1, col_vf2 = st.columns([3, 1])
            with col_vf1:
                vendor_search = st.text_input("Filter vendor or classification", key="vt_vendor_search", placeholder="e.g. Defender, trojan, clean...")
            with col_vf2:
                vendor_filter_type = st.selectbox("Filter Tier/Status", ["All Vendors", "⭐ Tier-1 EDRs Only", "🔴 Malicious Only", "🟡 Suspicious Only", "🟢 Clean Only"], key="vt_tier_filter")

            filtered_records = []
            for r in vendor_records:
                if vendor_search and (vendor_search.lower() not in r["Security Vendor"].lower() and vendor_search.lower() not in r["Threat Classification"].lower()):
                    continue
                if vendor_filter_type == "⭐ Tier-1 EDRs Only" and not r["is_tier1"]:
                    continue
                if vendor_filter_type == "🔴 Malicious Only" and "🔴" not in r["Status"]:
                    continue
                if vendor_filter_type == "🟡 Suspicious Only" and "🟡" not in r["Status"]:
                    continue
                if vendor_filter_type == "🟢 Clean Only" and "🟢" not in r["Status"]:
                    continue
                filtered_records.append({
                    "Security Vendor": r["Security Vendor"],
                    "Engine Classification": r["Threat Classification"],
                    "Detection Verdict": r["Status"]
                })

            if filtered_records:
                st.dataframe(pd.DataFrame(filtered_records), use_container_width=True, hide_index=True)
            else:
                st.info("No vendor detection records match the current filter criteria.")
        else:
            st.info("No active vendor detection alerts recorded for this indicator.")

    # TAB 3: Defense & Containment
    with tab_containment:
        if st.session_state.get("active_containment_tab"):
            active_cmd = st.session_state.get("last_containment_rule", "")
            if active_cmd:
                st.info(f"⚡ **Active Containment Command**: `{active_cmd}`")

        st.markdown("#### 📋 Recommended SOC Tactical Containment Playbook")
        for idx, action in enumerate(risk["actions"], 1):
            st.markdown(f"**Step {idx}:** {action}")

        st.markdown("---")
        st.markdown("#### 🛡️ 1-Click Defensive Rule Generator (Immediate Containment)")
        telemetry_dict = {"risk": risk, "vt": vt_data, "abuse": abuse_data, "otx": otx_data, "geo": geo_data}
        rule_bundle = generate_all_defensive_rules(target_ioc, detection["type"], telemetry_dict)

        tab_yara, tab_sigma, tab_fw = st.tabs(["🛡️ YARA (.yar)", "⚡ Sigma (YAML)", "🛑 Firewall Commands"])
        with tab_yara:
            st.caption("Standard YARA detection rule:")
            st.code(rule_bundle["yara"], language="c")
        with tab_sigma:
            st.caption("Generic SIEM detection signature (Sigma YAML):")
            st.code(rule_bundle["sigma"], language="yaml")
        with tab_fw:
            if rule_bundle.get("firewall"):
                fw = rule_bundle["firewall"]
                st.markdown("**Windows PowerShell:**")
                st.code(fw["powershell"], language="powershell")
                st.markdown("**Linux iptables / ip6tables:**")
                st.code(fw["iptables"], language="bash")
                st.markdown("**Cisco IOS ACL:**")
                st.code(fw["cisco_acl"], language="text")
            else:
                st.info("Firewall containment commands are only generated for IP indicators.")

        st.markdown("---")
        st.markdown("#### 🌐 Website Security Posture & SSL Health Audit")
        
        if not web_security or web_security.get("status") == "not_applicable":
            st.info("ℹ️ Website security headers and SSL audit is only applicable to web domains and URLs.")
        elif web_security.get("status") == "error":
            st.error(f"⚠️ {web_security.get('error', 'Error inspecting website security.')}")
        else:
            w_score = web_security.get("score", 0)
            w_grade = web_security.get("grade", "N/A")
            ssl_info = web_security.get("ssl") or {}
            redirect_info = web_security.get("redirect") or {}
            
            # Top Banner & Metrics
            m_col1, m_col2, m_col3, m_col4 = st.columns(4)
            with m_col1:
                st.metric(
                    label="Hardening Letter Grade",
                    value=f"Grade {w_grade}",
                    delta=f"{w_score}/100 Score"
                )
            with m_col2:
                days_left = ssl_info.get("expires_in_days", 0)
                st.metric(
                    label="SSL Certificate Status",
                    value=ssl_info.get("status_label", "Unknown"),
                    delta=f"{days_left} days left" if days_left >= 0 else f"Expired {abs(days_left)}d ago"
                )
            with m_col3:
                st.metric(
                    label="TLS Protocol",
                    value=ssl_info.get("protocol", "N/A"),
                    delta=ssl_info.get("cipher", "N/A")
                )
            with m_col4:
                enforced = redirect_info.get("enforced", False)
                st.metric(
                    label="HTTPS Enforcement",
                    value="Enforced (301/302)" if enforced else "Not Enforced",
                    delta="HTTPS Upgraded" if enforced else "Plaintext Allowed"
                )

            st.caption(f"**Website Rating Assessment:** {web_security.get('grade_description', '')}")

            # SSL Certificate Details Card
            st.markdown("---")
            st.markdown("##### 🔒 SSL/TLS Certificate Breakdown")
            c_ssl1, c_ssl2 = st.columns(2)
            with c_ssl1:
                st.markdown(f"""
                <div class="soc-card">
                    <div class="soc-card-label">Certificate Authority &amp; Subject</div>
                    <div style="font-size: 14px; font-weight: bold; color: #f8fafc; margin-top: 4px;">
                        Issuer: {ssl_info.get('issuer', 'N/A')}
                    </div>
                    <div style="font-size: 12px; color: #94a3b8; margin-top: 4px; font-family: monospace;">
                        Subject: {ssl_info.get('subject', 'N/A')}
                    </div>
                </div>
                """, unsafe_allow_html=True)
            with c_ssl2:
                st.markdown(f"""
                <div class="soc-card">
                    <div class="soc-card-label">Validity Window &amp; Expiration Date</div>
                    <div style="font-size: 14px; font-weight: bold; color: {ssl_info.get('status_color', '#10b981')}; margin-top: 4px;">
                        {ssl_info.get('expiry_date', 'N/A')}
                    </div>
                    <div style="font-size: 12px; color: #94a3b8; margin-top: 4px; font-family: monospace;">
                        Countdown: {ssl_info.get('expires_in_days', 0)} days until expiration
                    </div>
                </div>
                """, unsafe_allow_html=True)

            # Defensive HTTP Security Headers Matrix
            st.markdown("---")
            st.markdown("##### 🛡️ OWASP Defensive HTTP Security Headers Matrix")
            checklist = web_security.get("checklist", [])
            passing_count = sum(1 for item in checklist if item.get("passed"))
            st.caption(f"Passing {passing_count} of {len(checklist)} baseline defensive headers.")

            for item in checklist:
                passed = item.get("passed", False)
                status_icon = "✅ PASS" if passed else ("⚠️ WARN" if item.get("status") == "WARN" else "❌ FAIL")
                with st.expander(f"{status_icon} • **{item.get('header')}** — *{item.get('name')}*", expanded=not passed):
                    col_h1, col_h2 = st.columns([1, 2])
                    with col_h1:
                        st.markdown(f"**Importance:** `{item.get('importance', 'Medium')}`")
                        st.markdown(f"**Observed Value:** `{item.get('value', 'Missing')}`")
                    with col_h2:
                        st.markdown(f"**Security Purpose:** {item.get('description', '')}")
                        st.markdown(f"**Remediation Advice:** {item.get('remediation', '')}")

            # 1-Click Hardening Configs
            st.markdown("---")
            st.markdown("##### ⚙️ 1-Click Server Hardening Configurations")
            configs = web_security.get("configs", {})
            tab_nginx_cfg, tab_apache_cfg = st.tabs(["Nginx (nginx.conf)", "Apache (.htaccess / httpd.conf)"])
            with tab_nginx_cfg:
                st.caption("Add these security directives inside your Nginx server {} block:")
                st.code(configs.get("nginx", ""), language="nginx")
            with tab_apache_cfg:
                st.caption("Add these security directives inside your Apache .htaccess or VirtualHost:")
                st.code(configs.get("apache", ""), language="apache")

            # SOC Plain-English Recommendations
            recs = web_security.get("recommendations", [])
            if recs:
                st.markdown("---")
                st.markdown("##### 🎯 Prioritized SOC Hardening Steps")
                for r_idx, r_text in enumerate(recs, 1):
                    st.markdown(f"**[{r_idx}]** {r_text}")

        # =================================================================
        # Report Export Center
        # =================================================================
        st.markdown("---")
        st.markdown("### 📥 Investigation Export Center")
        col_exp1, col_exp2, col_exp3, col_exp4 = st.columns(4)

        # JSON Dossier
        with col_exp1:
            json_content = generate_json_report(
                target_ioc, detection["type"], risk, vt_data, abuse_data, otx_data, geo_data,
                web_security_data=web_security
            )
            st.download_button(
                label="📄 Export JSON Dossier",
                data=json_content,
                file_name=f"investigation_{target_ioc.replace(':', '_')}.json",
                mime="application/json",
                use_container_width=True
            )

        # PDF Dossier
        with col_exp2:
            pdf_bytes = generate_pdf_report(
                target_ioc, detection["type"], risk, vt_data, abuse_data, otx_data, geo_data,
                web_security_data=web_security
            )
            st.download_button(
                label="📑 Download PDF Report",
                data=pdf_bytes,
                file_name=f"soc_report_{target_ioc.replace(':', '_')}.pdf",
                mime="application/pdf",
                use_container_width=True
            )

        # Markdown Brief
        with col_exp3:
            md_content = generate_markdown_report(
                target_ioc, detection["type"], risk, vt_data, abuse_data, otx_data, geo_data,
                web_security_data=web_security
            )
            st.download_button(
                label="📋 Download Markdown Brief",
                data=md_content,
                file_name=f"brief_{target_ioc.replace(':', '_')}.md",
                mime="text/markdown",
                use_container_width=True
            )

        # STIX 2.1 Threat Bundle
        with col_exp4:
            stix_json_str = generate_stix_json(
                target_ioc, detection["type"], risk, vt_data, abuse_data, otx_data, geo_data
            )
            st.download_button(
                label="📦 Export STIX 2.1 Bundle",
                data=stix_json_str,
                file_name=f"stix21_{target_ioc.replace(':', '_')}.json",
                mime="application/json",
                use_container_width=True
            )

        # Progressive Disclosure: Raw Investigation JSON & Telemetry Dossier
        with st.expander("Details ▾ (Raw Multi-Source Telemetry & JSON Dossier)", expanded=False):
            st.caption("Complete multi-source forensic payload and telemetry records:")
            full_telemetry = {
                "ioc": target_ioc,
                "type": detection["type"],
                "risk": risk,
                "attacks": attacks,
                "virustotal": vt_data,
                "abuseipdb": abuse_data,
                "otx": otx_data,
                "geolocation": geo_data,
                "web_security": web_security
            }
            st.json(full_telemetry)

        # =================================================================
        # SOC Incident Alert Webhook Dispatcher
        # =================================================================
        with st.expander("📢 Dispatch SOC Incident Alert (Webhook)", expanded=False):
            st.markdown("Broadcast this investigation directly into SOC team messaging channels.")
            col_wh1, col_wh2 = st.columns([3, 1])
            with col_wh1:
                webhook_url = st.text_input(
                    "Incoming Webhook URL",
                    placeholder="https://discord.com/api/webhooks/... or https://hooks.slack.com/...",
                    key="wh_url_input"
                )
            with col_wh2:
                wh_platform = st.selectbox(
                    "Platform",
                    ["Auto-Detect", "Discord", "Slack", "Microsoft Teams"],
                    key="wh_plat_select"
                )
            wh_dry_run = st.checkbox("Simulation / Dry-Run (Test dispatch without calling endpoint)", value=False, key="wh_dry_run")

            if st.button("📢 Dispatch Incident Alert", use_container_width=True, key="wh_dispatch_btn"):
                if not webhook_url and not wh_dry_run:
                    st.warning("Please provide a valid incoming webhook URL.")
                else:
                    target_wh = webhook_url or "https://discord.com/api/webhooks/simulation/test"
                    plat = None if wh_platform == "Auto-Detect" else wh_platform.lower()
                    res = dispatch_webhook_alert(
                        webhook_url=target_wh,
                        ioc=target_ioc,
                        ioc_type=detection["type"],
                        risk_data=risk,
                        vt_data=vt_data,
                        otx_data=otx_data,
                        platform=plat,
                        dry_run=wh_dry_run
                    )
                    if res.get("success"):
                        st.success(f"Alert successfully dispatched! Platform: {res.get('platform', 'Webhook').title()} {'(Simulated)' if res.get('simulated') else ''}")
                    else:
                        st.error(f"Dispatch failed: {res.get('error', 'Unknown error')}")


    # =====================================================================
    # Tab 2: Bulk IOC Scanner
    # =====================================================================

def render_bulk_scanner(config: dict):
    st.markdown("### 📦 Bulk Threat Indicator Batch Scanner")
    st.caption("Upload a CSV/TXT list of IOCs or paste multiple indicators to run automated multi-source triage.")

    tab_upload, tab_paste = st.tabs(["📁 Upload File (CSV / TXT / TSV)", "📝 Paste List"])
    
    candidates = []
    header_keywords = {"ioc", "indicator", "ip", "ip_address", "ipaddress", "domain", "hash", "url", "target", "value"}

    with tab_upload:
        uploaded_file = st.file_uploader("Upload CSV, TSV, or TXT file with IOCs", type=["csv", "txt", "tsv"])
        if uploaded_file is not None:
            try:
                content = uploaded_file.read().decode("utf-8", errors="ignore")
                lines = [l.strip() for l in content.splitlines() if l.strip()]
                for idx, l in enumerate(lines):
                    # Check for delimiter
                    delim = "," if "," in l else ("\t" if "\t" in l else (";" if ";" in l else None))
                    first_val = l.split(delim)[0].strip().strip('"').strip("'") if delim else l
                    # Skip common header row on first line
                    if idx == 0 and first_val.lower() in header_keywords:
                        continue
                    if first_val:
                        candidates.append(first_val)
            except Exception as e:
                st.error(f"Error parsing uploaded file: {e}")

    with tab_paste:
        paste_text = st.text_area(
            "Paste indicators (one per line):",
            height=140,
            placeholder="185.220.101.5\n8.8.8.8\nsecure-login-paypal-verify[.]com\ned01ebf8342f1ab0ebf6853cb068e54094f70f4dcb353bec1a4f84d7aa9618cc\n45.33.32.156:8080"
        )
        if paste_text:
            pasted = [line.strip() for line in paste_text.splitlines() if line.strip()]
            for idx, p in enumerate(pasted):
                if idx == 0 and p.lower() in header_keywords:
                    continue
                candidates.append(p)

    # Deduplicate candidates while preserving order
    unique_candidates = list(dict.fromkeys(candidates))

    col_b1, col_b2 = st.columns([3, 1])
    with col_b1:
        if unique_candidates:
            st.info(f"Loaded **{len(unique_candidates)}** unique indicators ready for batch analysis.")
        else:
            st.caption("Upload a file or paste lines above to begin.")
    with col_b2:
        if st.session_state.bulk_results:
            if st.button("🗑️ Clear Batch Results", use_container_width=True):
                st.session_state.bulk_results = None
                st.rerun()

    if unique_candidates:
        if st.button("⚡ Start Bulk Investigation", type="primary", use_container_width=True):
            progress_bar = st.progress(0.0)
            status_text = st.empty()
            
            results = []
            total = len(unique_candidates)

            for idx, candidate in enumerate(unique_candidates):
                status_text.text(f"Scanning ({idx + 1}/{total}): {candidate}")
                
                det = detect_ioc_type(candidate)
                normalized = det["normalized"]
                
                if det["valid"]:
                    vt = query_virustotal(normalized, det["type"], config["vt_key"], config["demo_mode"])
                    abuse = query_abuseipdb(normalized, det["type"], config["abuse_key"], config["demo_mode"])
                    otx = query_alienvault(normalized, det["type"], config["otx_key"], config["demo_mode"])
                    geo = query_geolocation(normalized, det["type"], config["demo_mode"])
                    risk = calculate_risk_score(normalized, det["type"], vt, abuse, otx, geo_data=geo)
                    attack_data = analyze_attack_vector(
                        ioc=normalized,
                        ioc_type=det["type"],
                        vt_data=vt,
                        abuse_data=abuse,
                        otx_data=otx,
                        risk_score=risk["score"]
                    )
                    
                    country_name = geo.get("country", "N/A") if geo.get("status") == "success" else "N/A"
                    save_investigation(
                        ioc=normalized,
                        ioc_type=det["type"],
                        risk_score=risk["score"],
                        risk_level=risk["level"],
                        vt_malicious=vt.get("malicious", 0),
                        abuse_score=abuse.get("abuse_confidence_score", 0),
                        country=country_name,
                        analyst_notes=risk["summary"]
                    )

                    results.append({
                        "IOC": normalized,
                        "Type": det["type_label"],
                        "Attack Vector": f"{attack_data.get('icon', '❓')} {attack_data.get('name', 'Unclassified')}",
                        "Risk Score": risk["score"],
                        "Threat Level": risk["level"],
                        "VT Malicious": vt.get("malicious", 0),
                        "Abuse %": abuse.get("abuse_confidence_score", "N/A"),
                        "OTX Pulses": otx.get("pulse_count", 0),
                        "Country": country_name
                    })
                else:
                    results.append({
                        "IOC": candidate,
                        "Type": "Invalid / Unknown",
                        "Attack Vector": "❓ Unclassified",
                        "Risk Score": 0,
                        "Threat Level": "Invalid Format",
                        "VT Malicious": 0,
                        "Abuse %": "N/A",
                        "OTX Pulses": 0,
                        "Country": "N/A"
                    })

                progress_bar.progress((idx + 1) / total)

            status_text.success(f"Batch investigation complete for {total} indicators!")
            st.session_state.bulk_results = results
            st.rerun()

    # Persistent Display of Bulk Results
    if st.session_state.bulk_results:
        st.markdown("---")
        st.markdown("#### 📊 Bulk Triage Summary Metrics")
        
        res_list = st.session_state.bulk_results
        total_count = len(res_list)
        crit_count = sum(1 for r in res_list if r["Risk Score"] >= 61)
        susp_count = sum(1 for r in res_list if 21 <= r["Risk Score"] <= 60)
        benign_count = sum(1 for r in res_list if 1 <= r["Risk Score"] <= 20)
        invalid_count = sum(1 for r in res_list if r["Threat Level"] == "Invalid Format")

        sum_c1, sum_c2, sum_c3, sum_c4, sum_c5 = st.columns(5)
        sum_c1.metric("Total Scanned", total_count)
        sum_c2.metric("Critical Alerts", crit_count)
        sum_c3.metric("Suspicious Alerts", susp_count)
        sum_c4.metric("Benign Assets", benign_count)
        sum_c5.metric("Invalid IOCs", invalid_count)

        res_df = pd.DataFrame(res_list)
        res_df = res_df.sort_values(by="Risk Score", ascending=False)
        st.dataframe(res_df, use_container_width=True, hide_index=True)

        # Persistent Download CSV
        csv_data = res_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export Bulk Results CSV",
            data=csv_data,
            file_name=f"bulk_ioc_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )


# =====================================================================
# Tab 3: Investigation History & Audit Log
# =====================================================================
def render_history():
    st.markdown("### 🗃️ SOC Investigation History & Audit Log")
    st.caption("Persistent audit trail of previous analyst lookups stored in local SQLite database.")

    col_search, col_limit, col_clear = st.columns([3, 1, 1])
    with col_search:
        search_kw = st.text_input("Filter investigations by keyword or IOC:", placeholder="Search IP, Hash, Domain...")
    with col_limit:
        limit = st.selectbox("Show rows", [25, 50, 100, 250], index=1)
    with col_clear:
        st.write("")
        st.write("")
        if st.button("🗑️ Clear History", type="secondary"):
            clear_history()
            st.success("Investigation history cleared.")
            st.rerun()

    records = get_history(limit=limit, search_query=search_kw)

    if records:
        df = pd.DataFrame(records)
        df_display = df[["id", "timestamp", "ioc", "ioc_type", "risk_score", "risk_level", "vt_malicious", "abuse_score", "country", "analyst_notes"]].copy()
        df_display.columns = ["ID", "Timestamp (UTC)", "Indicator (IOC)", "Type", "Risk Score", "Verdict", "VT Hits", "Abuse %", "Country", "Notes"]
        st.dataframe(df_display, use_container_width=True, hide_index=True)

        # Action: Quick reload of past IOC into single scanner
        st.markdown("#### ⚡ Quick-Load Past Indicator into Live Scanner")
        col_sel, col_load = st.columns([3, 1])
        with col_sel:
            ioc_options = [f"ID {r['id']} | {r['ioc']} ({r['ioc_type']} - Score {r['risk_score']})" for r in records[:30]]
            selected_option = st.selectbox("Select past investigation:", ioc_options)
        with col_load:
            st.write("")
            st.write("")
            if st.button("🔍 Load into Scanner", use_container_width=True):
                # Extract IOC from selected option string
                selected_id = int(selected_option.split("|")[0].replace("ID", "").strip())
                record_match = next((r for r in records if r["id"] == selected_id), None)
                if record_match:
                    st.session_state["pending_ioc_input"] = record_match["ioc"]
                    st.session_state.trigger_scan = True
                    st.rerun()
    else:
        st.info("No past investigations found matching your filter criteria.")


# =====================================================================
# Tab 4: Threat Intelligence Knowledge & MITRE ATT&CK
# =====================================================================
def render_threat_feed():
    st.markdown("### 📡 Live Cyber Threat Intelligence Briefing & MITRE ATT&CK")
    st.caption("Global threat telemetry, active campaigns, and SOC triage playbooks.")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        #### 🚨 Trending Adversary Campaigns & Ransomware
        - **WannaCry / EternalBlue (MS17-010):** Continues automated internet-wide SMB reconnaissance. Exploit payload executes embedded doublepulsar backdoors.
        - **Cobalt Strike Team Servers:** Frequent deployment on bulletproof hosts and anonymization networks (Tor / VPN relays) for C2 beaconing.
        - **Emotet / Qakbot Resurgence:** High-volume phishing emails using malicious PDF and OneNote attachments delivering secondary stage DLL droppers.
        - **Credential Stuffing Clusters:** Distributed brute-force attacks targeting corporate SSO portals and VPN concentrators from residential proxies.
        """)

        st.markdown("""
        #### 🧩 MITRE ATT&CK Enterprise Matrix Mapping
        | Tactic | Technique ID | Technique Name | Common IOC Associated |
        | :--- | :--- | :--- | :--- |
        | **Initial Access** | T1566 | Phishing Links | Malicious Domains & URLs |
        | **Execution** | T1204 | User Execution | Dropper Executable Hashes |
        | **Persistence** | T1547 | Registry Run Keys | Staged DLL Hashes |
        | **Command & Control** | T1071 | Application Layer Protocol | C2 IP Addresses & Dynamic Domains |
        | **Exfiltration** | T1048 | Exfiltration Over Alternative Protocol | VPS Transit Hosts & Storage Buckets |
        """)

    with col2:
        st.markdown("""
        #### 🛡️ IOC Classification Reference
        - **IPv4 / IPv6:** Network layer indicators. Scanned against AbuseIPDB and AlienVault for past abusive activity, scanning, and geographic origin.
        - **File Hashes (MD5, SHA-1, SHA-256):** Cryptographic fingerprints for static malware identification. Scanned across 70+ Antivirus engines.
        - **Domains & URLs:** Host and web application layer indicators. Flagged for typosquatting, credential harvesting, or hosting malicious executables.
        - **Defanging (`hxxp`, `[.]`):** SOC standard to neutralize harmful links when logging and sharing intelligence records.
        """)

        st.markdown("""
        #### 🏷️ Defanging Cheat Sheet
        | Original Indicator | Defanged Notation | Safe Transmission Purpose |
        | :--- | :--- | :--- |
        | `https://evil.com/payload` | `hxxps://evil[.]com/payload` | Neutralize accidental clicks in email/chat |
        | `192.168.1.1` | `192[.]168[.]1[.]1` | Prevent hyperlink creation in ticket systems |
        | `attacker@phish.net` | `attacker[at]phish[.]net` | Mitigate auto-resolving mail recipients |
        | `http://1.2.3.4:8080` | `hxxp://1[.]2[.]3[.]4[:]8080` | Strip protocol & port resolution |
        """)


# =====================================================================
# Main Application Layout
# =====================================================================
def main():
    apply_custom_styles()

    # Top SOC Header Bar
    st.markdown(f"""
    <div class="soc-header">
        <h1>{APP_TITLE}</h1>
        <p>{APP_SUBTITLE} &bull; Classification: TLP:CLEAR &bull; Status: <span style="color: #10b981;">Operational</span></p>
    </div>
    """, unsafe_allow_html=True)

    # Render Sidebar and retrieve runtime configuration
    config = render_sidebar()

    # Main Tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔍 Single IOC Scanner",
        "📦 Bulk Batch Scanner",
        "🗃️ Audit History Log",
        "📡 Threat Feed & Knowledge"
    ])

    with tab1:
        render_single_investigation(config)

    with tab2:
        render_bulk_scanner(config)

    with tab3:
        render_history()

    with tab4:
        render_threat_feed()


if __name__ == "__main__":
    main()
