"""
Configuration and Environment Settings for Threat Intelligence Aggregator.
"""
import os
from typing import Dict, Any

# Attempt to load python-dotenv if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Application Metadata
APP_TITLE = "CYBERPULSE // SOC Threat Intelligence & IOC Aggregator"
APP_SUBTITLE = "Automated Multi-Source Cyber Threat Telemetry & Risk Triage Engine"
APP_VERSION = "2.4.0-SOC"

# API Endpoints
VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
IP_API_BASE_URL = "http://ip-api.com/json"

# API Request Timeouts (in seconds)
REQUEST_TIMEOUT = 10

# Risk Thresholds
RISK_LEVEL_BENIGN = "Benign / Low Risk"
RISK_LEVEL_SUSPICIOUS = "Suspicious / Moderate"
RISK_LEVEL_MALICIOUS = "Malicious / Critical"

# SOC Palette Colors
SOC_COLORS = {
    "background": "#0b0f19",
    "surface": "#111827",
    "card_border": "#1f2937",
    "cyber_cyan": "#00f0ff",
    "cyber_blue": "#3b82f6",
    "neon_green": "#10b981",
    "warning_yellow": "#f59e0b",
    "danger_red": "#ef4444",
    "text_muted": "#9ca3af",
    "text_light": "#f3f4f6",
}

def get_env_api_keys() -> Dict[str, str]:
    """Retrieves API keys from environment variables or .env file."""
    return {
        "virustotal": os.getenv("VT_API_KEY", "").strip(),
        "abuseipdb": os.getenv("ABUSEIPDB_API_KEY", "").strip(),
        "alienvault": os.getenv("OTX_API_KEY", "").strip(),
    }

def is_default_demo_mode() -> bool:
    """Checks if default demo mode is enabled in environment or fallback."""
    val = os.getenv("DEFAULT_DEMO_MODE", "True").lower()
    return val in ("true", "1", "yes")
