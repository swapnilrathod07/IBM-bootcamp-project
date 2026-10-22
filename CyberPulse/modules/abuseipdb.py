"""
AbuseIPDB v2 API Client with Graceful Mock Fallback.
Specialized for IPv4 & IPv6 Reputation and Abuse Reports.
"""
import requests
from typing import Dict, Any, Optional
from config import ABUSEIPDB_BASE_URL, REQUEST_TIMEOUT
from modules.mock_data import generate_mock_telemetry


def query_abuseipdb(
    ioc: str,
    ioc_type: str,
    api_key: Optional[str] = None,
    demo_mode: bool = False
) -> Dict[str, Any]:
    """
    Queries AbuseIPDB v2 API for the given IP address.
    If demo_mode is True or api_key is missing/invalid, falls back seamlessly to mock data.
    """
    if ioc_type not in ("IPV4", "IPV6"):
        return {
            "status": "not_applicable",
            "message": "AbuseIPDB only scans IP addresses (IPv4 / IPv6)."
        }

    if demo_mode or not api_key:
        mock = generate_mock_telemetry(ioc, ioc_type)
        res = mock.get("abuseipdb", {}).copy()
        res["source_mode"] = "demo_simulation"
        return res

    headers = {
        "Key": api_key.strip(),
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ioc,
        "maxAgeInDays": "90",
        "verbose": "true"
    }

    try:
        url = f"{ABUSEIPDB_BASE_URL}/check"
        response = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)

        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "status": "success",
                "source_mode": "live_api",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "distinct_users": data.get("numDistinctUsers", 0),
                "country_code": data.get("countryCode", "N/A"),
                "country_name": data.get("countryName", "Unknown"),
                "isp": data.get("isp", "Unknown ISP"),
                "domain": data.get("domain", "N/A"),
                "usage_type": data.get("usageType", "Unknown"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "last_reported_at": data.get("lastReportedAt")
            }

        elif response.status_code == 429:
            mock = generate_mock_telemetry(ioc, ioc_type)
            res = mock.get("abuseipdb", {}).copy()
            res["source_mode"] = "demo_fallback"
            res["warning"] = "AbuseIPDB daily limit reached. Using cached simulation."
            return res

        else:
            mock = generate_mock_telemetry(ioc, ioc_type)
            res = mock.get("abuseipdb", {}).copy()
            res["source_mode"] = "demo_fallback"
            res["warning"] = f"AbuseIPDB API HTTP {response.status_code}. Using fallback telemetry."
            return res

    except Exception as e:
        mock = generate_mock_telemetry(ioc, ioc_type)
        res = mock.get("abuseipdb", {}).copy()
        res["source_mode"] = "demo_fallback"
        res["warning"] = f"AbuseIPDB connection error ({type(e).__name__}). Using fallback telemetry."
        return res
