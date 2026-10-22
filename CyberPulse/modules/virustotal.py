"""
VirusTotal v3 API Client with Graceful Mock Fallback.
Supports: IP Addresses, Domains, URLs, and File Hashes.
"""
import base64
import requests
from typing import Dict, Any, Optional
from config import VT_BASE_URL, REQUEST_TIMEOUT
from modules.mock_data import generate_mock_telemetry


def query_virustotal(
    ioc: str,
    ioc_type: str,
    api_key: Optional[str] = None,
    demo_mode: bool = False
) -> Dict[str, Any]:
    """
    Queries the VirusTotal v3 API for the given IOC.
    If demo_mode is True or api_key is missing/invalid, falls back seamlessly to mock data.
    """
    if demo_mode or not api_key:
        mock = generate_mock_telemetry(ioc, ioc_type)
        res = mock.get("virustotal", {}).copy()
        res["source_mode"] = "demo_simulation"
        return res

    headers = {
        "x-apikey": api_key.strip(),
        "accept": "application/json"
    }

    try:
        endpoint = None
        if ioc_type in ("IPV4", "IPV6"):
            endpoint = f"{VT_BASE_URL}/ip_addresses/{ioc}"
        elif ioc_type == "DOMAIN":
            endpoint = f"{VT_BASE_URL}/domains/{ioc}"
        elif ioc_type in ("MD5", "SHA1", "SHA256"):
            endpoint = f"{VT_BASE_URL}/files/{ioc}"
        elif ioc_type == "URL":
            # VT URL identifier is base64 encoded without padding
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            endpoint = f"{VT_BASE_URL}/urls/{url_id}"
        else:
            return {"status": "unsupported", "error": f"VirusTotal does not support IOC type {ioc_type}"}

        response = requests.get(endpoint, headers=headers, timeout=REQUEST_TIMEOUT)

        if response.status_code == 200:
            data = response.json().get("data", {})
            attr = data.get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            results = attr.get("last_analysis_results", {})

            # Extract notable security vendor results
            vendors = {}
            for vendor_name, vendor_info in results.items():
                category = vendor_info.get("category", "undetected")
                result_str = vendor_info.get("result") or category
                if category in ("malicious", "suspicious"):
                    vendors[vendor_name] = f"{category.capitalize()} ({result_str})"
                elif len(vendors) < 10 and category == "harmless":
                    vendors[vendor_name] = "Clean / Harmless"

            return {
                "status": "success",
                "source_mode": "live_api",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attr.get("reputation", 0),
                "vendors": vendors,
                "categories": attr.get("categories", {}),
                "tags": attr.get("tags", [])
            }

        elif response.status_code == 404:
            return {
                "status": "success",
                "source_mode": "live_api",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "reputation": 0,
                "vendors": {},
                "notes": "Indicator not previously seen in VirusTotal dataset."
            }

        elif response.status_code == 429:
            # Rate limit exceeded -> return simulation with notice
            mock = generate_mock_telemetry(ioc, ioc_type)
            res = mock.get("virustotal", {}).copy()
            res["source_mode"] = "demo_fallback"
            res["warning"] = "VirusTotal Community rate limit exceeded (4 req/min). Using cached simulation."
            return res

        else:
            # Other error -> fallback gracefully
            mock = generate_mock_telemetry(ioc, ioc_type)
            res = mock.get("virustotal", {}).copy()
            res["source_mode"] = "demo_fallback"
            res["warning"] = f"VirusTotal API HTTP {response.status_code}. Using fallback telemetry."
            return res

    except Exception as e:
        mock = generate_mock_telemetry(ioc, ioc_type)
        res = mock.get("virustotal", {}).copy()
        res["source_mode"] = "demo_fallback"
        res["warning"] = f"VirusTotal request error ({type(e).__name__}). Using fallback telemetry."
        return res
