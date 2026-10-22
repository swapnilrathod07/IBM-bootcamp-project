"""
AlienVault OTX (Open Threat Exchange) API Client with Graceful Mock Fallback.
Provides Threat Pulse Correlations, Adversary Tags, and Malware Family Attributes.
"""
import requests
from typing import Dict, Any, Optional
from config import OTX_BASE_URL, REQUEST_TIMEOUT
from modules.mock_data import generate_mock_telemetry


def query_alienvault(
    ioc: str,
    ioc_type: str,
    api_key: Optional[str] = None,
    demo_mode: bool = False
) -> Dict[str, Any]:
    """
    Queries AlienVault OTX API for threat pulses and adversary associations.
    Falls back cleanly to mock data when in demo mode or if keys/limits are absent.
    """
    if demo_mode or not api_key:
        mock = generate_mock_telemetry(ioc, ioc_type)
        res = mock.get("alienvault", {}).copy()
        res["source_mode"] = "demo_simulation"
        return res

    headers = {
        "X-OTX-API-KEY": api_key.strip(),
        "Accept": "application/json"
    }

    type_mapping = {
        "IPV4": "IPv4",
        "IPV6": "IPv6",
        "DOMAIN": "domain",
        "MD5": "file",
        "SHA1": "file",
        "SHA256": "file",
        "URL": "url"
    }

    otx_section = type_mapping.get(ioc_type)
    if not otx_section:
        return {"status": "unsupported", "message": f"OTX does not support IOC type {ioc_type}"}

    try:
        url = f"{OTX_BASE_URL}/indicators/{otx_section}/{ioc}/general"
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

        if response.status_code == 200:
            data = response.json()
            pulse_info = data.get("pulse_info", {})
            raw_pulses = pulse_info.get("pulses", [])

            pulses = []
            tags = set()
            malware_families = set()

            for p in raw_pulses[:10]:
                pulses.append({
                    "name": p.get("name", "Unnamed Pulse"),
                    "author": p.get("author_name", "Anonymous"),
                    "tags": p.get("tags", []),
                    "created": p.get("created", "")
                })
                for tag in p.get("tags", []):
                    tags.add(tag.lower())
                for mf in p.get("malware_families", []):
                    if isinstance(mf, dict) and "display_name" in mf:
                        malware_families.add(mf["display_name"])
                    elif isinstance(mf, str):
                        malware_families.add(mf)

            return {
                "status": "success",
                "source_mode": "live_api",
                "pulse_count": pulse_info.get("count", 0),
                "pulses": pulses,
                "tags": sorted(list(tags))[:15],
                "malware_families": sorted(list(malware_families))[:10]
            }

        elif response.status_code == 404:
            return {
                "status": "success",
                "source_mode": "live_api",
                "pulse_count": 0,
                "pulses": [],
                "tags": [],
                "malware_families": [],
                "notes": "No active threat pulses recorded for this indicator in AlienVault OTX."
            }

        else:
            mock = generate_mock_telemetry(ioc, ioc_type)
            res = mock.get("alienvault", {}).copy()
            res["source_mode"] = "demo_fallback"
            res["warning"] = f"AlienVault OTX HTTP {response.status_code}. Using fallback telemetry."
            return res

    except Exception as e:
        mock = generate_mock_telemetry(ioc, ioc_type)
        res = mock.get("alienvault", {}).copy()
        res["source_mode"] = "demo_fallback"
        res["warning"] = f"AlienVault OTX connection error ({type(e).__name__}). Using fallback telemetry."
        return res
