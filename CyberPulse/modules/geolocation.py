"""
IP Geolocation Engine using Free IP-API with Mock Fallback.
Provides Latitude, Longitude, City, Country, AS Number, and ISP.
"""
import requests
from typing import Dict, Any
from config import IP_API_BASE_URL, REQUEST_TIMEOUT
from modules.mock_data import generate_mock_telemetry


def query_geolocation(
    ioc: str,
    ioc_type: str,
    demo_mode: bool = False
) -> Dict[str, Any]:
    """
    Fetches physical and network geolocation for IPv4/IPv6 addresses.
    Returns latitude, longitude, country, ISP, and Autonomous System.
    """
    if ioc_type not in ("IPV4", "IPV6"):
        return {
            "status": "not_applicable",
            "message": "Geolocation is only applicable to IP addresses."
        }

    if demo_mode:
        mock = generate_mock_telemetry(ioc, ioc_type)
        res = mock.get("geolocation", {}).copy()
        res["source_mode"] = "demo_simulation"
        return res

    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ioc.strip())
        is_loop = ip_obj.is_loopback or str(ip_obj).startswith("127.")
        is_rfc1918 = ip_obj.is_unspecified
        if isinstance(ip_obj, ipaddress.IPv4Address):
            octets = ip_obj.exploded.split(".")
            o0, o1 = int(octets[0]), int(octets[1])
            is_rfc1918 = is_rfc1918 or (o0 == 10) or (o0 == 172 and 16 <= o1 <= 31) or (o0 == 192 and o1 == 168) or (o0 == 169 and o1 == 254) or (o0 == 100 and 64 <= o1 <= 127)
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            is_rfc1918 = is_rfc1918 or (ip_obj.is_private and not ip_obj.is_multicast and not ip_obj.is_loopback)

        if is_loop or is_rfc1918:
            mock = generate_mock_telemetry(ioc, ioc_type)
            res = mock.get("geolocation", {}).copy()
            res["source_mode"] = "internal_asset"
            return res
    except ValueError:
        pass


    try:
        url = f"{IP_API_BASE_URL}/{ioc}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        response = requests.get(url, timeout=REQUEST_TIMEOUT)

        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "status": "success",
                    "source_mode": "live_api",
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "??"),
                    "region": data.get("region", ""),
                    "region_name": data.get("regionName", ""),
                    "city": data.get("city", "Unknown City"),
                    "zip": data.get("zip", ""),
                    "lat": data.get("lat", 0.0),
                    "lon": data.get("lon", 0.0),
                    "timezone": data.get("timezone", "UTC"),
                    "isp": data.get("isp", "Unknown ISP"),
                    "org": data.get("org", ""),
                    "as_info": data.get("as", "")
                }
            else:
                # Private IP or reserved range returned by ip-api
                return {
                    "status": "unresolvable",
                    "source_mode": "live_api",
                    "message": data.get("message", "IP address could not be geolocated.")
                }
        else:
            mock = generate_mock_telemetry(ioc, ioc_type)
            res = mock.get("geolocation", {}).copy()
            res["source_mode"] = "demo_fallback"
            return res

    except Exception:
        mock = generate_mock_telemetry(ioc, ioc_type)
        res = mock.get("geolocation", {}).copy()
        res["source_mode"] = "demo_fallback"
        return res
