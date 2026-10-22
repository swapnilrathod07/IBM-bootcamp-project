"""
OASIS STIX 2.1 Threat Intelligence Export Generator.
Converts investigated IOC telemetry into standardized, machine-readable STIX 2.1 JSON bundles
for ingestion by enterprise SIEMs (Splunk, Microsoft Sentinel), TIPs (OpenCTI, MISP), and SOAR platforms.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def _format_iso(dt: Optional[datetime] = None) -> str:
    """Formats datetime to STIX 2.1 required ISO-8601 format with millisecond precision and 'Z' suffix."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _generate_stix_pattern(ioc: str, ioc_type: str) -> str:
    """Produces compliant STIX 2.1 Pattern Expression for the indicator."""
    ioc_t = ioc_type.upper()
    clean_val = ioc.replace("'", "\\'")

    if ioc_t == "IPV4":
        return f"[ipv4-addr:value = '{clean_val}']"
    elif ioc_t == "IPV6":
        return f"[ipv6-addr:value = '{clean_val}']"
    elif ioc_t == "SHA256":
        return f"[file:hashes.'SHA-256' = '{clean_val}']"
    elif ioc_t == "MD5":
        return f"[file:hashes.MD5 = '{clean_val}']"
    elif ioc_t == "SHA1":
        return f"[file:hashes.'SHA-1' = '{clean_val}']"
    elif ioc_t == "HASH":
        if len(clean_val) == 64:
            return f"[file:hashes.'SHA-256' = '{clean_val}']"
        elif len(clean_val) == 40:
            return f"[file:hashes.'SHA-1' = '{clean_val}']"
        elif len(clean_val) == 32:
            return f"[file:hashes.MD5 = '{clean_val}']"
        else:
            return f"[file:hashes.'SHA-256' = '{clean_val}']"
    elif ioc_t == "DOMAIN":
        return f"[domain-name:value = '{clean_val}']"
    elif ioc_t == "URL":
        return f"[url:value = '{clean_val}']"
    else:
        return f"[network-traffic:dst_ref.value = '{clean_val}']"


def generate_stix_bundle(
    ioc: str,
    ioc_type: str,
    risk_data: Optional[Dict[str, Any]] = None,
    vt_data: Optional[Dict[str, Any]] = None,
    abuse_data: Optional[Dict[str, Any]] = None,
    otx_data: Optional[Dict[str, Any]] = None,
    geo_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Constructs a complete OASIS STIX 2.1 Bundle containing identity, indicator,
    malware, threat-actor, and relationship objects.
    """
    risk_data = risk_data or {}
    vt_data = vt_data or {}
    abuse_data = abuse_data or {}
    otx_data = otx_data or {}
    geo_data = geo_data or {}

    now_iso = _format_iso()
    bundle_id = f"bundle--{uuid.uuid4()}"

    # 1. Author Identity Object
    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'cyberpulse.threatintel.local')}"
    identity_obj = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_iso,
        "modified": now_iso,
        "name": "CyberPulse Threat Intelligence Platform",
        "description": "Automated CyberPulse SOC Threat Intelligence Engine",
        "identity_class": "system",
        "confidence": 95
    }

    objects: List[Dict[str, Any]] = [identity_obj]

    # 2. Indicator Object
    indicator_id = f"indicator--{uuid.uuid4()}"
    confidence = int(risk_data.get("score", 70))
    pattern = _generate_stix_pattern(ioc, ioc_type)

    indicator_types = ["malicious-activity"]
    if confidence < 30:
        indicator_types = ["anomalous-activity"]

    indicator_obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": now_iso,
        "modified": now_iso,
        "name": f"CyberPulse CTI - {ioc}",
        "description": f"Investigated IOC: {ioc} ({ioc_type}). Threat Level: {risk_data.get('level', 'N/A')}.",
        "indicator_types": indicator_types,
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": now_iso,
        "confidence": confidence,
        "created_by_ref": identity_id,
        "labels": ["cyberpulse", ioc_type.lower(), f"risk-{confidence}"]
    }
    objects.append(indicator_obj)

    # 3. Extract and build Malware objects
    malware_names = otx_data.get("malware_families", []) or []
    malware_objects = []

    for name in malware_names:
        m_id = f"malware--{uuid.uuid4()}"
        m_obj = {
            "type": "malware",
            "spec_version": "2.1",
            "id": m_id,
            "created": now_iso,
            "modified": now_iso,
            "name": name,
            "is_family": True,
            "malware_types": ["trojan", "ransomware"],
            "created_by_ref": identity_id
        }
        objects.append(m_obj)
        malware_objects.append(m_id)

        # Relationship: Indicator indicates Malware
        rel_indicates = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": m_id,
            "created_by_ref": identity_id
        }
        objects.append(rel_indicates)

    # 4. Extract Threat Actors from pulses / tags
    threat_actors = set()
    for pulse in otx_data.get("pulses", []):
        for tag in pulse.get("tags", []):
            tag_l = tag.lower()
            if "apt" in tag_l or tag_l in ("lazarus", "fin7", "unc757", "sandworm", "kimsuky"):
                threat_actors.add(tag.upper())

    for actor in threat_actors:
        actor_id = f"threat-actor--{uuid.uuid4()}"
        actor_obj = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": actor_id,
            "created": now_iso,
            "modified": now_iso,
            "name": actor,
            "threat_actor_types": ["nation-state", "cybercrime"],
            "created_by_ref": identity_id
        }
        objects.append(actor_obj)

        # Relationship: malware attributed-to threat actor, or indicator indicates threat actor
        if malware_objects:
            target_source = malware_objects[0]
            rel_type = "attributed-to"
        else:
            target_source = indicator_id
            rel_type = "indicates"

        rel_actor = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "relationship_type": rel_type,
            "source_ref": target_source,
            "target_ref": actor_id,
            "created_by_ref": identity_id
        }
        objects.append(rel_actor)

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects
    }


def generate_stix_json(
    ioc: str,
    ioc_type: str,
    risk_data: Optional[Dict[str, Any]] = None,
    vt_data: Optional[Dict[str, Any]] = None,
    abuse_data: Optional[Dict[str, Any]] = None,
    otx_data: Optional[Dict[str, Any]] = None,
    geo_data: Optional[Dict[str, Any]] = None
) -> str:
    """Serializes the generated STIX 2.1 bundle to an indented JSON string."""
    bundle = generate_stix_bundle(ioc, ioc_type, risk_data, vt_data, abuse_data, otx_data, geo_data)
    return json.dumps(bundle, indent=2)
