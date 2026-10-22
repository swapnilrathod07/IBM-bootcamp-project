"""
Interactive Threat Relationship Graph Generator.
Constructs force-directed graph models (nodes and edges) mapping relationships between
investigated indicators, malware families, threat actors, infrastructure, and campaigns.
"""
from typing import Dict, Any, List, Set, Optional
import re
from modules.detector import defang_ioc


def _sanitize_node_id(raw: str) -> str:
    """Creates a deterministic and safe string identifier for graph nodes."""
    cleaned = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(raw).strip())
    return cleaned.strip("_") or "node"


def _normalize_malware_name(name: str) -> str:
    """Standardizes malware family name to avoid duplicate nodes (e.g. Cobalt-Strike vs Cobalt Strike)."""
    clean = re.sub(r"[-_]+", " ", str(name)).strip()
    return clean.title() if clean else ""


def _normalize_actor_name(name: str) -> str:
    """Standardizes threat actor names to avoid duplicate nodes (e.g. APT-29 vs APT29)."""
    clean = str(name).strip().upper()
    clean = re.sub(r"\b(APT|FIN|UNC)-(\d+)\b", r"\1\2", clean)
    return clean


def generate_threat_graph(
    ioc: str,
    ioc_type: str,
    vt_data: Optional[Dict[str, Any]] = None,
    abuse_data: Optional[Dict[str, Any]] = None,
    otx_data: Optional[Dict[str, Any]] = None,
    geo_data: Optional[Dict[str, Any]] = None,
    risk_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Synthesizes a graph data structure { 'nodes': [...], 'edges': [...], 'summary': {...} }
    compatible with Vis.js Network, Cytoscape, and NetworkX/Plotly.
    """
    has_telemetry = any([vt_data, abuse_data, otx_data, geo_data, risk_data])

    vt = vt_data or {}
    abuse = abuse_data or {}
    otx = otx_data or {}
    geo = geo_data or {}
    risk = risk_data or {}

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    added_nodes: Set[str] = set()
    added_edges: Set[str] = set()

    def add_node(
        node_id: str,
        label: str,
        group: str,
        title: str = "",
        shape: str = "dot",
        color: str = "#3b82f6",
        size: int = 25
    ):
        if node_id not in added_nodes:
            nodes.append({
                "id": node_id,
                "label": label,
                "group": group,
                "title": title or label,
                "shape": shape,
                "color": color,
                "size": size,
                "font": {
                    "color": "#ffffff",
                    "face": "Inter, -apple-system, sans-serif",
                    "size": 12,
                    "strokeWidth": 2,
                    "strokeColor": "#070a13"
                }
            })
            added_nodes.add(node_id)

    def add_edge(
        source: str,
        target: str,
        label: str,
        color: str = "#64748b",
        dashes: bool = False
    ):
        if source == target or source not in added_nodes or target not in added_nodes:
            return
        edge_key = f"{source}->{target}:{label}"
        if edge_key not in added_edges:
            edges.append({
                "from": source,
                "to": target,
                "label": label,
                "color": {"color": color, "highlight": "#00f0ff"},
                "arrows": "to",
                "font": {
                    "color": "#94a3b8",
                    "size": 10,
                    "align": "middle",
                    "strokeWidth": 2,
                    "strokeColor": "#070a13",
                    "background": "#070a13"
                },
                "dashes": dashes
            })
            added_edges.add(edge_key)

    # 1. Central Indicator Node
    central_id = f"ioc_{_sanitize_node_id(ioc)}"
    raw_ioc = str(ioc).strip() if ioc else "indicator"
    defanged = defang_ioc(raw_ioc) or raw_ioc
    disp_label = (defanged[:28] + "...") if len(defanged) > 30 else defanged
    add_node(
        node_id=central_id,
        label=disp_label,
        group="ioc",
        title=f"Target Indicator: {raw_ioc} ({ioc_type or 'UNKNOWN'})",
        shape="star",
        color="#00f0ff",
        size=35
    )

    # Check if indicator is internal / loopback / RFC 1918
    is_internal = False
    is_loopback = False
    if risk.get("is_internal") or risk.get("is_private") or risk.get("is_loopback"):
        is_internal = True
        is_loopback = bool(risk.get("is_loopback"))
    elif "internal" in str(risk.get("level", "")).lower():
        is_internal = True
    else:
        clean_ioc = str(ioc or "").strip().lower()
        host = clean_ioc
        if "://" in clean_ioc:
            import urllib.parse
            try:
                host = urllib.parse.urlsplit(clean_ioc).hostname or clean_ioc
            except Exception:
                pass
        else:
            if "/" in host:
                host = host.split("/", 1)[0]
            if ":" in host and host.count(":") == 1:
                host = host.split(":", 1)[0]

        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "::") or host.endswith(".localhost"):
            is_internal = True
            is_loopback = host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")
        elif host.endswith((".local", ".internal", ".lan", ".home", ".corp")) or host in ("localhost.localdomain", "ip6-localhost", "ip6-loopback"):
            is_internal = True
        else:
            import ipaddress
            try:
                ip_cand = ipaddress.ip_address(host)
                if ip_cand.is_loopback or str(ip_cand).startswith("127."):
                    is_internal = True
                    is_loopback = True
                elif ip_cand.is_unspecified:
                    is_internal = True
                elif isinstance(ip_cand, ipaddress.IPv4Address):
                    octets = ip_cand.exploded.split(".")
                    o0, o1 = int(octets[0]), int(octets[1])
                    if (o0 == 10) or (o0 == 172 and 16 <= o1 <= 31) or (o0 == 192 and o1 == 168) or (o0 == 169 and o1 == 254) or (o0 == 100 and 64 <= o1 <= 127):
                        is_internal = True
                elif isinstance(ip_cand, ipaddress.IPv6Address) and ip_cand.is_private and not ip_cand.is_multicast and not ip_cand.is_loopback:
                    is_internal = True
            except ValueError:
                pass

    if is_internal:
        scope_label = "Local Loopback (RFC 1122)" if is_loopback else "RFC 1918 Private Subnet"
        internal_id = f"internal_{_sanitize_node_id(raw_ioc)}"
        add_node(
            node_id=internal_id,
            label=scope_label,
            group="internal",
            title=f"Network Scope: {scope_label} (Non-Routable)",
            shape="box",
            color="#10b981",
            size=24
        )
        add_edge(central_id, internal_id, label="network_scope", color="#10b981")

        clean_id = f"clean_{_sanitize_node_id(raw_ioc)}"
        add_node(
            node_id=clean_id,
            label="Internal Asset (No Block)",
            group="clean",
            title="Internal host with zero external threat actors or malware families.",
            shape="box",
            color="#06b6d4",
            size=22
        )
        add_edge(central_id, clean_id, label="reputation", color="#06b6d4", dashes=True)

        return {
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "node_count": len(nodes),
                "edge_count": len(edges),
                "actors_found": [],
                "malware_found": [],
                "reputation": "clean"
            }
        }

    # 2. Extract Malware Families and Threat Actors from OTX and VirusTotal
    extracted_actors: Set[str] = set()
    extracted_malware: Set[str] = set()


    # Direct malware families from OTX (handle list or single string)
    raw_malware = otx.get("malware_families", []) or []
    if isinstance(raw_malware, str):
        raw_malware = [raw_malware]
    for mf in raw_malware:
        if mf and isinstance(mf, str) and mf.strip():
            norm_m = _normalize_malware_name(mf)
            if norm_m:
                extracted_malware.add(norm_m)

    # Direct threat actors / adversaries from OTX
    raw_actors = otx.get("threat_actors", []) or []
    if isinstance(raw_actors, str):
        raw_actors = [raw_actors]
    for act in raw_actors:
        if act and isinstance(act, str) and act.strip():
            extracted_actors.add(_normalize_actor_name(act))
    adv_top = otx.get("adversary")
    if adv_top and isinstance(adv_top, str) and adv_top.strip():
        extracted_actors.add(_normalize_actor_name(adv_top))

    # Harvest from OTX pulses and tags
    actor_regex = re.compile(
        r"\b(apt-?\d{1,3}|lazarus|fin-?\d{1,2}|unc-?\d{3,4}|sandworm|kimsuky|cozy bear|fancy bear|wizard spider)\b",
        re.IGNORECASE
    )
    raw_pulses = otx.get("pulses", []) or []
    if isinstance(raw_pulses, dict):
        raw_pulses = [raw_pulses]
    elif not isinstance(raw_pulses, list):
        raw_pulses = []

    for pulse in raw_pulses:
        if not isinstance(pulse, dict):
            continue
        pulse_adv = pulse.get("adversary")
        if pulse_adv and isinstance(pulse_adv, str) and pulse_adv.strip():
            extracted_actors.add(_normalize_actor_name(pulse_adv))

        p_tags = pulse.get("tags", []) or []
        if isinstance(p_tags, str):
            p_tags = [p_tags]
        elif not isinstance(p_tags, list):
            p_tags = []

        for tag in p_tags:
            if not tag or not isinstance(tag, str):
                continue
            tag_clean = tag.strip()
            if not tag_clean:
                continue
            tag_lower = tag_clean.lower()

            m_act = actor_regex.search(tag_lower)
            if m_act or tag_lower in ("lazarus", "fin7", "unc757", "sandworm", "kimsuky"):
                actor_val = m_act.group(0) if m_act else tag_clean
                extracted_actors.add(_normalize_actor_name(actor_val))
            else:
                for mal_kw in ("wannacry", "cobalt strike", "cobalt-strike", "cobaltstrike", "mirai", "emotet", "trickbot", "qakbot", "lockbit", "redline"):
                    if mal_kw in tag_lower:
                        norm_m = _normalize_malware_name(mal_kw)
                        if norm_m:
                            extracted_malware.add(norm_m)
                        break

    # Harvest from VirusTotal security vendor detections & threat classification
    suggested_label = vt.get("suggested_threat_label") or vt.get("popular_threat_classification", {}).get("suggested_threat_label")
    if suggested_label and isinstance(suggested_label, str) and suggested_label.strip():
        norm_m = _normalize_malware_name(suggested_label)
        if norm_m:
            extracted_malware.add(norm_m)

    vendor_detections = vt.get("vendors", {})
    if isinstance(vendor_detections, dict):
        for v_res in vendor_detections.values():
            if not v_res or not isinstance(v_res, str):
                continue
            v_lower = v_res.lower()
            m_act = actor_regex.search(v_lower)
            if m_act:
                extracted_actors.add(_normalize_actor_name(m_act.group(0)))
            for mal_kw in ("wannacry", "cobalt strike", "cobaltstrike", "mirai", "emotet", "trickbot", "qakbot", "lockbit", "redline"):
                if mal_kw in v_lower:
                    norm_m = _normalize_malware_name(mal_kw)
                    if norm_m:
                        extracted_malware.add(norm_m)
                    break

    # Add Threat Actor Nodes (Crimson / Red)
    for actor in sorted(extracted_actors):
        actor_id = f"actor_{_sanitize_node_id(actor)}"
        add_node(
            node_id=actor_id,
            label=f"Actor: {actor}",
            group="actor",
            title=f"Threat Actor Group: {actor}",
            shape="diamond",
            color="#ef4444",
            size=28
        )
        add_edge(central_id, actor_id, label="attributed_to", color="#ef4444")

    # Add Malware Family Nodes (Purple)
    for mal in sorted(extracted_malware):
        mal_id = f"malware_{_sanitize_node_id(mal)}"
        add_node(
            node_id=mal_id,
            label=f"Malware: {mal}",
            group="malware",
            title=f"Malware Family: {mal}",
            shape="hexagon",
            color="#a855f7",
            size=26
        )
        add_edge(central_id, mal_id, label="associated_with", color="#a855f7")
        # If threat actors also exist, link malware to actor
        for actor in sorted(extracted_actors):
            actor_id = f"actor_{_sanitize_node_id(actor)}"
            add_edge(mal_id, actor_id, label="weaponized_by", color="#f87171", dashes=True)

    # 3. Fallback Status Node if no malware families or threat actors were found
    reputation_label = "unknown"
    if has_telemetry and len(extracted_actors) == 0 and len(extracted_malware) == 0:
        try:
            vt_mal = int(vt.get("malicious", 0) or 0)
        except (ValueError, TypeError):
            vt_mal = 0

        try:
            abuse_score = float(abuse.get("abuse_confidence_score", abuse.get("abuse_score", 0)) or 0)
        except (ValueError, TypeError):
            abuse_score = 0.0

        try:
            risk_score = float(risk.get("score", 0) or 0)
        except (ValueError, TypeError):
            risk_score = 0.0

        risk_level = str(risk.get("level", "")).strip().upper() if isinstance(risk, dict) else ""

        is_benign = (vt_mal == 0 and abuse_score == 0 and (not risk_level or risk_level in ("BENIGN", "LOW", "CLEAN")) and risk_score < 25)
        if is_benign:
            reputation_label = "clean"
            clean_id = f"clean_{_sanitize_node_id(ioc)}"
            add_node(
                node_id=clean_id,
                label="Clean Reputation",
                group="clean",
                title="Reputation: Clean — No threat actors or malware families associated",
                shape="box",
                color="#10b981",
                size=22
            )
            add_edge(central_id, clean_id, label="reputation", color="#10b981", dashes=True)
        else:
            reputation_label = "suspicious"
            unattr_id = f"status_{_sanitize_node_id(ioc)}"
            add_node(
                node_id=unattr_id,
                label="Unattributed Threat",
                group="status",
                title="Malicious/Suspicious activity detected, but no specific threat actor or malware family identified",
                shape="box",
                color="#f59e0b",
                size=22
            )
            add_edge(central_id, unattr_id, label="threat_status", color="#f59e0b", dashes=True)
    elif len(extracted_actors) > 0 or len(extracted_malware) > 0:
        reputation_label = "malicious"

    # 4. Infrastructure Nodes: ASN, Geolocation, ISP, Hosting
    # Geolocation node
    country = geo.get("country") or vt.get("country")
    if country and str(country).strip() not in ("N/A", "Unknown", "None", ""):
        country_str = str(country).strip()
        city = geo.get("city")
        city_str = str(city).strip() if city and str(city).strip() not in ("N/A", "Unknown", "None", "") else ""
        loc_label = f"{city_str}, {country_str}" if city_str else country_str
        geo_id = f"geo_{_sanitize_node_id(country_str)}"
        add_node(
            node_id=geo_id,
            label=f"Location: {loc_label}",
            group="geolocation",
            title=f"Host Physical Geolocation: {loc_label}",
            shape="dot",
            color="#10b981",
            size=20
        )
        add_edge(central_id, geo_id, label="located_in", color="#10b981")

    # ASN node
    asn = geo.get("as_info") or vt.get("as_owner")
    if asn and str(asn).strip() not in ("N/A", "Unknown", "None", ""):
        asn_str = str(asn).strip()
        asn_id = f"asn_{_sanitize_node_id(asn_str[:25])}"
        disp_asn = (asn_str[:22] + "...") if len(asn_str) > 25 else asn_str
        add_node(
            node_id=asn_id,
            label=f"ASN: {disp_asn}",
            group="asn",
            title=f"Autonomous System: {asn_str}",
            shape="square",
            color="#3b82f6",
            size=22
        )
        add_edge(central_id, asn_id, label="routed_by", color="#3b82f6")

    # ISP / Hosting Provider
    isp = geo.get("isp") or abuse.get("isp")
    if isp and str(isp).strip() not in ("N/A", "Unknown", "None", "") and str(isp).strip() != str(asn).strip():
        isp_str = str(isp).strip()
        isp_id = f"isp_{_sanitize_node_id(isp_str[:25])}"
        disp_isp = (isp_str[:20] + "...") if len(isp_str) > 22 else isp_str
        add_node(
            node_id=isp_id,
            label=f"ISP: {disp_isp}",
            group="isp",
            title=f"Internet Service Provider / Host: {isp_str}",
            shape="box",
            color="#06b6d4",
            size=18
        )
        add_edge(central_id, isp_id, label="hosted_on", color="#06b6d4")

    # 5. AlienVault OTX Threat Pulses (Amber)
    pulses = otx.get("pulses", []) or []
    if isinstance(pulses, dict):
        pulses = [pulses]
    elif not isinstance(pulses, list):
        pulses = []

    for idx, p in enumerate(pulses[:3]):  # Top 3 pulses to keep visualization readable
        if isinstance(p, dict):
            p_name = str(p.get("name", f"Threat Pulse {idx+1}")).strip()
            author = str(p.get("author", "Unknown")).strip()
        elif isinstance(p, str) and p.strip():
            p_name = p.strip()
            author = "Unknown"
        else:
            continue
        pulse_id = f"pulse_{idx}_{_sanitize_node_id(p_name[:20])}"
        disp_p_name = (p_name[:22] + "...") if len(p_name) > 25 else p_name
        add_node(
            node_id=pulse_id,
            label=f"Pulse: {disp_p_name}",
            group="pulse",
            title=f"AlienVault Pulse: {p_name} (by {author})",
            shape="triangle",
            color="#f59e0b",
            size=18
        )
        add_edge(central_id, pulse_id, label="flagged_in", color="#f59e0b", dashes=True)

    # 6. File details if Hash
    file_type = vt.get("file_type")
    if file_type and str(file_type).strip() not in ("N/A", "Unknown", "None", ""):
        ft_str = str(file_type).strip()
        ft_id = f"ftype_{_sanitize_node_id(ft_str[:20])}"
        disp_ft = (ft_str[:20] + "...") if len(ft_str) > 22 else ft_str
        add_node(
            node_id=ft_id,
            label=f"Format: {disp_ft}",
            group="file_type",
            title=f"File Classification: {ft_str}",
            shape="ellipse",
            color="#8b5cf6",
            size=18
        )
        add_edge(central_id, ft_id, label="format", color="#8b5cf6")

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "actors_found": sorted(list(extracted_actors)),
            "malware_found": sorted(list(extracted_malware)),
            "reputation": reputation_label
        }
    }
