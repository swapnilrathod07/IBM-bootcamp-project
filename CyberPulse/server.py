"""
CyberPulse SOC Command Center - Web Server & REST API.
Exposes high-performance threat intelligence endpoints wrapping the core detection,
scoring, multi-source telemetry, history, and report generation modules.
"""
import os
import io
import json
import re
from typing import Dict, Any, List, Optional
from flask import Flask, request, jsonify, render_template, send_file, Response

from config import (
    APP_TITLE, APP_SUBTITLE, APP_VERSION,
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
from modules.report_gen import generate_json_report, generate_markdown_report, generate_pdf_report, generate_stix_report
from modules.rule_gen import generate_all_defensive_rules
from modules.graph_gen import generate_threat_graph
from modules.stix_gen import generate_stix_json
from modules.webhook import dispatch_webhook_alert
from modules.attack_analyzer import (
    analyze_attack_vector, get_adversary_tool,
    get_adversary_tool_catalog, get_attack_vector_catalog
)
from modules.web_security import audit_website_security

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates"),
    static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
)

# Enable CORS for local cross-origin development and standalone client file access
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, Accept, X-Requested-With"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    return response


@app.route("/", methods=["GET"])
def index():
    """Serves the CyberPulse SOC Command Center HTML Interface."""
    return render_template("index.html", app_title=APP_TITLE, app_version=APP_VERSION)


@app.route("/api/health", methods=["GET"])
def health():
    """Healthcheck endpoint for monitoring uptime and status."""
    return jsonify({
        "status": "online",
        "app": APP_TITLE,
        "version": APP_VERSION
    })


@app.route("/api/config", methods=["GET"])
def get_config():
    """Returns safe runtime configuration and configured integration status."""
    keys = get_env_api_keys()
    return jsonify({
        "version": APP_VERSION,
        "title": APP_TITLE,
        "subtitle": APP_SUBTITLE,
        "default_demo_mode": is_default_demo_mode(),
        "integrations": {
            "virustotal": bool(keys.get("virustotal")),
            "abuseipdb": bool(keys.get("abuseipdb")),
            "alienvault": bool(keys.get("alienvault"))
        }
    })


@app.errorhandler(400)
def bad_request_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": str(getattr(e, "description", e)) or "Bad Request", "status_code": 400}), 400
    return e


@app.errorhandler(404)
def not_found_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Endpoint not found", "status_code": 404}), 404
    return e


@app.errorhandler(405)
def method_not_allowed_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": f"Method {request.method} not allowed on this endpoint", "status_code": 405}), 405
    return e


@app.errorhandler(500)
def internal_server_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Internal server error occurred during threat processing", "status_code": 500}), 500
    return e


def _get_request_data() -> dict:
    """Extracts JSON body, form data, or query args robustly across GET and POST, merging query params."""
    combined = {}
    if request.args:
        combined.update(request.args.to_dict())
    if request.is_json:
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            combined.update(data)
    else:
        data = request.get_json(silent=True)
        if isinstance(data, dict) and data:
            combined.update(data)
        elif request.form:
            combined.update(request.form.to_dict())
    return combined


def _parse_bool(val: Any, default: Optional[bool] = None) -> Optional[bool]:
    """Coerces strings like 'true', '1', 'false', '0' to booleans cleanly."""
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    return default


def _execute_single_scan(
    ioc: str,
    demo_mode: Any = None,
    vt_key: str = "",
    abuse_key: str = "",
    otx_key: str = "",
    persist: bool = True,
    days_elapsed: Optional[float] = None,
    domain_age_days: Optional[int] = None,
    is_nrd: Optional[bool] = None,
    ports: Optional[List[int]] = None
) -> Dict[str, Any]:
    """Helper executing the complete multi-source threat telemetry workflow."""
    env_keys = get_env_api_keys()
    parsed_demo = _parse_bool(demo_mode, default=is_default_demo_mode())
    if parsed_demo is None:
        parsed_demo = is_default_demo_mode()

    vt_k = vt_key.strip() if vt_key else env_keys.get("virustotal", "")
    abuse_k = abuse_key.strip() if abuse_key else env_keys.get("abuseipdb", "")
    otx_k = otx_key.strip() if otx_key else env_keys.get("alienvault", "")

    detection = detect_ioc_type(ioc)
    if not detection["valid"]:
        return {
            "success": False,
            "error": "Invalid indicator format. Supported: IPv4, IPv6, MD5, SHA-1, SHA-256, Domain, URL.",
            "detection": detection
        }

    normalized = detection["normalized"]
    ioc_type = detection["type"]

    # Multi-engine asynchronous/synchronous execution
    vt_data = query_virustotal(normalized, ioc_type, api_key=vt_k, demo_mode=parsed_demo)
    abuse_data = query_abuseipdb(normalized, ioc_type, api_key=abuse_k, demo_mode=parsed_demo)
    otx_data = query_alienvault(normalized, ioc_type, api_key=otx_k, demo_mode=parsed_demo)
    geo_data = query_geolocation(normalized, ioc_type, demo_mode=parsed_demo)

    risk = calculate_risk_score(
        normalized, ioc_type, vt_data, abuse_data, otx_data,
        geo_data=geo_data,
        days_elapsed=days_elapsed,
        domain_age_days=domain_age_days,
        is_nrd=is_nrd,
        is_private=detection.get("is_private"),
        is_loopback=detection.get("is_loopback")
    )


    attack_data = analyze_attack_vector(
        ioc=normalized,
        ioc_type=ioc_type,
        vt_data=vt_data,
        abuse_data=abuse_data,
        otx_data=otx_data,
        geo_data=geo_data,
        risk_data=risk,
        domain_age_days=domain_age_days,
        is_nrd=is_nrd,
        ports=ports
    )

    web_security_data = audit_website_security(normalized, demo_mode=parsed_demo)

    velocity_data = generate_attack_velocity(
        ioc=normalized,
        ioc_type=ioc_type,
        vt_data=vt_data,
        abuse_data=abuse_data,
        otx_data=otx_data,
        days_elapsed=days_elapsed
    )

    inv_id = None
    if persist:
        country_name = geo_data.get("country", "N/A") if geo_data.get("status") == "success" else "N/A"
        try:
            inv_id = save_investigation(
                ioc=normalized,
                ioc_type=ioc_type,
                risk_score=risk["score"],
                risk_level=risk["level"],
                vt_malicious=vt_data.get("malicious", 0),
                abuse_score=abuse_data.get("abuse_confidence_score", 0),
                country=country_name,
                analyst_notes=risk["summary"]
            )
        except Exception:
            pass

    return {
        "success": True,
        "id": inv_id,
        "ioc": normalized,
        "raw_ioc": ioc,
        "detection": detection,
        "risk": risk,
        "attacks": attack_data,
        "web_security": web_security_data,
        "velocity": velocity_data,
        "vt": vt_data,
        "abuse": abuse_data,
        "otx": otx_data,
        "geo": geo_data
    }


@app.route("/api/scan", methods=["GET", "POST", "OPTIONS"])
def api_scan():
    """Scans a single IOC indicator and persists findings into the audit log."""
    if request.method == "OPTIONS":
        return "", 204

    data = _get_request_data()
    ioc = str(data.get("ioc", "")).strip().strip("'\"")
    if not ioc:
        return jsonify({"success": False, "error": "Missing 'ioc' parameter in request"}), 400
    if len(ioc) > 4096:
        return jsonify({"success": False, "error": "IOC parameter exceeds maximum allowed length (4096 characters)"}), 400

    demo_mode = data.get("demo_mode", None)
    vt_key = data.get("vt_key", "")
    abuse_key = data.get("abuse_key", "")
    otx_key = data.get("otx_key", "")

    days_elapsed = data.get("days_elapsed")
    if days_elapsed is not None:
        try:
            days_elapsed = float(days_elapsed)
        except (ValueError, TypeError):
            days_elapsed = None

    domain_age_days = data.get("domain_age_days")
    if domain_age_days is not None:
        try:
            domain_age_days = int(domain_age_days)
        except (ValueError, TypeError):
            domain_age_days = None

    is_nrd = _parse_bool(data.get("is_nrd"), default=None)

    ports = data.get("ports")
    result = _execute_single_scan(
        ioc=ioc,
        demo_mode=demo_mode,
        vt_key=vt_key,
        abuse_key=abuse_key,
        otx_key=otx_key,
        persist=True,
        days_elapsed=days_elapsed,
        domain_age_days=domain_age_days,
        is_nrd=is_nrd,
        ports=ports
    )

    if not result.get("success"):
        return jsonify(result), 400

    return jsonify(result)


@app.route("/api/detect", methods=["GET", "POST", "OPTIONS"])
def api_detect():
    """Instant IOC classification and defanging analysis without triggering queries."""
    if request.method == "OPTIONS":
        return "", 204

    data = _get_request_data()
    ioc = str(data.get("ioc", "")).strip().strip("'\"")
    if len(ioc) > 4096:
        return jsonify({"success": False, "error": "IOC parameter exceeds maximum allowed length (4096 characters)"}), 400
    detection = detect_ioc_type(ioc)
    return jsonify({
        "success": True,
        "detection": detection
    })


HEADER_KEYWORDS = {
    "ioc", "iocs", "indicator", "indicators", "ip", "ips", "ip_address",
    "hash", "hashes", "domain", "domains", "url", "urls"
}


@app.route("/api/bulk", methods=["POST", "OPTIONS"])
def api_bulk():
    """Batch scans a list of indicators and returns aggregated triage results."""
    if request.method == "OPTIONS":
        return "", 204

    data = _get_request_data()
    raw_iocs = data.get("iocs") if "iocs" in data else data.get("ioc", [])
    if isinstance(raw_iocs, str):
        # Support raw newline, comma, semicolon, pipe, or tab separated text
        iocs = [line.strip().strip("'\"") for line in re.split(r"[\r\n,;|\t]+", raw_iocs) if line.strip().strip("'\"")]
    elif isinstance(raw_iocs, list):
        iocs = raw_iocs
    elif raw_iocs:
        iocs = [raw_iocs]
    else:
        iocs = []

    if not iocs:
        return jsonify({"success": False, "error": "Missing or empty 'iocs' list"}), 400

    # Clean & strip quotes
    cleaned_tokens = [str(i).strip().strip("'\"") for i in iocs if str(i).strip().strip("'\"")]

    # Discard CSV/table header row if user uploaded a file with a header column
    if cleaned_tokens and cleaned_tokens[0].lower() in HEADER_KEYWORDS:
        cleaned_tokens = cleaned_tokens[1:]

    # Clean & deduplicate while maintaining order
    unique_iocs = list(dict.fromkeys(cleaned_tokens))
    if not unique_iocs:
        return jsonify({"success": False, "error": "No valid indicator tokens found in request"}), 400

    max_batch = 100
    processed_iocs = unique_iocs[:max_batch]

    demo_mode = data.get("demo_mode", None)
    vt_key = data.get("vt_key", "")
    abuse_key = data.get("abuse_key", "")
    otx_key = data.get("otx_key", "")

    results = []
    for item in processed_iocs:
        res = _execute_single_scan(
            ioc=item,
            demo_mode=demo_mode,
            vt_key=vt_key,
            abuse_key=abuse_key,
            otx_key=otx_key,
            persist=True
        )
        if res.get("success"):
            attacks = res.get("attacks") or {}
            results.append({
                "ioc": res["ioc"],
                "type": res["detection"]["type"],
                "risk_score": res["risk"]["score"],
                "risk_level": res["risk"]["level"],
                "risk_color": res["risk"]["color"],
                "attack_vector": attacks.get("name", "Unclassified"),
                "attack_icon": attacks.get("icon", "❓"),
                "vt_malicious": res["vt"].get("malicious", 0),
                "abuse_score": res["abuse"].get("abuse_confidence_score", 0),
                "country": res["geo"].get("country", "N/A"),
                "summary": res["risk"]["summary"],
                "details": res
            })
        else:
            results.append({
                "ioc": item,
                "type": "UNKNOWN",
                "risk_score": 0,
                "risk_level": "Invalid IOC",
                "risk_color": "#9ca3af",
                "attack_vector": "Invalid",
                "attack_icon": "⚠️",
                "vt_malicious": 0,
                "abuse_score": 0,
                "country": "N/A",
                "summary": res.get("error", "Invalid indicator format"),
                "details": res
            })

    return jsonify({
        "success": True,
        "count": len(results),
        "results": results
    })


@app.route("/api/history", methods=["GET", "DELETE", "OPTIONS"])
def api_history():
    """Retrieves or clears persistent investigation records."""
    if request.method == "OPTIONS":
        return "", 204

    if request.method == "DELETE":
        clear_history()
        return jsonify({"success": True, "message": "Investigation history cleared successfully"})

    limit = request.args.get("limit", 100, type=int)
    search = request.args.get("q", "", type=str)

    records = get_history(limit=limit, search_query=search)
    stats = get_history_stats()

    return jsonify({
        "success": True,
        "count": len(records),
        "history": records,
        "stats": stats
    })


@app.route("/api/history/<int:inv_id>", methods=["GET", "DELETE", "OPTIONS"])
def api_history_item(inv_id: int):
    """Retrieves or deletes a single investigation record by primary ID."""
    if request.method == "OPTIONS":
        return "", 204

    if request.method == "DELETE":
        ok = delete_investigation(inv_id)
        if ok:
            return jsonify({"success": True, "message": f"Investigation #{inv_id} deleted"})
        return jsonify({"success": False, "error": f"Investigation #{inv_id} not found"}), 404

    record = get_investigation_by_id(inv_id)
    if not record:
        return jsonify({"success": False, "error": f"Investigation #{inv_id} not found"}), 404

    return jsonify({"success": True, "investigation": record})


@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Returns SOC triage audit summary statistics."""
    stats = get_history_stats()
    return jsonify({"success": True, "stats": stats})


def _resolve_export_data(data: dict) -> tuple:
    """Helper resolving telemetry objects from either explicit payload or on-the-fly scan."""
    if ("risk" in data and isinstance(data["risk"], dict)) or ("vt" in data and isinstance(data["vt"], dict)) or ("otx" in data and isinstance(data["otx"], dict)):
        raw_ioc = str(data.get("ioc") or "indicator").strip()
        ioc_type = data.get("detection", {}).get("type") or data.get("ioc_type")
        ioc = raw_ioc
        if not ioc_type or str(ioc_type).upper() == "UNKNOWN":
            if raw_ioc and raw_ioc != "indicator":
                det = detect_ioc_type(raw_ioc)
                ioc_type = det.get("type", "UNKNOWN")
                if det.get("normalized"):
                    ioc = det["normalized"]
            else:
                ioc_type = "UNKNOWN"
        ioc_type = str(ioc_type).upper()
        risk = data.get("risk", {})
        vt = data.get("vt", {})
        abuse = data.get("abuse", {})
        otx = data.get("otx", {})
        geo = data.get("geo", {})
        return ioc, ioc_type, risk, vt, abuse, otx, geo

    ioc = str(data.get("ioc", "")).strip().strip("'\"")
    if not ioc:
        return None, None, None, None, None, None, None

    days_elapsed = data.get("days_elapsed")
    if days_elapsed is not None:
        try:
            days_elapsed = float(days_elapsed)
        except (ValueError, TypeError):
            days_elapsed = None

    domain_age_days = data.get("domain_age_days")
    if domain_age_days is not None:
        try:
            domain_age_days = int(domain_age_days)
        except (ValueError, TypeError):
            domain_age_days = None

    is_nrd = _parse_bool(data.get("is_nrd"), default=None)

    res = _execute_single_scan(
        ioc=ioc,
        demo_mode=data.get("demo_mode", None),
        vt_key=data.get("vt_key", ""),
        abuse_key=data.get("abuse_key", ""),
        otx_key=data.get("otx_key", ""),
        persist=False,
        days_elapsed=days_elapsed,
        domain_age_days=domain_age_days,
        is_nrd=is_nrd
    )
    if not res.get("success"):
        return None, None, None, None, None, None, None

    if "web_security" not in data and "web_security" in res:
        data["web_security"] = res["web_security"]
    if "attacks" not in data and "attacks" in res:
        data["attacks"] = res["attacks"]

    return (
        res["ioc"],
        res["detection"]["type"],
        res["risk"],
        res["vt"],
        res["abuse"],
        res["otx"],
        res["geo"]
    )


@app.route("/api/export/pdf", methods=["GET", "POST", "OPTIONS"])
def api_export_pdf():
    """Generates and streams an executive-grade PDF investigation report."""
    if request.method == "OPTIONS":
        return "", 204

    data = _get_request_data()
    ioc, ioc_type, risk, vt, abuse, otx, geo = _resolve_export_data(data)

    if not ioc:
        return jsonify({"success": False, "error": "Invalid or missing IOC payload"}), 400

    web_sec = data.get("web_security")
    attack_data = data.get("attacks")
    pdf_bytes = generate_pdf_report(
        ioc, ioc_type, risk, vt, abuse, otx, geo,
        attack_data=attack_data, web_security_data=web_sec
    )
    safe_filename = re.sub(r'[^a-zA-Z0-9_\.-]', '_', ioc)

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=soc_report_{safe_filename}.pdf",
            "Content-Type": "application/pdf"
        }
    )


@app.route("/api/export/json", methods=["GET", "POST", "OPTIONS"])
def api_export_json():
    """Generates and streams a comprehensive JSON threat dossier."""
    if request.method == "OPTIONS":
        return "", 204

    data = _get_request_data()
    ioc, ioc_type, risk, vt, abuse, otx, geo = _resolve_export_data(data)

    if not ioc:
        return jsonify({"success": False, "error": "Invalid or missing IOC payload"}), 400

    web_sec = data.get("web_security")
    attack_data = data.get("attacks")
    json_str = generate_json_report(
        ioc, ioc_type, risk, vt, abuse, otx, geo,
        attack_data=attack_data, web_security_data=web_sec
    )
    safe_filename = re.sub(r'[^a-zA-Z0-9_\.-]', '_', ioc)

    return Response(
        json_str,
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=soc_dossier_{safe_filename}.json",
            "Content-Type": "application/json"
        }
    )


@app.route("/api/export/markdown", methods=["GET", "POST", "OPTIONS"])
def api_export_markdown():
    """Generates and streams a Markdown incident response brief."""
    if request.method == "OPTIONS":
        return "", 204

    data = _get_request_data()
    ioc, ioc_type, risk, vt, abuse, otx, geo = _resolve_export_data(data)

    if not ioc:
        return jsonify({"success": False, "error": "Invalid or missing IOC payload"}), 400

    web_sec = data.get("web_security")
    attack_data = data.get("attacks")
    md_str = generate_markdown_report(
        ioc, ioc_type, risk, vt, abuse, otx, geo,
        attack_data=attack_data, web_security_data=web_sec
    )
    safe_filename = re.sub(r'[^a-zA-Z0-9_\.-]', '_', ioc)

    return Response(
        md_str,
        mimetype="text/markdown",
        headers={
            "Content-Disposition": f"attachment; filename=soc_brief_{safe_filename}.md",
            "Content-Type": "text/markdown; charset=utf-8"
        }
    )


@app.route("/api/rules", methods=["GET", "POST", "OPTIONS"])
def api_rules():
    """Generates 1-click defensive rules (YARA, Sigma, and Firewall)."""
    if request.method == "OPTIONS":
        return "", 204

    data = _get_request_data()
    ioc, ioc_type, risk, vt, abuse, otx, geo = _resolve_export_data(data)
    if not ioc:
        return jsonify({"success": False, "error": "Invalid or missing IOC payload"}), 400

    telemetry = {"risk": risk, "vt": vt, "abuse": abuse, "otx": otx, "geo": geo}
    rules = generate_all_defensive_rules(ioc, ioc_type, telemetry)
    return jsonify({
        "success": True,
        "ioc": ioc,
        "ioc_type": ioc_type,
        "rules": rules
    })


@app.route("/api/web-security", methods=["GET", "POST", "OPTIONS"])
def api_web_security():
    """Performs a dedicated website security posture, SSL, and defensive headers audit."""
    if request.method == "OPTIONS":
        return "", 204

    data = _get_request_data()
    target = str(data.get("target") or data.get("ioc") or data.get("domain") or data.get("url") or "").strip().strip("'\"")
    if not target:
        return jsonify({"success": False, "error": "Missing 'target' or 'ioc' parameter in request"}), 400
    if len(target) > 4096:
        return jsonify({"success": False, "error": "Target parameter exceeds maximum allowed length (4096 characters)"}), 400

    demo_mode = data.get("demo_mode", None)
    parsed_demo = _parse_bool(demo_mode, default=is_default_demo_mode())
    if parsed_demo is None:
        parsed_demo = is_default_demo_mode()

    audit_result = audit_website_security(target, demo_mode=parsed_demo)
    return jsonify({
        "success": True,
        "target": target,
        "web_security": audit_result
    })


@app.route("/api/attacks", methods=["GET", "POST", "OPTIONS"])
def api_attacks():
    """Predicts attack vectors, TTPs, and adversary toolsets from an IOC or telemetry payload."""
    if request.method == "OPTIONS":
        return "", 204

    data = _get_request_data()
    
    # 1. Query individual hacker tool by ID
    tool_id = request.args.get("tool") or data.get("tool")
    if tool_id:
        tool_data = get_adversary_tool(str(tool_id))
        if tool_data:
            return jsonify({"success": True, "tool": tool_data})
        return jsonify({"success": False, "error": f"Adversary tool '{tool_id}' not found"}), 404

    # 2. Query full catalogs (vectors + tools)
    if _parse_bool(request.args.get("catalog")) or _parse_bool(data.get("catalog")):
        return jsonify({
            "success": True,
            "vectors": get_attack_vector_catalog(),
            "tools": get_adversary_tool_catalog()
        })

    # 3. Direct telemetry evaluation payload
    if ("risk" in data and isinstance(data["risk"], dict)) or ("vt" in data and isinstance(data["vt"], dict)) or ("otx" in data and isinstance(data["otx"], dict)):
        ioc = str(data.get("ioc") or "indicator").strip()
        ioc_type = data.get("detection", {}).get("type") or data.get("ioc_type") or "UNKNOWN"
        risk = data.get("risk", {})
        vt = data.get("vt", {})
        abuse = data.get("abuse", {})
        otx = data.get("otx", {})
        geo = data.get("geo", {})
        domain_age_days = data.get("domain_age_days")
        if domain_age_days is not None:
            try:
                domain_age_days = int(domain_age_days)
            except (ValueError, TypeError):
                domain_age_days = None
        is_nrd = _parse_bool(data.get("is_nrd"), default=None)
        ports = data.get("ports")
        attack_profile = analyze_attack_vector(
            ioc, ioc_type, vt, abuse, otx, geo, risk,
            domain_age_days=domain_age_days, ports=ports, is_nrd=is_nrd
        )
        return jsonify({
            "success": True,
            "ioc": ioc,
            "ioc_type": ioc_type,
            "attacks": attack_profile
        })

    # 4. On-the-fly indicator evaluation
    ioc = str(data.get("ioc", "")).strip().strip("'\"")
    if not ioc:
        return jsonify({"success": False, "error": "Missing 'ioc' or 'tool' parameter in request"}), 400

    days_elapsed = data.get("days_elapsed")
    if days_elapsed is not None:
        try:
            days_elapsed = float(days_elapsed)
        except (ValueError, TypeError):
            days_elapsed = None

    domain_age_days = data.get("domain_age_days")
    if domain_age_days is not None:
        try:
            domain_age_days = int(domain_age_days)
        except (ValueError, TypeError):
            domain_age_days = None

    is_nrd = _parse_bool(data.get("is_nrd"), default=None)
    ports = data.get("ports")

    scan_res = _execute_single_scan(
        ioc=ioc,
        demo_mode=data.get("demo_mode"),
        vt_key=data.get("vt_key", ""),
        abuse_key=data.get("abuse_key", ""),
        otx_key=data.get("otx_key", ""),
        persist=False,
        days_elapsed=days_elapsed,
        domain_age_days=domain_age_days,
        is_nrd=is_nrd,
        ports=ports
    )
    if not scan_res.get("success"):
        return jsonify(scan_res), 400

    return jsonify({
        "success": True,
        "ioc": scan_res["ioc"],
        "ioc_type": scan_res["detection"]["type"],
        "attacks": scan_res.get("attacks")
    })


@app.route("/api/velocity", methods=["GET", "POST", "OPTIONS"])
def api_velocity():
    """Generates 14-day attack activity and velocity analytics for an IOC."""
    if request.method == "OPTIONS":
        return "", 204

    try:
        data = _get_request_data()

        # 1. If pre-resolved telemetry objects are supplied
        if ("vt" in data and isinstance(data["vt"], dict)) or ("abuse" in data and isinstance(data["abuse"], dict)):
            raw_ioc = str(data.get("ioc") or "indicator").strip()
            detection = detect_ioc_type(raw_ioc) if raw_ioc and raw_ioc != "indicator" else {"type": "UNKNOWN", "normalized": raw_ioc}
            normalized = detection.get("normalized") or raw_ioc
            ioc_type = data.get("detection", {}).get("type") or data.get("ioc_type")
            if not ioc_type or str(ioc_type).upper() == "UNKNOWN":
                ioc_type = detection.get("type", "UNKNOWN")
            ioc_type = str(ioc_type).upper()
            ioc = normalized or raw_ioc

            vt = data.get("vt", {})
            abuse = data.get("abuse", {})
            otx = data.get("otx", {})
            days_elapsed = data.get("days_elapsed")
            if days_elapsed is not None:
                try:
                    days_elapsed = float(days_elapsed)
                except (ValueError, TypeError):
                    days_elapsed = None
            velocity = generate_attack_velocity(ioc, ioc_type, vt, abuse, otx, days_elapsed=days_elapsed)
            return jsonify({
                "success": True,
                "ioc": ioc,
                "ioc_type": ioc_type,
                "velocity": velocity
            })

        # 2. On-the-fly scan evaluation
        ioc = str(data.get("ioc", "")).strip().strip("'\"")
        if not ioc:
            return jsonify({"success": False, "error": "Missing 'ioc' parameter in request"}), 400

        days_elapsed = data.get("days_elapsed")
        if days_elapsed is not None:
            try:
                days_elapsed = float(days_elapsed)
            except (ValueError, TypeError):
                days_elapsed = None

        scan_res = _execute_single_scan(
            ioc=ioc,
            demo_mode=data.get("demo_mode"),
            vt_key=data.get("vt_key", ""),
            abuse_key=data.get("abuse_key", ""),
            otx_key=data.get("otx_key", ""),
            persist=False,
            days_elapsed=days_elapsed
        )
        if not scan_res.get("success"):
            return jsonify(scan_res), 400

        return jsonify({
            "success": True,
            "ioc": scan_res["ioc"],
            "ioc_type": scan_res["detection"]["type"],
            "velocity": scan_res.get("velocity")
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to generate attack velocity: {str(e)}"}), 500


@app.route("/api/graph", methods=["GET", "POST", "OPTIONS"])
def api_graph():
    """Generates force-directed relationship graph data for IOC."""
    if request.method == "OPTIONS":
        return "", 204

    try:
        data = _get_request_data()
        ioc, ioc_type, risk, vt, abuse, otx, geo = _resolve_export_data(data)
        if not ioc:
            return jsonify({"success": False, "error": "Invalid or missing IOC payload"}), 400

        graph_data = generate_threat_graph(ioc, ioc_type, vt, abuse, otx, geo, risk_data=risk)
        return jsonify({
            "success": True,
            "ioc": ioc,
            "ioc_type": ioc_type,
            "graph": graph_data
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to generate threat graph: {str(e)}"}), 500


@app.route("/api/export/stix", methods=["GET", "POST", "OPTIONS"])
def api_export_stix():
    """Generates and streams an OASIS STIX 2.1 threat intelligence bundle."""
    if request.method == "OPTIONS":
        return "", 204

    data = _get_request_data()
    ioc, ioc_type, risk, vt, abuse, otx, geo = _resolve_export_data(data)
    if not ioc:
        return jsonify({"success": False, "error": "Invalid or missing IOC payload"}), 400

    stix_str = generate_stix_json(ioc, ioc_type, risk, vt, abuse, otx, geo)
    safe_filename = re.sub(r'[^a-zA-Z0-9_\.-]', '_', ioc)
    return Response(
        stix_str,
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=stix21_{safe_filename}.json",
            "Content-Type": "application/json"
        }
    )


@app.route("/api/webhook/dispatch", methods=["POST", "OPTIONS"])
def api_webhook_dispatch():
    """Dispatches a formatted SOC incident alert to Discord, Slack, or MS Teams."""
    if request.method == "OPTIONS":
        return "", 204

    data = _get_request_data()
    webhook_url = str(data.get("webhook_url", "")).strip()
    if not webhook_url:
        return jsonify({"success": False, "error": "Missing 'webhook_url' in request"}), 400
    if not (webhook_url.startswith("http://") or webhook_url.startswith("https://")):
        return jsonify({"success": False, "error": "Invalid webhook URL scheme. Must start with http:// or https://"}), 400

    platform = data.get("platform")
    dry_run = _parse_bool(data.get("dry_run", False), default=False)

    ioc, ioc_type, risk, vt, abuse, otx, geo = _resolve_export_data(data)
    if not ioc:
        return jsonify({"success": False, "error": "Invalid or missing IOC payload"}), 400

    dispatch_res = dispatch_webhook_alert(
        webhook_url=webhook_url,
        ioc=ioc,
        ioc_type=ioc_type,
        risk_data=risk,
        vt_data=vt,
        otx_data=otx,
        platform=platform,
        dry_run=dry_run
    )

    status_code = 200 if dispatch_res.get("success") else 400
    return jsonify(dispatch_res), status_code


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f">> Starting CyberPulse SOC Server on http://127.0.0.1:{port} <<")
    app.run(host="0.0.0.0", port=port, debug=True)
