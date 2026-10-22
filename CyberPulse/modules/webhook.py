"""
SOC Incident Alert Webhook Dispatcher.
Formats and dispatches high-priority threat notifications to Discord, Slack,
and Microsoft Teams incoming webhooks.
"""
import requests
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from modules.detector import defang_ioc


def detect_webhook_platform(url: str) -> str:
    """Infers target messaging platform from incoming webhook URL structure."""
    u = url.lower()
    if "discord.com/api/webhooks" in u:
        return "discord"
    if "hooks.slack.com" in u:
        return "slack"
    if "office.com" in u or "webhook.office" in u:
        return "teams"
    return "generic"


def _color_hex_to_int(hex_str: str) -> int:
    """Converts hex color string (#ef4444) to decimal integer for Discord embeds."""
    try:
        clean = hex_str.lstrip("#")
        return int(clean, 16)
    except Exception:
        return 0xef4444


def format_discord_payload(
    ioc: str,
    ioc_type: str,
    risk_data: Dict[str, Any],
    vt_data: Optional[Dict[str, Any]] = None,
    otx_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Generates rich Discord webhook embed payload."""
    vt_data = vt_data or {}
    otx_data = otx_data or {}
    score = risk_data.get("score", 0)
    level = risk_data.get("level", "Unknown")
    color_hex = risk_data.get("color", "#ef4444")
    defanged = defang_ioc(ioc)

    malware = otx_data.get("malware_families") or []
    malware_str = ", ".join(malware) if malware else "None Identified"

    actions = risk_data.get("actions") or []
    actions_str = "\n".join([f"• {a}" for a in actions[:3]]) if actions else "Review in SIEM"

    embed = {
        "title": f"🚨 CyberPulse Incident Alert: {defanged}",
        "description": f"An automated investigation flagged target indicator with a **{score}/100** Threat Index.",
        "color": _color_hex_to_int(color_hex),
        "fields": [
            {"name": "Indicator", "value": f"`{defanged}`", "inline": True},
            {"name": "Type", "value": ioc_type, "inline": True},
            {"name": "Threat Level", "value": f"**{level}** ({score}/100)", "inline": True},
            {"name": "VirusTotal Malicious", "value": f"{vt_data.get('malicious', 0)} engines", "inline": True},
            {"name": "AlienVault Pulses", "value": f"{otx_data.get('pulse_count', 0)} active", "inline": True},
            {"name": "Malware Families", "value": malware_str, "inline": True},
            {"name": "Immediate Containment Actions", "value": actions_str, "inline": False}
        ],
        "footer": {
            "text": "CyberPulse SOC Command Center • Automated Triage"
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    return {
        "username": "CyberPulse SOC Bot",
        "avatar_url": "https://img.icons8.com/color/96/shield.png",
        "embeds": [embed]
    }


def format_slack_payload(
    ioc: str,
    ioc_type: str,
    risk_data: Dict[str, Any],
    vt_data: Optional[Dict[str, Any]] = None,
    otx_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Generates rich Slack Block Kit / Attachment webhook payload."""
    vt_data = vt_data or {}
    otx_data = otx_data or {}
    score = risk_data.get("score", 0)
    level = risk_data.get("level", "Unknown")
    color_hex = risk_data.get("color", "#ef4444")
    defanged = defang_ioc(ioc)

    malware = otx_data.get("malware_families") or []
    malware_str = ", ".join(malware) if malware else "None"

    actions = risk_data.get("actions") or []
    actions_str = "\n".join([f"• {a}" for a in actions[:3]]) if actions else "Review in SIEM"

    return {
        "text": f"🚨 CyberPulse SOC Alert: {defanged} ({score}/100 - {level})",
        "attachments": [
            {
                "color": color_hex,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"🚨 High-Priority Threat Alert: {defanged}", "emoji": True}
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Indicator:*\n`{defanged}`"},
                            {"type": "mrkdwn", "text": f"*Classification:*\n{ioc_type}"},
                            {"type": "mrkdwn", "text": f"*Risk Level:*\n*{level}* ({score}/100)"},
                            {"type": "mrkdwn", "text": f"*Malware Families:*\n{malware_str}"}
                        ]
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Recommended SOC Actions:*\n{actions_str}"}
                    }
                ]
            }
        ]
    }


def format_teams_payload(
    ioc: str,
    ioc_type: str,
    risk_data: Dict[str, Any],
    vt_data: Optional[Dict[str, Any]] = None,
    otx_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Generates Microsoft Teams MessageCard webhook payload."""
    vt_data = vt_data or {}
    otx_data = otx_data or {}
    score = risk_data.get("score", 0)
    level = risk_data.get("level", "Unknown")
    color_hex = risk_data.get("color", "#ef4444").lstrip("#")
    defanged = defang_ioc(ioc)

    malware = otx_data.get("malware_families") or []
    malware_str = ", ".join(malware) if malware else "None"

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color_hex,
        "summary": f"CyberPulse Alert: {defanged}",
        "title": f"🚨 CyberPulse Threat Alert: {defanged}",
        "sections": [
            {
                "activityTitle": f"Risk Score: **{score}/100** ({level})",
                "activitySubtitle": f"Target Indicator: {defanged} ({ioc_type})",
                "facts": [
                    {"name": "IOC:", "value": defanged},
                    {"name": "Type:", "value": ioc_type},
                    {"name": "VirusTotal Malicious:", "value": str(vt_data.get("malicious", 0))},
                    {"name": "AlienVault Pulses:", "value": str(otx_data.get("pulse_count", 0))},
                    {"name": "Malware:", "value": malware_str}
                ],
                "markdown": True
            }
        ]
    }


def dispatch_webhook_alert(
    webhook_url: str,
    ioc: str,
    ioc_type: str,
    risk_data: Dict[str, Any],
    vt_data: Optional[Dict[str, Any]] = None,
    otx_data: Optional[Dict[str, Any]] = None,
    platform: Optional[str] = None,
    timeout: int = 10,
    dry_run: bool = False
) -> Dict[str, Any]:
    """
    Constructs and transmits the webhook notification.
    If dry_run is True or URL is a test simulation, bypasses actual HTTP POST.
    """
    clean_url = str(webhook_url).strip()
    if not clean_url:
        return {"success": False, "error": "Webhook URL cannot be empty"}

    target_platform = (platform or detect_webhook_platform(clean_url)).lower()

    if target_platform == "discord":
        payload = format_discord_payload(ioc, ioc_type, risk_data, vt_data, otx_data)
    elif target_platform == "slack":
        payload = format_slack_payload(ioc, ioc_type, risk_data, vt_data, otx_data)
    elif target_platform == "teams":
        payload = format_teams_payload(ioc, ioc_type, risk_data, vt_data, otx_data)
    else:
        # Default generic payload
        payload = format_slack_payload(ioc, ioc_type, risk_data, vt_data, otx_data)

    if dry_run or "example.com" in clean_url or "localhost" in clean_url or clean_url == "simulation":
        return {
            "success": True,
            "simulated": True,
            "platform": target_platform,
            "status_code": 200,
            "message": f"Alert successfully dispatched to {target_platform.title()} (dry-run mode)",
            "payload": payload
        }

    try:
        resp = requests.post(clean_url, json=payload, timeout=timeout)
        if resp.status_code in (200, 201, 204):
            return {
                "success": True,
                "simulated": False,
                "platform": target_platform,
                "status_code": resp.status_code,
                "message": f"Alert successfully delivered to {target_platform.title()}"
            }
        else:
            return {
                "success": False,
                "simulated": False,
                "platform": target_platform,
                "status_code": resp.status_code,
                "error": f"Webhook returned HTTP {resp.status_code}: {resp.text[:200]}"
            }
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "simulated": False,
            "platform": target_platform,
            "error": f"Network exception during dispatch: {str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "simulated": False,
            "platform": target_platform,
            "error": f"Dispatch error ({type(e).__name__}): {str(e)}"
        }
