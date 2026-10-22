"""
Automated Threat Intelligence Report Generator.
Produces Executive SOC Investigation Reports in JSON, Markdown, and PDF formats.
"""
import io
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from xml.sax.saxutils import escape as xml_escape

# Attempt reportlab import; provide graceful fallback if not yet installed
REPORTLAB_AVAILABLE = False
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


from modules.attack_analyzer import analyze_attack_vector


def safe_text(val: Any) -> str:
    """Escapes XML/HTML entities so ReportLab's Paragraph parser never crashes."""
    if val is None:
        return ""
    return xml_escape(str(val))


def generate_json_report(
    ioc: str,
    ioc_type: str,
    risk_data: Dict[str, Any],
    vt_data: Dict[str, Any],
    abuse_data: Dict[str, Any],
    otx_data: Dict[str, Any],
    geo_data: Dict[str, Any],
    attack_data: Optional[Dict[str, Any]] = None,
    domain_age_days: Optional[int] = None,
    ports: Optional[List[int]] = None,
    is_nrd: Optional[bool] = None,
    web_security_data: Optional[Dict[str, Any]] = None
) -> str:
    """Formats full investigation telemetry into an indented JSON dossier."""
    if attack_data is None:
        attack_data = analyze_attack_vector(
            ioc, ioc_type, vt_data, abuse_data, otx_data, geo_data, risk_data,
            domain_age_days=domain_age_days, ports=ports, is_nrd=is_nrd
        )

    if web_security_data is None:
        if ioc_type in ("DOMAIN", "URL"):
            from modules.web_security import audit_website_security
            from config import is_default_demo_mode
            web_security_data = audit_website_security(ioc, demo_mode=is_default_demo_mode())
        else:
            web_security_data = {
                "status": "not_applicable",
                "message": f"Website security headers and SSL audit is only applicable to web domains and URLs (current type: {ioc_type})."
            }

    dossier = {
        "metadata": {
            "report_type": "SOC Threat Intelligence Dossier",
            "generator": "CyberPulse SOC Engine v2.4.0",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "target_indicator": ioc,
            "indicator_type": ioc_type
        },
        "unified_risk_assessment": {
            "score": risk_data.get("score", 0),
            "severity": risk_data.get("level", "Unknown"),
            "summary": risk_data.get("summary", ""),
            "soc_recommendations": risk_data.get("actions", []),
            "breakdown": risk_data.get("breakdown", {})
        },
        "website_security_posture": web_security_data,
        "attack_prediction": {
            "vector_id": attack_data.get("vector_id"),
            "name": attack_data.get("name"),
            "icon": attack_data.get("icon"),
            "confidence": attack_data.get("confidence"),
            "severity": attack_data.get("severity"),
            "hacker_objective": attack_data.get("hacker_objective"),
            "blast_radius": attack_data.get("blast_radius"),
            "mitre_techniques": attack_data.get("mitre_techniques", []),
            "adversary_tools": attack_data.get("adversary_tools", [])
        },
        "telemetry_sources": {
            "virustotal": vt_data,
            "abuseipdb": abuse_data,
            "alienvault_otx": otx_data,
            "geolocation": geo_data
        }
    }
    return json.dumps(dossier, indent=2)


def generate_markdown_report(
    ioc: str,
    ioc_type: str,
    risk_data: Dict[str, Any],
    vt_data: Dict[str, Any],
    abuse_data: Dict[str, Any],
    otx_data: Dict[str, Any],
    geo_data: Dict[str, Any],
    attack_data: Optional[Dict[str, Any]] = None,
    domain_age_days: Optional[int] = None,
    ports: Optional[List[int]] = None,
    is_nrd: Optional[bool] = None,
    web_security_data: Optional[Dict[str, Any]] = None
) -> str:
    """Creates a Markdown investigation brief for ServiceNow / Jira / TheHive."""
    if attack_data is None:
        attack_data = analyze_attack_vector(
            ioc, ioc_type, vt_data, abuse_data, otx_data, geo_data, risk_data,
            domain_age_days=domain_age_days, ports=ports, is_nrd=is_nrd
        )

    if web_security_data is None and ioc_type in ("DOMAIN", "URL"):
        from modules.web_security import audit_website_security
        from config import is_default_demo_mode
        web_security_data = audit_website_security(ioc, demo_mode=is_default_demo_mode())

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    score = risk_data.get("score", 0)
    level = risk_data.get("level", "Unknown")
    actions = risk_data.get("actions", [])
    
    geo_str = "N/A"
    if geo_data.get("status") == "success":
        geo_str = f"{geo_data.get('city')}, {geo_data.get('country')} ({geo_data.get('isp', 'Unknown ISP')})"

    md = f"""# 🛡️ SOC Threat Intelligence Report: `{ioc}`

- **Generated:** {now_str}
- **IOC Type:** {ioc_type}
- **Unified Risk Score:** **{score}/100** ({level})
- **Geolocation:** {geo_str}

---

## 🎯 Predicted Attack Vector & Adversary Toolset
- **Primary Attack Vector:** {attack_data.get('icon', '')} **{attack_data.get('name', 'Unclassified')}** (Severity: {attack_data.get('severity', 'UNKNOWN')} &bull; Confidence: {attack_data.get('confidence', 0)}%)
- **Hacker Tactical Objective:** {attack_data.get('hacker_objective', 'N/A')}
- **Expected Blast Radius / Impact:** {attack_data.get('blast_radius', 'N/A')}

### 🛡️ MITRE ATT&CK TTP Mapping
"""
    for ttp in attack_data.get("mitre_techniques", []):
        md += f"- **{ttp.get('id')}**: {ttp.get('name')} (*{ttp.get('tactic', 'Tactic')}*) - {ttp.get('url', '')}\n"

    md += "\n### ⚔️ Real-World Adversary Toolset & Containment\n"
    for tool in attack_data.get("adversary_tools", []):
        md += f"#### 🔧 {tool.get('name')} ({tool.get('category')})\n"
        md += f"- **Hacker's Tactical Purpose:** {tool.get('tactical_purpose')}\n"
        md += f"- **SOC Forensic Artifacts:** {tool.get('forensic_artifacts')}\n"
        md += f"- **Targeted Containment Step:** {tool.get('containment_step')}\n\n"

    if web_security_data and web_security_data.get("status") == "success":
        ssl_d = web_security_data.get("ssl", {})
        red_d = web_security_data.get("redirect", {})
        md += f"""---

## 🌐 Website Security Posture & SSL Health
- **Hardening Grade:** **{web_security_data.get('grade')}** ({web_security_data.get('score')}/100) &bull; {web_security_data.get('grade_description', '')}
- **SSL Certificate:** {ssl_d.get('issuer', 'N/A')} (Protocol: {ssl_d.get('protocol', 'N/A')}, Status: {ssl_d.get('status_label', 'N/A')}, Expires in: {ssl_d.get('expires_in_days', 0)} days)
- **HTTPS Enforcement:** {'Enforced' if red_d.get('enforced') else 'Not Enforced'} ({red_d.get('details', '')})

### 🛡️ Defensive Security Headers Matrix
"""
        for h in web_security_data.get("checklist", []):
            stat_icon = "✅ PASS" if h.get("passed") else "❌ FAIL"
            val_txt = h.get("value") if h.get("passed") else h.get("remediation")
            md += f"- **{h.get('header')}**: {stat_icon} &bull; {val_txt}\n"


    md += f"""---

## 📊 Telemetry Summary
- **VirusTotal:** {vt_data.get('malicious', 0)} malicious / {vt_data.get('suspicious', 0)} suspicious engines (Reputation: {vt_data.get('reputation', 0)})
- **AbuseIPDB:** {abuse_data.get('abuse_confidence_score', 'N/A')}% confidence score ({abuse_data.get('total_reports', 0)} reports)
- **AlienVault OTX:** {otx_data.get('pulse_count', 0)} active threat pulses

## 🎯 Recommended SOC Actions
"""
    for action in actions:
        md += f"- [ ] {action}\n"

    md += "\n*Generated automatically by CyberPulse Threat Intelligence Engine.*"
    return md


def generate_pdf_report(
    ioc: str,
    ioc_type: str,
    risk_data: Dict[str, Any],
    vt_data: Dict[str, Any],
    abuse_data: Dict[str, Any],
    otx_data: Dict[str, Any],
    geo_data: Dict[str, Any],
    attack_data: Optional[Dict[str, Any]] = None,
    domain_age_days: Optional[int] = None,
    ports: Optional[List[int]] = None,
    is_nrd: Optional[bool] = None,
    web_security_data: Optional[Dict[str, Any]] = None
) -> bytes:
    """
    Renders an executive-grade PDF investigation report using ReportLab.
    Safely escapes all dynamic strings so malformed characters or markup never throw parser exceptions.
    Falls back gracefully if ReportLab is unavailable.
    """
    if attack_data is None:
        attack_data = analyze_attack_vector(
            ioc, ioc_type, vt_data, abuse_data, otx_data, geo_data, risk_data,
            domain_age_days=domain_age_days, ports=ports, is_nrd=is_nrd
        )

    if web_security_data is None and ioc_type in ("DOMAIN", "URL"):
        from modules.web_security import audit_website_security
        from config import is_default_demo_mode
        web_security_data = audit_website_security(ioc, demo_mode=is_default_demo_mode())

    if not REPORTLAB_AVAILABLE:
        # Fallback text representation packaged into bytes
        fallback_text = generate_markdown_report(
            ioc, ioc_type, risk_data, vt_data, abuse_data, otx_data, geo_data,
            attack_data=attack_data, web_security_data=web_security_data
        )
        return fallback_text.encode("utf-8")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    header_style = ParagraphStyle(
        'SOCHeader',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'SOCSubtitle',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=12
    )
    section_title = ParagraphStyle(
        'SOCSection',
        parent=styles['Heading2'],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'SOCBody',
        parent=styles['Normal'],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    bold_style = ParagraphStyle(
        'SOCBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    elements = []

    # Title & Header
    elements.append(Paragraph("CYBERPULSE // SOC THREAT INTELLIGENCE DOSSIER", header_style))
    elements.append(Paragraph(
        f"Automated Investigation Report &bull; Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} &bull; Classification: TLP:CLEAR",
        subtitle_style
    ))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#3b82f6'), spaceAfter=14))

    # Target Indicator & Unified Risk Score Banner
    score = risk_data.get("score", 0)
    level = risk_data.get("level", "Unknown")

    if score <= 20:
        score_hex = "#10b981"
    elif score <= 60:
        score_hex = "#f59e0b"
    else:
        score_hex = "#ef4444"

    banner_data = [
        [
            Paragraph(f"<b>Target IOC:</b> <font name='Courier'>{safe_text(ioc)}</font>", body_style),
            Paragraph(f"<b>Indicator Type:</b> {safe_text(ioc_type)}", body_style)
        ],
        [
            Paragraph(f"<b>Risk Assessment:</b> <font color='{score_hex}'><b>{score}/100 &mdash; {safe_text(level)}</b></font>", body_style),
            Paragraph(f"<b>Summary:</b> {safe_text(risk_data.get('summary', 'N/A'))}", body_style)
        ]
    ]
    banner_table = Table(banner_data, colWidths=[270, 270])
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(banner_table)
    elements.append(Spacer(1, 14))

    # Predicted Attack Vector & Adversary Toolset Section
    elements.append(Paragraph("PREDICTED ATTACK VECTOR & ADVERSARY TOOLSET", section_title))
    attack_summary_rows = [
        [
            Paragraph("<b>Primary Attack Vector</b>", bold_style),
            Paragraph(f"<b>{safe_text(attack_data.get('name'))}</b> &bull; Severity: <font color='{attack_data.get('color', '#ef4444')}'><b>{safe_text(attack_data.get('severity'))}</b></font> &bull; Confidence: <b>{attack_data.get('confidence', 0)}%</b>", body_style)
        ],
        [
            Paragraph("<b>Hacker Objective</b>", bold_style),
            Paragraph(safe_text(attack_data.get('hacker_objective', 'N/A')), body_style)
        ],
        [
            Paragraph("<b>Expected Blast Radius</b>", bold_style),
            Paragraph(safe_text(attack_data.get('blast_radius', 'N/A')), body_style)
        ]
    ]
    attack_summary_table = Table(attack_summary_rows, colWidths=[140, 400])
    attack_summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(attack_summary_table)
    elements.append(Spacer(1, 10))

    # Mapped Adversary Tools Table
    adv_tools = attack_data.get("adversary_tools", [])
    if adv_tools:
        tool_rows = [[
            Paragraph("<b>Hacker Tool</b>", bold_style),
            Paragraph("<b>Tactical Purpose</b>", bold_style),
            Paragraph("<b>SOC Forensic Artifacts</b>", bold_style),
            Paragraph("<b>Targeted Containment</b>", bold_style)
        ]]
        for tool in adv_tools[:4]:  # Top tools for executive summary
            tool_rows.append([
                Paragraph(f"<b>{safe_text(tool.get('name'))}</b><br/><font size='7' color='#64748b'>{safe_text(tool.get('category'))}</font>", body_style),
                Paragraph(safe_text(tool.get('tactical_purpose')), body_style),
                Paragraph(safe_text(tool.get('forensic_artifacts')), body_style),
                Paragraph(safe_text(tool.get('containment_step')), body_style)
            ])
        tools_table = Table(tool_rows, colWidths=[100, 130, 150, 160])
        tools_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(tools_table)
        elements.append(Spacer(1, 12))

    # Telemetry Breakdown Section
    elements.append(Paragraph("MULTI-SOURCE TELEMETRY BREAKDOWN", section_title))
    
    geo_display = "N/A (Not an IP address)"
    if geo_data.get("status") == "success":
        geo_display = f"{geo_data.get('city')}, {geo_data.get('country')} &bull; AS: {geo_data.get('as_info', 'N/A')}"

    telemetry_rows = [
        [Paragraph("<b>Intelligence Source</b>", bold_style), Paragraph("<b>Key Telemetry Metrics</b>", bold_style), Paragraph("<b>Telemetry Verdict</b>", bold_style)],
        [
            Paragraph("VirusTotal v3", body_style),
            Paragraph(f"Malicious: {vt_data.get('malicious', 0)} | Suspicious: {vt_data.get('suspicious', 0)} | Harmless: {vt_data.get('harmless', 0)}", body_style),
            Paragraph(f"Reputation Score: {vt_data.get('reputation', 0)}", body_style)
        ],
        [
            Paragraph("AbuseIPDB v2", body_style),
            Paragraph(f"Abuse Confidence: {abuse_data.get('abuse_confidence_score', 'N/A')}% | Total Reports: {abuse_data.get('total_reports', 0)}", body_style),
            Paragraph(f"ISP: {safe_text(abuse_data.get('isp', 'N/A'))}", body_style)
        ],
        [
            Paragraph("AlienVault OTX", body_style),
            Paragraph(f"Active Threat Pulses: {otx_data.get('pulse_count', 0)}", body_style),
            Paragraph(f"Tags: {safe_text(', '.join(otx_data.get('tags', [])[:5])) or 'None'}", body_style)
        ],
        [
            Paragraph("IP Geolocation", body_style),
            Paragraph(safe_text(geo_display), body_style),
            Paragraph(f"Coordinates: {geo_data.get('lat', 'N/A')}, {geo_data.get('lon', 'N/A')}", body_style)
        ]
    ]

    telemetry_table = Table(telemetry_rows, colWidths=[120, 260, 160])
    telemetry_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    elements.append(telemetry_table)
    elements.append(Spacer(1, 14))

    # Top Security Vendor Detections
    vendors = vt_data.get("vendors", {})
    if vendors:
        elements.append(Paragraph("SECURITY VENDOR DETECTIONS MATRIX", section_title))
        vendor_rows = [[Paragraph("<b>Vendor / Engine</b>", bold_style), Paragraph("<b>Analysis Result</b>", bold_style)]]
        for v_name, v_res in list(vendors.items())[:12]:
            v_color = "#ef4444" if 'malicious' in str(v_res).lower() else "#334155"
            vendor_rows.append([
                Paragraph(safe_text(v_name), body_style),
                Paragraph(f"<font color='{v_color}'>{safe_text(v_res)}</font>", body_style)
            ])
        v_table = Table(vendor_rows, colWidths=[200, 340])
        v_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ]))
        elements.append(v_table)
        elements.append(Spacer(1, 14))

    # Website Security Posture & Defensive Headers
    if web_security_data and web_security_data.get("status") == "success":
        elements.append(Paragraph("WEBSITE SECURITY POSTURE & DEFENSIVE HEADERS", section_title))
        web_grade = safe_text(web_security_data.get("grade", "N/A"))
        web_score = web_security_data.get("score", 0)
        web_color = web_security_data.get("grade_color", "#10b981")
        ssl_d = web_security_data.get("ssl") or {}
        red_d = web_security_data.get("redirect") or {}

        web_summary_rows = [
            [
                Paragraph(f"<b>Hardening Grade:</b> <font color='{web_color}'><b>Grade {web_grade} ({web_score}/100)</b></font>", body_style),
                Paragraph(f"<b>HTTPS Enforcement:</b> {'Enforced (301/302)' if red_d.get('enforced') else 'Not Enforced'}", body_style)
            ],
            [
                Paragraph(f"<b>SSL Certificate:</b> {safe_text(ssl_d.get('issuer', 'N/A'))} &bull; {safe_text(ssl_d.get('protocol', 'TLS'))}", body_style),
                Paragraph(f"<b>SSL Status:</b> {safe_text(ssl_d.get('status_label', 'N/A'))} ({ssl_d.get('expires_in_days', 0)} days remaining)", body_style)
            ]
        ]
        web_summary_table = Table(web_summary_rows, colWidths=[270, 270])
        web_summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(web_summary_table)
        elements.append(Spacer(1, 8))

        checklist_items = web_security_data.get("checklist", [])
        if checklist_items:
            hdr_rows = [[
                Paragraph("<b>Defensive Header</b>", bold_style),
                Paragraph("<b>Status</b>", bold_style),
                Paragraph("<b>Assessment / Recommendation</b>", bold_style)
            ]]
            for h in checklist_items[:7]:
                h_status = safe_text(h.get("status", "FAIL"))
                h_color = "#10b981" if h_status == "PASS" else ("#f59e0b" if h_status == "WARN" else "#ef4444")
                val_or_rem = safe_text(h.get("value") if h.get("passed") else h.get("remediation"))
                hdr_rows.append([
                    Paragraph(f"<b>{safe_text(h.get('header'))}</b>", body_style),
                    Paragraph(f"<font color='{h_color}'><b>{h_status}</b></font>", body_style),
                    Paragraph(val_or_rem, body_style)
                ])
            hdr_table = Table(hdr_rows, colWidths=[150, 70, 320])
            hdr_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(hdr_table)
            elements.append(Spacer(1, 14))

    # SOC Triage Playbook & Recommended Actions
    elements.append(Paragraph("SOC TRIAGE PLAYBOOK & MITIGATION STEPS", section_title))
    action_items = risk_data.get("actions", [])
    action_rows = []
    for idx, act in enumerate(action_items, 1):
        action_rows.append([
            Paragraph(f"<b>[Step {idx}]</b>", bold_style),
            Paragraph(safe_text(act), body_style)
        ])
    if action_rows:
        action_table = Table(action_rows, colWidths=[70, 470])
        action_table.setStyle(TableStyle([
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#f1f5f9')),
        ]))
        elements.append(action_table)

    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0'), spaceAfter=8))
    elements.append(Paragraph(
        "Confidential SOC Investigation Record &bull; For Authorized Personnel Only &bull; CyberPulse Threat Intelligence Engine",
        ParagraphStyle('Footer', parent=subtitle_style, fontSize=7.5, textColor=colors.HexColor('#94a3b8'))
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()


def generate_stix_report(
    ioc: str,
    ioc_type: str,
    risk_data: Dict[str, Any],
    vt_data: Dict[str, Any],
    abuse_data: Dict[str, Any],
    otx_data: Dict[str, Any],
    geo_data: Dict[str, Any]
) -> str:
    """Generates an OASIS STIX 2.1 JSON Threat Bundle."""
    from modules.stix_gen import generate_stix_json
    return generate_stix_json(ioc, ioc_type, risk_data, vt_data, abuse_data, otx_data, geo_data)

