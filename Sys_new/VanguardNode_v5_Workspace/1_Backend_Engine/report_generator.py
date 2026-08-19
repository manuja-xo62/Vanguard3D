import io
from pathlib import Path
from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_pdf_report(scan_data: Dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize = letter, rightMargin = 36, leftMargin = 36, bottomMargin = 36)
    story = []

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TitleStyle', parent = styles['Heading1'], fontSize = 22, textColor = colors.HexColor('#00E5FF'))
    subtitle_style = ParagraphStyle('SubTitleStyle', parent=styles['Normal'], fontSize = 11, textColor=colors.gray)

    story.append(Paragraph("VanguardNode 3D - Security Audit Report", style=title_style))
    story.append(Paragraph(f"Scan ID: {scan_data.get('scan_id', 'N/A')} | Target: {scan_data.get('target_path', 'N/A')}", subtitle_style))
    story.append(Spacer(1,18))

    r_global = scan_data.get("r_global", scan_data.get("R_global", 0.0))
    summary_text = f"<b>Global Risk Score (R_global):</b> {r_global:.2f}"
    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1,12))

    table_data = [["File Path", "Risk Score (R_file)", "Status"]]
    for f in scan_data.get("files", scan_data.get("findings", [])):
        path = f.get("file_path", "Unknown")
        r_file = f.get("R_file", f.get("r_file", 0.0))
        status = f.get("status", "Analyzed")
        table_data.append([path, f"{r_file:.2f}, status"])
    
    t = Table(table_data, colWidths=[300,120,100])
    t.setStyle(TableStyle)
    ([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#334155')),
    ])
    story.append(t)

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
    
    