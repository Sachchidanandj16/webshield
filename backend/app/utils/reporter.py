import os
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(scan_id: int, target_url: str, score: int, findings: list, filename: str):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    story = []
    styles = getSampleStyleSheet()
    
    # Custom Palette
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#00E5FF'), # Cyan Accent
        spaceAfter=20
    )
    
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#0A192F')
    )

    # Document Header
    story.append(Paragraph("WebShield Assessment Report", title_style))
    story.append(Spacer(1, 15))
    
    # Metadata block
    meta_text = f"<b>Target URL:</b> {target_url}<br/><b>Overall Security Score:</b> {score}/100<br/><b>Scan Run Identification:</b> #{scan_id}"
    story.append(Paragraph(meta_text, body_style))
    story.append(Spacer(1, 20))
    
    # Tabular Findings Presentation
    table_data = [["Compliance Metric", "Severity", "Finding Status"]]
    
    for f in findings:
        table_data.append([
            f.item_checked,
            f.severity,
            f.status
        ])
        
    t = Table(table_data, colWidths=[3.0*inch, 1.5*inch, 2.0*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0A192F')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#F4F6F9'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#D3D3D3')),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
    ]))
    
    story.append(t)
    doc.build(story)