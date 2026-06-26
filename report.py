from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from datetime import datetime

class ReportGenerator:
    def __init__(self, target, scan_results, cve_results):
        self.target = target
        self.scan_results = scan_results
        self.cve_results = cve_results
        self.styles = getSampleStyleSheet()

    def generate(self, output_path):
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=inch,
            bottomMargin=inch
        )

        story = []
        story += self._header()
        story += self._summary()
        story += self._ports_table()
        story += self._cve_section()

        doc.build(story)
        print(f"\n[✔] Report saved: {output_path}")

    def _header(self):
        title_style = ParagraphStyle(
            'Title',
            parent=self.styles['Title'],
            fontSize=24,
            textColor=colors.HexColor('#E63946'),
            spaceAfter=10
        )
        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.grey
        )

        return [
            Paragraph("Vulnerability Scan Report", title_style),
            Paragraph(f"Target: {self.target}", subtitle_style),
            Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style),
            Spacer(1, 0.3 * inch)
        ]

    def _summary(self):
        heading_style = ParagraphStyle(
            'Heading',
            parent=self.styles['Heading2'],
            textColor=colors.HexColor('#E63946')
        )

        open_ports = [r for r in self.scan_results if r["state"] == "open"]
        total_cves = sum(len(v) for v in self.cve_results.values())

        return [
            Paragraph("Executive Summary", heading_style),
            Paragraph(f"• Open Ports Found: {len(open_ports)}", self.styles['Normal']),
            Paragraph(f"• Total CVEs Found: {total_cves}", self.styles['Normal']),
            Paragraph(f"• Scan Coverage: Ports 1-1024", self.styles['Normal']),
            Spacer(1, 0.2 * inch)
        ]

    def _ports_table(self):
        heading_style = ParagraphStyle(
            'Heading',
            parent=self.styles['Heading2'],
            textColor=colors.HexColor('#E63946')
        )

        data = [["Port", "Protocol", "State", "Service", "Version"]]
        for r in self.scan_results:
            data.append([
                str(r["port"]),
                r["protocol"],
                r["state"],
                r["name"],
                f"{r['product']} {r['version']}".strip()
            ])

        table = Table(data, colWidths=[0.8*inch, 1*inch, 0.8*inch, 1.2*inch, 2.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E63946')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8F8F8')]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))

        return [
            Paragraph("Open Ports & Services", heading_style),
            Spacer(1, 0.1 * inch),
            table,
            Spacer(1, 0.3 * inch)
        ]

    def _cve_section(self):
        heading_style = ParagraphStyle(
            'Heading',
            parent=self.styles['Heading2'],
            textColor=colors.HexColor('#E63946')
        )
        subheading_style = ParagraphStyle(
            'SubHeading',
            parent=self.styles['Heading3'],
            textColor=colors.HexColor('#457B9D')
        )

        severity_colors = {
            "CRITICAL": colors.HexColor('#E63946'),
            "HIGH": colors.HexColor('#F4A261'),
            "MEDIUM": colors.HexColor('#E9C46A'),
            "LOW": colors.HexColor('#2A9D8F'),
            "N/A": colors.grey
        }

        elements = [Paragraph("CVE Findings", heading_style)]

        for service, cves in self.cve_results.items():
            if not cves:
                continue
            elements.append(Paragraph(f"Service: {service}", subheading_style))

            for cve in cves:
                sev_color = severity_colors.get(cve['severity'], colors.grey)
                data = [
                    ["CVE ID", cve['id']],
                    ["Severity", cve['severity']],
                    ["Score", str(cve['score'])],
                    ["Description", cve['description']]
                ]
                table = Table(data, colWidths=[1.2*inch, 5.1*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F0F0F0')),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('TEXTCOLOR', (1, 1), (1, 1), sev_color),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('PADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(table)
                elements.append(Spacer(1, 0.15 * inch))

        return elements
