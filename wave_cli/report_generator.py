# wave_cli/report_generator.py

from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
)
from reportlab.lib import colors
import datetime


class WavePDFReport:
    """Générateur de rapports PDF"""
    
    def __init__(self, output_path: Path, target: str):
        self.output_path = output_path
        self.target = target
        self.doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch,
            leftMargin=0.75*inch,
            rightMargin=0.75*inch,
        )
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
    def _setup_custom_styles(self):
        """Configure les styles personnalisés."""
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f2937'),
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#374151'),
            spaceAfter=8,
            spaceBefore=8,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='Finding',
            parent=self.styles['Normal'],
            fontSize=10,
            leftIndent=20,
            spaceAfter=4,
            textColor=colors.HexColor('#1f2937'),
            fontName='Helvetica'
        ))
        
        self.styles.add(ParagraphStyle(
            name='Summary',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=6,
            textColor=colors.HexColor('#374151'),
            fontName='Helvetica'
        ))
        
        self.styles.add(ParagraphStyle(
            name='Metadata',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#6b7280'),
            alignment=TA_CENTER,
            fontName='Helvetica'
        ))
    
    def _create_title_page(self, story):
        """Crée la première page (titre)."""
        story.append(Spacer(1, 1.5*inch))
        
        # Titre
        story.append(Paragraph(
            "WAVE scanning Report",
            self.styles['CustomHeading1']
        ))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Sous-titre
        story.append(Paragraph(
            "Website Assessment Vulnerability Engine",
            self.styles['Metadata']
        ))
        
        story.append(Spacer(1, 0.8*inch))
        
        # Cible
        story.append(Paragraph(
            f"<b>Target :</b> {self.target}",
            self.styles['Summary']
        ))
        
        # Date/Heure
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        story.append(Paragraph(
            f"<b>Scan Date :</b> {now}",
            self.styles['Summary']
        ))
        
        story.append(Spacer(1, 1*inch))
        story.append(PageBreak())
    
    def _create_executive_summary(self, story, findings_dict):
        """Crée le résumé exécutif."""
        story.append(Paragraph("Executive Summary", self.styles['CustomHeading2']))
        story.append(Spacer(1, 0.2*inch))
        
        # Compter les découvertes
        total_findings = sum(len(items) for items in findings_dict.values())
        
        # Résumé
        summary_text = f"This scan discovered <b>{total_findings} findings</b> across multiple assessment categories."
        story.append(Paragraph(summary_text, self.styles['Summary']))
        story.append(Spacer(1, 0.3*inch))
        
        # Table de synthèse
        data = [['Category', 'Count']]
        for category, items in findings_dict.items():
            data.append([category, str(len(items))])
        
        table = Table(data, colWidths=[3*inch, 1*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#374151')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f3f4f6')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d1d5db')),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')])
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.4*inch))
        story.append(PageBreak())
    
    def _add_findings_section(self, story, section_title, findings_list, emoji="📋"):
        """Ajoute une section de découvertes."""
        story.append(Paragraph(f"{emoji} {section_title}", self.styles['CustomHeading2']))
        story.append(Spacer(1, 0.15*inch))
        
        if not findings_list:
            story.append(Paragraph("<i>No findings in this category.</i>", self.styles['Summary']))
        else:
            # Créer une liste avec des bullets
            for i, finding in enumerate(findings_list, 1):
                # Limiter à 100 caractères pour éviter débordement
                finding_text = finding[:100] + "..." if len(finding) > 100 else finding
                story.append(Paragraph(
                    f"<b>{i}.</b> {finding_text}",
                    self.styles['Finding']
                ))
        
        story.append(Spacer(1, 0.3*inch))
    
    def generate_report(self, findings_dict):
        """
        Génère le rapport PDF complet.
        
        Args:
            findings_dict: Dict[str, List[str]]
                {
                    'Directories': ['/admin', '/api', ...],
                    'Subdomains': ['mail.example.com', ...],
                    'Internal Links': ['https://example.com/page', ...]
                }
        """
        story = []
        
        # 1. Page de titre
        self._create_title_page(story)
        
        # 2. Résumé exécutif
        self._create_executive_summary(story, findings_dict)
        
        # 3. Sections par catégorie
        emojis = {
            'Directories': '📁',
            'Subdomains': '🔍',
            'Internal Links': '🔗'
        }
        
        for section, findings in findings_dict.items():
            emoji = emojis.get(section, '📋')
            self._add_findings_section(story, section, findings, emoji)
        
        # 4. Page finale
        story.append(PageBreak())
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph(
            "End of Report",
            self.styles['CustomHeading2']
        ))
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph(
            "Generated by WAVE - Website Assessment Vulnerability Engine",
            self.styles['Metadata']
        ))
        
        # Générer le PDF
        self.doc.build(story)
        return str(self.output_path)
