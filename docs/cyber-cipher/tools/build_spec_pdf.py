"""Build a readable consolidated PDF from the Cyber Cipher Markdown baseline."""

from __future__ import annotations

import re
from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT.parents[1] / "output" / "pdf" / "Cyber_Cipher_Design_Baseline_v1.pdf"
DOCS = [
    "01_UPDATED_SRS.md",
    "02_THREAT_MODEL_AND_DATA_FLOWS.md",
    "03_CRYPTOGRAPHIC_PROTOCOL.md",
    "04_CBOR_SCHEMAS_AND_TEST_VECTORS.md",
    "05_DATABASE_AND_API_CONTRACTS.md",
    "06_SERVICE_ARCHITECTURE.md",
    "07_IMPLEMENTATION_ROADMAP.md",
    "08_SECURITY_AND_ACCEPTANCE_TEST_PLAN.md",
]


def clean_text(value: str) -> str:
    replacements = {
        "\u2013": "-",
        "\u2014": "-",
        "\u2011": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2192": "->",
        "\u2194": "<->",
        "\u2265": ">=",
        "\u2264": "<=",
    }
    for old, new in replacements.items():
        value = value.replace(old, new)
    return value


def inline_markup(value: str) -> str:
    value = escape(clean_text(value.strip()))
    value = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"<u>\1</u>", value)
    value = re.sub(r"`([^`]+)`", r'<font name="Courier">\1</font>', value)
    value = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", value)
    return value


styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=24, leading=29, textColor=colors.HexColor("#123B5D"), alignment=TA_CENTER, spaceAfter=16))
styles.add(ParagraphStyle(name="CoverSub", parent=styles["Normal"], fontSize=11, leading=16, textColor=colors.HexColor("#476477"), alignment=TA_CENTER))
styles.add(ParagraphStyle(name="DocH1", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=colors.HexColor("#123B5D"), spaceBefore=8, spaceAfter=10))
styles.add(ParagraphStyle(name="DocH2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=colors.HexColor("#185A7D"), spaceBefore=11, spaceAfter=6, keepWithNext=True))
styles.add(ParagraphStyle(name="DocH3", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=10.5, leading=13, textColor=colors.HexColor("#2A667F"), spaceBefore=8, spaceAfter=4, keepWithNext=True))
styles.add(ParagraphStyle(name="BodyCC", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.7, leading=12, textColor=colors.HexColor("#18242D"), spaceAfter=5))
styles.add(ParagraphStyle(name="BulletCC", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.4, leading=11.5, leftIndent=12, firstLineIndent=-7, bulletIndent=4, spaceAfter=3))
styles.add(ParagraphStyle(name="CodeCC", fontName="Courier", fontSize=6.5, leading=8.2, leftIndent=6, rightIndent=6, borderColor=colors.HexColor("#D4E0E7"), borderWidth=0.5, borderPadding=6, backColor=colors.HexColor("#F4F7F9"), spaceBefore=4, spaceAfter=6))
styles.add(ParagraphStyle(name="TableCell", fontName="Helvetica", fontSize=6.4, leading=8.1, textColor=colors.HexColor("#18242D")))
styles.add(ParagraphStyle(name="TableHead", fontName="Helvetica-Bold", fontSize=6.5, leading=8.2, textColor=colors.white))


def page(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#D7E1E8"))
    canvas.line(18 * mm, 17 * mm, A4[0] - 18 * mm, 17 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#5D7180"))
    canvas.drawString(18 * mm, 11 * mm, "Cyber Cipher - Design Baseline v1.0")
    canvas.drawRightString(A4[0] - 18 * mm, 11 * mm, f"Page {doc.page}")
    canvas.restoreState()


class SpecDoc(BaseDocTemplate):
    def __init__(self, filename: str):
        super().__init__(filename, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=17 * mm, bottomMargin=22 * mm, title="Cyber Cipher Design Baseline v1.0", author="Team Cyber Ciphers")
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="body")
        self.addPageTemplates(PageTemplate(id="all", frames=frame, onPage=page))


def parse_table(lines: list[str], start: int, width: float):
    raw_rows = []
    i = start
    while i < len(lines) and lines[i].strip().startswith("|"):
        cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
        raw_rows.append(cells)
        i += 1
    if len(raw_rows) < 2:
        return None, start
    raw_rows.pop(1)
    cols = max(len(r) for r in raw_rows)
    rows = []
    for ri, row in enumerate(raw_rows):
        row += [""] * (cols - len(row))
        sty = styles["TableHead"] if ri == 0 else styles["TableCell"]
        rows.append([Paragraph(inline_markup(cell), sty) for cell in row])
    weights = []
    for ci in range(cols):
        sample = max((len(re.sub(r"[`*]", "", r[ci])) for r in raw_rows if ci < len(r)), default=1)
        weights.append(min(max(sample, 8), 42))
    total = sum(weights)
    widths = [width * w / total for w in weights]
    table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#185A7D")),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#AFC1CC")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F8FA")]),
    ]))
    return table, i


def markdown_story(path: Path, doc_width: float):
    lines = path.read_text(encoding="utf-8").splitlines()
    story = []
    i = 0
    in_code = False
    code_lang = ""
    code_lines: list[str] = []
    paragraph: list[str] = []

    def flush_paragraph():
        nonlocal paragraph
        if paragraph:
            story.append(Paragraph(inline_markup(" ".join(p.strip() for p in paragraph)), styles["BodyCC"]))
            paragraph = []

    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            flush_paragraph()
            if in_code:
                if code_lang == "mermaid":
                    story.append(Paragraph("Diagram source is preserved in the editable Markdown package.", styles["BodyCC"]))
                else:
                    story.append(Preformatted(clean_text("\n".join(code_lines)), styles["CodeCC"], maxLineLength=105))
                code_lines = []
                in_code = False
                code_lang = ""
            else:
                in_code = True
                code_lang = line[3:].strip().lower()
            i += 1
            continue
        if in_code:
            code_lines.append(line)
            i += 1
            continue
        if line.strip().startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|?\s*:?-+", lines[i + 1]):
            flush_paragraph()
            table, i2 = parse_table(lines, i, doc_width)
            if table:
                story.extend([table, Spacer(1, 6)])
                i = i2
                continue
        if not line.strip():
            flush_paragraph()
            i += 1
            continue
        if line.startswith("# "):
            flush_paragraph()
            story.append(Paragraph(inline_markup(line[2:]), styles["DocH1"]))
        elif line.startswith("## "):
            flush_paragraph()
            story.append(Paragraph(inline_markup(line[3:]), styles["DocH2"]))
        elif line.startswith("### "):
            flush_paragraph()
            story.append(Paragraph(inline_markup(line[4:]), styles["DocH3"]))
        elif re.match(r"^\s*[-*]\s+", line):
            flush_paragraph()
            text = re.sub(r"^\s*[-*]\s+", "", line)
            story.append(Paragraph(inline_markup(text), styles["BulletCC"], bulletText="-"))
        elif re.match(r"^\s*\d+\.\s+", line):
            flush_paragraph()
            match = re.match(r"^\s*(\d+)\.\s+(.*)", line)
            story.append(Paragraph(inline_markup(match.group(2)), styles["BulletCC"], bulletText=match.group(1) + "."))
        else:
            paragraph.append(line)
        i += 1
    flush_paragraph()
    return story


def architecture_drawing(width: float) -> Drawing:
    height = 270
    d = Drawing(width, height)
    navy = colors.HexColor("#123B5D")
    blue = colors.HexColor("#DCECF4")
    green = colors.HexColor("#E3F1E8")
    sand = colors.HexColor("#F5EBD5")
    purple = colors.HexColor("#EAE2F3")

    def zone(x, y, w, h, title, lines, fill):
        d.add(Rect(x, y, w, h, rx=6, ry=6, fillColor=fill, strokeColor=navy, strokeWidth=1))
        d.add(String(x + 7, y + h - 15, title, fontName="Helvetica-Bold", fontSize=8, fillColor=navy))
        for n, text in enumerate(lines):
            d.add(String(x + 7, y + h - 29 - n * 11, text, fontName="Helvetica", fontSize=6.5, fillColor=colors.HexColor("#243943")))

    def arrow(x1, y1, x2, y2, label):
        d.add(Line(x1, y1, x2, y2, strokeColor=navy, strokeWidth=1))
        dx, dy = x2 - x1, y2 - y1
        length = max((dx * dx + dy * dy) ** 0.5, 1)
        ux, uy = dx / length, dy / length
        px, py = -uy, ux
        tip = (x2, y2)
        back = (x2 - ux * 7, y2 - uy * 7)
        d.add(Polygon([tip[0], tip[1], back[0] + px * 3, back[1] + py * 3, back[0] - px * 3, back[1] - py * 3], fillColor=navy, strokeColor=navy))
        d.add(String((x1 + x2) / 2 - 24, (y1 + y2) / 2 + 4, label, fontName="Helvetica", fontSize=5.8, fillColor=navy))

    zone(5, 95, 95, 85, "User device", ["Secrets and recovery bundle", "CBOR, encryption, ZK prover", "Receipt/log verification"], blue)
    zone(145, 175, 130, 80, "Identity zone", ["Enrollment and eligibility", "Blind RSA issuance", "Membership and recovery"], green)
    zone(145, 45, 130, 95, "Complaint zone", ["Privacy ingress", "Proof verifier and intake", "Ciphertext, mailbox, outbox"], sand)
    zone(width - 140, 45, 130, 95, "Handler zone", ["WebAuthn and authorization", "Organization HPKE/KMS", "Safe viewer and redaction"], purple)
    zone(width - 140, 175, 130, 80, "Public audit zone", ["Merkle transparency log", "Three witnesses; 2-of-3", "Community and auditor"], blue)

    arrow(100, 160, 145, 210, "identified only")
    arrow(100, 110, 145, 95, "proof + ciphertext")
    arrow(275, 95, width - 140, 95, "assigned ciphertext")
    arrow(275, 205, width - 140, 205, "public roots")
    arrow(275, 125, width - 140, 185, "commitments/events")
    arrow(width - 75, 140, width - 75, 175, "redacted only")
    return d


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    doc = SpecDoc(str(OUTPUT))
    story = [
        Spacer(1, 50 * mm),
        Paragraph("Cyber Cipher", styles["CoverTitle"]),
        Paragraph("Anonymous Complaint Platform", styles["CoverSub"]),
        Spacer(1, 8 * mm),
        Paragraph("Consolidated Design Baseline v1.0", styles["CoverTitle"]),
        Spacer(1, 8 * mm),
        Paragraph("Updated SRS, threat and privacy model, cryptographic protocol, canonical schemas and vectors, data/API contracts, architecture, roadmap, and security acceptance plan", styles["CoverSub"]),
        Spacer(1, 30 * mm),
        Paragraph("Team Cyber Ciphers | 25 September 2026", styles["CoverSub"]),
        PageBreak(),
        Paragraph("Document set", styles["DocH1"]),
    ]
    for idx, name in enumerate(DOCS, 1):
        title = (ROOT / name).read_text(encoding="utf-8").splitlines()[0].lstrip("# ")
        story.append(Paragraph(f"{idx}. {inline_markup(title)}", styles["BodyCC"]))
    story.append(PageBreak())
    for idx, name in enumerate(DOCS):
        if idx:
            story.append(PageBreak())
        section = markdown_story(ROOT / name, doc.width)
        if name == "06_SERVICE_ARCHITECTURE.md":
            section.insert(1, Spacer(1, 4))
            section.insert(2, architecture_drawing(doc.width))
            section.insert(3, Spacer(1, 8))
        story.extend(section)
    doc.build(story)
    print(OUTPUT)


if __name__ == "__main__":
    main()
