"""Layer 1: PDF Structural Analysis.

Inspects text spans, fonts, bounding boxes, opaque/whiteout vector rectangles,
embedded image objects, annotations, form widgets, cross-reference revision structure,
injected third-party fonts, editor placeholder residue, and exact text modifications.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import difflib
import io
import logging
from pathlib import Path
import re
from typing import Any

try:
    import pymupdf as fitz
except ImportError:
    try:
        import fitz
    except ImportError:
        fitz = None

import pikepdf

from app.schemas.analysis import ForensicFinding
from app.services.pdf_analysis.pdf_loader import LoadedPdf
from app.services.pdf_analysis.revision_forensics import analyze_revision_structure
from app.services.pdf_analysis.structural_forensics import analyze_structural_forensics

logger = logging.getLogger("pdf_analyser.structural_analysis")

EDITOR_PLACEHOLDER_REGEX = re.compile(
    r"^(type\s+your\s+text|insert\s+text(\s+here)?|click\s+(here\s+)?to\s+(add|edit|type)\s+text|"
    r"add\s+text(\s+here)?|enter\s+text(\s+here)?|your\s+text\s+here|sample\s+text|"
    r"double\s+click\s+to\s+edit|text\s+box|placeholder(\s+text)?|lorem\s+ipsum)",
    re.IGNORECASE,
)

GENERIC_FALLBACK_FONTS = frozenset({
    "liberationsans", "arial", "helvetica", "calibri",
})


@dataclass
class TextSpanRecord:
    page: int
    text: str
    bbox: list[float]
    font_name: str
    font_size: float
    color_rgb: tuple[int, int, int]
    flags: int
    opacity: float = 1.0
    char_spacing: float = 0.0
    render_mode: int = 0
    line_bbox: list[float] | None = None
    block_idx: int = 0
    line_idx: int = 0
    is_in_table: bool = False
    is_highlighted: bool = False


@dataclass
class ImageRecord:
    page: int
    xref: int
    width: int
    height: int
    bbox: list[float] | None
    colorspace: str


@dataclass
class AnnotationRecord:
    page: int
    type_name: str
    rect: list[float]
    flags: int
    field_name: str | None = None
    is_highlight: bool = False


@dataclass
class WhiteoutPatchRecord:
    page: int
    rect: list[float]
    fill_color: tuple[float, ...]
    has_overlying_text: bool
    overlying_text: str = ""


@dataclass
class StructuralLayerResult:
    """Consolidated outcome of Layer 1 Structural Analysis."""

    status: str  # completed | partial | failed | skipped
    summary: str
    findings: list[ForensicFinding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    text_spans: list[TextSpanRecord] = field(default_factory=list)
    images: list[ImageRecord] = field(default_factory=list)
    annotations: list[AnnotationRecord] = field(default_factory=list)
    whiteout_patches: list[WhiteoutPatchRecord] = field(default_factory=list)
    revision_count: int = 1
    has_recoverable_revisions: bool = False

    # Granular text tampering & object overlay counters
    formatting_anomalies_count: int = 0
    text_overlaps_count: int = 0
    covering_objects_count: int = 0
    text_replacements_count: int = 0
    text_insertions_count: int = 0
    revision_history_available: bool = False
    historical_comparison_status: str = "unavailable"


def _rects_intersect(r1: list[float], r2: list[float]) -> bool:
    """Check if two bounding boxes [x0, y0, x1, y1] intersect meaningfully."""
    return not (r1[2] <= r2[0] or r1[0] >= r2[2] or r1[3] <= r2[1] or r1[1] >= r2[3])


def _boxes_overlap(b1: list[float], b2: list[float], min_overlap_ratio: float = 0.15) -> bool:
    """Check if two bounding boxes [x0, y0, x1, y1] overlap meaningfully."""
    ix0 = max(b1[0], b2[0])
    iy0 = max(b1[1], b2[1])
    ix1 = min(b1[2], b2[2])
    iy1 = min(b1[3], b2[3])
    if ix1 <= ix0 or iy1 <= iy0:
        return False
    inter_area = (ix1 - ix0) * (iy1 - iy0)
    area1 = max(1.0, (b1[2] - b1[0]) * (b1[3] - b1[1]))
    area2 = max(1.0, (b2[2] - b2[0]) * (b2[3] - b2[1]))
    min_area = min(area1, area2)
    return (inter_area / min_area) >= min_overlap_ratio


def _rect_contains(outer: list[float], inner: list[float], margin: float = 2.0) -> bool:
    """Check if inner rect is mostly or entirely contained within outer rect."""
    return (
        inner[0] >= outer[0] - margin
        and inner[1] >= outer[1] - margin
        and inner[2] <= outer[2] + margin
        and inner[3] <= outer[3] + margin
    )


def _normalize_font_family(font_name: str) -> str:
    """Extract standard base font family name from subset or internal font tag."""
    cleaned = font_name.split("+")[-1].split("-")[0].split("_")[0].lower()
    for fam in ("montserrat", "lato", "helvetica", "liberationsans", "arial", "times", "courier", "calibri", "verdana", "georgia", "roboto", "opensans"):
        if fam in cleaned:
            return fam
    return cleaned


def _is_subheading_or_label(sp: TextSpanRecord) -> bool:
    """Check if a text span is a section subheading, label, or header rather than tabular data."""
    txt = sp.text.strip()
    if not txt:
        return False
    # Ends with colon, e.g. "New capital:", "Sales:", "NAB:", "New owners:"
    if txt.endswith(":"):
        return True
    # Explicit bold flag (PyMuPDF bit 4 = 16) or bold in font name
    is_bold = bool(sp.flags & 16) or any(w in sp.font_name.lower() for w in ("bold", "700", "800", "900", "black", "semibold"))
    # Short bold phrase (like a section header)
    if is_bold and len(txt.split()) <= 5:
        return True
    # Larger heading font size
    if sp.font_size >= 13.5:
        return True
    return False


def analyze_structural_layer(
    loaded_pdf: LoadedPdf,
    original_source: bytes | Path | None = None,
) -> StructuralLayerResult:
    """Execute complete Layer 1 structural analysis on the provided PDF."""
    if not loaded_pdf.is_valid:
        return StructuralLayerResult(
            status="failed",
            summary=f"Structural analysis skipped: {loaded_pdf.error_message or 'PDF parsing error'}",
            limitations=["Document could not be parsed as a valid PDF."],
        )

    findings: list[ForensicFinding] = []
    limitations: list[str] = [
        "Structural analysis inspects text spans, vector paths, fonts, and object graphs without a reference copy.",
        "Non-standard PDF generators or CAD export tools may produce unusual object placement without malicious intent.",
    ]
    all_spans: list[TextSpanRecord] = []
    all_images: list[ImageRecord] = []
    all_annots: list[AnnotationRecord] = []
    all_whiteout_patches: list[WhiteoutPatchRecord] = []

    # 1. Revision History & Cross-Reference Analysis (Existing module integration)
    rev_count = 1
    has_revs = False
    try:
        rev_outcome = analyze_revision_structure(loaded_pdf)
        findings.extend(rev_outcome.findings)
        limitations.extend([l for l in rev_outcome.limitations if l not in limitations])
        rev_count = rev_outcome.revision_count
        has_revs = rev_outcome.has_revisions
    except Exception as rev_err:
        logger.warning("Revision structure analysis error: %s", rev_err)
        limitations.append(f"Revision history inspection error: {rev_err}")

    # 2. Content Stream Operators & Orphan Objects (Existing module integration)
    try:
        stream_outcome = analyze_structural_forensics(loaded_pdf)
        findings.extend(stream_outcome.findings)
        limitations.extend([l for l in stream_outcome.limitations if l not in limitations])
    except Exception as stream_err:
        logger.warning("Stream forensics error: %s", stream_err)
        limitations.append(f"Content-stream operator audit error: {stream_err}")

    # 3. PyMuPDF Deep Page-Level Inspection: Text Spans, Drawings, Images, Annotations
    if fitz is None:
        logger.warning("PyMuPDF (fitz) is not installed in the runtime environment; skipping page-level span audit.")
        limitations.append("PyMuPDF is not installed in the runtime environment; page-level text span and vector drawing inspection was skipped.")
        return StructuralLayerResult(
            status="partial",
            summary="Structural analysis partially completed; PyMuPDF is not installed in this environment.",
            findings=findings,
            limitations=limitations,
            revision_count=rev_count,
            has_recoverable_revisions=has_revs,
        )

    try:
        doc = fitz.open(stream=loaded_pdf.file_bytes, filetype="pdf")
    except Exception as doc_err:
        logger.error("PyMuPDF failed to open document: %s", doc_err)
        return StructuralLayerResult(
            status="partial",
            summary="Structural analysis partially completed; PyMuPDF page inspection failed.",
            findings=findings,
            limitations=limitations,
        )

    try:
        # Pre-pass: Document-wide font family distribution to determine the genuine primary palette
        doc_font_fam_counts: dict[str, int] = {}
        heading_font_families: set[str] = set()
        for p_idx in range(len(doc)):
            try:
                p_dict = doc[p_idx].get_text("dict")
                for b in p_dict.get("blocks", []):
                    if b.get("type") == 0:
                        for l in b.get("lines", []):
                            for s in l.get("spans", []):
                                t = s.get("text", "").strip()
                                if t:
                                    fam = _normalize_font_family(s.get("font", ""))
                                    doc_font_fam_counts[fam] = doc_font_fam_counts.get(fam, 0) + len(t.split())
                                    if s.get("size", 10.0) >= 13.5:
                                        heading_font_families.add(fam)
            except Exception:
                pass

        total_doc_words = sum(doc_font_fam_counts.values())
        primary_font_families: set[str] = set()
        if total_doc_words > 0:
            primary_font_families = {
                f for f, cnt in doc_font_fam_counts.items()
                if (cnt / total_doc_words) >= 0.15
            }
        primary_font_families.update(heading_font_families)

        # Page-level inspection loop with failure isolation per page
        for page_idx in range(len(doc)):
            page_num = page_idx + 1
            try:
                page = doc[page_idx]

                # 1. Annotations & Highlight Extraction
                page_annots: list[AnnotationRecord] = []
                highlight_rects: list[list[float]] = []
                for annot in page.annots():
                    rect = annot.rect
                    info = annot.info
                    t_name = str(annot.type[1]) if isinstance(annot.type, (list, tuple)) else str(annot.type)
                    annot_rect = [float(round(c, 2)) for c in [rect.x0, rect.y0, rect.x1, rect.y1]]
                    is_hl = (t_name.lower() == "highlight") or (getattr(annot, "type", None) == 8)
                    if is_hl:
                        highlight_rects.append(annot_rect)

                    rec_annot = AnnotationRecord(
                        page=page_num,
                        type_name=t_name,
                        rect=annot_rect,
                        flags=annot.flags,
                        field_name=info.get("title") or info.get("content"),
                        is_highlight=is_hl,
                    )
                    page_annots.append(rec_annot)
                    all_annots.append(rec_annot)

                for widget in page.widgets():
                    rect = widget.rect
                    widget_rect = [float(round(c, 2)) for c in [rect.x0, rect.y0, rect.x1, rect.y1]]
                    all_annots.append(
                        AnnotationRecord(
                            page=page_num,
                            type_name="Widget",
                            rect=widget_rect,
                            flags=0,
                            field_name=widget.field_name,
                        )
                    )

                # 2. Extract Vector Drawings & Detect Containers / Table Outlines
                drawings = page.get_drawings()
                table_or_framed_rects: list[list[float]] = []
                page_whiteouts: list[WhiteoutPatchRecord] = []
                opaque_shapes: list[dict[str, Any]] = []

                for draw in drawings:
                    r = draw.get("rect")
                    if r and (r.width > 20 or r.height > 20):
                        table_or_framed_rects.append([r.x0, r.y0, r.x1, r.y1])

                    fill = draw.get("fill")
                    if fill is not None and r:
                        is_white = False
                        if len(fill) >= 3 and fill[0] >= 0.95 and fill[1] >= 0.95 and fill[2] >= 0.95:
                            is_white = True
                        elif len(fill) == 1 and fill[0] >= 0.95:
                            is_white = True

                        rect_coords = [float(round(c, 2)) for c in [r.x0, r.y0, r.x1, r.y1]]
                        opaque_shapes.append({
                            "rect": rect_coords,
                            "fill": fill,
                            "is_white": is_white,
                            "width": r.width,
                            "height": r.height,
                        })

                # 3. Extract Text Spans with Rich Metadata
                page_spans: list[TextSpanRecord] = []
                page_dict = page.get_text("dict")
                for b_idx, block in enumerate(page_dict.get("blocks", [])):
                    if block.get("type") == 0:  # Text block
                        for l_idx, line in enumerate(block.get("lines", [])):
                            l_bbox = [float(round(c, 2)) for c in line.get("bbox", [0, 0, 0, 0])]
                            for span in line.get("spans", []):
                                txt = span.get("text", "").strip()
                                if not txt:
                                    continue
                                raw_color = span.get("color", 0)
                                color_rgb = (
                                    (raw_color >> 16) & 255,
                                    (raw_color >> 8) & 255,
                                    raw_color & 255,
                                )
                                s_bbox = [float(round(c, 2)) for c in span.get("bbox", [0, 0, 0, 0])]
                                is_hl = any(_boxes_overlap(s_bbox, hr, min_overlap_ratio=0.20) for hr in highlight_rects)
                                is_tbl = any(
                                    abs(s_bbox[0] - tr[0]) < 6 or abs(s_bbox[1] - tr[1]) < 6 or abs(s_bbox[2] - tr[2]) < 6 or abs(s_bbox[3] - tr[3]) < 6
                                    for tr in table_or_framed_rects
                                )

                                rec = TextSpanRecord(
                                    page=page_num,
                                    text=txt,
                                    bbox=s_bbox,
                                    font_name=span.get("font", "unknown"),
                                    font_size=float(round(span.get("size", 10.0), 2)),
                                    color_rgb=color_rgb,
                                    flags=span.get("flags", 0),
                                    line_bbox=l_bbox,
                                    block_idx=b_idx,
                                    line_idx=l_idx,
                                    is_in_table=is_tbl,
                                    is_highlighted=is_hl,
                                )
                                page_spans.append(rec)
                                all_spans.append(rec)

                white_spans = [
                    sp for sp in page_spans
                    if (sp.color_rgb[0] >= 235 and sp.color_rgb[1] >= 235 and sp.color_rgb[2] >= 235)
                ]
                visible_spans = [
                    sp for sp in page_spans
                    if not (sp.color_rgb[0] >= 235 and sp.color_rgb[1] >= 235 and sp.color_rgb[2] >= 235)
                ]

                # 4. Check A: Text Replacement & Whiteout Covering
                for shape in opaque_shapes:
                    if not shape["is_white"]:
                        continue
                    w = shape["width"]
                    h = shape["height"]
                    r_coords = shape["rect"]

                    # Exclude canvas background, whole page containers, microscopic dots
                    if w >= 0.88 * page.rect.width and h >= 0.75 * page.rect.height:
                        continue
                    if h > 60 and (w > 280 or h > 120):
                        continue
                    if w < 12 or h < 6:
                        continue

                    overlying = [
                        sp for sp in visible_spans
                        if _rect_contains(r_coords, sp.bbox, margin=4.0) or _boxes_overlap(r_coords, sp.bbox, min_overlap_ratio=0.15)
                    ]

                    # Filter out table row bands spanning entire width
                    if w > 360 and len(overlying) >= 4:
                        overlying = []

                    has_over = bool(overlying)
                    sample_texts = [sp.text for sp in overlying[:3]]
                    patch_rec = WhiteoutPatchRecord(
                        page=page_num,
                        rect=r_coords,
                        fill_color=tuple(float(round(c, 2)) for c in shape["fill"]),
                        has_overlying_text=has_over,
                        overlying_text=" ".join(sample_texts),
                    )
                    page_whiteouts.append(patch_rec)
                    all_whiteout_patches.append(patch_rec)

                    if has_over:
                        findings.append(
                            ForensicFinding(
                                code="STRUCT_WHITEOUT_RECTANGLE_OVERLAY",
                                category="possible_text_replacement",
                                domain="content_stream",
                                severity="medium",
                                confidence=0.75,
                                anomaly_confidence=0.90,
                                tampering_confidence=0.70,
                                description=(
                                    f"Page {page_num} contains an opaque whiteout vector rectangle at {r_coords} "
                                    f"directly covered by replacement text ('{', '.join(sample_texts[:2])}'). "
                                    "This pattern is characteristic of online PDF editors used to redact or alter figures."
                                ),
                                evidence={
                                    "page": page_num,
                                    "rect": r_coords,
                                    "overlaid_text": sample_texts,
                                    "sample_overlaid_text": ", ".join(sample_texts)[:200],
                                },
                                alternative_explanations=[
                                    "Legitimate form field or intentional white card container in document design.",
                                    "Authorized redaction with new replacement figure.",
                                ],
                                recommended_action="Inspect the highlighted region to verify whether original figures were altered.",
                            )
                        )

                # 5. Check B: White Text Masking Layer
                white_text_overlays: list[tuple[TextSpanRecord, TextSpanRecord]] = []
                for wsp in white_spans:
                    for vsp in visible_spans:
                        if _boxes_overlap(wsp.bbox, vsp.bbox, min_overlap_ratio=0.12):
                            white_text_overlays.append((wsp, vsp))

                if white_text_overlays:
                    sample_w, sample_v = white_text_overlays[0]
                    findings.append(
                        ForensicFinding(
                            code="STRUCT_WHITE_TEXT_LAYER_OVERLAY",
                            category="possible_text_replacement",
                            domain="content_stream",
                            severity="high",
                            confidence=0.85,
                            anomaly_confidence=0.95,
                            tampering_confidence=0.85,
                            description=(
                                f"Page {page_num} contains a white text masking layer ('{sample_w.text}') directly colliding with "
                                f"visible text ('{sample_v.text}'). This technique is employed in document forgery to visually wipe out "
                                "original headings or numbers while superimposing altered text without rasterization."
                            ),
                            evidence={
                                "page": page_num,
                                "white_layer_text": sample_w.text,
                                "visible_text": sample_v.text,
                                "white_layer_bbox": sample_w.bbox,
                                "visible_bbox": sample_v.bbox,
                                "overlay_count": len(white_text_overlays),
                            },
                            alternative_explanations=[
                                "Reverse-contrast typography (white text on dark vector background).",
                            ],
                            recommended_action="Verify surrounding background color and check if original text was hidden.",
                        )
                    )
                elif white_spans:
                    sample_w = white_spans[0]
                    findings.append(
                        ForensicFinding(
                            code="STRUCT_INVISIBLE_WHITE_TEXT",
                            category="suspicious",
                            domain="content_stream",
                            severity="medium",
                            confidence=0.55,
                            anomaly_confidence=0.85,
                            tampering_confidence=0.45,
                            description=(
                                f"Page {page_num} contains {len(white_spans)} invisible white text span(s) ('{sample_w.text}'). "
                                "White text on white background is invisible to readers and may indicate hidden redaction remnants or search-indexing padding."
                            ),
                            evidence={
                                "page": page_num,
                                "sample_text": sample_w.text,
                                "bbox": sample_w.bbox,
                                "white_span_count": len(white_spans),
                            },
                            alternative_explanations=[
                                "Search indexing, accessibility padding, or dark background styling.",
                            ],
                            recommended_action="Inspect whether the text is visible to readers or hidden in the background.",
                        )
                    )

                # 6. Check C: Opaque Covering Objects & Non-White Intersections
                for shape in opaque_shapes:
                    if shape["is_white"]:
                        continue  # Handled above
                    r_coords = shape["rect"]
                    # Exclude full page banners or giant cards
                    if shape["width"] >= 0.88 * page.rect.width and shape["height"] >= 0.75 * page.rect.height:
                        continue
                    if shape["width"] < 12 or shape["height"] < 6:
                        continue

                    # Check if this opaque shape intersects text
                    intersecting = [
                        sp for sp in page_spans
                        if not sp.is_highlighted and _boxes_overlap(r_coords, sp.bbox, min_overlap_ratio=0.30)
                    ]
                    if 1 <= len(intersecting) <= 3 and shape["width"] <= 250 and shape["height"] <= 45:
                        findings.append(
                            ForensicFinding(
                                code="STRUCT_POSSIBLE_COVERING_OBJECT",
                                category="possible_covering_object",
                                domain="content_stream",
                                severity="medium",
                                confidence=0.60,
                                anomaly_confidence=0.85,
                                tampering_confidence=0.50,
                                description=(
                                    f"Page {page_num} contains an opaque graphical object at {r_coords} "
                                    f"intersecting text ('{', '.join(s.text for s in intersecting)}'). "
                                    "This pattern can indicate a redaction patch or obscured content."
                                ),
                                evidence={
                                    "page": page_num,
                                    "rect": r_coords,
                                    "intersecting_text": [s.text for s in intersecting],
                                },
                                alternative_explanations=[
                                    "Designed callout badge, colored button, or intentional banner background.",
                                ],
                                recommended_action="Inspect whether text inside the object is legibly styled or obscured.",
                            )
                        )

                # 7. Check D: Editor Placeholder Residue Text (e.g. "Type your text", "Insert text")
                for sp in visible_spans:
                    if EDITOR_PLACEHOLDER_REGEX.match(sp.text):
                        findings.append(
                            ForensicFinding(
                                code="STRUCT_EDITOR_PLACEHOLDER_TEXT",
                                category="possible_text_insertion",
                                domain="content_stream",
                                severity="high",
                                confidence=0.85,
                                anomaly_confidence=0.95,
                                tampering_confidence=0.85,
                                description=(
                                    f"Page {page_num} contains PDF editor placeholder residue text '{sp.text}' at {sp.bbox}. "
                                    "This string is a default placeholder created by PDF editing tools when a user adds a text box."
                                ),
                                evidence={
                                    "page": page_num,
                                    "text": sp.text,
                                    "font": sp.font_name,
                                    "bbox": sp.bbox,
                                },
                                alternative_explanations=[
                                    "Sample form or instructional template containing placeholder instructions.",
                                ],
                                recommended_action="Verify if an unauthorized text box was inserted into the document.",
                            )
                        )

                # 8. Check E: Foreign / Injected Font Text Detection
                if primary_font_families:
                    foreign_spans: list[TextSpanRecord] = []
                    for sp in visible_spans:
                        if _is_subheading_or_label(sp) or sp.font_size >= 13.5:
                            continue
                        fam = _normalize_font_family(sp.font_name)
                        if fam not in primary_font_families and fam in GENERIC_FALLBACK_FONTS:
                            foreign_spans.append(sp)

                    if foreign_spans:
                        # Group foreign spans by line (within 4 pt vertically)
                        line_groups: list[list[TextSpanRecord]] = []
                        for fsp in sorted(foreign_spans, key=lambda s: (s.bbox[1], s.bbox[0])):
                            if line_groups and abs(fsp.bbox[1] - line_groups[-1][0].bbox[1]) <= 4.0:
                                line_groups[-1].append(fsp)
                            else:
                                line_groups.append([fsp])

                        for l_grp in line_groups:
                            l_grp.sort(key=lambda s: s.bbox[0])
                            l_text = " ".join(s.text for s in l_grp)
                            l_bbox = [
                                round(min(s.bbox[0] for s in l_grp), 2),
                                round(min(s.bbox[1] for s in l_grp), 2),
                                round(max(s.bbox[2] for s in l_grp), 2),
                                round(max(s.bbox[3] for s in l_grp), 2),
                            ]
                            sample_font = l_grp[0].font_name
                            findings.append(
                                ForensicFinding(
                                    code="STRUCT_FOREIGN_FONT_TEXT_INSERTION",
                                    category="possible_text_insertion",
                                    domain="content_stream",
                                    severity="medium",
                                    confidence=0.75,
                                    anomaly_confidence=0.90,
                                    tampering_confidence=0.70,
                                    description=(
                                        f"Page {page_num} contains text '{l_text[:80]}' using injected font "
                                        f"'{sample_font}' at {l_bbox}, which does not match the document's established "
                                        f"font palette ({', '.join(sorted(primary_font_families))}). "
                                        "This pattern indicates text added or edited with a third-party PDF editor."
                                    ),
                                    evidence={
                                        "page": page_num,
                                        "text": l_text,
                                        "font": sample_font,
                                        "bbox": l_bbox,
                                        "primary_fonts": list(primary_font_families),
                                    },
                                    alternative_explanations=[
                                        "Intentional font styling or mixed-font template design.",
                                    ],
                                    recommended_action="Inspect the highlighted text to verify whether it represents unauthorized replacement or inserted text.",
                                )
                            )

                # 9. Check F: Appended Secondary Content Streams with Text
                try:
                    c_xrefs = page.get_contents()
                    if isinstance(c_xrefs, (list, tuple)) and len(c_xrefs) > 1:
                        appended_text_streams = []
                        for idx in range(1, len(c_xrefs)):
                            s_bytes = doc.xref_stream(c_xrefs[idx])
                            if (b"Tj" in s_bytes) or (b"TJ" in s_bytes) or (b"'" in s_bytes) or (b'"' in s_bytes):
                                appended_text_streams.append(idx + 1)
                        if appended_text_streams and not any(
                            f.code == "STREAM_APPENDED_CONTENT_STREAM_TEXT" and f.evidence.get("page") == page_num
                            for f in findings
                        ):
                            findings.append(
                                ForensicFinding(
                                    code="STREAM_APPENDED_CONTENT_STREAM_TEXT",
                                    category="possible_text_insertion",
                                    domain="content_stream",
                                    severity="medium",
                                    confidence=0.70,
                                    anomaly_confidence=0.85,
                                    tampering_confidence=0.65,
                                    description=(
                                        f"Page {page_num} renders text from appended secondary content stream(s) "
                                        f"(stream(s) {', '.join(str(i) for i in appended_text_streams)} of {len(c_xrefs)}). "
                                        "This layered architecture commonly results when an editor overlays new text on an existing PDF."
                                    ),
                                    evidence={
                                        "page": page_num,
                                        "stream_count": len(c_xrefs),
                                        "appended_text_streams": appended_text_streams,
                                    },
                                    alternative_explanations=[
                                        "Document management system watermark or automated stamp layer.",
                                    ],
                                    recommended_action="Review text on this page to identify overlayed content.",
                                )
                            )
                except Exception as stream_check_err:
                    logger.debug("Page stream check note: %s", stream_check_err)

                # 10. Check G: Context-Aware Formatting Consistency (excluding legitimate subheadings)
                if len(visible_spans) >= 5:
                    col_groups: dict[int, list[TextSpanRecord]] = {}
                    for sp in visible_spans:
                        if sp.font_size >= 14.0 or sp.is_highlighted or _is_subheading_or_label(sp):
                            continue
                        col_key = int(sp.bbox[0] / 15.0) * 15
                        col_groups.setdefault(col_key, []).append(sp)

                    for col_key, group in col_groups.items():
                        if len(group) >= 4:
                            font_hist: dict[str, int] = {}
                            for s in group:
                                font_hist[s.font_name] = font_hist.get(s.font_name, 0) + 1
                            dom_font = max(font_hist, key=font_hist.get)
                            if font_hist[dom_font] >= len(group) - 1 and len(font_hist) > 1:
                                outliers = [
                                    s for s in group
                                    if s.font_name != dom_font
                                    and not s.is_highlighted
                                    and not (s.flags & 2)
                                    and not _is_subheading_or_label(s)
                                ]
                                if outliers:
                                    out_sp = outliers[0]
                                    findings.append(
                                        ForensicFinding(
                                            code="STRUCT_FORMATTING_ANOMALY",
                                            category="formatting_anomaly",
                                            domain="layout_analysis",
                                            severity="low",
                                            confidence=0.40,
                                            anomaly_confidence=0.85,
                                            tampering_confidence=0.35,
                                            description=(
                                                f"Page {page_num} contains an isolated value '{out_sp.text}' using font "
                                                f"'{out_sp.font_name}' in a column where all other items use '{dom_font}'. "
                                                "Isolated font differences in tabular columns can indicate pasted or edited values."
                                            ),
                                            evidence={
                                                "page": page_num,
                                                "text": out_sp.text,
                                                "font": out_sp.font_name,
                                                "expected_font": dom_font,
                                                "bbox": out_sp.bbox,
                                            },
                                            alternative_explanations=[
                                                "Intentional emphasis, font substitution, or template design variation.",
                                            ],
                                            recommended_action="Verify if the figure matches the surrounding data context.",
                                        )
                                    )

                    # General page dominant font check for body paragraphs
                    font_counts: dict[str, int] = {}
                    for sp in visible_spans:
                        font_counts[sp.font_name] = font_counts.get(sp.font_name, 0) + len(sp.text.split())

                    total_words = sum(font_counts.values())
                    if total_words > 10:
                        dominant_font = max(font_counts, key=font_counts.get)
                        dominant_share = font_counts[dominant_font] / total_words
                        if dominant_share >= 0.70:
                            isolated_spans = [
                                sp for sp in visible_spans
                                if sp.font_name != dominant_font
                                and len(sp.text.split()) <= 6
                                and font_counts.get(sp.font_name, 0) <= 6
                                and not sp.is_highlighted
                                and not _is_subheading_or_label(sp)
                                and not any(f.evidence.get("text") == sp.text for f in findings if f.code in ("STRUCT_FORMATTING_ANOMALY", "STRUCT_FOREIGN_FONT_TEXT_INSERTION", "STRUCT_EDITOR_PLACEHOLDER_TEXT"))
                            ]
                            if isolated_spans:
                                sample = isolated_spans[0]
                                findings.append(
                                    ForensicFinding(
                                        code="STRUCT_INCONSISTENT_FONT_SWITCH",
                                        category="formatting_anomaly",
                                        domain="layout_analysis",
                                        severity="low",
                                        confidence=0.35,
                                        anomaly_confidence=0.80,
                                        tampering_confidence=0.30,
                                        description=(
                                            f"Page {page_num} has an isolated text segment '{sample.text}' using font "
                                            f"'{sample.font_name}' in a page where {int(dominant_share * 100)}% of body text uses '{dominant_font}'."
                                        ),
                                        evidence={
                                            "page": page_num,
                                            "isolated_text": sample.text,
                                            "isolated_font": sample.font_name,
                                            "dominant_font": dominant_font,
                                            "bbox": sample.bbox,
                                        },
                                        alternative_explanations=[
                                            "Intentional stylistic emphasis, footer/header markup, or brand naming.",
                                        ],
                                        recommended_action="Inspect the text in document context.",
                                    )
                                )

                # 11. Check H: Text-to-Text Overlaps
                overlaps_found = 0
                for i in range(len(page_spans)):
                    for j in range(i + 1, len(page_spans)):
                        s1 = page_spans[i]
                        s2 = page_spans[j]
                        if s1.text != s2.text and _boxes_overlap(s1.bbox, s2.bbox, min_overlap_ratio=0.30):
                            ix0 = max(s1.bbox[0], s2.bbox[0])
                            iy0 = max(s1.bbox[1], s2.bbox[1])
                            ix1 = min(s1.bbox[2], s2.bbox[2])
                            iy1 = min(s1.bbox[3], s2.bbox[3])
                            area_overlap = max(0.0, ix1 - ix0) * max(0.0, iy1 - iy0)
                            area_s1 = max(1.0, (s1.bbox[2] - s1.bbox[0]) * (s1.bbox[3] - s1.bbox[1]))
                            if (area_overlap / area_s1) > 0.40:
                                overlaps_found += 1
                                if overlaps_found == 1:
                                    findings.append(
                                        ForensicFinding(
                                            code="STRUCT_TEXT_OVERLAP",
                                            category="text_overlap",
                                            domain="layout_analysis",
                                            severity="medium",
                                            confidence=0.60,
                                            anomaly_confidence=0.90,
                                            tampering_confidence=0.55,
                                            description=(
                                                f"Page {page_num} contains conflicting overlapping text strings: "
                                                f"'{s1.text}' overlaps with '{s2.text}'."
                                            ),
                                            evidence={
                                                "page": page_num,
                                                "string1": s1.text,
                                                "string2": s2.text,
                                                "bbox1": s1.bbox,
                                                "bbox2": s2.bbox,
                                            },
                                            alternative_explanations=[
                                                "Complex vector graphics, watermarks, or typography kerning effects.",
                                            ],
                                            recommended_action="Inspect whether the text collision was caused by superimposed edits.",
                                        )
                                    )

                # 12. Check I: Embedded Images Inspection & Text-over-Image
                page_images = page.get_images(full=True)
                for img_info in page_images:
                    xref = img_info[0]
                    w = img_info[2]
                    h = img_info[3]
                    cs = str(img_info[5])
                    img_rects = page.get_image_rects(xref)
                    img_bbox = None
                    if img_rects:
                        r = img_rects[0]
                        img_bbox = [float(round(c, 2)) for c in [r.x0, r.y0, r.x1, r.y1]]

                    img_rec = ImageRecord(
                        page=page_num,
                        xref=xref,
                        width=w,
                        height=h,
                        bbox=img_bbox,
                        colorspace=cs,
                    )
                    all_images.append(img_rec)

                    if img_bbox and (img_bbox[2] - img_bbox[0] > 150) and (img_bbox[3] - img_bbox[1] > 150):
                        overlying_text_words: list[str] = []
                        for sp in page_spans:
                            if not sp.is_highlighted and _rect_contains(img_bbox, sp.bbox, margin=0.0):
                                overlying_text_words.extend(sp.text.split())

                        if 1 <= len(overlying_text_words) <= 8:
                            findings.append(
                                ForensicFinding(
                                    code="STRUCT_TEXT_OVER_IMAGE",
                                    category="possible_text_insertion",
                                    domain="layout_analysis",
                                    severity="medium",
                                    confidence=0.50,
                                    anomaly_confidence=0.85,
                                    tampering_confidence=0.50,
                                    description=(
                                        f"Page {page_num} contains sparse digital text ({len(overlying_text_words)} words: "
                                        f"'{' '.join(overlying_text_words)}') directly overlying an embedded bitmap image. "
                                        "This pattern occurs when numerical figures or names are typed over scanned receipts or letters."
                                    ),
                                    evidence={
                                        "page": page_num,
                                        "overlaid_text": " ".join(overlying_text_words),
                                        "image_bbox": img_bbox,
                                    },
                                    alternative_explanations=[
                                        "OCR text layer placed over a scanned document page.",
                                    ],
                                    recommended_action="Verify whether the text matches an OCR layer or was typed manually.",
                                )
                            )

                # 13. Check J: Annotation and Form Field Overlays
                for annot_rec in page_annots:
                    t_name = annot_rec.type_name
                    annot_rect = annot_rec.rect
                    if t_name in ("FreeText", "Square", "Redact", "Stamp") and not annot_rec.is_highlight:
                        covered_texts = [sp.text for sp in page_spans if _boxes_overlap(annot_rect, sp.bbox, min_overlap_ratio=0.20)]
                        if covered_texts:
                            findings.append(
                                ForensicFinding(
                                    code="STRUCT_ANNOTATION_OVERLAY",
                                    category="possible_covering_object",
                                    domain="content_stream",
                                    severity="medium",
                                    confidence=0.70,
                                    anomaly_confidence=0.90,
                                    tampering_confidence=0.65,
                                    description=(
                                        f"Page {page_num} contains a {t_name} annotation placed over underlying text "
                                        f"('{', '.join(covered_texts[:3])}'). Annotations covering body text often represent unauthorized edits."
                                    ),
                                    evidence={"page": page_num, "annotation_type": t_name, "rect": annot_rect, "covered_text": covered_texts},
                                    alternative_explanations=[
                                        "Legitimate reviewer comment, callout note, or authorized redaction mark.",
                                    ],
                                    recommended_action="Check the annotation author and review underlying covered content.",
                                )
                            )

            except Exception as page_err:
                logger.warning("Error during structural inspection of page %d: %s", page_num, page_err, exc_info=True)
                limitations.append(f"Page {page_num} structural inspection error: {page_err}")

        # 14. Exact Structural Comparison when Reference Original is Provided
        if original_source is not None:
            try:
                orig_bytes = original_source.read_bytes() if isinstance(original_source, Path) else original_source
                if orig_bytes:
                    doc_orig = fitz.open(stream=orig_bytes, filetype="pdf")
                    for p_idx in range(min(len(doc_orig), len(doc))):
                        p_num = p_idx + 1
                        words_orig = [w[4] for w in doc_orig[p_idx].get_text("words", sort=True)]
                        cand_words_meta = doc[p_idx].get_text("words", sort=True)
                        words_cand = [w[4] for w in cand_words_meta]
                        sm = difflib.SequenceMatcher(None, words_orig, words_cand)
                        for tag, i1, i2, j1, j2 in sm.get_opcodes():
                            if tag == "replace":
                                old_txt = " ".join(words_orig[i1:i2])
                                new_txt = " ".join(words_cand[j1:j2])
                                matching_boxes = [cand_words_meta[k][:4] for k in range(j1, j2)]
                                c_bbox = [
                                    round(min(b[0] for b in matching_boxes), 1),
                                    round(min(b[1] for b in matching_boxes), 1),
                                    round(max(b[2] for b in matching_boxes), 1),
                                    round(max(b[3] for b in matching_boxes), 1),
                                ] if matching_boxes else None
                                findings.append(
                                    ForensicFinding(
                                        code="STRUCT_EXACT_TEXT_MODIFIED",
                                        category="confirmed",
                                        domain="content_stream",
                                        severity="high",
                                        confidence=0.98,
                                        anomaly_confidence=0.98,
                                        tampering_confidence=0.95,
                                        description=(
                                            f"Page {p_num} exact text change confirmed against reference original: "
                                            f"'{old_txt}' was replaced with '{new_txt}' at {c_bbox}."
                                        ),
                                        evidence={
                                            "page": p_num,
                                            "old_text": old_txt,
                                            "new_text": new_txt,
                                            "bbox": c_bbox,
                                        },
                                        alternative_explanations=[
                                            "Authorized revision or editorial update.",
                                        ],
                                        recommended_action="Verify if the modification was authorized by the document owner.",
                                    )
                                )
                            elif tag == "insert":
                                new_txt = " ".join(words_cand[j1:j2])
                                matching_boxes = [cand_words_meta[k][:4] for k in range(j1, j2)]
                                c_bbox = [
                                    round(min(b[0] for b in matching_boxes), 1),
                                    round(min(b[1] for b in matching_boxes), 1),
                                    round(max(b[2] for b in matching_boxes), 1),
                                    round(max(b[3] for b in matching_boxes), 1),
                                ] if matching_boxes else None
                                findings.append(
                                    ForensicFinding(
                                        code="STRUCT_EXACT_TEXT_ADDED",
                                        category="confirmed",
                                        domain="content_stream",
                                        severity="high",
                                        confidence=0.98,
                                        anomaly_confidence=0.98,
                                        tampering_confidence=0.95,
                                        description=(
                                            f"Page {p_num} exact text insertion confirmed against reference original: "
                                            f"'{new_txt}' was added at {c_bbox}."
                                        ),
                                        evidence={
                                            "page": p_num,
                                            "added_text": new_txt,
                                            "bbox": c_bbox,
                                        },
                                        alternative_explanations=[
                                            "Authorized revision or editorial addition.",
                                        ],
                                        recommended_action="Inspect the added text segment.",
                                    )
                                )
                    doc_orig.close()
            except Exception as orig_diff_err:
                logger.debug("Exact structural original diff note: %s", orig_diff_err)

    finally:
        try:
            doc.close()
        except Exception:
            pass

    # Calculate granular counts for enhanced text tampering audit
    formatting_count = sum(1 for f in findings if f.category == "formatting_anomaly")
    overlaps_count = sum(1 for f in findings if f.category == "text_overlap")
    covering_count = sum(1 for f in findings if f.category == "possible_covering_object")
    replacements_count = sum(
        1 for f in findings
        if f.category in ("possible_text_replacement", "revision_change_detected")
        or f.code in ("STRUCT_EXACT_TEXT_MODIFIED", "VERIFY_TEXT_DIFF_MODIFIED")
    )
    insertions_count = sum(
        1 for f in findings
        if f.category == "possible_text_insertion"
        or f.code in (
            "STRUCT_EXACT_TEXT_ADDED",
            "STRUCT_FOREIGN_FONT_TEXT_INSERTION",
            "STRUCT_EDITOR_PLACEHOLDER_TEXT",
            "STREAM_APPENDED_CONTENT_STREAM_TEXT",
            "VERIFY_TEXT_DIFF_ADDED",
        )
    )

    # Build summary
    exact_mods = sum(1 for f in findings if f.code in ("STRUCT_EXACT_TEXT_MODIFIED", "STRUCT_EXACT_TEXT_ADDED"))
    confirmed_count = sum(1 for f in findings if f.category in ("confirmed", "revision_change_detected"))
    suspicious_count = sum(1 for f in findings if f.category in ("suspicious", "possible_text_replacement", "possible_covering_object", "possible_text_insertion"))

    if exact_mods > 0:
        summary = f"Structural analysis and reference comparison identified {exact_mods} confirmed exact text change(s)."
    elif confirmed_count > 0:
        summary = f"Structural analysis identified {confirmed_count} confirmed structural modification(s)."
    elif insertions_count > 0 or replacements_count > 0 or covering_count > 0 or overlaps_count > 0:
        parts = []
        if insertions_count > 0:
            parts.append(f"{insertions_count} text insertion(s)")
        if replacements_count > 0:
            parts.append(f"{replacements_count} replacement(s)")
        if covering_count > 0:
            parts.append(f"{covering_count} covering object(s)")
        if overlaps_count > 0:
            parts.append(f"{overlaps_count} overlap(s)")
        summary = f"Structural analysis identified potential text tampering indicator(s) ({', '.join(parts)})."
    elif formatting_count > 0:
        summary = f"Structural analysis completed; {formatting_count} formatting anomaly/anomalies detected without structural cover-ups."
    else:
        summary = "Structural analysis completed; internal object graph, fonts, and text layout appear consistent."

    return StructuralLayerResult(
        status="completed",
        summary=summary,
        findings=findings,
        limitations=limitations,
        text_spans=all_spans,
        images=all_images,
        annotations=all_annots,
        whiteout_patches=all_whiteout_patches,
        revision_count=rev_count,
        has_recoverable_revisions=has_revs,
        formatting_anomalies_count=formatting_count,
        text_overlaps_count=overlaps_count,
        covering_objects_count=covering_count,
        text_replacements_count=replacements_count,
        text_insertions_count=insertions_count,
        revision_history_available=has_revs,
        historical_comparison_status="available" if has_revs else "unavailable_fully_rewritten",
    )
