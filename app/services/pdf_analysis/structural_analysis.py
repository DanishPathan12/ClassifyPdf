"""Layer 1: PDF Structural Analysis.

Inspects text spans, fonts, bounding boxes, opaque/whiteout vector rectangles,
embedded image objects, annotations, form widgets, and cross-reference revision structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import io
import logging
from typing import Any

import fitz  # PyMuPDF
import pikepdf

from app.schemas.analysis import ForensicFinding
from app.services.pdf_analysis.pdf_loader import LoadedPdf
from app.services.pdf_analysis.revision_forensics import analyze_revision_structure
from app.services.pdf_analysis.structural_forensics import analyze_structural_forensics

logger = logging.getLogger("pdf_analyser.structural_analysis")


@dataclass
class TextSpanRecord:
    page: int
    text: str
    bbox: list[float]
    font_name: str
    font_size: float
    color_rgb: tuple[int, int, int]
    flags: int


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


def _rects_intersect(r1: list[float], r2: list[float]) -> bool:
    """Check if two bounding boxes [x0, y0, x1, y1] intersect meaningfully."""
    return not (r1[2] <= r2[0] or r1[0] >= r2[2] or r1[3] <= r2[1] or r1[1] >= r2[3])


def _rect_contains(outer: list[float], inner: list[float], margin: float = 2.0) -> bool:
    """Check if inner rect is mostly or entirely contained within outer rect."""
    return (
        inner[0] >= outer[0] - margin
        and inner[1] >= outer[1] - margin
        and inner[2] <= outer[2] + margin
        and inner[3] <= outer[3] + margin
    )


def analyze_structural_layer(loaded_pdf: LoadedPdf) -> StructuralLayerResult:
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
        for page_idx in range(len(doc)):
            page_num = page_idx + 1
            page = doc[page_idx]

            # A. Extract Text Spans & Styling
            page_spans: list[TextSpanRecord] = []
            page_dict = page.get_text("dict")
            for block in page_dict.get("blocks", []):
                if block.get("type") == 0:  # Text block
                    for line in block.get("lines", []):
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
                            rec = TextSpanRecord(
                                page=page_num,
                                text=txt,
                                bbox=[float(round(c, 2)) for c in span.get("bbox", [0, 0, 0, 0])],
                                font_name=span.get("font", "unknown"),
                                font_size=float(round(span.get("size", 10.0), 2)),
                                color_rgb=color_rgb,
                                flags=span.get("flags", 0),
                            )
                            page_spans.append(rec)
                            all_spans.append(rec)

            # B. Detect Opaque / White Vector Rectangles (Sejda/Acrobat Whiteout Redactions)
            drawings = page.get_drawings()
            page_whiteouts: list[WhiteoutPatchRecord] = []
            for draw in drawings:
                fill = draw.get("fill")
                if fill is not None:
                    # Check for white or near-white fill
                    is_white = False
                    if len(fill) >= 3 and fill[0] >= 0.96 and fill[1] >= 0.96 and fill[2] >= 0.96:
                        is_white = True
                    elif len(fill) == 1 and fill[0] >= 0.96:
                        is_white = True

                    if is_white:
                        rect = draw.get("rect")
                        if rect and (rect.width > 10 and rect.height > 6):
                            rect_coords = [float(round(c, 2)) for c in [rect.x0, rect.y0, rect.x1, rect.y1]]
                            # Check if any text span is placed over this white rectangle
                            over_texts: list[str] = []
                            for sp in page_spans:
                                if _rect_contains(rect_coords, sp.bbox, margin=4.0):
                                    over_texts.append(sp.text)

                            has_over = bool(over_texts)
                            patch_rec = WhiteoutPatchRecord(
                                page=page_num,
                                rect=rect_coords,
                                fill_color=tuple(float(round(c, 2)) for c in fill),
                                has_overlying_text=has_over,
                                overlying_text=" ".join(over_texts[:6]),
                            )
                            page_whiteouts.append(patch_rec)
                            all_whiteout_patches.append(patch_rec)

            if page_whiteouts:
                patches_with_text = [p for p in page_whiteouts if p.has_overlying_text]
                if patches_with_text:
                    sample_texts = [p.overlying_text for p in patches_with_text[:3] if p.overlying_text]
                    findings.append(
                        ForensicFinding(
                            code="STRUCT_WHITEOUT_RECTANGLE_OVERLAY",
                            category="suspicious",
                            domain="content_stream",
                            severity="medium",
                            confidence=0.65,
                            description=(
                                f"Page {page_num} contains {len(patches_with_text)} opaque white vector rectangle(s) "
                                f"directly covered by new digital text ({', '.join(sample_texts[:2])}). "
                                "This pattern is a characteristic signature of online PDF editors (e.g. Sejda, SmallPDF) "
                                "used to redact or whiteout original document figures and type altered text on top."
                            ),
                            evidence={
                                "page": page_num,
                                "whiteout_count": len(patches_with_text),
                                "sample_rects": [p.rect for p in patches_with_text[:3]],
                                "sample_overlaid_text": sample_texts,
                            },
                            limitations=[
                                "Some document design templates legitimately use white background cards or text containers.",
                                "Compare surrounding page styling to confirm whether the white patch matches the document background.",
                            ],
                        )
                    )

            # B.2 Detect White Text Masking Layers & Invisible White Text
            white_spans = [
                sp for sp in page_spans
                if (sp.color_rgb[0] >= 240 and sp.color_rgb[1] >= 240 and sp.color_rgb[2] >= 240)
            ]
            visible_spans = [
                sp for sp in page_spans
                if not (sp.color_rgb[0] >= 240 and sp.color_rgb[1] >= 240 and sp.color_rgb[2] >= 240)
            ]

            white_text_overlays: list[tuple[TextSpanRecord, TextSpanRecord]] = []
            for wsp in white_spans:
                for vsp in visible_spans:
                    if _rects_intersect(wsp.bbox, vsp.bbox):
                        ix0 = max(wsp.bbox[0], vsp.bbox[0])
                        iy0 = max(wsp.bbox[1], vsp.bbox[1])
                        ix1 = min(wsp.bbox[2], vsp.bbox[2])
                        iy1 = min(wsp.bbox[3], vsp.bbox[3])
                        v_overlap = (iy1 - iy0) / max(1.0, min(wsp.bbox[3] - wsp.bbox[1], vsp.bbox[3] - vsp.bbox[1]))
                        h_overlap = (ix1 - ix0) / max(1.0, min(wsp.bbox[2] - wsp.bbox[0], vsp.bbox[2] - vsp.bbox[0]))
                        if v_overlap > 0.40 and h_overlap > 0.20:
                            white_text_overlays.append((wsp, vsp))

            if white_text_overlays:
                sample_w, sample_v = white_text_overlays[0]
                findings.append(
                    ForensicFinding(
                        code="STRUCT_WHITE_TEXT_LAYER_OVERLAY",
                        category="suspicious",
                        domain="content_stream",
                        severity="high",
                        confidence=0.75,
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
                        limitations=[
                            "Confirm whether the surrounding page background is white or dark (reverse contrast text).",
                        ],
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
                        limitations=[
                            "Ensure the document does not render a dark vector rectangle behind the white text.",
                        ],
                    )
                )

            # C. Inconsistent Font Styling & Abrupt Font Switches
            if len(page_spans) >= 4:
                font_counts: dict[str, int] = {}
                for sp in page_spans:
                    font_counts[sp.font_name] = font_counts.get(sp.font_name, 0) + len(sp.text.split())
                total_words = sum(font_counts.values())
                if total_words > 0:
                    dominant_font = max(font_counts, key=font_counts.get)
                    dominant_share = font_counts[dominant_font] / total_words

                    # If document is 85%+ in one font, look for isolated text lines using a rare font
                    if dominant_share >= 0.85:
                        isolated_spans = [
                            sp for sp in page_spans
                            if sp.font_name != dominant_font and len(sp.text.split()) <= 4 and font_counts[sp.font_name] <= 5
                        ]
                        if isolated_spans:
                            sample = isolated_spans[0]
                            findings.append(
                                ForensicFinding(
                                    code="STRUCT_INCONSISTENT_FONT_SWITCH",
                                    category="suspicious",
                                    domain="layout_analysis",
                                    severity="low",
                                    confidence=0.35,
                                    description=(
                                        f"Page {page_num} has an isolated text segment '{sample.text}' using font "
                                        f"'{sample.font_name}' ({sample.font_size} pt) in a page where {int(dominant_share * 100)}% "
                                        f"of text uses '{dominant_font}'. Abrupt font switches in small values often indicate pasted edits."
                                    ),
                                    evidence={
                                        "page": page_num,
                                        "isolated_text": sample.text,
                                        "isolated_font": sample.font_name,
                                        "dominant_font": dominant_font,
                                        "bbox": sample.bbox,
                                    },
                                    limitations=[
                                        "Headings, table headers, watermarks, and callout badges legitimately use different fonts.",
                                        "Evaluate whether the isolated text appears in a body paragraph or distinct visual element.",
                                    ],
                                )
                            )

            # D. Text-to-Text Overlaps
            overlaps_found = 0
            for i in range(len(page_spans)):
                for j in range(i + 1, len(page_spans)):
                    s1 = page_spans[i]
                    s2 = page_spans[j]
                    if s1.text != s2.text and _rects_intersect(s1.bbox, s2.bbox):
                        # Verify significant intersection (not just adjacent edge)
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
                                        category="suspicious",
                                        domain="layout_analysis",
                                        severity="low",
                                        confidence=0.30,
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
                                        limitations=[
                                            "Complex vector graphics, watermarks, and optical effects may cause intentional overlaps.",
                                        ],
                                    )
                                )

            # E. Embedded Images Inspection & Text-over-Image Detection
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

                # Check if sparse digital text is overlaid over a large scanned bitmap image
                if img_bbox and (img_bbox[2] - img_bbox[0] > 150) and (img_bbox[3] - img_bbox[1] > 150):
                    overlying_text_words: list[str] = []
                    for sp in page_spans:
                        if _rect_contains(img_bbox, sp.bbox, margin=0.0):
                            overlying_text_words.extend(sp.text.split())

                    # If only a small amount of digital text sits over a full page image, flag as possible overlay
                    if 1 <= len(overlying_text_words) <= 8:
                        findings.append(
                            ForensicFinding(
                                code="STRUCT_TEXT_OVER_IMAGE",
                                category="suspicious",
                                domain="layout_analysis",
                                severity="medium",
                                confidence=0.35,
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
                                limitations=[
                                    "OCR text layers in scanned documents can produce text over images; verify whether text is invisible (3 Tr) or styled vector font.",
                                ],
                            )
                        )

            # F. Annotations and Form Field Inspection
            for annot in page.annots():
                rect = annot.rect
                info = annot.info
                all_annots.append(
                    AnnotationRecord(
                        page=page_num,
                        type_name=str(annot.type[1]) if isinstance(annot.type, (list, tuple)) else str(annot.type),
                        rect=[float(round(c, 2)) for c in [rect.x0, rect.y0, rect.x1, rect.y1]],
                        flags=annot.flags,
                        field_name=info.get("title") or info.get("content"),
                    )
                )

            for widget in page.widgets():
                rect = widget.rect
                all_annots.append(
                    AnnotationRecord(
                        page=page_num,
                        type_name="Widget",
                        rect=[float(round(c, 2)) for c in [rect.x0, rect.y0, rect.x1, rect.y1]],
                        flags=0,
                        field_name=widget.field_name,
                    )
                )

        doc.close()
    except Exception as page_err:
        logger.warning("Error during structural page iteration: %s", page_err, exc_info=True)
        limitations.append(f"Page structural inspection error: {page_err}")

    # Build summary
    suspicious_count = sum(1 for f in findings if f.category == "suspicious")
    confirmed_count = sum(1 for f in findings if f.category == "confirmed")
    if confirmed_count > 0:
        summary = f"Structural analysis identified {confirmed_count} confirmed structural modification(s)."
    elif suspicious_count > 0:
        summary = f"Structural analysis identified {suspicious_count} suspicious structural anomaly/anomalies (fonts, overlays, or streams)."
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
    )

