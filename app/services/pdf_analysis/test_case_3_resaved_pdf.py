"""Test Case 3: Fully Re-saved PDF Without Revision History.

Analyzes PDF content, typography, and page geometry for suspicious layout anomalies
when previous revision history cannot be recovered.
"""

from __future__ import annotations

from collections import Counter
import logging

from app.schemas.analysis import (
    ChangeLocation,
    ResavedFinding,
    TestCase3ResavedResult,
)
from app.services.pdf_analysis.pdf_loader import LoadedPdf
from app.services.pdf_analysis.shared_utils import (
    PageLayout,
    TextSpan,
    box_contains,
    boxes_intersect,
    extract_pdf_layout,
)

logger = logging.getLogger("pdf_analyser.test_case_3")


def analyze_resaved_pdf(
    loaded_pdf: LoadedPdf,
    historical_comparison_available: bool = False,
) -> TestCase3ResavedResult:
    """Analyze a PDF for suspicious layout, text overlap, and font inconsistencies.

    Args:
        loaded_pdf: Safely loaded PDF with preserved bytes.
        historical_comparison_available: True if Test Case 1 or 2 recovered a previous revision.

    Returns:
        TestCase3ResavedResult containing detected anomalies and methodological limitations.
    """
    limitations: list[str] = [
        "No recoverable earlier revision was available." if not historical_comparison_available
        else "Historical revision recovered; layout scan provides complementary visual anomaly checks.",
        "Exact original content cannot be established from this PDF alone.",
        "Layout anomalies such as mixed fonts or overlapping elements may have innocent formatting origins.",
    ]

    if not loaded_pdf.is_valid or not loaded_pdf.file_bytes:
        return TestCase3ResavedResult(
            status="inconclusive",
            historical_comparison_available=historical_comparison_available,
            findings=[],
            limitations=[loaded_pdf.error_message or "PDF is invalid or unreadable."],
        )

    findings: list[ResavedFinding] = []

    try:
        pages = extract_pdf_layout(loaded_pdf.file_bytes)
    except Exception as e:
        logger.warning("Failed to extract layout for re-saved analysis: %s", e)
        return TestCase3ResavedResult(
            status="inconclusive",
            historical_comparison_available=historical_comparison_available,
            findings=[],
            limitations=[f"Layout extraction failed: {e}"] + limitations,
        )

    for layout in pages:
        page_num = layout.page_num

        # Check 1: Unusual Text Overlap between different text lines
        _detect_text_overlap(layout, page_num, findings)

        # Check 2: Digital Text Overlaid on Scanned/Bitmap Image
        _detect_text_over_image(layout, page_num, findings)

        # Check 3: Inconsistent Font / Size Anomaly within Uniform Lines
        _detect_inconsistent_fonts_in_line(layout, page_num, findings)

    status = "suspicious_indicators_found" if findings else "no_anomalies_detected"

    return TestCase3ResavedResult(
        status=status,
        historical_comparison_available=historical_comparison_available,
        findings=findings,
        limitations=limitations,
    )


def resaved_findings_to_forensic(resaved_result: TestCase3ResavedResult) -> list[ForensicFinding]:
    """Convert layout-level resaved findings into standardized ForensicFinding objects."""
    from app.schemas.analysis import ForensicFinding

    code_map = {
        "unusual_text_overlap": "LAYOUT_TEXT_OVERLAP",
        "text_over_image": "LAYOUT_TEXT_OVER_IMAGE",
        "inconsistent_font_anomaly": "LAYOUT_INCONSISTENT_FONT",
        "isolated_text_overlay": "LAYOUT_ISOLATED_OVERLAY",
    }
    forensic_findings: list[ForensicFinding] = []
    for rf in resaved_result.findings:
        code = code_map.get(rf.type, f"LAYOUT_{rf.type.upper()}")
        conf = 0.30 if rf.confidence == "medium" else 0.20
        forensic_findings.append(
            ForensicFinding(
                code=code,
                category="layout_analysis",
                severity="low" if rf.confidence == "low" else "medium",
                confidence=conf,
                description=rf.description,
                evidence=rf.evidence if isinstance(rf.evidence, dict) else {"details": str(rf.evidence)},
                limitations=[
                    "Layout and typographic anomalies may reflect intentional document design, watermarks, "
                    "multi-column typography, or OCR layers, and do not prove manipulation independently."
                ],
            )
        )
    return forensic_findings


def _detect_text_overlap(
    layout: PageLayout,
    page_num: int,
    findings: list[ResavedFinding],
) -> None:
    """Detect distinct text blocks whose bounding boxes overlap significantly."""
    lines = layout.text_lines
    seen_pairs: set[tuple[int, int]] = set()

    for i in range(len(lines)):
        for j in range(i + 1, len(lines)):
            l1 = lines[i]
            l2 = lines[j]

            # Skip identical text (e.g. bolding simulation / drop shadow)
            if l1.text.strip().lower() == l2.text.strip().lower():
                continue

            if boxes_intersect(l1.bbox, l2.bbox, min_overlap_ratio=0.35):
                pair_key = (min(i, j), max(i, j))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                combined_bbox = [
                    min(l1.bbox[0], l2.bbox[0]),
                    min(l1.bbox[1], l2.bbox[1]),
                    max(l1.bbox[2], l2.bbox[2]),
                    max(l1.bbox[3], l2.bbox[3]),
                ]

                findings.append(
                    ResavedFinding(
                        type="unusual_text_overlap",
                        page=page_num,
                        description=f"Distinct text blocks overlap in an unusual region: '{l1.text}' and '{l2.text}'",
                        location=ChangeLocation(bbox=combined_bbox),
                        evidence={
                            "text1": l1.text,
                            "bbox1": l1.bbox,
                            "text2": l2.text,
                            "bbox2": l2.bbox,
                        },
                        confidence="low",
                        interpretation="Potential anomaly; not proof of editing",
                    )
                )


def _detect_text_over_image(
    layout: PageLayout,
    page_num: int,
    findings: list[ResavedFinding],
) -> None:
    """Detect sparse digital vector text placed directly over a large image or scanned document."""
    page_area = max(1.0, layout.width * layout.height)

    for img in layout.images:
        img_w = max(0.0, img.bbox[2] - img.bbox[0])
        img_h = max(0.0, img.bbox[3] - img.bbox[1])
        img_area = img_w * img_h

        # Only evaluate large images (covering > 30% of page area, e.g. scanned forms/receipts)
        if (img_area / page_area) < 0.30:
            continue

        # Find words positioned inside this image
        overlaid_words = [
            w for w in layout.words
            if box_contains(img.bbox, w.bbox)
        ]

        # If a scanned image has isolated vector words typed on top (1 to 15 words)
        if 1 <= len(overlaid_words) <= 15:
            words_text = [w.text for w in overlaid_words]
            x0 = min(w.bbox[0] for w in overlaid_words)
            y0 = min(w.bbox[1] for w in overlaid_words)
            x1 = max(w.bbox[2] for w in overlaid_words)
            y1 = max(w.bbox[3] for w in overlaid_words)

            findings.append(
                ResavedFinding(
                    type="text_over_image",
                    page=page_num,
                    description=f"Sparse digital text ({len(overlaid_words)} words) detected directly overlying a scanned/bitmap image",
                    location=ChangeLocation(bbox=[x0, y0, x1, y1]),
                    evidence={
                        "image_bbox": img.bbox,
                        "overlaid_words": words_text,
                        "overlaid_text": " ".join(words_text),
                        "word_count": len(overlaid_words),
                    },
                    confidence="medium",
                    interpretation="Potential anomaly; common when typing new values over scanned documents or receipts",
                )
            )


def _detect_inconsistent_fonts_in_line(
    layout: PageLayout,
    page_num: int,
    findings: list[ResavedFinding],
) -> None:
    """Detect individual words in a uniform text line that have anomalous font family or size."""
    if not layout.words:
        return

    # Cluster words that share a horizontal baseline within 5.0 pt tolerance
    sorted_words = sorted(layout.words, key=lambda w: w.bbox[1])
    clusters: list[list[TextSpan]] = []
    current_cluster: list[TextSpan] = [sorted_words[0]]

    for w in sorted_words[1:]:
        if abs(w.bbox[1] - current_cluster[0].bbox[1]) <= 5.0:
            current_cluster.append(w)
        else:
            clusters.append(current_cluster)
            current_cluster = [w]
    if current_cluster:
        clusters.append(current_cluster)

    for words in clusters:
        if len(words) < 3:
            continue

        # Sort words left-to-right
        words.sort(key=lambda w: w.bbox[0])

        font_families = [w.font_name.split("+")[-1].split("-")[0].lower() for w in words]
        font_sizes = [round(w.font_size, 1) for w in words]

        fam_counter = Counter(font_families)
        most_common_fam, most_common_fam_count = fam_counter.most_common(1)[0]

        size_counter = Counter(font_sizes)
        most_common_size, most_common_size_count = size_counter.most_common(1)[0]

        # If majority of words (>= 65%) share font family and size, but 1 or 2 words differ
        if most_common_fam_count >= len(words) * 0.65:
            for w, fam, sz in zip(words, font_families, font_sizes):
                if fam != most_common_fam or abs(sz - most_common_size) >= 2.5:
                    findings.append(
                        ResavedFinding(
                            type="inconsistent_font_anomaly",
                            page=page_num,
                            description=f"Word '{w.text}' uses font '{w.font_name}' ({w.font_size}pt), differing from predominant line font family '{most_common_fam}' ({most_common_size}pt)",
                            location=ChangeLocation(bbox=w.bbox),
                            evidence={
                                "anomalous_word": w.text,
                                "anomalous_font": w.font_name,
                                "anomalous_size": w.font_size,
                                "predominant_family": most_common_fam,
                                "predominant_size": most_common_size,
                                "line_text": " ".join(item.text for item in words),
                            },
                            confidence="low",
                            interpretation="Potential anomaly; not proof of editing (may reflect intentional emphasis)",
                        )
                    )


def _detect_placeholder_text(
    layout: PageLayout,
    page_num: int,
    findings: list[ResavedFinding],
) -> None:
    """Detect default PDF editor placeholder residue like 'Type your text'."""
    import re
    pat = re.compile(
        r"^(type\s+your\s+text|insert\s+text(\s+here)?|click\s+(here\s+)?to\s+(add|edit|type)\s+text|"
        r"add\s+text(\s+here)?|enter\s+text(\s+here)?|your\s+text\s+here|sample\s+text|"
        r"double\s+click\s+to\s+edit|text\s+box|placeholder(\s+text)?|lorem\s+ipsum)",
        re.IGNORECASE,
    )
    for line in layout.text_lines:
        txt = line.text.strip()
        if pat.match(txt):
            findings.append(
                ResavedFinding(
                    type="isolated_text_overlay",
                    page=page_num,
                    description=f"Editor placeholder residue text '{txt}' detected at {line.bbox}",
                    location=ChangeLocation(bbox=line.bbox),
                    evidence={"text": txt, "bbox": line.bbox},
                    confidence="medium",
                    interpretation="Potential anomaly; placeholder strings are characteristic artifacts of manual PDF editing tools",
                )
            )
