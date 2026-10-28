"""Layer 2: Pixel-Level and Visual Forensics.

Renders PDF pages via PyMuPDF and utilizes OpenCV and NumPy for:
- Text-edge sharpness and antialiasing consistency analysis.
- Background uniformity and rectangular whiteout/patch detection.
- Copy-move / duplicate region detection.
- Error Level Analysis (ELA) as an auxiliary experimental signal.
- Visual heatmap and suspicious-region overlay generation.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import io
import logging
from typing import Any

import cv2
import fitz  # PyMuPDF
import numpy as np
from PIL import Image

from app.schemas.analysis import ForensicFinding
from app.services.pdf_analysis.pdf_loader import LoadedPdf

logger = logging.getLogger("pdf_analyser.visual_analysis")

DEFAULT_RENDER_DPI: int = 150
MAX_PAGES_TO_RENDER: int = 5  # Performance protection for large documents


@dataclass
class SuspiciousVisualRegion:
    """A bounded region on a page showing visual anomalies."""

    page: int
    bbox_pdf: list[float]  # [x0, y0, x1, y1] in points (72 DPI)
    bbox_px: list[int]  # [x0, y0, x1, y1] in pixels
    technique: str  # text_edge | background_texture | copy_move | ela
    description: str
    confidence: float
    severity: str = "medium"


@dataclass
class PageVisualPreview:
    """Rendered visual preview and suspicious overlay for a page."""

    page_number: int
    width_px: int
    height_px: int
    dpi: int
    original_image_base64: str  # data:image/png;base64,...
    overlay_image_base64: str  # data:image/png;base64,... with highlighted regions
    suspicious_regions: list[SuspiciousVisualRegion] = field(default_factory=list)


@dataclass
class VisualLayerResult:
    """Consolidated outcome of Layer 2 Visual Analysis."""

    status: str  # completed | partial | failed | skipped
    summary: str
    findings: list[ForensicFinding] = field(default_factory=list)
    page_previews: list[PageVisualPreview] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def _mat_to_base64_png(image_rgb: np.ndarray) -> str:
    """Encode an RGB NumPy image array to a data:image/png;base64 URI string."""
    image_bgr = cv2.cvtColor(image_rgb, cv2.COLOR_RGB2BGR)
    success, buffer = cv2.imencode(".png", image_bgr)
    if not success:
        return ""
    b64_str = base64.b64encode(buffer).decode("ascii")
    return f"data:image/png;base64,{b64_str}"


def _compute_text_edge_sharpness(
    gray_img: np.ndarray,
    bbox_px: list[int],
) -> float:
    """Calculate edge sharpness of a text patch using Laplacian variance."""
    x0, y0, x1, y1 = bbox_px
    h, w = gray_img.shape
    x0, y0 = max(0, x0), max(0, y0)
    x1, y1 = min(w, x1), min(h, y1)

    if x1 - x0 < 6 or y1 - y0 < 6:
        return 0.0

    crop = gray_img[y0:y1, x0:x1]
    laplacian = cv2.Laplacian(crop, cv2.CV_64F)
    return float(laplacian.var())


def _compute_background_uniformity(
    gray_img: np.ndarray,
    bbox_px: list[int],
) -> tuple[float, float]:
    """Calculate mean and standard deviation of background around a box."""
    x0, y0, x1, y1 = bbox_px
    h, w = gray_img.shape
    x0, y0 = max(0, x0), max(0, y0)
    x1, y1 = min(w, x1), min(h, y1)

    if x1 - x0 < 6 or y1 - y0 < 6:
        return 255.0, 0.0

    crop = gray_img[y0:y1, x0:x1]
    return float(np.mean(crop)), float(np.std(crop))


def _detect_copy_move_regions(
    gray_img: np.ndarray,
    scale: float,
    page_num: int,
) -> list[SuspiciousVisualRegion]:
    """Identify candidate duplicate / copy-move regions on the page image."""
    h, w = gray_img.shape
    block_size = 32
    step = 24
    regions: list[SuspiciousVisualRegion] = []

    # Downsample if image is very large for performance
    if h > 1600 or w > 1200:
        downsample_factor = 2
        small_gray = cv2.resize(gray_img, (w // 2, h // 2))
        bs = block_size // 2
        st = step // 2
    else:
        downsample_factor = 1
        small_gray = gray_img
        bs = block_size
        st = step

    sh, sw = small_gray.shape
    blocks: list[tuple[int, int, np.ndarray, float]] = []

    for y in range(0, sh - bs, st):
        for x in range(0, sw - bs, st):
            blk = small_gray[y : y + bs, x : x + bs]
            std_dev = float(np.std(blk))
            # Ignore mostly uniform white (background) or black blocks
            if std_dev < 12.0:
                continue
            # Simple 8-bin normalized intensity histogram as block descriptor
            hist = cv2.calcHist([blk], [0], None, [8], [0, 256]).flatten()
            norm = np.linalg.norm(hist)
            if norm > 0:
                hist = hist / norm
            blocks.append((x, y, hist, std_dev))

    # Pairwise comparison with spatial distance threshold
    matches: list[tuple[int, int, int, int]] = []
    min_spatial_dist_sq = (60 // downsample_factor) ** 2
    max_matches = 12

    for i in range(len(blocks)):
        if len(matches) >= max_matches:
            break
        x1, y1, h1, _ = blocks[i]
        for j in range(i + 1, min(i + 200, len(blocks))):
            x2, y2, h2, _ = blocks[j]
            spatial_dist_sq = (x1 - x2) ** 2 + (y1 - y2) ** 2
            if spatial_dist_sq < min_spatial_dist_sq:
                continue

            # Cosine similarity between histograms
            sim = float(np.dot(h1, h2))
            if sim > 0.992:
                # Double check with direct normalized cross-correlation
                blk1 = small_gray[y1 : y1 + bs, x1 : x1 + bs]
                blk2 = small_gray[y2 : y2 + bs, x2 : x2 + bs]
                res = cv2.matchTemplate(blk1, blk2, cv2.TM_CCOEFF_NORMED)[0][0]
                if res > 0.985:
                    matches.append(
                        (
                            x1 * downsample_factor,
                            y1 * downsample_factor,
                            x2 * downsample_factor,
                            y2 * downsample_factor,
                        )
                    )
                    break

    # If meaningful duplicate blocks were found (and not dozens of repeated grid lines)
    if 2 <= len(matches) <= 8:
        for x1, y1, x2, y2 in matches[:3]:
            # Scale coordinates back to PDF points
            pdf_b1 = [
                round(x1 / scale, 2),
                round(y1 / scale, 2),
                round((x1 + block_size) / scale, 2),
                round((y1 + block_size) / scale, 2),
            ]
            regions.append(
                SuspiciousVisualRegion(
                    page=page_num,
                    bbox_pdf=pdf_b1,
                    bbox_px=[x1, y1, x1 + block_size, y1 + block_size],
                    technique="copy_move",
                    description=f"Candidate duplicate image region detected at ({pdf_b1[0]}, {pdf_b1[1]}) matching another location on page {page_num}",
                    confidence=0.45,
                    severity="medium",
                )
            )

    return regions


def _perform_ela(rgb_img: np.ndarray, quality: int = 90) -> tuple[np.ndarray, float]:
    """Compute Error Level Analysis (ELA) map by recompressing to JPEG in memory."""
    # Encode to JPEG in memory
    success, enc = cv2.imencode(".jpg", cv2.cvtColor(rgb_img, cv2.COLOR_RGB2BGR), [cv2.IMWRITE_JPEG_QUALITY, quality])
    if not success:
        return np.zeros_like(rgb_img), 0.0

    # Decode recompressed JPEG
    dec_bgr = cv2.imdecode(enc, cv2.IMREAD_COLOR)
    dec_rgb = cv2.cvtColor(dec_bgr, cv2.COLOR_BGR2RGB)

    # Calculate absolute difference
    diff = cv2.absdiff(rgb_img, dec_rgb)
    # Scale difference to enhance visibility
    scale_factor = 15
    diff_enhanced = np.clip(diff.astype(np.float32) * scale_factor, 0, 255).astype(np.uint8)
    mean_diff = float(np.mean(diff))
    return diff_enhanced, mean_diff


def analyze_visual_layer(
    loaded_pdf: LoadedPdf,
    dpi: int = DEFAULT_RENDER_DPI,
    max_pages: int = MAX_PAGES_TO_RENDER,
) -> VisualLayerResult:
    """Execute complete Layer 2 pixel-level and visual analysis."""
    if not loaded_pdf.is_valid:
        return VisualLayerResult(
            status="failed",
            summary=f"Visual analysis skipped: {loaded_pdf.error_message or 'PDF parsing error'}",
            limitations=["Document could not be parsed as a valid PDF."],
        )

    findings: list[ForensicFinding] = []
    page_previews: list[PageVisualPreview] = []
    limitations: list[str] = [
        "Visual analysis evaluates rendered pixels and edge gradients without access to an original baseline image.",
        "Different PDF rendering engines, embedded font antialiasing settings, and printer rasterizers can naturally create edge sharpness variations.",
        "Error Level Analysis (ELA) is an experimental heuristic and is not conclusive on rendered vector PDFs.",
    ]

    try:
        doc = fitz.open(stream=loaded_pdf.file_bytes, filetype="pdf")
    except Exception as doc_err:
        logger.error("Failed to render PDF in visual layer: %s", doc_err)
        return VisualLayerResult(
            status="failed",
            summary=f"Visual analysis failed during rendering: {doc_err}",
            limitations=limitations,
        )

    total_pages = len(doc)
    pages_to_process = min(total_pages, max_pages)
    scale = dpi / 72.0

    try:
        for page_idx in range(pages_to_process):
            page_num = page_idx + 1
            page = doc[page_idx]

            # 1. Render page at target DPI
            pix = page.get_pixmap(dpi=dpi, alpha=False)
            img_rgb = np.frombuffer(pix.samples, dtype=np.uint8).reshape((pix.height, pix.width, pix.n))
            if pix.n == 4:
                img_rgb = cv2.cvtColor(img_rgb, cv2.COLOR_RGBA2RGB)

            gray = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2GRAY)
            h_px, w_px = gray.shape

            page_regions: list[SuspiciousVisualRegion] = []

            # 2. Extract Text Spans for White Text Masking, Text Collision & Hidden Text
            page_dict = page.get_text("dict")
            page_spans_vis: list[dict[str, Any]] = []
            for blk in page_dict.get("blocks", []):
                if blk.get("type") == 0:
                    for line in blk.get("lines", []):
                        for sp in line.get("spans", []):
                            txt = sp.get("text", "").strip()
                            if not txt:
                                continue
                            raw_color = sp.get("color", 0)
                            color_rgb = (
                                (raw_color >> 16) & 255,
                                (raw_color >> 8) & 255,
                                raw_color & 255,
                            )
                            sb = sp.get("bbox", [0, 0, 0, 0])
                            is_w = (color_rgb[0] >= 240 and color_rgb[1] >= 240 and color_rgb[2] >= 240) or (raw_color in (16777215, -1))
                            page_spans_vis.append({
                                "text": txt,
                                "bbox_pdf": [round(c, 2) for c in sb],
                                "bbox_px": [int(sb[0] * scale), int(sb[1] * scale), int(sb[2] * scale), int(sb[3] * scale)],
                                "color_rgb": color_rgb,
                                "font": sp.get("font", "unknown"),
                                "size": float(round(sp.get("size", 10.0), 2)),
                                "is_white": is_w,
                            })

            white_spans = [s for s in page_spans_vis if s["is_white"]]
            visible_spans = [s for s in page_spans_vis if not s["is_white"]]

            # Check for white text masking layers
            for wsp in white_spans:
                wx0, wy0, wx1, wy1 = wsp["bbox_px"]
                wx0, wy0 = max(0, wx0), max(0, wy0)
                wx1, wy1 = min(w_px, wx1), min(h_px, wy1)
                mean_bg = float(np.mean(gray[wy0:wy1, wx0:wx1])) if (wx1 > wx0 and wy1 > wy0) else 255.0

                # Only evaluate as masking or invisible if page background is light/white
                if mean_bg >= 180.0:
                    found_overlay = False
                    for vsp in visible_spans:
                        wb = wsp["bbox_pdf"]
                        vb = vsp["bbox_pdf"]
                        ix0 = max(wb[0], vb[0])
                        iy0 = max(wb[1], vb[1])
                        ix1 = min(wb[2], vb[2])
                        iy1 = min(wb[3], vb[3])
                        if ix1 > ix0 and iy1 > iy0:
                            v_overlap = (iy1 - iy0) / max(1.0, min(wb[3] - wb[1], vb[3] - vb[1]))
                            h_overlap = (ix1 - ix0) / max(1.0, min(wb[2] - wb[0], vb[2] - vb[0]))
                            if v_overlap > 0.40 and h_overlap > 0.20:
                                found_overlay = True
                                u_pdf = [min(wb[0], vb[0]), min(wb[1], vb[1]), max(wb[2], vb[2]), max(wb[3], vb[3])]
                                u_px = [int(u_pdf[0] * scale), int(u_pdf[1] * scale), int(u_pdf[2] * scale), int(u_pdf[3] * scale)]
                                page_regions.append(
                                    SuspiciousVisualRegion(
                                        page=page_num,
                                        bbox_pdf=u_pdf,
                                        bbox_px=u_px,
                                        technique="white_text_layer",
                                        description=(
                                            f"White text masking layer detected at ({u_pdf[0]}, {u_pdf[1]}): "
                                            f"white text '{wsp['text']}' collides with visible text '{vsp['text']}'"
                                        ),
                                        confidence=0.85,
                                        severity="high",
                                    )
                                )
                                break
                    if not found_overlay and len(wsp["text"]) >= 2:
                        page_regions.append(
                            SuspiciousVisualRegion(
                                page=page_num,
                                bbox_pdf=wsp["bbox_pdf"],
                                bbox_px=wsp["bbox_px"],
                                technique="hidden_white_text",
                                description=f"Invisible white text '{wsp['text']}' on light background at {wsp['bbox_pdf']}",
                                confidence=0.65,
                                severity="medium",
                            )
                        )

            # Check for co-located text collision between visible spans
            for i in range(len(visible_spans)):
                for j in range(i + 1, len(visible_spans)):
                    s1 = visible_spans[i]
                    s2 = visible_spans[j]
                    if s1["text"] != s2["text"]:
                        b1 = s1["bbox_pdf"]
                        b2 = s2["bbox_pdf"]
                        ix0 = max(b1[0], b2[0])
                        iy0 = max(b1[1], b2[1])
                        ix1 = min(b1[2], b2[2])
                        iy1 = min(b1[3], b2[3])
                        if ix1 > ix0 and iy1 > iy0:
                            v_overlap = (iy1 - iy0) / max(1.0, min(b1[3] - b1[1], b2[3] - b2[1]))
                            h_overlap = (ix1 - ix0) / max(1.0, min(b1[2] - b1[0], b2[2] - b2[0]))
                            if v_overlap > 0.50 and h_overlap > 0.35:
                                u_pdf = [min(b1[0], b2[0]), min(b1[1], b2[1]), max(b1[2], b2[2]), max(b1[3], b2[3])]
                                u_px = [int(u_pdf[0] * scale), int(u_pdf[1] * scale), int(u_pdf[2] * scale), int(u_pdf[3] * scale)]
                                already = any(
                                    abs(r.bbox_px[0] - u_px[0]) < 10 and abs(r.bbox_px[1] - u_px[1]) < 10
                                    for r in page_regions
                                )
                                if not already:
                                    page_regions.append(
                                        SuspiciousVisualRegion(
                                            page=page_num,
                                            bbox_pdf=u_pdf,
                                            bbox_px=u_px,
                                            technique="text_collision",
                                            description=f"Co-located text layers colliding: '{s1['text']}' overlaps '{s2['text']}'",
                                            confidence=0.30,
                                            severity="low",
                                        )
                                    )

            # 3. Extract text block coordinates from page to test local edge sharpness
            text_blocks = page.get_text("blocks")
            edge_scores: list[tuple[float, list[float], list[int], str]] = []

            for blk in text_blocks:
                bx0, by0, bx1, by1, btext, bno, btype = blk
                if btype == 0 and btext.strip():  # Text block
                    px0 = int(bx0 * scale)
                    py0 = int(by0 * scale)
                    px1 = int(bx1 * scale)
                    py1 = int(by1 * scale)
                    sharpness = _compute_text_edge_sharpness(gray, [px0, py0, px1, py1])
                    if sharpness > 10.0:
                        edge_scores.append((sharpness, [bx0, by0, bx1, by1], [px0, py0, px1, py1], btext.strip()))

            # Evaluate sharpness consistency across text blocks
            if len(edge_scores) >= 5:
                scores_only = [s[0] for s in edge_scores]
                median_sharpness = float(np.median(scores_only))
                q75, q25 = np.percentile(scores_only, [75, 25])
                iqr = max(15.0, q75 - q25)

                for shp, b_pdf, b_px, txt in edge_scores:
                    # Flag outliers (text substantially sharper or blurrier than page median)
                    if (shp > median_sharpness + (1.75 * iqr) and shp > 100.0) or (shp < median_sharpness - (1.75 * iqr) and shp < 25.0 and median_sharpness > 80.0):
                        page_regions.append(
                            SuspiciousVisualRegion(
                                page=page_num,
                                bbox_pdf=[round(c, 2) for c in b_pdf],
                                bbox_px=b_px,
                                technique="text_edge",
                                description=f"Anomalous text edge sharpness ({int(shp)} vs median {int(median_sharpness)}) on '{txt[:30]}'",
                                confidence=0.40,
                                severity="low",
                            )
                        )
            elif 2 <= len(edge_scores) < 5:
                scores_only = [s[0] for s in edge_scores]
                min_shp = min(scores_only)
                max_shp = max(scores_only)
                if min_shp > 5.0 and (max_shp / min_shp) >= 2.5 and max_shp > 100.0:
                    for shp, b_pdf, b_px, txt in edge_scores:
                        if shp == max_shp:
                            page_regions.append(
                                SuspiciousVisualRegion(
                                    page=page_num,
                                    bbox_pdf=[round(c, 2) for c in b_pdf],
                                    bbox_px=b_px,
                                    technique="text_edge",
                                    description=f"Significant text edge sharpness disparity ({int(max_shp)} vs min {int(min_shp)}) on '{txt[:30]}'",
                                    confidence=0.40,
                                    severity="low",
                                )
                            )

            # 4. Detect Whiteout / Rectangular Texture Drop Patches (vector drawings)
            drawings = page.get_drawings()
            for draw in drawings:
                fill = draw.get("fill")
                is_white_fill = False
                if fill is not None:
                    if len(fill) >= 3 and fill[0] >= 0.96 and fill[1] >= 0.96 and fill[2] >= 0.96:
                        is_white_fill = True
                    elif len(fill) == 1 and fill[0] >= 0.96:
                        is_white_fill = True

                if is_white_fill:
                    r = draw.get("rect")
                    if r and r.width > 12 and r.height > 8:
                        rx0, ry0, rx1, ry1 = int(r.x0 * scale), int(r.y0 * scale), int(r.x1 * scale), int(r.y1 * scale)
                        mean_val, std_val = _compute_background_uniformity(gray, [rx0, ry0, rx1, ry1])
                        if mean_val >= 210.0 or std_val < 5.0:
                            page_regions.append(
                                SuspiciousVisualRegion(
                                    page=page_num,
                                    bbox_pdf=[round(c, 2) for c in [r.x0, r.y0, r.x1, r.y1]],
                                    bbox_px=[rx0, ry0, rx1, ry1],
                                    technique="background_texture",
                                    description="Flat rectangular whiteout patch detected covering underlying content",
                                    confidence=0.60,
                                    severity="medium",
                                )
                            )

            # 5. Copy-Move / Duplicate Region Detection
            copy_move_candidates = _detect_copy_move_regions(gray, scale, page_num)
            page_regions.extend(copy_move_candidates)

            # 6. Error Level Analysis (ELA)
            ela_map, mean_diff = _perform_ela(img_rgb)
            if mean_diff > 12.0:
                findings.append(
                    ForensicFinding(
                        code="VISUAL_ELA_HIGH_COMPRESSION_VARIANCE",
                        category="suspicious",
                        domain="layout_analysis",
                        severity="low",
                        confidence=0.25,
                        description=f"Page {page_num} exhibits elevated JPEG Error Level Analysis variance ({mean_diff:.1f}); may indicate multi-generation raster compression",
                        evidence={"page": page_num, "mean_ela_diff": round(mean_diff, 2)},
                        limitations=["ELA is an experimental indicator and is easily skewed by normal font antialiasing."],
                    )
                )

            # 6. Generate Visual Overlay Image with Highlighted Regions
            overlay_rgb = img_rgb.copy()
            # Draw semi-transparent bounding box overlays for detected regions
            for reg in page_regions:
                rx0, ry0, rx1, ry1 = reg.bbox_px
                rx0, ry0 = max(0, rx0), max(0, ry0)
                rx1, ry1 = min(w_px, rx1), min(h_px, ry1)

                # Color based on severity: Red for medium/high, Amber for low
                box_color = (239, 68, 68) if reg.severity in ("medium", "high") else (245, 158, 11)
                cv2.rectangle(overlay_rgb, (rx0, ry0), (rx1, ry1), box_color, 3)

                # Label background
                label = reg.technique.replace("_", " ").upper()
                cv2.putText(
                    overlay_rgb,
                    label,
                    (rx0, max(15, ry0 - 6)),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.45,
                    box_color,
                    1,
                    cv2.LINE_AA,
                )

            # Create base64 preview representations
            orig_b64 = _mat_to_base64_png(img_rgb)
            overlay_b64 = _mat_to_base64_png(overlay_rgb)

            page_previews.append(
                PageVisualPreview(
                    page_number=page_num,
                    width_px=w_px,
                    height_px=h_px,
                    dpi=dpi,
                    original_image_base64=orig_b64,
                    overlay_image_base64=overlay_b64,
                    suspicious_regions=page_regions,
                )
            )

            # Add findings for detected regions
            seen_finding_keys: set[str] = set()
            for reg in page_regions:
                f_key = f"{reg.technique}_{reg.bbox_pdf}"
                if f_key in seen_finding_keys:
                    continue
                seen_finding_keys.add(f_key)

                if reg.technique == "white_text_layer":
                    findings.append(
                        ForensicFinding(
                            code="VISUAL_WHITE_TEXT_LAYER_OVERLAY",
                            category="suspicious",
                            domain="layout_analysis",
                            severity="high",
                            confidence=reg.confidence,
                            description=reg.description,
                            evidence={"page": page_num, "bbox_pdf": reg.bbox_pdf, "technique": reg.technique},
                            limitations=["Confirm whether document template uses intentional reverse-contrast (white text on dark background)."],
                        )
                    )
                elif reg.technique == "hidden_white_text":
                    findings.append(
                        ForensicFinding(
                            code="VISUAL_HIDDEN_WHITE_TEXT",
                            category="suspicious",
                            domain="layout_analysis",
                            severity="medium",
                            confidence=reg.confidence,
                            description=reg.description,
                            evidence={"page": page_num, "bbox_pdf": reg.bbox_pdf, "technique": reg.technique},
                            limitations=["Search indexing or accessibility tags occasionally include hidden text."],
                        )
                    )
                elif reg.technique == "text_collision":
                    findings.append(
                        ForensicFinding(
                            code="VISUAL_TEXT_COLLISION_OVERLAY",
                            category="suspicious",
                            domain="layout_analysis",
                            severity=reg.severity,
                            confidence=reg.confidence,
                            description=reg.description,
                            evidence={"page": page_num, "bbox_pdf": reg.bbox_pdf, "technique": reg.technique},
                            limitations=["Complex vector graphics or watermarks may intentionally overlap typography."],
                        )
                    )
                elif reg.technique == "background_texture":
                    findings.append(
                        ForensicFinding(
                            code="VISUAL_WHITEOUT_PATCH_DETECTED",
                            category="suspicious",
                            domain="layout_analysis",
                            severity="medium",
                            confidence=reg.confidence,
                            description=f"Page {page_num} contains a visually flat whiteout patch at coordinates {reg.bbox_pdf}",
                            evidence={"page": page_num, "bbox_pdf": reg.bbox_pdf, "technique": reg.technique},
                            limitations=["Legitimate forms and modern templates use card-like background containers."],
                        )
                    )
                elif reg.technique == "copy_move":
                    findings.append(
                        ForensicFinding(
                            code="VISUAL_DUPLICATE_REGION_CANDIDATE",
                            category="suspicious",
                            domain="layout_analysis",
                            severity="medium",
                            confidence=reg.confidence,
                            description=reg.description,
                            evidence={"page": page_num, "bbox_pdf": reg.bbox_pdf, "technique": reg.technique},
                            limitations=["Repeated logos, letterhead emblems, and table borders naturally produce duplicate blocks."],
                        )
                    )
                elif reg.technique == "text_edge":
                    findings.append(
                        ForensicFinding(
                            code="VISUAL_INCONSISTENT_TEXT_SHARPNESS",
                            category="suspicious",
                            domain="layout_analysis",
                            severity="low",
                            confidence=reg.confidence,
                            description=reg.description,
                            evidence={"page": page_num, "bbox_pdf": reg.bbox_pdf, "technique": reg.technique},
                            limitations=["Titles, bold headers, and font subsets naturally render with higher contrast than body text."],
                        )
                    )

        doc.close()
    except Exception as render_err:
        logger.warning("Error during visual page rendering: %s", render_err, exc_info=True)
        limitations.append(f"Visual page rendering note: {render_err}")

    # Build summary
    total_regions = sum(len(p.suspicious_regions) for p in page_previews)
    if total_regions > 0:
        summary = f"Visual analysis identified {total_regions} candidate region(s) across {len(page_previews)} rendered page(s) warranting visual review."
    else:
        summary = f"Visual analysis completed across {len(page_previews)} page(s); rendered text sharpness, backgrounds, and textures appear consistent."

    return VisualLayerResult(
        status="completed",
        summary=summary,
        findings=findings,
        page_previews=page_previews,
        limitations=limitations,
    )
