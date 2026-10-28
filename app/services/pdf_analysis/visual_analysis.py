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

try:
    import cv2
except ImportError:
    cv2 = None

try:
    import pymupdf as fitz
except ImportError:
    try:
        import fitz
    except ImportError:
        fitz = None

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
    try:
        from PIL import Image

        buf = io.BytesIO()
        img = Image.fromarray(image_rgb)
        img.save(buf, format="PNG")
        b64_str = base64.b64encode(buf.getvalue()).decode("ascii")
        return f"data:image/png;base64,{b64_str}"
    except Exception:
        if cv2 is not None:
            image_bgr = cv2.cvtColor(image_rgb, cv2.COLOR_RGB2BGR)
            success, buffer = cv2.imencode(".png", image_bgr)
            if success:
                b64_str = base64.b64encode(buffer).decode("ascii")
                return f"data:image/png;base64,{b64_str}"
        return ""


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


def _compute_text_edge_sharpness(
    gray_img: np.ndarray,
    bbox_px: list[int],
) -> float:
    """Calculate edge sharpness of a text patch using Laplacian variance, insetting to avoid table borders."""
    x0, y0, x1, y1 = bbox_px
    h, w = gray_img.shape
    x0, y0 = max(0, x0), max(0, y0)
    x1, y1 = min(w, x1), min(h, y1)

    # Inset by 2-4 pixels to avoid picking up outer table borders or cell divider lines
    pad_x = min(4, max(1, (x1 - x0) // 10))
    pad_y = min(3, max(1, (y1 - y0) // 10))
    x0 += pad_x
    x1 -= pad_x
    y0 += pad_y
    y1 -= pad_y

    if x1 - x0 < 10 or y1 - y0 < 8:
        return 0.0

    crop = gray_img[y0:y1, x0:x1]
    if cv2 is not None:
        laplacian = cv2.Laplacian(crop, cv2.CV_64F)
        return float(laplacian.var())
    dx = np.diff(crop.astype(np.float64), axis=1)
    dy = np.diff(crop.astype(np.float64), axis=0)
    return float(np.var(dx) + np.var(dy))


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
    image_rects_px: list[list[int]],
) -> list[SuspiciousVisualRegion]:
    """Identify candidate duplicate / copy-move regions on raster image areas of the page."""
    if not image_rects_px or cv2 is None:
        return []

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

    # Scale image bounding boxes to downsampled coordinates
    scaled_img_rects = [
        [r[0] // downsample_factor, r[1] // downsample_factor, r[2] // downsample_factor, r[3] // downsample_factor]
        for r in image_rects_px
    ]

    for y in range(0, sh - bs, st):
        for x in range(0, sw - bs, st):
            # Only consider blocks located inside an embedded raster image
            in_image = any(
                r[0] <= x and y >= r[1] and (x + bs) <= r[2] and (y + bs) <= r[3]
                for r in scaled_img_rects
            )
            if not in_image:
                continue

            blk = small_gray[y : y + bs, x : x + bs]
            std_dev = float(np.std(blk))
            # Must have substantial texture (exclude flat color bars, charts, white/black backgrounds)
            if std_dev < 25.0:
                continue
            # Simple 8-bin normalized intensity histogram as block descriptor
            hist = cv2.calcHist([blk], [0], None, [8], [0, 256]).flatten()
            norm = np.linalg.norm(hist)
            if norm > 0:
                hist = hist / norm
            blocks.append((x, y, hist, std_dev))

    if len(blocks) < 2:
        return []

    # Pairwise comparison with spatial distance threshold
    matches: list[tuple[int, int, int, int]] = []
    min_spatial_dist_sq = (80 // downsample_factor) ** 2
    max_matches = 8

    for i in range(len(blocks)):
        if len(matches) >= max_matches:
            break
        x1, y1, h1, _ = blocks[i]
        for j in range(i + 1, min(i + 150, len(blocks))):
            x2, y2, h2, _ = blocks[j]
            spatial_dist_sq = (x1 - x2) ** 2 + (y1 - y2) ** 2
            if spatial_dist_sq < min_spatial_dist_sq:
                continue

            # Cosine similarity between histograms
            sim = float(np.dot(h1, h2))
            if sim > 0.995:
                # Double check with direct normalized cross-correlation
                blk1 = small_gray[y1 : y1 + bs, x1 : x1 + bs]
                blk2 = small_gray[y2 : y2 + bs, x2 : x2 + bs]
                res = cv2.matchTemplate(blk1, blk2, cv2.TM_CCOEFF_NORMED)[0][0]
                if res > 0.990:
                    matches.append(
                        (
                            x1 * downsample_factor,
                            y1 * downsample_factor,
                            x2 * downsample_factor,
                            y2 * downsample_factor,
                        )
                    )
                    break

    # If meaningful duplicate blocks were found
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
                    description=f"Duplicate raster image texture candidate at ({pdf_b1[0]}, {pdf_b1[1]}) on page {page_num}",
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

    if fitz is None or cv2 is None:
        missing_deps = []
        if fitz is None:
            missing_deps.append("PyMuPDF (fitz)")
        if cv2 is None:
            missing_deps.append("OpenCV (cv2)")
        dep_str = ", ".join(missing_deps)
        logger.warning("Visual analysis skipped: required dependencies (%s) not installed.", dep_str)
        return VisualLayerResult(
            status="skipped",
            summary=f"Visual analysis skipped: required dependencies ({dep_str}) not installed in this runtime.",
            limitations=limitations + [f"Visual layer requires {dep_str} which are not installed in this environment."],
        )

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
                wb = wsp["bbox_pdf"]
                found_overlay = False
                for vsp in visible_spans:
                    vb = vsp["bbox_pdf"]
                    if _boxes_overlap(wb, vb, min_overlap_ratio=0.12):
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

                # If no collision with visible text, check if it's standalone invisible white text on light background
                if not found_overlay and len(wsp["text"].strip()) >= 1:
                    wx0, wy0, wx1, wy1 = wsp["bbox_px"]
                    wx0, wy0 = max(0, wx0), max(0, wy0)
                    wx1, wy1 = min(w_px, wx1), min(h_px, wy1)
                    mean_bg = float(np.mean(gray[wy0:wy1, wx0:wx1])) if (wx1 > wx0 and wy1 > wy0) else 255.0
                    if mean_bg >= 180.0:
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

            # Check for co-located text collision between visible spans (direct overwrite)
            for i in range(len(visible_spans)):
                for j in range(i + 1, len(visible_spans)):
                    s1 = visible_spans[i]
                    s2 = visible_spans[j]
                    if s1["text"] != s2["text"] and _boxes_overlap(s1["bbox_pdf"], s2["bbox_pdf"], min_overlap_ratio=0.20):
                        u_pdf = [
                            min(s1["bbox_pdf"][0], s2["bbox_pdf"][0]),
                            min(s1["bbox_pdf"][1], s2["bbox_pdf"][1]),
                            max(s1["bbox_pdf"][2], s2["bbox_pdf"][2]),
                            max(s1["bbox_pdf"][3], s2["bbox_pdf"][3]),
                        ]
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
                                    confidence=0.75,
                                    severity="high",
                                )
                            )

            # 3. Extract Drawings & Detect Opaque Whiteout Patches
            # Exclude whole-page backgrounds, empty graph canvases, and chart spacing without text overlays
            drawings = page.get_drawings()
            table_or_framed_rects: list[list[float]] = []
            for draw in drawings:
                r = draw.get("rect")
                if r and (r.width > 20 or r.height > 20):
                    table_or_framed_rects.append([r.x0, r.y0, r.x1, r.y1])

                fill = draw.get("fill")
                is_white_fill = False
                if fill is not None:
                    if len(fill) >= 3 and fill[0] >= 0.95 and fill[1] >= 0.95 and fill[2] >= 0.95:
                        is_white_fill = True
                    elif len(fill) == 1 and fill[0] >= 0.95:
                        is_white_fill = True

                if is_white_fill and r:
                    # Ignore canvas background or entire page card
                    if r.width >= 0.88 * page.rect.width and r.height >= 0.75 * page.rect.height:
                        continue
                    # Ignore microscopic pixel artifacts
                    if r.width < 12 or r.height < 6:
                        continue
                    # Exclude chart plot areas, large card containers, and document panels
                    # True whiteout patches are localized (height <= 60 pt for lines/numbers, or <= 120 pt and width <= 320 pt for paragraphs)
                    if r.height > 60 and (r.width > 280 or r.height > 120):
                        continue

                    r_pdf = [float(round(c, 2)) for c in [r.x0, r.y0, r.x1, r.y1]]
                    rx0, ry0, rx1, ry1 = int(r.x0 * scale), int(r.y0 * scale), int(r.x1 * scale), int(r.y1 * scale)

                    # Check if visible text spans are placed inside / over this white rectangle
                    overlying_spans = [
                        vsp
                        for vsp in visible_spans
                        if _boxes_overlap(r_pdf, vsp["bbox_pdf"], min_overlap_ratio=0.15)
                    ]

                    # If large width with multiple spans spread out across a row, it's a table row or card
                    if r.width > 360 and len(overlying_spans) >= 4:
                        continue

                    if overlying_spans:
                        max_text_size = max((s.get("size", 10.0) for s in overlying_spans), default=10.0)
                        if (max_text_size / r.height) < 0.20 and r.height > 40:
                            continue  # Text is just a tiny label inside a background box

                        sample_t = " ".join(s["text"] for s in overlying_spans[:4])
                        page_regions.append(
                            SuspiciousVisualRegion(
                                page=page_num,
                                bbox_pdf=r_pdf,
                                bbox_px=[rx0, ry0, rx1, ry1],
                                technique="background_texture",
                                description=f"Whiteout patch at ({r_pdf[0]}, {r_pdf[1]}) with overlaid altered text: '{sample_t}'",
                                confidence=0.75,
                                severity="high",
                            )
                        )
                    elif r.width <= 250 and r.height <= 45:
                        # Isolated small whiteout patch in text region (redaction / cover-up)
                        has_nearby_text = any(
                            abs(vsp["bbox_pdf"][1] - r_pdf[1]) < 25 or abs(vsp["bbox_pdf"][3] - r_pdf[3]) < 25
                            for vsp in visible_spans
                        )
                        if has_nearby_text:
                            page_regions.append(
                                SuspiciousVisualRegion(
                                    page=page_num,
                                    bbox_pdf=r_pdf,
                                    bbox_px=[rx0, ry0, rx1, ry1],
                                    technique="background_texture",
                                    description=f"Isolated whiteout patch detected in text region at ({r_pdf[0]}, {r_pdf[1]})",
                                    confidence=0.60,
                                    severity="medium",
                                )
                            )

            # 4. Text Block Edge Sharpness (Excludes table cells, borders, and bar graph numbers)
            text_blocks = page.get_text("blocks")
            edge_scores: list[tuple[float, list[float], list[int], str]] = []

            for blk in text_blocks:
                bx0, by0, bx1, by1, btext, bno, btype = blk
                btext_clean = btext.strip()
                # Require multi-word text block (at least 3 words / 15 chars) to avoid single digits and table cells
                if btype == 0 and len(btext_clean.split()) >= 3 and len(btext_clean) >= 15:
                    # Skip if enclosed or bounded by table borders
                    is_table = any(
                        abs(bx0 - tr[0]) < 6 or abs(by0 - tr[1]) < 6 or abs(bx1 - tr[2]) < 6 or abs(by1 - tr[3]) < 6
                        for tr in table_or_framed_rects
                    )
                    if is_table:
                        continue

                    px0 = int(bx0 * scale)
                    py0 = int(by0 * scale)
                    px1 = int(bx1 * scale)
                    py1 = int(by1 * scale)
                    sharpness = _compute_text_edge_sharpness(gray, [px0, py0, px1, py1])
                    if sharpness > 10.0:
                        edge_scores.append((sharpness, [bx0, by0, bx1, by1], [px0, py0, px1, py1], btext_clean))

            # Evaluate sharpness consistency across comparable body text blocks
            if len(edge_scores) >= 5:
                scores_only = [s[0] for s in edge_scores]
                median_sharpness = float(np.median(scores_only))
                q75, q25 = np.percentile(scores_only, [75, 25])
                iqr = max(25.0, q75 - q25)

                for shp, b_pdf, b_px, txt in edge_scores:
                    if (shp > median_sharpness + (3.5 * iqr) and shp > 250.0) or (
                        shp < median_sharpness - (2.5 * iqr) and shp < 20.0 and median_sharpness > 120.0
                    ):
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

            # 5. Copy-Move / Duplicate Region Detection (Only on embedded raster images)
            page_images = page.get_images(full=True)
            if page_images:
                img_rects_px: list[list[int]] = []
                for img_info in page_images:
                    xref = img_info[0]
                    for ir in page.get_image_rects(xref):
                        if ir.width >= 40 and ir.height >= 40:
                            img_rects_px.append([
                                int(ir.x0 * scale),
                                int(ir.y0 * scale),
                                int(ir.x1 * scale),
                                int(ir.y1 * scale),
                            ])
                if img_rects_px:
                    copy_move_candidates = _detect_copy_move_regions(gray, scale, page_num, img_rects_px)
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

            # 7. Generate Visual Overlay Image with Clean Badges
            overlay_rgb = img_rgb.copy()
            for reg in page_regions:
                rx0, ry0, rx1, ry1 = reg.bbox_px
                rx0, ry0 = max(0, rx0), max(0, ry0)
                rx1, ry1 = min(w_px - 1, rx1), min(h_px - 1, ry1)
                if rx1 <= rx0 or ry1 <= ry0:
                    continue

                # Color based on severity: Red for medium/high, Amber for low
                box_color = (239, 68, 68) if reg.severity in ("medium", "high") else (245, 158, 11)

                if cv2 is not None:
                    cv2.rectangle(overlay_rgb, (rx0, ry0), (rx1, ry1), box_color, 3)

                    # Clean readable badge
                    label_map = {
                        "white_text_layer": "WHITE TEXT MASK",
                        "hidden_white_text": "HIDDEN WHITE TEXT",
                        "background_texture": "WHITEOUT EDIT",
                        "text_collision": "TEXT OVERWRITE",
                        "copy_move": "DUPLICATE REGION",
                        "text_edge": "TEXT EDGE ANOMALY",
                        "annotation_overlay": "ANNOTATION OVERLAY",
                    }
                    label = label_map.get(reg.technique, reg.technique.replace("_", " ").upper())

                    font_scale = 0.42
                    font_thickness = 1
                    (text_w, text_h), baseline = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, font_scale, font_thickness)
                    badge_y0 = max(0, ry0 - text_h - 8)
                    badge_y1 = badge_y0 + text_h + 6
                    badge_x1 = min(w_px - 1, rx0 + text_w + 10)
                    cv2.rectangle(overlay_rgb, (rx0, badge_y0), (badge_x1, badge_y1), box_color, -1)
                    cv2.putText(
                        overlay_rgb,
                        label,
                        (rx0 + 5, badge_y0 + text_h + 3),
                        cv2.FONT_HERSHEY_SIMPLEX,
                        font_scale,
                        (255, 255, 255),
                        font_thickness,
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
