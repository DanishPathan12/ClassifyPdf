"""Shared utilities for PDF inspection, text extraction, geometry, and layout analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
import io
import logging
from typing import Any

from pdfminer.high_level import extract_pages
from pdfminer.layout import LTAnno, LTChar, LTFigure, LTImage, LTPage, LTTextBox, LTTextLine

from app.schemas.analysis import ChangeLocation, RevisionChange

logger = logging.getLogger("pdf_analyser.shared_utils")


@dataclass
class TextSpan:
    """An individual text span or word with positional and font metadata."""

    text: str
    bbox: list[float]  # [x0, y0, x1, y1]
    font_name: str = "unknown"
    font_size: float = 10.0
    is_bold: bool = False
    is_italic: bool = False
    color: Any = None
    page: int = 1


@dataclass
class ImageElement:
    """An image element extracted from a PDF page."""

    bbox: list[float]  # [x0, y0, x1, y1]
    page: int = 1


@dataclass
class PageLayout:
    """Consolidated layout objects for a single PDF page."""

    page_num: int
    width: float = 612.0
    height: float = 792.0
    rotation: int = 0
    text_lines: list[TextSpan] = field(default_factory=list)
    words: list[TextSpan] = field(default_factory=list)
    images: list[ImageElement] = field(default_factory=list)


def boxes_intersect(
    box1: list[float],
    box2: list[float],
    min_overlap_ratio: float = 0.3,
) -> bool:
    """Determine whether two bounding boxes intersect significantly.

    Args:
        box1: [x0, y0, x1, y1]
        box2: [x0, y0, x1, y1]
        min_overlap_ratio: Minimum ratio of intersection area relative to smaller box.

    Returns:
        True if intersection area ratio exceeds min_overlap_ratio.
    """
    x_left = max(box1[0], box2[0])
    y_bottom = max(box1[1], box2[1])
    x_right = min(box1[2], box2[2])
    y_top = min(box1[3], box2[3])

    if x_right <= x_left or y_top <= y_bottom:
        return False

    intersection_area = (x_right - x_left) * (y_top - y_bottom)
    area1 = max(0.0, (box1[2] - box1[0]) * (box1[3] - box1[1]))
    area2 = max(0.0, (box2[2] - box2[0]) * (box2[3] - box2[1]))
    min_area = min(area1, area2)

    if min_area <= 0.0:
        return False

    return (intersection_area / min_area) >= min_overlap_ratio


def box_contains(
    container: list[float],
    item: list[float],
    tolerance: float = 2.0,
) -> bool:
    """Check if container box geometrically encloses item box within tolerance."""
    return (
        item[0] >= container[0] - tolerance
        and item[1] >= container[1] - tolerance
        and item[2] <= container[2] + tolerance
        and item[3] <= container[3] + tolerance
    )


def extract_pdf_layout(pdf_bytes: bytes) -> list[PageLayout]:
    """Extract page dimensions, text lines, words, fonts, and images from PDF bytes.

    Uses PyMuPDF if functional; falls back to pdfminer.six for pure-Python execution.
    """
    # Attempt PyMuPDF first if available and unblocked
    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        pages: list[PageLayout] = []
        for p_idx, page in enumerate(doc, start=1):
            rect = page.rect
            layout = PageLayout(
                page_num=p_idx,
                width=float(rect.width),
                height=float(rect.height),
                rotation=page.rotation,
            )

            # Extract words: (x0, y0, x1, y1, word, block_no, line_no, word_no)
            words_data = page.get_text("words")
            for w in words_data:
                w_text = str(w[4]).strip()
                if w_text:
                    layout.words.append(
                        TextSpan(
                            text=w_text,
                            bbox=[round(float(c), 2) for c in w[:4]],
                            page=p_idx,
                        )
                    )

            # Extract text blocks / lines with font details
            text_dict = page.get_text("dict")
            for block in text_dict.get("blocks", []):
                if block.get("type") == 0:  # text
                    for line in block.get("lines", []):
                        spans = line.get("spans", [])
                        line_text = "".join(s.get("text", "") for s in spans).strip()
                        if line_text:
                            primary_font = spans[0].get("font", "unknown") if spans else "unknown"
                            primary_size = round(float(spans[0].get("size", 10.0)), 2) if spans else 10.0
                            is_bold = bool(spans[0].get("flags", 0) & 2) if spans else False
                            is_italic = bool(spans[0].get("flags", 0) & 1) if spans else False
                            layout.text_lines.append(
                                TextSpan(
                                    text=line_text,
                                    bbox=[round(float(c), 2) for c in line.get("bbox", [0, 0, 0, 0])],
                                    font_name=primary_font,
                                    font_size=primary_size,
                                    is_bold=is_bold,
                                    is_italic=is_italic,
                                    page=p_idx,
                                )
                            )
                elif block.get("type") == 1:  # image
                    layout.images.append(
                        ImageElement(
                            bbox=[round(float(c), 2) for c in block.get("bbox", [0, 0, 0, 0])],
                            page=p_idx,
                        )
                    )
            pages.append(layout)
        doc.close()
        return pages
    except Exception as e:
        logger.debug("PyMuPDF unavailable or blocked (%s); using pdfminer.six layout extractor", e)

    # Fallback to pure-python pdfminer.six
    pages = []
    try:
        buffer = io.BytesIO(pdf_bytes)
        for page_idx, page_layout in enumerate(extract_pages(buffer), start=1):
            p_width = float(getattr(page_layout, "width", 612.0))
            p_height = float(getattr(page_layout, "height", 792.0))
            layout = PageLayout(
                page_num=page_idx,
                width=p_width,
                height=p_height,
                rotation=0,
            )
            _extract_elements_pdfminer(page_layout, layout, page_idx)
            pages.append(layout)
    except Exception as err:
        logger.warning("Layout extraction failed with pdfminer: %s", err)

    return pages


def _extract_elements_pdfminer(container: Any, layout: PageLayout, page_num: int) -> None:
    """Recursively collect text lines, words, fonts, and images from pdfminer container."""
    for element in container:
        if isinstance(element, (LTTextBox, LTTextLine)):
            # If it's a box with multiple lines, recurse into lines
            if isinstance(element, LTTextBox):
                for line in element:
                    if isinstance(line, LTTextLine):
                        _process_text_line_pdfminer(line, layout, page_num)
            else:
                _process_text_line_pdfminer(element, layout, page_num)
        elif isinstance(element, LTImage):
            bbox = [round(float(c), 2) for c in element.bbox]
            layout.images.append(ImageElement(bbox=bbox, page=page_num))
        elif isinstance(element, LTFigure):
            _extract_elements_pdfminer(element, layout, page_num)


def _process_text_line_pdfminer(line: LTTextLine, layout: PageLayout, page_num: int) -> None:
    """Extract full line and individual words with fonts from an LTTextLine."""
    line_text = line.get_text().strip()
    if not line_text:
        return

    # Extract character properties
    fonts: list[str] = []
    sizes: list[float] = []
    current_word_chars: list[LTChar] = []

    for item in line:
        if isinstance(item, LTChar):
            fonts.append(item.fontname)
            sizes.append(round(item.size, 2))
            current_word_chars.append(item)
        elif isinstance(item, LTAnno):
            anno_text = item.get_text()
            if anno_text in (" ", "\t", "\n", "\r") and current_word_chars:
                _commit_word_pdfminer(current_word_chars, layout, page_num)
                current_word_chars = []

    if current_word_chars:
        _commit_word_pdfminer(current_word_chars, layout, page_num)

    primary_font = fonts[0] if fonts else "unknown"
    primary_size = sizes[0] if sizes else 10.0
    is_bold = "bold" in primary_font.lower() or "black" in primary_font.lower()
    is_italic = "italic" in primary_font.lower() or "oblique" in primary_font.lower()

    layout.text_lines.append(
        TextSpan(
            text=line_text,
            bbox=[round(float(c), 2) for c in line.bbox],
            font_name=primary_font,
            font_size=primary_size,
            is_bold=is_bold,
            is_italic=is_italic,
            page=page_num,
        )
    )


def _commit_word_pdfminer(chars: list[LTChar], layout: PageLayout, page_num: int) -> None:
    """Build a TextSpan word from an accumulated list of characters."""
    word_text = "".join(c.get_text() for c in chars).strip()
    if not word_text:
        return

    x0 = min(c.bbox[0] for c in chars)
    y0 = min(c.bbox[1] for c in chars)
    x1 = max(c.bbox[2] for c in chars)
    y1 = max(c.bbox[3] for c in chars)

    font_name = chars[0].fontname
    font_size = round(chars[0].size, 2)
    is_bold = "bold" in font_name.lower() or "black" in font_name.lower()
    is_italic = "italic" in font_name.lower() or "oblique" in font_name.lower()

    layout.words.append(
        TextSpan(
            text=word_text,
            bbox=[round(float(x0), 2), round(float(y0), 2), round(float(x1), 2), round(float(y1), 2)],
            font_name=font_name,
            font_size=font_size,
            is_bold=is_bold,
            is_italic=is_italic,
            page=page_num,
        )
    )


def compare_revisions_content(
    old_pages: list[PageLayout],
    new_pages: list[PageLayout],
) -> list[RevisionChange]:
    """Compare page layouts between two revision states and identify additions/removals/modifications."""
    changes: list[RevisionChange] = []

    old_page_count = len(old_pages)
    new_page_count = len(new_pages)

    # Check page count differences
    if new_page_count > old_page_count:
        for p in range(old_page_count + 1, new_page_count + 1):
            changes.append(
                RevisionChange(
                    type="page_added",
                    page=p,
                    old_text=None,
                    new_text=f"Page {p} added in newer revision",
                    location=None,
                    evidence="Page count increased from older to newer revision",
                )
            )
    elif new_page_count < old_page_count:
        for p in range(new_page_count + 1, old_page_count + 1):
            changes.append(
                RevisionChange(
                    type="page_removed",
                    page=p,
                    old_text=f"Page {p} present in older revision",
                    new_text=None,
                    location=None,
                    evidence="Page count decreased in newer revision",
                )
            )

    # Compare page-by-page text content
    common_page_count = min(old_page_count, new_page_count)
    for p_idx in range(common_page_count):
        old_page = old_pages[p_idx]
        new_page = new_pages[p_idx]
        page_num = p_idx + 1

        old_lines = list(old_page.text_lines)
        new_lines = list(new_page.text_lines)

        # Match lines by text and approximate position
        matched_new_indices: set[int] = set()
        matched_old_indices: set[int] = set()

        # Pass 1: exact text matches
        for n_i, n_line in enumerate(new_lines):
            for o_i, o_line in enumerate(old_lines):
                if o_i in matched_old_indices:
                    continue
                if n_line.text == o_line.text:
                    matched_new_indices.add(n_i)
                    matched_old_indices.add(o_i)
                    break

        # Pass 2: check remaining lines for text modifications in overlapping positions
        for n_i, n_line in enumerate(new_lines):
            if n_i in matched_new_indices:
                continue
            for o_i, o_line in enumerate(old_lines):
                if o_i in matched_old_indices:
                    continue
                # If they occupy nearly the same location, it's a text_changed event
                if boxes_intersect(n_line.bbox, o_line.bbox, min_overlap_ratio=0.2):
                    matched_new_indices.add(n_i)
                    matched_old_indices.add(o_i)
                    changes.append(
                        RevisionChange(
                            type="text_changed",
                            page=page_num,
                            old_text=o_line.text,
                            new_text=n_line.text,
                            location=ChangeLocation(bbox=n_line.bbox),
                            evidence="Line replaced in corresponding bounding box between revisions",
                        )
                    )
                    break

        # Pass 3: remaining new lines are text_added
        for n_i, n_line in enumerate(new_lines):
            if n_i not in matched_new_indices:
                changes.append(
                    RevisionChange(
                        type="text_added",
                        page=page_num,
                        old_text=None,
                        new_text=n_line.text,
                        location=ChangeLocation(bbox=n_line.bbox),
                        evidence="Text line present in newer revision but absent in older revision",
                    )
                )

        # Pass 4: remaining old lines are text_removed
        for o_i, o_line in enumerate(old_lines):
            if o_i not in matched_old_indices:
                changes.append(
                    RevisionChange(
                        type="text_removed",
                        page=page_num,
                        old_text=o_line.text,
                        new_text=None,
                        location=ChangeLocation(bbox=o_line.bbox),
                        evidence="Text line present in older revision but removed in newer revision",
                    )
                )

    return changes

