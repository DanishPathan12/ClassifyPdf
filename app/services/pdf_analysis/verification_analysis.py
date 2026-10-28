"""Layer 3: Independent Verification.

Validates stronger forms of evidence when available:
- Digital signature cryptographic validity, ByteRange integrity, and post-signing alterations.
- Trusted-original PDF structural, text, and visual pixel diff comparison.
- Reference SHA-256 hash integrity comparison.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import difflib
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

from app.schemas.analysis import ForensicFinding, SignatureValidationResult
from app.services.pdf_analysis.pdf_loader import LoadedPdf, load_pdf
from app.services.pdf_analysis.signature_forensics import analyze_digital_signatures_forensics

logger = logging.getLogger("pdf_analyser.verification_analysis")


@dataclass
class HashVerificationResult:
    """Result of comparing document SHA-256 against an expected reference hash."""

    status: str  # verified_match | hash_mismatch | reference_not_provided
    computed_hash: str
    expected_hash: str | None = None
    matches: bool | None = None
    description: str = ""
    limitations: list[str] = field(default_factory=list)


@dataclass
class PageDiffRecord:
    """Comparison diff between an original page and candidate page."""

    page_number: int
    status: str  # modified | identical | added | removed
    added_text: list[str] = field(default_factory=list)
    removed_text: list[str] = field(default_factory=list)
    changed_pixel_count: int = 0
    diff_image_base64: str | None = None  # data:image/png;base64,...
    bounding_boxes: list[list[float]] = field(default_factory=list)


@dataclass
class OriginalComparisonResult:
    """Outcome of comparing submitted document against a trusted original PDF."""

    status: str  # completed | unavailable | failed
    differences_detected: bool = False
    original_filename: str | None = None
    original_sha256: str | None = None
    page_count_comparison: dict[str, Any] = field(default_factory=dict)
    page_diffs: list[PageDiffRecord] = field(default_factory=list)
    summary: str = ""
    limitations: list[str] = field(default_factory=list)


@dataclass
class VerificationLayerResult:
    """Consolidated outcome of Layer 3 Independent Verification."""

    status: str  # completed | partial | unavailable
    summary: str
    signature_results: list[SignatureValidationResult] = field(default_factory=list)
    original_comparison: OriginalComparisonResult | None = None
    hash_verification: HashVerificationResult | None = None
    findings: list[ForensicFinding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def _mat_to_base64(mat_rgb: np.ndarray) -> str:
    """Convert an RGB NumPy image to a data:image/png;base64 URI."""
    mat_bgr = cv2.cvtColor(mat_rgb, cv2.COLOR_RGB2BGR)
    success, buffer = cv2.imencode(".png", mat_bgr)
    if not success:
        return ""
    b64 = base64.b64encode(buffer).decode("ascii")
    return f"data:image/png;base64,{b64}"


def verify_hash_integrity(
    computed_hash: str,
    expected_hash: str | None = None,
) -> HashVerificationResult:
    """Compare computed file SHA-256 against an expected reference hash if provided."""
    if not expected_hash:
        return HashVerificationResult(
            status="reference_not_provided",
            computed_hash=computed_hash,
            expected_hash=None,
            matches=None,
            description="Document SHA-256 hash was calculated for reference tracking. No pre-recorded reference hash was supplied for verification.",
            limitations=[
                "A hash generated for the first time during analysis establishes file identity, but does not prove historical authenticity without a pre-existing trusted record.",
            ],
        )

    clean_computed = computed_hash.strip().lower()
    clean_expected = expected_hash.strip().lower()
    matches = clean_computed == clean_expected

    if matches:
        desc = "Document SHA-256 exactly matches the trusted reference hash. Byte-level integrity confirmed."
        status = "verified_match"
    else:
        desc = (
            f"Document SHA-256 ({clean_computed[:16]}...) does NOT match the expected reference hash "
            f"({clean_expected[:16]}...). The file contents have been modified or re-saved."
        )
        status = "hash_mismatch"

    return HashVerificationResult(
        status=status,
        computed_hash=clean_computed,
        expected_hash=clean_expected,
        matches=matches,
        description=desc,
        limitations=[
            "Cryptographic hashing guarantees exact byte identity; even benign re-saving without content changes produces a completely different SHA-256 hash.",
        ],
    )


def compare_against_trusted_original(
    candidate_pdf: LoadedPdf,
    original_bytes: bytes | None,
    original_filename: str = "trusted_original.pdf",
    render_dpi: int = 120,
) -> OriginalComparisonResult:
    """Perform structural, text, and visual pixel diff between trusted original and candidate."""
    if original_bytes is None or len(original_bytes) == 0:
        return OriginalComparisonResult(
            status="unavailable",
            differences_detected=False,
            summary="Trusted-original comparison unavailable; no reference original PDF was supplied. Single-PDF forensic analysis performed.",
            limitations=[
                "Without a reference original, analysis relies solely on internal structural anomalies, metadata, and visual heuristics.",
            ],
        )

    if fitz is None or cv2 is None:
        missing_deps = []
        if fitz is None:
            missing_deps.append("PyMuPDF (fitz)")
        if cv2 is None:
            missing_deps.append("OpenCV (cv2)")
        dep_str = ", ".join(missing_deps)
        return OriginalComparisonResult(
            status="unavailable",
            differences_detected=False,
            summary=f"Trusted original comparison unavailable: required libraries ({dep_str}) not installed in this runtime.",
            limitations=limitations + [f"Original comparison requires {dep_str}."],
        )

    orig_loaded = load_pdf(original_bytes, filename=original_filename)
    if not orig_loaded.is_valid:
        return OriginalComparisonResult(
            status="failed",
            summary=f"Trusted original PDF could not be parsed: {orig_loaded.error_message}",
            limitations=["The uploaded reference original document was malformed or password-protected."],
        )

    page_diffs: list[PageDiffRecord] = []
    differences_detected = False

    try:
        doc_orig = fitz.open(stream=orig_loaded.file_bytes, filetype="pdf")
        doc_cand = fitz.open(stream=candidate_pdf.file_bytes, filetype="pdf")
    except Exception as e:
        logger.error("Failed opening documents for comparison: %s", e)
        return OriginalComparisonResult(
            status="failed",
            summary=f"Comparison failed during PDF loading: {e}",
            limitations=[f"Comparison engine exception: {e}"],
        )

    orig_pages = len(doc_orig)
    cand_pages = len(doc_cand)
    scale = render_dpi / 72.0

    page_comparison_meta = {
        "original_pages": orig_pages,
        "candidate_pages": cand_pages,
        "match": orig_pages == cand_pages,
    }
    if orig_pages != cand_pages:
        differences_detected = True

    max_pages = max(orig_pages, cand_pages)

    for p_idx in range(max_pages):
        p_num = p_idx + 1

        if p_idx >= orig_pages:
            # Page added in candidate
            page_diffs.append(
                PageDiffRecord(
                    page_number=p_num,
                    status="added",
                    added_text=["[Page added in candidate document]"],
                )
            )
            differences_detected = True
            continue

        if p_idx >= cand_pages:
            # Page removed in candidate
            page_diffs.append(
                PageDiffRecord(
                    page_number=p_num,
                    status="removed",
                    removed_text=["[Page deleted from original document]"],
                )
            )
            differences_detected = True
            continue

        # Both pages exist: compare text and rendered pixels
        page_orig = doc_orig[p_idx]
        page_cand = doc_cand[p_idx]

        orig_words = [w[4] for w in page_orig.get_text("words")]
        cand_words = [w[4] for w in page_cand.get_text("words")]

        sm = difflib.SequenceMatcher(None, orig_words, cand_words)
        added_words: list[str] = []
        removed_words: list[str] = []

        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag in ("replace", "delete"):
                removed_words.extend(orig_words[i1:i2])
            if tag in ("replace", "insert"):
                added_words.extend(cand_words[j1:j2])

        # Visual pixel diff at render_dpi
        pix_orig = page_orig.get_pixmap(dpi=render_dpi, alpha=False)
        pix_cand = page_cand.get_pixmap(dpi=render_dpi, alpha=False)

        im_orig = np.frombuffer(pix_orig.samples, dtype=np.uint8).reshape((pix_orig.height, pix_orig.width, pix_orig.n))
        im_cand = np.frombuffer(pix_cand.samples, dtype=np.uint8).reshape((pix_cand.height, pix_cand.width, pix_cand.n))

        if pix_orig.n == 4:
            im_orig = cv2.cvtColor(im_orig, cv2.COLOR_RGBA2RGB)
        if pix_cand.n == 4:
            im_cand = cv2.cvtColor(im_cand, cv2.COLOR_RGBA2RGB)

        # Handle dimension mismatch by resizing canvas
        target_h = max(im_orig.shape[0], im_cand.shape[0])
        target_w = max(im_orig.shape[1], im_cand.shape[1])

        canvas_orig = np.full((target_h, target_w, 3), 255, dtype=np.uint8)
        canvas_cand = np.full((target_h, target_w, 3), 255, dtype=np.uint8)

        canvas_orig[: im_orig.shape[0], : im_orig.shape[1]] = im_orig
        canvas_cand[: im_cand.shape[0], : im_cand.shape[1]] = im_cand

        diff = cv2.absdiff(canvas_orig, canvas_cand)
        gray_diff = cv2.cvtColor(diff, cv2.COLOR_RGB2GRAY)
        _, thresh = cv2.threshold(gray_diff, 25, 255, cv2.THRESH_BINARY)

        changed_px = int(np.count_nonzero(thresh))

        diff_bboxes: list[list[float]] = []
        diff_b64: str | None = None

        if changed_px > 50:
            differences_detected = True
            contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            diff_vis = canvas_cand.copy()

            for cnt in contours:
                x, y, w, h = cv2.boundingRect(cnt)
                if w > 4 and h > 4:
                    # Draw red bounding box on diff visualization
                    cv2.rectangle(diff_vis, (x, y), (x + w, y + h), (239, 68, 68), 2)
                    pdf_bbox = [
                        round(x / scale, 2),
                        round(y / scale, 2),
                        round((x + w) / scale, 2),
                        round((y + h) / scale, 2),
                    ]
                    diff_bboxes.append(pdf_bbox)

            diff_b64 = _mat_to_base64(diff_vis)
            p_status = "modified"
        else:
            p_status = "identical"

        page_diffs.append(
            PageDiffRecord(
                page_number=p_num,
                status=p_status,
                added_text=added_words[:15],
                removed_text=removed_words[:15],
                changed_pixel_count=changed_px,
                diff_image_base64=diff_b64,
                bounding_boxes=diff_bboxes[:10],
            )
        )

    doc_orig.close()
    doc_cand.close()

    if differences_detected:
        mod_count = sum(1 for p in page_diffs if p.status in ("modified", "added", "removed"))
        summary = (
            f"Confirmed differences detected between candidate and trusted original document across {mod_count} page(s). "
            "Inserted, altered, or removed elements were isolated."
        )
    else:
        summary = "Candidate document matches trusted original page count, text content, and visual rendering with no discrepancies."

    return OriginalComparisonResult(
        status="completed",
        differences_detected=differences_detected,
        original_filename=original_filename,
        original_sha256=orig_loaded.sha256,
        page_count_comparison=page_comparison_meta,
        page_diffs=page_diffs,
        summary=summary,
        limitations=[
            "Visual pixel differences can arise from subtle font rendering, antialiasing differences, or different PDF generation engines without deliberate alteration.",
        ],
    )


def analyze_verification_layer(
    loaded_pdf: LoadedPdf,
    original_bytes: bytes | None = None,
    original_filename: str = "trusted_original.pdf",
    expected_hash: str | None = None,
) -> VerificationLayerResult:
    """Execute complete Layer 3 independent verification analysis."""
    findings: list[ForensicFinding] = []
    limitations: list[str] = [
        "Cryptographic digital signatures only protect documents where a signing entity applied an asymmetric signature before modification.",
        "A certificate cannot be declared trusted unless a trusted root certificate authority chain is verifiable.",
    ]

    # 1. Digital Signatures Verification (via signature_forensics module)
    sig_results: list[SignatureValidationResult] = []
    sig_status = "no_signatures_found"
    try:
        sig_outcome = analyze_digital_signatures_forensics(loaded_pdf)
        sig_results = sig_outcome.signature_results
        findings.extend(sig_outcome.findings)
        limitations.extend([l for l in sig_outcome.limitations if l not in limitations])
        sig_status = sig_outcome.module_status
    except Exception as sig_err:
        logger.warning("Digital signature forensic error: %s", sig_err)
        limitations.append(f"Signature evaluation error: {sig_err}")

    # 2. Trusted Original Comparison
    orig_comp = compare_against_trusted_original(
        candidate_pdf=loaded_pdf,
        original_bytes=original_bytes,
        original_filename=original_filename,
    )
    if orig_comp.differences_detected:
        findings.append(
            ForensicFinding(
                code="VERIFY_ORIGINAL_DIFF_DETECTED",
                category="confirmed",
                domain="digital_signatures",
                severity="high",
                confidence=0.95,
                description=orig_comp.summary,
                evidence={
                    "original_sha256": orig_comp.original_sha256,
                    "candidate_sha256": loaded_pdf.sha256,
                    "pages_modified": [p.page_number for p in orig_comp.page_diffs if p.status != "identical"],
                },
                limitations=orig_comp.limitations,
            )
        )
    limitations.extend([l for l in orig_comp.limitations if l not in limitations])

    # 3. Hash Verification
    hash_result = verify_hash_integrity(loaded_pdf.sha256, expected_hash)
    if hash_result.matches is False:
        findings.append(
            ForensicFinding(
                code="VERIFY_REFERENCE_HASH_MISMATCH",
                category="confirmed",
                domain="digital_signatures",
                severity="high",
                confidence=0.90,
                description=hash_result.description,
                evidence={
                    "computed_hash": hash_result.computed_hash,
                    "expected_hash": hash_result.expected_hash,
                },
                limitations=hash_result.limitations,
            )
        )
    elif hash_result.matches is True:
        findings.append(
            ForensicFinding(
                code="VERIFY_REFERENCE_HASH_CONFIRMED",
                category="confirmed",
                domain="digital_signatures",
                severity="info",
                confidence=0.95,
                description=hash_result.description,
                evidence={
                    "computed_hash": hash_result.computed_hash,
                    "expected_hash": hash_result.expected_hash,
                },
                limitations=hash_result.limitations,
            )
        )
    limitations.extend([l for l in hash_result.limitations if l not in limitations])

    # Build Layer Summary
    has_signatures = len(sig_results) > 0
    has_original = orig_comp.status == "completed"

    if orig_comp.differences_detected:
        summary = f"Independent verification confirmed modifications when compared against trusted original ({orig_comp.original_filename})."
        layer_status = "completed"
    elif hash_result.matches is False:
        summary = "Independent verification confirmed integrity failure: document SHA-256 hash does not match the reference hash."
        layer_status = "completed"
    elif any(f.category == "confirmed" and f.severity == "high" for f in findings):
        summary = "Independent verification confirmed cryptographic signature failure or unauthorized post-signature changes."
        layer_status = "completed"
    elif has_signatures:
        summary = f"Digital signature verification completed: {len(sig_results)} signature(s) analyzed."
        layer_status = "completed"
    elif has_original:
        summary = "Trusted original comparison completed with zero discrepancies detected."
        layer_status = "completed"
    else:
        summary = "Independent verification methods (trusted original and digital signatures) were not present or available for this document."
        layer_status = "unavailable"

    return VerificationLayerResult(
        status=layer_status,
        summary=summary,
        signature_results=sig_results,
        original_comparison=orig_comp,
        hash_verification=hash_result,
        findings=findings,
        limitations=limitations,
    )

