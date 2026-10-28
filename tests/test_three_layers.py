"""Tests for Three-Layer Forensic Tampering Detection System.

Covers:
1. Layer 1: Structural Analysis (Text styling, whiteout patches, images, overlays)
2. Layer 2: Visual Analysis (DPI rendering, text-edges, texture drop, overlays)
3. Layer 3: Independent Verification (Signatures, trusted original diff, hash integrity)
4. End-to-End Three-Layer Orchestration & API integration
"""

from __future__ import annotations

import fitz  # PyMuPDF
from fastapi.testclient import TestClient

from app.main import app
from app.services.pdf_analysis.pdf_loader import load_pdf
from app.services.pdf_analysis.structural_analysis import analyze_structural_layer
from app.services.pdf_analysis.verification_analysis import (
    analyze_verification_layer,
    compare_against_trusted_original,
    verify_hash_integrity,
)
from app.services.pdf_analysis.visual_analysis import analyze_visual_layer
from tests.fixtures.pdf_generators import make_normal_pdf

client = TestClient(app)


def _make_pdf_with_whiteout_overlay() -> bytes:
    """Generate a PDF containing an opaque white vector rectangle covered by new text (Sejda pattern)."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)

    # Base background text
    page.insert_text(fitz.Point(72, 100), "Official Bank Statement - Account Summary", fontsize=14)
    page.insert_text(fitz.Point(72, 140), "Original Balance: $1,250.00", fontsize=11)

    # Whiteout patch covering the original balance
    white_rect = fitz.Rect(160, 125, 260, 150)
    page.draw_rect(white_rect, color=(1.0, 1.0, 1.0), fill=(1.0, 1.0, 1.0))

    # Overlying modified text typed into the whiteout area
    page.insert_text(fitz.Point(165, 140), "$98,500.00", fontsize=11, color=(0, 0, 0))

    data = doc.tobytes()
    doc.close()
    return data


def _make_pdf_with_white_text_heading_overlay() -> bytes:
    """Generate a PDF containing an original heading, an opaque white text masking layer, and altered text."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)

    # 1. Original heading in black
    page.insert_text(fitz.Point(72, 100), "ORIGINAL EMPLOYMENT CONTRACT", fontsize=18, color=(0, 0, 0))

    # 2. White text layer placed directly over the heading as a mask/whiteout
    page.insert_text(fitz.Point(72, 100), "ORIGINAL EMPLOYMENT CONTRACT", fontsize=18, color=(1, 1, 1))

    # 3. New altered heading typed on top of the white text layer
    page.insert_text(fitz.Point(72, 100), "ALTERED CONSULTING AGREEMENT", fontsize=18, color=(0, 0, 0))

    data = doc.tobytes()
    doc.close()
    return data


def _make_pdf_with_inconsistent_fonts() -> bytes:
    """Generate a PDF where 95% is Helvetica but one isolated number switches to Times-Bold."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)

    # Dominant text
    for y in range(100, 300, 25):
        page.insert_text(
            fitz.Point(72, y),
            f"Standard report paragraph line {y} generated with normal corporate styling and formatting.",
            fontname="helv",
            fontsize=10,
        )

    # Abrupt isolated font switch
    page.insert_text(
        fitz.Point(200, 350),
        "$999,999.00",
        fontname="times-bold",
        fontsize=14,
    )

    data = doc.tobytes()
    doc.close()
    return data


# ==============================================================================
# Layer 1: Structural Analysis Tests
# ==============================================================================


def test_structural_layer_detects_whiteout_rectangle() -> None:
    """Layer 1 must detect opaque white vector rectangles directly covered by text."""
    pdf_bytes = _make_pdf_with_whiteout_overlay()
    loaded = load_pdf(pdf_bytes, filename="whiteout_test.pdf")

    res = analyze_structural_layer(loaded)
    assert res.status == "completed"

    whiteout_findings = [f for f in res.findings if f.code == "STRUCT_WHITEOUT_RECTANGLE_OVERLAY"]
    assert len(whiteout_findings) >= 1
    f = whiteout_findings[0]
    assert f.severity == "medium"
    assert f.confidence >= 0.60
    assert "98,500" in str(f.evidence.get("sample_overlaid_text", ""))


def test_structural_layer_clean_pdf() -> None:
    """Layer 1 on standard clean document must complete with zero whiteout patches."""
    pdf_bytes = make_normal_pdf(text="Untouched legal contract between party A and party B.")
    loaded = load_pdf(pdf_bytes, filename="clean.pdf")

    res = analyze_structural_layer(loaded)
    assert res.status == "completed"
    assert len(res.whiteout_patches) == 0
    assert not any(f.code == "STRUCT_WHITEOUT_RECTANGLE_OVERLAY" for f in res.findings)


def test_structural_layer_extracts_spans_and_images() -> None:
    """Layer 1 accurately records text spans and bounding boxes."""
    pdf_bytes = _make_pdf_with_inconsistent_fonts()
    loaded = load_pdf(pdf_bytes, filename="spans_test.pdf")

    res = analyze_structural_layer(loaded)
    assert res.status == "completed"
    assert len(res.text_spans) >= 5
    span = res.text_spans[0]
    assert span.page == 1
    assert len(span.bbox) == 4
    assert span.font_size > 0


# ==============================================================================
# Layer 2: Visual & Pixel-Level Analysis Tests
# ==============================================================================


def test_visual_layer_renders_page_previews() -> None:
    """Layer 2 renders pages and produces base64 PNG data URLs."""
    pdf_bytes = make_normal_pdf(text="Page rendering test.")
    loaded = load_pdf(pdf_bytes, filename="visual_test.pdf")

    res = analyze_visual_layer(loaded, dpi=120)
    assert res.status == "completed"
    assert len(res.page_previews) >= 1

    preview = res.page_previews[0]
    assert preview.page_number == 1
    assert preview.width_px > 0
    assert preview.height_px > 0
    assert preview.original_image_base64.startswith("data:image/png;base64,")
    assert preview.overlay_image_base64.startswith("data:image/png;base64,")


def test_visual_layer_detects_whiteout_texture_patch() -> None:
    """Layer 2 identifies rectangular flat texture drop patches."""
    pdf_bytes = _make_pdf_with_whiteout_overlay()
    loaded = load_pdf(pdf_bytes, filename="visual_whiteout.pdf")

    res = analyze_visual_layer(loaded, dpi=120)
    assert res.status == "completed"
    preview = res.page_previews[0]
    assert len(preview.suspicious_regions) >= 1


def test_visual_and_structural_detect_white_text_layer_overlay() -> None:
    """Both Layer 1 and Layer 2 must detect white text masking layers in headings and flag overlays."""
    pdf_bytes = _make_pdf_with_white_text_heading_overlay()
    loaded = load_pdf(pdf_bytes, filename="white_text_heading.pdf")

    # Layer 1: Structural Analysis
    struct_res = analyze_structural_layer(loaded)
    assert struct_res.status == "completed"
    struct_findings = [f for f in struct_res.findings if f.code == "STRUCT_WHITE_TEXT_LAYER_OVERLAY"]
    assert len(struct_findings) >= 1
    assert struct_findings[0].severity == "high"
    assert struct_findings[0].confidence >= 0.70

    # Layer 2: Visual Analysis
    vis_res = analyze_visual_layer(loaded, dpi=120)
    assert vis_res.status == "completed"
    vis_findings = [f for f in vis_res.findings if f.code == "VISUAL_WHITE_TEXT_LAYER_OVERLAY"]
    assert len(vis_findings) >= 1
    assert vis_findings[0].severity == "high"

    # Must generate preview with suspicious region highlighted
    assert len(vis_res.page_previews) >= 1
    preview = vis_res.page_previews[0]
    white_regions = [r for r in preview.suspicious_regions if r.technique == "white_text_layer"]
    assert len(white_regions) >= 1
    assert white_regions[0].severity == "high"

    # End-to-end API test: Must produce likely_edited verdict and populate page_previews
    resp = client.post(
        "/analyze",
        files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "likely_edited"
    assert data["edit_detected"] is True
    assert data["overall_assessment"]["status"] == "suspicious_indicators_detected"
    assert data["overall_assessment"]["score"] >= 0.75
    assert len(data["analyses"]["visual"]["page_previews"][0]["suspicious_regions"]) >= 1


def test_visual_layer_detects_standalone_hidden_white_text() -> None:
    """Layer 2 must detect standalone invisible white text on white page."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)
    page.insert_text(fitz.Point(72, 100), "Normal visible text", fontsize=12, color=(0, 0, 0))
    page.insert_text(fitz.Point(72, 200), "Secret Hidden Keywords", fontsize=12, color=(1, 1, 1))
    data = doc.tobytes()
    doc.close()

    loaded = load_pdf(data, filename="hidden_text.pdf")
    vis_res = analyze_visual_layer(loaded, dpi=120)
    hidden_findings = [f for f in vis_res.findings if f.code == "VISUAL_HIDDEN_WHITE_TEXT"]
    assert len(hidden_findings) >= 1


# ==============================================================================
# Layer 3: Independent Verification Tests
# ==============================================================================


def test_verification_hash_integrity() -> None:
    """Hash integrity correctly validates matches and detects discrepancies."""
    real_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Match
    res_match = verify_hash_integrity(real_hash, expected_hash=real_hash)
    assert res_match.status == "verified_match"
    assert res_match.matches is True

    # Mismatch
    res_mismatch = verify_hash_integrity(real_hash, expected_hash="0000000000000000000000000000000000000000000000000000000000000000")
    assert res_mismatch.status == "hash_mismatch"
    assert res_mismatch.matches is False

    # No reference
    res_none = verify_hash_integrity(real_hash, expected_hash=None)
    assert res_none.status == "reference_not_provided"
    assert res_none.matches is None


def test_verification_trusted_original_unavailable_when_not_provided() -> None:
    """When no trusted original PDF is provided, status is cleanly reported as unavailable."""
    pdf_bytes = make_normal_pdf(text="Single document test")
    loaded = load_pdf(pdf_bytes, filename="single.pdf")

    comp = compare_against_trusted_original(loaded, original_bytes=None)
    assert comp.status == "unavailable"
    assert comp.differences_detected is False


def test_verification_trusted_original_exact_match() -> None:
    """Comparing identical documents confirms zero differences."""
    pdf_bytes = make_normal_pdf(text="Identical content verification test.")
    loaded = load_pdf(pdf_bytes, filename="doc1.pdf")

    comp = compare_against_trusted_original(loaded, original_bytes=pdf_bytes)
    assert comp.status == "completed"
    assert comp.differences_detected is False
    assert len(comp.page_diffs) == 1
    assert comp.page_diffs[0].status == "identical"


def test_verification_trusted_original_detects_altered_content() -> None:
    """Comparing against a trusted original isolates altered text and visual pixel differences."""
    # Create original
    doc_orig = fitz.open()
    p_orig = doc_orig.new_page()
    p_orig.insert_text(fitz.Point(72, 100), "Original Invoice Amount: $100.00")
    orig_bytes = doc_orig.tobytes()
    doc_orig.close()

    # Create candidate with modified amount
    doc_cand = fitz.open()
    p_cand = doc_cand.new_page()
    p_cand.insert_text(fitz.Point(72, 100), "Original Invoice Amount: $9,500.00")
    cand_bytes = doc_cand.tobytes()
    doc_cand.close()

    loaded_cand = load_pdf(cand_bytes, filename="candidate.pdf")

    res = analyze_verification_layer(
        loaded_cand,
        original_bytes=orig_bytes,
        original_filename="invoice_original.pdf",
    )
    assert res.status == "completed"
    assert res.original_comparison is not None
    assert res.original_comparison.differences_detected is True

    # Must flag VERIFY_ORIGINAL_DIFF_DETECTED with high confidence
    diff_findings = [f for f in res.findings if f.code == "VERIFY_ORIGINAL_DIFF_DETECTED"]
    assert len(diff_findings) >= 1
    f = diff_findings[0]
    assert f.severity == "high"
    assert f.confidence == 0.95


# ==============================================================================
# End-to-End API and Schema Tests
# ==============================================================================


def test_three_layer_api_single_pdf_upload() -> None:
    """API returns full three-layer schema on standard single PDF upload."""
    pdf_bytes = make_normal_pdf(text="End-to-end API single upload test.")
    response = client.post(
        "/analyze",
        files={"file": ("report.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    # Check top-level overall_assessment
    assert "overall_assessment" in data
    assess = data["overall_assessment"]
    assert assess["status"] in (
        "confirmed_integrity_failure",
        "suspicious_indicators_detected",
        "no_suspicious_indicators_detected",
        "inconclusive",
    )
    assert assess["score"] is not None

    # Check analyses container and three layers
    assert "analyses" in data
    analyses = data["analyses"]
    assert "structural" in analyses
    assert "visual" in analyses
    assert "verification" in analyses

    assert analyses["structural"]["status"] == "completed"
    assert analyses["visual"]["status"] == "completed"
    assert analyses["verification"]["status"] == "unavailable"
    assert len(analyses["visual"]["page_previews"]) >= 1

    # Check key findings and next steps
    assert isinstance(data["key_findings"], list)
    assert isinstance(data["recommended_next_steps"], list)
    assert len(data["recommended_next_steps"]) >= 1


def test_three_layer_api_with_trusted_original_and_hash() -> None:
    """API executes verification comparison when original_file and expected_hash are provided."""
    # Create original
    doc_orig = fitz.open()
    p_orig = doc_orig.new_page()
    p_orig.insert_text(fitz.Point(72, 100), "Baseline Original Contract")
    orig_bytes = doc_orig.tobytes()
    doc_orig.close()

    # Create altered candidate
    doc_cand = fitz.open()
    p_cand = doc_cand.new_page()
    p_cand.insert_text(fitz.Point(72, 100), "Modified Fraudulent Contract")
    cand_bytes = doc_cand.tobytes()
    doc_cand.close()

    response = client.post(
        "/analyze",
        files={
            "file": ("modified_contract.pdf", cand_bytes, "application/pdf"),
            "original_file": ("trusted_baseline.pdf", orig_bytes, "application/pdf"),
        },
        data={"expected_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    )
    assert response.status_code == 200
    data = response.json()

    # Verification must be completed and detect differences
    assert data["analyses"]["verification"]["status"] == "completed"
    assert data["analyses"]["verification"]["original_comparison"]["differences_detected"] is True
    assert data["overall_assessment"]["status"] == "confirmed_integrity_failure"
    assert data["overall_assessment"]["score"] >= 0.90

