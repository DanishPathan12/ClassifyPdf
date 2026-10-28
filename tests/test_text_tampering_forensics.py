"""Comprehensive Forensic Test Suite: PDF Text Tampering, Covering, Replacement, and Revision Forensics.

Covers all 12 specific test scenarios:
1. Normal PDF with consistent formatting.
2. PDF with intentional yellow highlighting (/Highlight annotations).
3. PDF with bold headings and differently colored text.
4. PDF containing tables, forms, and repeated labels.
5. PDF with legitimate overlapping graphical elements (card container backgrounds).
6. PDF with opaque rectangle covering existing text.
7. PDF with new text placed over covered value (cover-and-replace edit).
8. PDF with inserted text using a different font.
9. PDF with inserted text matching surrounding font and alignment.
10. PDF with multiple incremental revisions and text alteration.
11. Fully rewritten PDF without accessible prior revisions (historical comparison unavailable).
12. PDF with legitimate annotations or redactions.
"""

from __future__ import annotations

import io
import fitz  # PyMuPDF
import pikepdf
import pytest

from app.schemas.analysis import StructuralAnalysisLayer, UnifiedAnalysisResponse
from app.services.pdf_analysis.orchestrator import run_pdf_analysis
from app.services.pdf_analysis.pdf_loader import load_pdf
from app.services.pdf_analysis.structural_analysis import analyze_structural_layer
from tests.fixtures.pdf_generators import make_incremental_pdf, make_normal_pdf


# ==============================================================================
# Helper PDF Generators
# ==============================================================================

def _make_normal_uniform_pdf() -> bytes:
    """Case 1: Normal document with uniform font, size, and layout."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)
    for i, y in enumerate(range(100, 450, 30)):
        page.insert_text(
            fitz.Point(72, y),
            f"Paragraph line {i+1}: This standard corporate memo is formatted consistently with uniform styling.",
            fontname="helv",
            fontsize=11,
            color=(0, 0, 0),
        )
    data = doc.tobytes()
    doc.close()
    return data


def _make_pdf_with_yellow_highlight() -> bytes:
    """Case 2: Document with intentional yellow /Highlight annotation."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)
    p = page.insert_text(fitz.Point(72, 120), "Important clause: The payment terms are Net 30 days.", fontname="helv", fontsize=11)
    
    # Add genuine PDF /Highlight annotation over "Net 30 days"
    annot_rect = fitz.Rect(180, 108, 280, 126)
    annot = page.add_highlight_annot(annot_rect)
    annot.set_colors(stroke=(1.0, 1.0, 0.0))  # Yellow highlight
    annot.update()

    for y in range(160, 320, 30):
        page.insert_text(fitz.Point(72, y), "Standard uniform follow-up terms and condition text.", fontname="helv", fontsize=11)

    data = doc.tobytes()
    doc.close()
    return data


def _make_pdf_with_bold_headings_and_colors() -> bytes:
    """Case 3: Document with intentional bold headings and colored text."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)

    # Bold section heading
    page.insert_text(fitz.Point(72, 80), "SECTION 1: FINANCIAL OVERVIEW", fontname="hebo", fontsize=16, color=(0.1, 0.2, 0.5))

    # Normal body
    for y in range(110, 220, 25):
        page.insert_text(fitz.Point(72, y), "Regular body text describing standard corporate operations.", fontname="helv", fontsize=10, color=(0.1, 0.1, 0.1))

    # Styled callout in green
    page.insert_text(fitz.Point(72, 260), "STATUS: APPROVED BY AUDITOR", fontname="hebo", fontsize=11, color=(0.0, 0.6, 0.2))

    data = doc.tobytes()
    doc.close()
    return data


def _make_pdf_with_table_and_forms() -> bytes:
    """Case 4: Document with structured table columns and form fields."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)

    page.insert_text(fitz.Point(72, 60), "PURCHASE ORDER INVOICE", fontname="hebo", fontsize=14)

    # Form labels
    page.insert_text(fitz.Point(72, 90), "Date: 2026-10-28", fontname="helv", fontsize=10)
    page.insert_text(fitz.Point(250, 90), "Invoice #: INV-2026-09", fontname="helv", fontsize=10)
    page.insert_text(fitz.Point(420, 90), "Customer ID: CUST-881", fontname="helv", fontsize=10)

    # Table columns
    items = [
        ("Item 1 - Standard Consulting Service", "$1,500.00"),
        ("Item 2 - Cloud Infrastructure Hosting", "$2,400.00"),
        ("Item 3 - Security Vulnerability Audit", "$3,100.00"),
        ("Item 4 - Database Migration Pipeline", "$4,200.00"),
    ]
    y = 130
    for desc, amt in items:
        page.insert_text(fitz.Point(72, y), desc, fontname="helv", fontsize=10)
        page.insert_text(fitz.Point(400, y), amt, fontname="helv", fontsize=10)
        y += 24

    data = doc.tobytes()
    doc.close()
    return data


def _make_pdf_with_container_card_background() -> bytes:
    """Case 5: Document with legitimate overlapping background card."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)

    # Large container card background
    card_rect = fitz.Rect(60, 80, 550, 300)
    page.draw_rect(card_rect, color=(0.9, 0.9, 0.95), fill=(0.93, 0.93, 0.97))

    # Text naturally positioned inside the container card
    page.insert_text(fitz.Point(80, 110), "Executive Summary Card", fontname="hebo", fontsize=14, color=(0.2, 0.2, 0.2))
    page.insert_text(fitz.Point(80, 140), "This content is enclosed inside a legitimate layout container shape.", fontname="helv", fontsize=11, color=(0.2, 0.2, 0.2))
    page.insert_text(fitz.Point(80, 170), "It represents ordinary graphic design rather than a cover-up.", fontname="helv", fontsize=11, color=(0.2, 0.2, 0.2))

    data = doc.tobytes()
    doc.close()
    return data


def _make_pdf_with_opaque_covering_rect() -> bytes:
    """Case 6: Document with opaque rectangle covering existing text."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)

    page.insert_text(fitz.Point(72, 100), "Confidential Settlement Agreement Terms", fontname="helv", fontsize=12)
    page.insert_text(fitz.Point(72, 140), "Settlement Amount: $500,000 to be wired immediately.", fontname="helv", fontsize=11)

    # Opaque rectangle covering the settlement amount
    cover_rect = fitz.Rect(170, 126, 260, 148)
    page.draw_rect(cover_rect, color=(0.2, 0.2, 0.2), fill=(0.2, 0.2, 0.2))

    data = doc.tobytes()
    doc.close()
    return data


def _make_pdf_with_cover_and_replace() -> bytes:
    """Case 7: Document with opaque patch covering old text and new text placed on top."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)

    page.insert_text(fitz.Point(72, 100), "Official Monthly Statement", fontname="helv", fontsize=12)
    # Original text
    page.insert_text(fitz.Point(72, 140), "Total Balance Due: $1,250.00", fontname="helv", fontsize=11)

    # Whiteout patch directly over the number
    white_rect = fitz.Rect(180, 126, 260, 146)
    page.draw_rect(white_rect, color=(1.0, 1.0, 1.0), fill=(1.0, 1.0, 1.0))

    # Altered replacement text typed into the patch
    page.insert_text(fitz.Point(185, 140), "$98,500.00", fontname="helv", fontsize=11, color=(0, 0, 0))

    data = doc.tobytes()
    doc.close()
    return data


def _make_pdf_with_inconsistent_inserted_font() -> bytes:
    """Case 8: Document with inserted text using a different font."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)

    for y in range(100, 300, 25):
        page.insert_text(fitz.Point(72, y), f"Uniform corporate paragraph row {y} generated with normal typography.", fontname="helv", fontsize=10)

    # Inserted clause in Courier
    page.insert_text(fitz.Point(200, 360), "Altered settlement amount", fontname="courier", fontsize=10)

    data = doc.tobytes()
    doc.close()
    return data


def _make_pdf_with_clean_matching_inserted_text() -> bytes:
    """Case 9: Document with inserted text matching surrounding font and alignment."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)

    for y in range(100, 250, 30):
        page.insert_text(fitz.Point(72, y), f"Corporate standard agreement paragraph row {y}.", fontname="helv", fontsize=10)

    # Clean addition with exact font, size, and normal margins
    page.insert_text(fitz.Point(72, 280), "Payment will be disbursed within 15 business days.", fontname="helv", fontsize=10)

    data = doc.tobytes()
    doc.close()
    return data


def _make_pdf_with_redaction_annotation() -> bytes:
    """Case 12: PDF with legitimate user annotation / redaction markup."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)

    page.insert_text(fitz.Point(72, 100), "Public Records Release - Case #9921", fontname="helv", fontsize=12)
    page.insert_text(fitz.Point(72, 140), "Social Security Number: 123-45-6789", fontname="helv", fontsize=11)

    # Add standard PDF annotation (Text note or Redact markup)
    page.add_text_annot(fitz.Point(220, 140), "Redacted under Privacy Act Exemption 6")

    data = doc.tobytes()
    doc.close()
    return data


# ==============================================================================
# 12 Test Cases
# ==============================================================================

def test_case_01_normal_pdf_consistent_formatting() -> None:
    """Case 1: Normal PDF with consistent formatting produces 0 cover/replacement findings and clean verdict."""
    pdf_bytes = make_normal_pdf(text="Paragraph line: This standard corporate memo is formatted consistently with uniform styling.")
    res = run_pdf_analysis(pdf_bytes, filename="normal.pdf")

    assert res.analyses.structural.covering_objects_count == 0
    assert res.analyses.structural.text_replacements_count == 0
    assert res.analyses.structural.formatting_anomalies_count == 0
    assert res.verdict == "no_edit_evidence_found"
    assert res.edit_detected is False
    assert res.confidence == 0.0


def test_case_02_intentional_highlight_not_flagged() -> None:
    """Case 2: PDF with intentional yellow highlight annotation does not trigger false positive tampering flags."""
    pdf_bytes = _make_pdf_with_yellow_highlight()
    res = run_pdf_analysis(pdf_bytes, filename="highlighted.pdf")

    # Highlighting should NOT be flagged as covering object or text replacement
    assert res.analyses.structural.covering_objects_count == 0
    assert res.analyses.structural.text_replacements_count == 0
    # Findings must not include STRUCT_POSSIBLE_TEXT_REPLACEMENT or STRUCT_WHITEOUT_RECTANGLE_OVERLAY
    codes = {f.code for f in res.findings}
    assert "STRUCT_POSSIBLE_TEXT_REPLACEMENT" not in codes
    assert "STRUCT_WHITEOUT_RECTANGLE_OVERLAY" not in codes


def test_case_03_bold_headings_and_colors_not_flagged() -> None:
    """Case 3: Bold headings and intentionally colored text are recognized as valid layout styling."""
    pdf_bytes = _make_pdf_with_bold_headings_and_colors()
    res = run_pdf_analysis(pdf_bytes, filename="styled_headings.pdf")

    # Intentional headings and color badges should not be flagged as tampering
    assert res.analyses.structural.text_replacements_count == 0
    codes = {f.code for f in res.findings}
    assert "STRUCT_POSSIBLE_TEXT_REPLACEMENT" not in codes
    assert "STRUCT_WHITE_TEXT_LAYER_OVERLAY" not in codes


def test_case_04_tables_and_forms_recognized() -> None:
    """Case 4: Structured tables and form fields with repeated labels do not trigger false tampering flags."""
    pdf_bytes = _make_pdf_with_table_and_forms()
    res = run_pdf_analysis(pdf_bytes, filename="invoice_table.pdf")

    assert res.analyses.structural.text_replacements_count == 0
    assert res.analyses.structural.covering_objects_count == 0
    codes = {f.code for f in res.findings}
    assert "STRUCT_POSSIBLE_TEXT_REPLACEMENT" not in codes


def test_case_05_legitimate_overlapping_card_background() -> None:
    """Case 5: Legitimate container background shapes are distinguished from suspicious cover patches."""
    pdf_bytes = _make_pdf_with_container_card_background()
    res = run_pdf_analysis(pdf_bytes, filename="container_card.pdf")

    # Large container card background should not be treated as a small cover-up patch
    assert res.analyses.structural.text_replacements_count == 0
    codes = {f.code for f in res.findings}
    assert "STRUCT_POSSIBLE_TEXT_REPLACEMENT" not in codes
    assert "STRUCT_WHITEOUT_RECTANGLE_OVERLAY" not in codes


def test_case_06_opaque_covering_rectangle_detected() -> None:
    """Case 6: Opaque rectangle covering existing text is identified as a possible covering object."""
    pdf_bytes = _make_pdf_with_opaque_covering_rect()
    loaded = load_pdf(pdf_bytes, filename="covered.pdf")
    res = analyze_structural_layer(loaded)

    assert res.status == "completed"
    covering_findings = [
        f for f in res.findings
        if f.code in ("STRUCT_POSSIBLE_COVERING_OBJECT", "STRUCT_WHITEOUT_RECTANGLE_OVERLAY")
    ]
    assert len(covering_findings) >= 1
    f = covering_findings[0]
    assert f.anomaly_confidence >= 0.80
    assert f.tampering_confidence >= 0.40
    assert len(f.alternative_explanations) >= 1
    assert f.recommended_action is not None


def test_case_07_cover_and_replace_detected() -> None:
    """Case 7: Whiteout patch with altered text typed on top is detected with high confidence."""
    pdf_bytes = _make_pdf_with_cover_and_replace()
    res = run_pdf_analysis(pdf_bytes, filename="altered_balance.pdf")

    assert res.analyses.structural.text_replacements_count >= 1 or res.analyses.structural.covering_objects_count >= 1
    codes = {f.code for f in res.findings}
    assert "STRUCT_WHITEOUT_RECTANGLE_OVERLAY" in codes or "STRUCT_POSSIBLE_TEXT_REPLACEMENT" in codes

    finding = next(f for f in res.findings if f.code in ("STRUCT_WHITEOUT_RECTANGLE_OVERLAY", "STRUCT_POSSIBLE_TEXT_REPLACEMENT"))
    assert finding.anomaly_confidence >= 0.85
    assert finding.tampering_confidence >= 0.60
    assert finding.region is not None
    assert finding.page == 1


def test_case_08_inserted_text_different_font_flagged_with_explanations() -> None:
    """Case 8: Inserted text using an isolated font is flagged as a formatting anomaly without claiming definite tampering."""
    pdf_bytes = _make_pdf_with_inconsistent_inserted_font()
    res = run_pdf_analysis(pdf_bytes, filename="font_switch.pdf")

    codes = {f.code for f in res.findings}
    assert "STRUCT_INCONSISTENT_FONT_SWITCH" in codes or "STRUCT_FORMATTING_ANOMALY" in codes

    finding = next(f for f in res.findings if f.code in ("STRUCT_INCONSISTENT_FONT_SWITCH", "STRUCT_FORMATTING_ANOMALY"))
    # Confidence is appropriately calibrated, not jumping to 100% tampering
    assert finding.tampering_confidence <= 0.60
    assert len(finding.alternative_explanations) >= 1
    assert "emphasis" in finding.alternative_explanations[0].lower() or "design" in finding.alternative_explanations[0].lower() or "substitution" in finding.alternative_explanations[0].lower()


def test_case_09_clean_matching_inserted_text_handles_single_pdf_limits() -> None:
    """Case 9: Matching inserted text without structural collisions does not trigger false structural alarms."""
    pdf_bytes = _make_pdf_with_clean_matching_inserted_text()
    res = run_pdf_analysis(pdf_bytes, filename="clean_addition.pdf")

    # Without reference or collisions, clean text must not be hallucinated as a tampering event
    assert res.analyses.structural.covering_objects_count == 0
    assert res.analyses.structural.text_replacements_count == 0
    assert res.verdict != "likely_edited"


def test_case_10_multiple_revisions_detect_text_alteration() -> None:
    """Case 10: Multi-revision PDF with altered text triggers REV_TEXT_CHANGE_DETECTED."""
    pdf_bytes = make_incremental_pdf(
        original_text="Approved Contract Amount: $10,000",
        appended_text="Approved Contract Amount: $99,000",
    )
    res = run_pdf_analysis(pdf_bytes, filename="multi_rev.pdf")

    assert res.analyses.structural.revision_history_available is True
    codes = {f.code for f in res.findings}
    assert "REV_TEXT_CHANGE_DETECTED" in codes

    rev_finding = next(f for f in res.findings if f.code == "REV_TEXT_CHANGE_DETECTED")
    assert rev_finding.anomaly_confidence >= 0.90
    assert "old_text_sample" in rev_finding.evidence
    assert "new_text_sample" in rev_finding.evidence
    assert len(rev_finding.limitations) >= 1


def test_case_11_single_revision_reports_comparison_unavailable() -> None:
    """Case 11: Fully rewritten single-revision PDF explicitly reports historical comparison unavailable."""
    pdf_bytes = _make_normal_uniform_pdf()
    res = run_pdf_analysis(pdf_bytes, filename="single_rev.pdf")

    assert res.analyses.structural.revision_history_available is False
    status = res.analyses.structural.historical_comparison_status
    assert status is not None
    assert "single revision" in status.lower() or "unavailable" in status.lower() or "rewritten" in status.lower()


def test_case_12_legitimate_annotations_acknowledged() -> None:
    """Case 12: PDF with legitimate user annotations includes alternative explanations and limitations."""
    pdf_bytes = _make_pdf_with_redaction_annotation()
    res = run_pdf_analysis(pdf_bytes, filename="annotated.pdf")

    # Annotations should have balanced assessment
    for f in res.findings:
        if "ANNOT" in f.code:
            assert len(f.alternative_explanations) >= 1 or len(f.limitations) >= 1
            assert f.tampering_confidence <= 0.70


def test_case_13_editor_placeholder_text_detected() -> None:
    """Case 13: Editor placeholder text ('Type your text') is flagged with high confidence."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)
    for y in range(100, 300, 30):
        page.insert_text(fitz.Point(72, y), f"Quarterly operational report line item {y}", fontname="helv", fontsize=10)
    page.insert_text(fitz.Point(200, 450), "Type your text", fontname="helv", fontsize=12)
    pdf_bytes = doc.tobytes()
    doc.close()

    res = run_pdf_analysis(pdf_bytes, filename="placeholder.pdf")
    codes = {f.code for f in res.findings}
    assert "STRUCT_EDITOR_PLACEHOLDER_TEXT" in codes
    ph_finding = next(f for f in res.findings if f.code == "STRUCT_EDITOR_PLACEHOLDER_TEXT")
    assert ph_finding.severity == "high"
    assert ph_finding.confidence >= 0.80
    assert "Type your text" in str(ph_finding.evidence)
    assert res.verdict == "likely_edited"
    assert res.edit_detected is True


def test_case_14_exact_text_diff_detected() -> None:
    """Case 14: Comparing modified PDF against trusted original identifies exact altered and added words."""
    doc_orig = fitz.open()
    page_orig = doc_orig.new_page(width=612, height=792)
    page_orig.insert_text(fitz.Point(72, 100), "The contract total is USD 5,000 payable in Poland.", fontname="helv", fontsize=11)
    orig_bytes = doc_orig.tobytes()
    doc_orig.close()

    doc_mod = fitz.open()
    page_mod = doc_mod.new_page(width=612, height=792)
    page_mod.insert_text(fitz.Point(72, 100), "The contract total is USD 95,000 payable in Poland.", fontname="helv", fontsize=11)
    page_mod.insert_text(fitz.Point(72, 200), "Type your text", fontname="helv", fontsize=11)
    mod_bytes = doc_mod.tobytes()
    doc_mod.close()

    res = run_pdf_analysis(mod_bytes, filename="tampered.pdf", original_source=orig_bytes, original_filename="original.pdf")
    codes = {f.code for f in res.findings}
    assert "STRUCT_EXACT_TEXT_MODIFIED" in codes or "VERIFY_TEXT_DIFF_MODIFIED" in codes
    assert "STRUCT_EXACT_TEXT_ADDED" in codes or "VERIFY_TEXT_DIFF_ADDED" in codes
    assert res.verdict == "likely_edited"
    assert res.edit_detected is True
    assert res.confidence == 1.0

