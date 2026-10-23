"""Unit tests for Test Case 3: Fully Re-saved PDF Analysis Without History."""

from __future__ import annotations

from app.services.pdf_analysis.pdf_loader import load_pdf
from app.services.pdf_analysis.test_case_3_resaved_pdf import analyze_resaved_pdf
from tests.fixtures.pdf_generators import (
    make_legitimate_mixed_font_pdf,
    make_normal_pdf,
    make_resaved_pdf_with_font_anomaly,
    make_resaved_pdf_with_overlap,
    make_resaved_pdf_with_text_over_image,
)


def test_resaved_pdf_detects_text_overlap() -> None:
    """PDF with overlapping distinct text blocks must flag unusual_text_overlap."""
    pdf_bytes = make_resaved_pdf_with_overlap()
    loaded = load_pdf(pdf_bytes, filename="overlap.pdf")
    result = analyze_resaved_pdf(loaded)

    assert result.test_case == "resaved_pdf_analysis"
    assert result.status == "suspicious_indicators_found"
    assert result.historical_comparison_available is False
    assert len(result.findings) >= 1

    overlap_finding = next(f for f in result.findings if f.type == "unusual_text_overlap")
    assert overlap_finding.page == 1
    assert overlap_finding.location is not None
    assert overlap_finding.location.bbox is not None
    assert overlap_finding.confidence in ("low", "medium")
    assert "not proof of editing" in overlap_finding.interpretation.lower()


def test_resaved_pdf_detects_font_anomaly() -> None:
    """Isolated word with distinct font/size in a uniform line must flag inconsistent_font_anomaly."""
    pdf_bytes = make_resaved_pdf_with_font_anomaly()
    loaded = load_pdf(pdf_bytes, filename="font_anomaly.pdf")
    result = analyze_resaved_pdf(loaded)

    assert result.status == "suspicious_indicators_found"
    font_findings = [f for f in result.findings if f.type == "inconsistent_font_anomaly"]
    assert len(font_findings) >= 1

    finding = font_findings[0]
    assert finding.page == 1
    assert "90000" in finding.evidence.get("anomalous_word", "")
    assert finding.confidence == "low"


def test_resaved_pdf_detects_text_over_image() -> None:
    """Sparse digital text overlying a raster image must flag text_over_image."""
    pdf_bytes = make_resaved_pdf_with_text_over_image()
    loaded = load_pdf(pdf_bytes, filename="text_over_image.pdf")
    result = analyze_resaved_pdf(loaded)

    assert result.status == "suspicious_indicators_found"
    img_findings = [f for f in result.findings if f.type == "text_over_image"]
    assert len(img_findings) >= 1

    finding = img_findings[0]
    assert finding.page == 1
    assert finding.confidence == "medium"
    assert "Altered Value" in str(finding.evidence)


def test_legitimate_mixed_fonts_no_anomalies() -> None:
    """Standard document with legitimate bold title and normal body text must not trigger false positives."""
    pdf_bytes = make_legitimate_mixed_font_pdf()
    loaded = load_pdf(pdf_bytes, filename="clean_multidoc.pdf")
    result = analyze_resaved_pdf(loaded)

    assert result.status == "no_anomalies_detected"
    assert len(result.findings) == 0


def test_resaved_pdf_explicit_limitations() -> None:
    """Re-saved PDF analysis must explicitly disclaim knowledge of unrecoverable original content."""
    pdf_bytes = make_normal_pdf()
    loaded = load_pdf(pdf_bytes, filename="clean.pdf")
    result = analyze_resaved_pdf(loaded)

    assert result.historical_comparison_available is False
    assert any("exact original content cannot be established" in lim.lower() for lim in result.limitations)

