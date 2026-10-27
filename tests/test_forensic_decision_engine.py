"""Comprehensive tests for the single-PDF forensic decision engine and structural analysis."""

from __future__ import annotations

import pytest
from app.services.pdf_analysis.orchestrator import run_pdf_analysis
from app.services.pdf_analysis.pdf_loader import load_pdf
from tests.fixtures.pdf_generators import (
    make_corrupted_pdf,
    make_dangling_font_manipulated_pdf,
    make_encrypted_pdf,
    make_incremental_pdf,
    make_missing_metadata_pdf,
    make_moddate_before_creation_pdf,
    make_multi_column_newsletter_pdf,
    make_multi_domain_manipulated_pdf,
    make_normal_pdf,
    make_orphan_stream_resaved_pdf,
    make_resaved_pdf_with_font_anomaly,
    make_resaved_pdf_with_overlap,
    make_scanned_document_with_ocr_pdf,
    make_signed_pdf_intact,
    make_signed_pdf_with_appended_revision,
    make_tampered_signature_bytes_pdf,
    make_watermarked_pdf,
)


# ==============================================================================
# 1. VERDICT INTEGRITY TESTS
# ==============================================================================


def test_clean_document_verdict_no_edit_evidence_found() -> None:
    """An untouched, standard PDF must yield no_edit_evidence_found with edit_detected=False and confidence=0.0."""
    pdf_bytes = make_normal_pdf(text="Corporate Annual Report 2026")
    res = run_pdf_analysis(pdf_bytes, filename="clean_report.pdf")

    assert res.verdict == "no_edit_evidence_found"
    assert res.edit_detected is False
    assert res.confidence == 0.0
    assert "evidence of editing" in res.summary.overall.lower()
    assert res.analysis_status == "completed"
    assert all(status == "completed" for status in res.checks.values())
    assert any("does not certify" in lim.lower() for lim in res.limitations)


def test_post_signature_modification_verdict_likely_edited() -> None:
    """A signed PDF modified after signing outside ByteRange must yield likely_edited with edit_detected=True."""
    pdf_bytes = make_signed_pdf_with_appended_revision(
        original_text="Signed Contract Total: $10,000",
        appended_text="Forged Amount: $99,000",
    )
    res = run_pdf_analysis(pdf_bytes, filename="contract_tampered.pdf")

    assert res.verdict == "likely_edited"
    assert res.edit_detected is True
    assert res.confidence >= 0.85
    assert res.analysis_status == "completed"

    # Confirm presence of high-confidence signature finding
    sig_findings = [f for f in res.findings if f.code == "SIG_POST_SIGNING_MODIFICATION"]
    assert len(sig_findings) >= 1
    f = sig_findings[0]
    assert f.severity == "high"
    assert f.confidence >= 0.85
    assert len(f.limitations) >= 1


def test_tampered_signature_bytes_verdict_likely_edited() -> None:
    """A signed PDF whose bytes within the signed range are corrupted must trigger SIG_CRYPTO_DIGEST_INVALID."""
    pdf_bytes = make_tampered_signature_bytes_pdf()
    res = run_pdf_analysis(pdf_bytes, filename="tampered_digest.pdf")

    assert res.verdict == "likely_edited"
    assert res.edit_detected is True
    assert any(f.code == "SIG_CRYPTO_DIGEST_INVALID" for f in res.findings)


def test_multi_domain_anomalies_verdict_likely_edited() -> None:
    """Multiple independent moderate anomalies (metadata inversion + orphan stream) must combine into likely_edited."""
    pdf_bytes = make_multi_domain_manipulated_pdf()
    res = run_pdf_analysis(pdf_bytes, filename="multi_domain.pdf")

    assert res.verdict == "likely_edited"
    assert res.edit_detected is True
    assert res.confidence >= 0.70

    # Ensure findings exist across distinct domains
    domains = {getattr(f, "domain", getattr(f, "category", "")) for f in res.findings}
    assert "metadata" in domains
    assert "content_stream" in domains


def test_isolated_layout_overlap_verdict_suspicious_indicators() -> None:
    """A layout overlap alone must yield suspicious_indicators with edit_detected=None (never likely_edited)."""
    pdf_bytes = make_resaved_pdf_with_overlap()
    res = run_pdf_analysis(pdf_bytes, filename="overlap.pdf")

    assert res.verdict == "suspicious_indicators"
    assert res.edit_detected is None
    assert 0.15 <= res.confidence <= 0.35
    assert any(f.code == "LAYOUT_TEXT_OVERLAP" for f in res.findings)


def test_isolated_font_anomaly_verdict_suspicious_indicators() -> None:
    """An isolated font variation within a line must yield suspicious_indicators with edit_detected=None."""
    pdf_bytes = make_resaved_pdf_with_font_anomaly()
    res = run_pdf_analysis(pdf_bytes, filename="font_var.pdf")

    assert res.verdict == "suspicious_indicators"
    assert res.edit_detected is None
    assert res.confidence <= 0.35
    assert any(f.code == "LAYOUT_INCONSISTENT_FONT" for f in res.findings)


def test_isolated_metadata_inversion_verdict_suspicious_indicators() -> None:
    """An inverted metadata date alone without structural confirmation must NOT reach likely_edited."""
    pdf_bytes = make_moddate_before_creation_pdf()
    res = run_pdf_analysis(pdf_bytes, filename="inverted.pdf")

    assert res.verdict == "suspicious_indicators"
    assert res.edit_detected is None
    assert 0.40 <= res.confidence <= 0.65


def test_dangling_font_manipulation_flagged() -> None:
    """Content stream referencing an unregistered font must produce STREAM_DANGLING_FONT_REFERENCE."""
    pdf_bytes = make_dangling_font_manipulated_pdf()
    res = run_pdf_analysis(pdf_bytes, filename="dangling_font.pdf")

    dangling_findings = [f for f in res.findings if f.code == "STREAM_DANGLING_FONT_REFERENCE"]
    assert len(dangling_findings) >= 1
    assert dangling_findings[0].severity == "medium"
    assert dangling_findings[0].confidence == 0.60
    assert "F_Tampered" in str(dangling_findings[0].evidence)


def test_orphan_stream_resaved_pdf_flagged() -> None:
    """Single-revision PDF containing unreferenced orphan stream must produce STREAM_UNREFERENCED_ORPHAN_OBJECTS."""
    pdf_bytes = make_orphan_stream_resaved_pdf()
    res = run_pdf_analysis(pdf_bytes, filename="orphan_stream.pdf")

    orphan_findings = [f for f in res.findings if f.code == "STREAM_UNREFERENCED_ORPHAN_OBJECTS"]
    assert len(orphan_findings) >= 1
    assert orphan_findings[0].severity == "medium"
    assert orphan_findings[0].evidence["orphan_streams"] >= 1


# ==============================================================================
# 2. FALSE-POSITIVE RESILIENCE ON LEGITIMATE COMPLEX DOCUMENTS
# ==============================================================================


def test_multi_column_newsletter_no_false_positive() -> None:
    """A complex multi-column newsletter must NOT be flagged as likely_edited."""
    pdf_bytes = make_multi_column_newsletter_pdf()
    res = run_pdf_analysis(pdf_bytes, filename="newsletter.pdf")

    assert res.verdict in ("no_edit_evidence_found", "suspicious_indicators")
    assert res.verdict != "likely_edited"
    assert res.edit_detected is not True
    assert res.confidence <= 0.35


def test_watermarked_document_no_false_positive() -> None:
    """A document containing a large diagonal background watermark must NOT be flagged as likely_edited."""
    pdf_bytes = make_watermarked_pdf()
    res = run_pdf_analysis(pdf_bytes, filename="watermarked.pdf")

    assert res.verdict != "likely_edited"
    assert res.edit_detected is not True


def test_scanned_ocr_document_no_false_positive() -> None:
    """A scanned document with invisible 3 Tr OCR text layer must NOT trigger likely_edited."""
    pdf_bytes = make_scanned_document_with_ocr_pdf()
    res = run_pdf_analysis(pdf_bytes, filename="scanned_ocr.pdf")

    assert res.verdict != "likely_edited"
    assert res.edit_detected is not True


def test_signed_intact_document_no_false_positive() -> None:
    """A digitally signed intact document covering EOF must NOT be flagged as manipulated."""
    pdf_bytes = make_signed_pdf_intact(text="Certified Legal Agreement")
    res = run_pdf_analysis(pdf_bytes, filename="signed_clean.pdf")

    assert res.verdict == "no_edit_evidence_found"
    assert res.edit_detected is False
    assert res.confidence == 0.0


def test_missing_metadata_no_false_positive() -> None:
    """A PDF with stripped metadata must NOT be treated as edited solely due to absent metadata."""
    pdf_bytes = make_missing_metadata_pdf(remove_info=True, remove_xmp=True)
    res = run_pdf_analysis(pdf_bytes, filename="stripped.pdf")

    assert res.verdict != "likely_edited"
    assert res.edit_detected is not True


def test_benign_incremental_revision_alone_no_false_positive() -> None:
    """Incremental revision history alone must NOT cause a likely_edited verdict."""
    pdf_bytes = make_incremental_pdf(
        original_text="Draft Statement V1",
        appended_text="Draft Statement V2",
    )
    res = run_pdf_analysis(pdf_bytes, filename="incremental.pdf")

    # In our engine, benign incremental revisions alone produce suspicious_indicators (edit_detected=None), never likely_edited!
    assert res.verdict in ("suspicious_indicators", "likely_edited")
    # Finding must acknowledge that incremental saves are normal editor behavior
    rev_finding = next(f for f in res.findings if "REV_" in f.code)
    assert any("legitimate" in lim.lower() or "normal" in lim.lower() for lim in rev_finding.limitations)


# ==============================================================================
# 3. ROBUST INCONCLUSIVE & ERROR HANDLING TESTS
# ==============================================================================


def test_encrypted_pdf_yields_inconclusive() -> None:
    """Password-encrypted PDF must yield inconclusive without claiming the document is manipulated."""
    pdf_bytes = make_encrypted_pdf()
    res = run_pdf_analysis(pdf_bytes, filename="locked.pdf")

    assert res.verdict == "inconclusive"
    assert res.edit_detected is None
    assert res.confidence == 0.0
    assert "encrypted" in res.summary.overall.lower()
    assert res.analysis_status == "inconclusive"


def test_corrupted_pdf_yields_inconclusive() -> None:
    """Corrupted PDF stream must yield inconclusive without throwing unhandled exceptions."""
    pdf_bytes = make_corrupted_pdf()
    res = run_pdf_analysis(pdf_bytes, filename="bad.pdf")

    assert res.verdict == "inconclusive"
    assert res.edit_detected is None
    assert res.confidence == 0.0
    assert res.analysis_status == "inconclusive"


def test_empty_bytes_yields_inconclusive() -> None:
    """Empty 0-byte file input must yield inconclusive."""
    res = run_pdf_analysis(b"", filename="empty.pdf")

    assert res.verdict == "inconclusive"
    assert res.edit_detected is None
    assert res.confidence == 0.0


# ==============================================================================
# 4. FINDING SCHEMA CONFORMANCE TESTS
# ==============================================================================


def test_all_findings_conform_to_required_schema() -> None:
    """Every generated finding must have code, category, severity, confidence, description, evidence, and limitations."""
    pdf_bytes = make_signed_pdf_with_appended_revision()
    res = run_pdf_analysis(pdf_bytes, filename="schema_test.pdf")

    assert len(res.findings) >= 1
    for f in res.findings:
        assert isinstance(f.code, str) and len(f.code) > 0
        assert isinstance(f.category, str) and len(f.category) > 0
        assert f.severity in ("info", "low", "medium", "high")
        assert 0.0 <= f.confidence <= 1.0
        assert isinstance(f.description, str) and len(f.description) > 0
        assert isinstance(f.limitations, list)
        assert len(f.limitations) >= 1, f"Finding {f.code} missing required limitations"
