"""Unit tests for Test Case 2: Digital Signatures and Post-Signature Changes."""

from __future__ import annotations

from app.services.pdf_analysis.pdf_loader import load_pdf
from app.services.pdf_analysis.test_case_2_digital_signatures import analyze_digital_signatures
from tests.fixtures.pdf_generators import (
    make_corrupted_pdf,
    make_normal_pdf,
    make_signed_pdf_intact,
    make_signed_pdf_with_appended_revision,
)


def test_signed_pdf_intact_no_later_changes() -> None:
    """Intact digitally signed PDF must validate signature and confirm no later changes."""
    signed_bytes = make_signed_pdf_intact(text="Certified Immutable Agreement")
    loaded = load_pdf(signed_bytes, filename="signed_intact.pdf")
    result = analyze_digital_signatures(loaded)

    assert result.test_case == "digital_signatures"
    assert result.status == "signed_intact_no_later_changes"
    assert result.signatures_found == 1
    assert len(result.signature_results) == 1

    sig = result.signature_results[0]
    assert sig.cryptographic_integrity == "valid"
    assert sig.certificate_trust == "not_evaluated"
    assert sig.covers_current_file is True
    assert sig.later_revision_evidence is False
    assert len(sig.post_signature_changes) == 0
    assert any("root certificate store" in lim.lower() for lim in sig.limitations)


def test_signed_pdf_modified_after_signing() -> None:
    """Digitally signed PDF with appended revision must detect post-signature changes."""
    appended_bytes = make_signed_pdf_with_appended_revision(
        original_text="Approved Budget: $10,000",
        appended_text="Forged Budget: $99,000",
    )
    loaded = load_pdf(appended_bytes, filename="signed_modified.pdf")
    result = analyze_digital_signatures(loaded)

    assert result.test_case == "digital_signatures"
    assert result.status == "post_signature_changes_detected"
    assert result.signatures_found == 1

    sig = result.signature_results[0]
    assert sig.covers_current_file is False
    assert sig.later_revision_evidence is True
    assert len(sig.post_signature_changes) >= 1

    added_changes = [c for c in sig.post_signature_changes if c.type in ("text_added", "text_changed")]
    assert len(added_changes) >= 1
    assert any("Forged Budget" in (c.new_text or "") for c in added_changes)


def test_unsigned_pdf_no_signatures_found() -> None:
    """Unsigned PDF must report no_signatures_found and not be treated as tampered."""
    normal_bytes = make_normal_pdf()
    loaded = load_pdf(normal_bytes, filename="unsigned.pdf")
    result = analyze_digital_signatures(loaded)

    assert result.test_case == "digital_signatures"
    assert result.status == "no_signatures_found"
    assert result.signatures_found == 0
    assert len(result.signature_results) == 0
    assert any("unsigned" in lim.lower() for lim in result.limitations)


def test_corrupted_pdf_signature_inconclusive() -> None:
    """Corrupted PDF must return inconclusive without crashing."""
    corrupted_bytes = make_corrupted_pdf()
    loaded = load_pdf(corrupted_bytes, filename="corrupted.pdf")
    result = analyze_digital_signatures(loaded)

    assert result.status == "inconclusive"
    assert result.signatures_found == 0

