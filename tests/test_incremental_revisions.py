"""Unit tests for Test Case 1: Incremental Revision Analysis."""

from __future__ import annotations

from app.services.pdf_analysis.pdf_loader import load_pdf
from app.services.pdf_analysis.test_case_1_incremental_revisions import analyze_incremental_revisions
from tests.fixtures.pdf_generators import (
    make_corrupted_pdf,
    make_incremental_pdf,
    make_normal_pdf,
)


def test_incremental_pdf_detects_changes() -> None:
    """PDF with appended incremental update must detect changes and recover earlier revision."""
    pdf_bytes = make_incremental_pdf(
        original_text="Original Balance: $100",
        appended_text="Modified Balance: $900",
    )
    loaded = load_pdf(pdf_bytes, filename="incremental.pdf")
    result = analyze_incremental_revisions(loaded)

    assert result.test_case == "incremental_revisions"
    assert result.status == "changes_detected"
    assert result.revision_count >= 2
    assert result.previous_revision_recovered is True
    assert len(result.changes) >= 1

    # Verify change structure
    added_changes = [c for c in result.changes if c.type in ("text_added", "text_changed")]
    assert len(added_changes) >= 1

    first_change = added_changes[0]
    assert first_change.page == 1
    assert "Modified Balance" in (first_change.new_text or "")
    assert first_change.location is not None
    assert first_change.location.bbox is not None
    assert len(first_change.location.bbox) == 4
    assert len(first_change.evidence) > 0


def test_normal_pdf_no_revision_evidence() -> None:
    """Normal PDF without incremental updates must report no_revision_evidence."""
    pdf_bytes = make_normal_pdf()
    loaded = load_pdf(pdf_bytes, filename="normal.pdf")
    result = analyze_incremental_revisions(loaded)

    assert result.test_case == "incremental_revisions"
    assert result.status == "no_revision_evidence"
    assert result.revision_count == 1
    assert result.previous_revision_recovered is False
    assert len(result.changes) == 0
    assert len(result.limitations) >= 1


def test_corrupted_pdf_inconclusive() -> None:
    """Malformed or corrupted PDF must yield inconclusive without unhandled exceptions."""
    pdf_bytes = make_corrupted_pdf()
    loaded = load_pdf(pdf_bytes, filename="corrupted.pdf")
    result = analyze_incremental_revisions(loaded)

    assert result.status == "inconclusive"
    assert result.previous_revision_recovered is False
    assert len(result.changes) == 0
    assert len(result.limitations) >= 1


def test_empty_bytes_inconclusive() -> None:
    """Empty payload must yield inconclusive gracefully."""
    loaded = load_pdf(b"", filename="empty.pdf")
    result = analyze_incremental_revisions(loaded)

    assert result.status == "inconclusive"
    assert result.previous_revision_recovered is False
    assert len(result.limitations) >= 1

