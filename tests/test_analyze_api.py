"""Integration tests for the unified /analyze endpoint."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from tests.fixtures.pdf_generators import (
    make_incremental_pdf,
    make_normal_pdf,
    make_resaved_pdf_with_overlap,
    make_signed_pdf_with_appended_revision,
)

client = TestClient(app)


def test_api_analyze_normal_pdf() -> None:
    """Analyze endpoint must return complete unified response for normal PDF."""
    pdf_bytes = make_normal_pdf()
    response = client.post(
        "/analyze",
        files={"file": ("report.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    assert "file" in data
    assert "metadata" in data
    assert "findings" in data
    assert "test_cases" in data
    assert "summary" in data

    tc = data["test_cases"]
    assert "incremental_revisions" in tc
    assert "digital_signatures" in tc
    assert "resaved_pdf_analysis" in tc

    assert tc["incremental_revisions"]["status"] == "no_revision_evidence"
    assert tc["digital_signatures"]["status"] == "no_signatures_found"

    summary = data["summary"]
    assert summary["classification"] in ("no_edit_evidence_found", "suspicious_indicators", "inconclusive")
    assert "authentic" not in summary["overall"].lower()
    assert "forged" not in summary["overall"].lower()


def test_api_analyze_incremental_pdf() -> None:
    """Analyze endpoint must detect and report confirmed changes for incremental PDF."""
    pdf_bytes = make_incremental_pdf(
        original_text="Grant Total: $10,000",
        appended_text="Grant Total: $90,000",
    )
    response = client.post(
        "/analyze",
        files={"file": ("grant_edited.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    tc1 = data["test_cases"]["incremental_revisions"]
    assert tc1["status"] == "changes_detected"
    assert tc1["revision_count"] >= 2
    assert tc1["previous_revision_recovered"] is True
    assert len(tc1["changes"]) >= 1

    summary = data["summary"]
    assert summary["classification"] == "confirmed_changes"
    assert summary["confirmed_changes"] >= 1


def test_api_analyze_signed_modified_pdf() -> None:
    """Analyze endpoint must report post-signature modifications."""
    pdf_bytes = make_signed_pdf_with_appended_revision(
        original_text="Signed Contract $5,000",
        appended_text="Forged Clause $50,000",
    )
    response = client.post(
        "/analyze",
        files={"file": ("contract_tampered.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    tc2 = data["test_cases"]["digital_signatures"]
    assert tc2["status"] == "post_signature_changes_detected"
    assert tc2["signatures_found"] == 1
    assert len(tc2["signature_results"][0]["post_signature_changes"]) >= 1

    summary = data["summary"]
    assert summary["classification"] == "confirmed_changes"


def test_api_analyze_resaved_overlap_pdf() -> None:
    """Analyze endpoint must flag layout anomalies in re-saved PDF."""
    pdf_bytes = make_resaved_pdf_with_overlap()
    response = client.post(
        "/analyze",
        files={"file": ("overlap.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    tc3 = data["test_cases"]["resaved_pdf_analysis"]
    assert tc3["status"] == "suspicious_indicators_found"
    assert len(tc3["findings"]) >= 1

    summary = data["summary"]
    assert summary["suspicious_indicators"] >= 1


def test_api_v1_router_endpoint() -> None:
    """The modular /api/v1/analyze endpoint must execute the pipeline and return valid schema."""
    pdf_bytes = make_normal_pdf()
    response = client.post(
        "/api/v1/analyze",
        files={"file": ("v1_test.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()
    assert "test_cases" in data
    assert data["test_cases"]["incremental_revisions"]["status"] == "no_revision_evidence"

