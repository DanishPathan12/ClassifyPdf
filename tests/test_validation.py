"""Tests for file validation and rejection behavior."""

from __future__ import annotations

import io
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.validation import MAX_FILE_SIZE_BYTES
from tests.fixtures.pdf_generators import (
    make_corrupted_image,
    make_corrupted_pdf,
    make_encrypted_pdf,
    make_non_pdf,
    make_valid_image_with_exif,
    make_valid_pdf,
)

client = TestClient(app)


def test_health_check() -> None:
    """GET /health must return status ok."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_reject_no_file_uploaded() -> None:
    """Request with no file field provided must be rejected with HTTP 400."""
    response = client.post("/analyze")
    assert response.status_code == 400
    assert "no file was provided" in response.json()["detail"].lower()


def test_reject_empty_filename() -> None:
    """Upload with empty filename must be rejected with HTTP 400."""
    response = client.post(
        "/analyze",
        files={"file": ("", b"%PDF-1.7\n%test", "application/pdf")},
    )
    assert response.status_code == 400
    assert "no file was provided" in response.json()["detail"].lower()


def test_analysis_timeout_handling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hostile/slow PDF analysis must trigger a 504 Gateway Timeout."""
    import time
    import app.main as main_mod

    def slow_analyzer(*args: any, **kwargs: any) -> any:
        time.sleep(0.05)
        raise RuntimeError("Should have timed out")

    monkeypatch.setattr(main_mod, "ANALYSIS_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(main_mod, "analyze_pdf_file", slow_analyzer)

    pdf_bytes = make_valid_pdf()
    response = client.post(
        "/analyze",
        files={"file": ("slow.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 504
    assert "timed out" in response.json()["detail"].lower()


def test_reject_empty_file() -> None:
    """Empty upload (0 bytes) must be rejected with HTTP 400."""
    empty_bytes = b""
    response = client.post(
        "/analyze",
        files={"file": ("empty.pdf", empty_bytes, "application/pdf")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_reject_non_pdf_magic_bytes() -> None:
    """Non-PDF file with .pdf extension must be rejected with HTTP 415."""
    txt_data = make_non_pdf(b"This is a text file masquerading as a PDF.\n")
    response = client.post(
        "/analyze",
        files={"file": ("document.pdf", txt_data, "application/pdf")},
    )
    assert response.status_code == 415
    assert "%PDF-" in response.json()["detail"]


def test_reject_corrupted_pdf() -> None:
    """Corrupted PDF payload starting with %PDF- must be rejected with HTTP 422."""
    corrupted_data = make_corrupted_pdf()
    response = client.post(
        "/analyze",
        files={"file": ("corrupted.pdf", corrupted_data, "application/pdf")},
    )
    assert response.status_code == 422
    assert "corrupted" in response.json()["detail"].lower()


def test_reject_encrypted_pdf() -> None:
    """Password-protected PDF must be rejected with HTTP 422 stating it cannot be analyzed."""
    enc_data = make_encrypted_pdf(user_pw="secret123")
    response = client.post(
        "/analyze",
        files={"file": ("locked.pdf", enc_data, "application/pdf")},
    )
    assert response.status_code == 422
    assert "encrypted" in response.json()["detail"].lower()


def test_reject_oversized_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """Upload exceeding max allowed size must be rejected with HTTP 413."""
    # Temporarily set max size to 1024 bytes to test chunked early abort without 20MB allocation
    import app.validation as validation_module
    monkeypatch.setattr(validation_module, "MAX_FILE_SIZE_BYTES", 1024)

    # Valid PDF larger than 1024 bytes
    large_pdf_data = make_valid_pdf() * 2
    assert len(large_pdf_data) > 1024

    response = client.post(
        "/analyze",
        files={"file": ("oversized.pdf", large_pdf_data, "application/pdf")},
    )
    assert response.status_code == 413
    assert "exceeds" in response.json()["detail"].lower()


def test_accept_valid_pdf() -> None:
    """Valid PDF must be accepted and return HTTP 200 with complete response structure."""
    pdf_bytes = make_valid_pdf()
    response = client.post(
        "/analyze",
        files={"file": ("sample.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    assert "file" in data
    assert "metadata" in data
    assert "findings" in data
    assert "summary" in data

    assert data["file"]["name"] == "sample.pdf"
    assert data["file"]["size_bytes"] == len(pdf_bytes)
    assert len(data["file"]["sha256"]) == 64
    assert data["file"]["page_count"] == 1


def test_index_view() -> None:
    """GET / must return HTML UI dashboard with status 200."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "PDF & Document Forensic Analyzer" in response.text
    assert "dropZone" in response.text
    assert "previewContainer" in response.text
    assert "imagePreview" in response.text


def test_accept_valid_image() -> None:
    """Valid image with EXIF metadata must be accepted and return HTTP 200."""
    img_bytes = make_valid_image_with_exif()
    response = client.post(
        "/analyze",
        files={"file": ("photo.jpg", img_bytes, "image/jpeg")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["file"]["name"] == "photo.jpg"
    assert data["file"]["size_bytes"] == len(img_bytes)
    assert data["file"]["pdf_version"] == "Image (JPEG)"
    assert data["file"]["page_count"] == 1

    # Check standardized human-readable date format
    assert "creation_date" in data["metadata"]["dates"]
    assert "modification_date" in data["metadata"]["dates"]
    assert " at " in data["metadata"]["dates"]["creation_date"]
    assert "UTC" in data["metadata"]["dates"]["creation_date"]

    # Verify findings are populated
    finding_ids = [f["id"] for f in data["findings"]]
    assert "META_MODDATE_BEFORE_CREATION" in finding_ids
    assert "META_KNOWN_EDITING_TOOL" in finding_ids


def test_reject_corrupted_image() -> None:
    """Corrupted image starting with image magic bytes must be rejected with HTTP 422."""
    corrupted_data = make_corrupted_image()
    response = client.post(
        "/analyze",
        files={"file": ("broken.jpg", corrupted_data, "image/jpeg")},
    )
    assert response.status_code == 422
    assert "corrupted" in response.json()["detail"].lower()

