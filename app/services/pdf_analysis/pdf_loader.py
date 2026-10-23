"""PDF Loader: Safely loads, validates, hashes, and preserves PDF bytes."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
from pathlib import Path
import pikepdf


@dataclass
class LoadedPdf:
    """Container holding preserved bytes and basic attributes of a loaded PDF."""

    file_bytes: bytes
    sha256: str
    file_size: int
    filename: str
    page_count: int
    pdf_version: str
    is_encrypted: bool
    is_valid: bool
    error_message: str | None = None


def load_pdf(
    source: bytes | Path | io.BytesIO,
    filename: str = "document.pdf",
) -> LoadedPdf:
    """Safely inspect, validate, and load PDF bytes into memory.

    Args:
        source: Raw PDF bytes, file Path, or BytesIO buffer.
        filename: Original file name.

    Returns:
        LoadedPdf with preserved original bytes and structural facts.
    """
    if isinstance(source, Path):
        file_bytes = source.read_bytes()
    elif isinstance(source, io.BytesIO):
        file_bytes = source.getvalue()
    elif isinstance(source, (bytes, bytearray)):
        file_bytes = bytes(source)
    else:
        raise TypeError(f"Unsupported source type: {type(source)}")

    file_size = len(file_bytes)
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    # Empty file check
    if file_size == 0:
        return LoadedPdf(
            file_bytes=b"",
            sha256=sha256,
            file_size=0,
            filename=filename,
            page_count=0,
            pdf_version="",
            is_encrypted=False,
            is_valid=False,
            error_message="File is empty (0 bytes).",
        )

    # Magic byte check: must contain %PDF- in the first 1024 bytes
    header_chunk = file_bytes[:1024]
    pdf_marker_idx = header_chunk.find(b"%PDF-")
    if pdf_marker_idx == -1:
        return LoadedPdf(
            file_bytes=file_bytes,
            sha256=sha256,
            file_size=file_size,
            filename=filename,
            page_count=0,
            pdf_version="",
            is_encrypted=False,
            is_valid=False,
            error_message="File does not begin with valid %PDF- magic bytes within the first 1024 bytes.",
        )

    # Extract version from header e.g. %PDF-1.7
    version_str = "1.7"
    try:
        ver_bytes = header_chunk[pdf_marker_idx + 5 : pdf_marker_idx + 8]
        decoded_ver = ver_bytes.decode("ascii", errors="ignore")
        if decoded_ver and decoded_ver[0].isdigit():
            version_str = decoded_ver
    except Exception:
        pass

    # Open with pikepdf to check integrity and password encryption
    try:
        with pikepdf.Pdf.open(io.BytesIO(file_bytes)) as pdf:
            page_count = len(pdf.pages)
            if hasattr(pdf, "pdf_version"):
                version_str = str(pdf.pdf_version)
            return LoadedPdf(
                file_bytes=file_bytes,
                sha256=sha256,
                file_size=file_size,
                filename=filename,
                page_count=page_count,
                pdf_version=version_str,
                is_encrypted=False,
                is_valid=True,
                error_message=None,
            )
    except pikepdf.PasswordError:
        return LoadedPdf(
            file_bytes=file_bytes,
            sha256=sha256,
            file_size=file_size,
            filename=filename,
            page_count=0,
            pdf_version=version_str,
            is_encrypted=True,
            is_valid=False,
            error_message="PDF is password-encrypted and cannot be analyzed.",
        )
    except Exception as e:
        return LoadedPdf(
            file_bytes=file_bytes,
            sha256=sha256,
            file_size=file_size,
            filename=filename,
            page_count=0,
            pdf_version=version_str,
            is_encrypted=False,
            is_valid=False,
            error_message=f"PDF parsing failed (corrupted or malformed): {e}",
        )

