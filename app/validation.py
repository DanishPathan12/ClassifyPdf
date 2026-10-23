"""Upload validation and secure temporary file storage."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from fastapi import HTTPException, UploadFile
import pikepdf
from PIL import Image

# Maximum file size allowed for upload: 20 MB (configurable)
MAX_FILE_SIZE_BYTES: int = 20 * 1024 * 1024

# Stream chunk size for reading uploads (64 KB)
CHUNK_SIZE: int = 64 * 1024

# First N bytes to inspect for the PDF/image magic bytes
MAGIC_BYTES_LIMIT: int = 1024

# Magic byte signatures
PDF_MAGIC_BYTES: bytes = b"%PDF-"
JPEG_MAGIC_BYTES: bytes = b"\xFF\xD8\xFF"
PNG_MAGIC_BYTES: bytes = b"\x89PNG\r\n\x1a\n"
TIFF_LE_MAGIC: bytes = b"II*\x00"
TIFF_BE_MAGIC: bytes = b"MM\x00*"


async def validate_and_save_upload(
    file: UploadFile,
    max_size_bytes: int | None = None,
) -> tuple[Path, int, str, str]:
    """Validate incoming upload and save to an unpredictable temporary file.

    Performs:
    1. Rejects if file is missing or has an empty filename (HTTP 400).
    2. Enforces maximum file size by reading in chunks and aborting early (HTTP 413).
    3. Rejects empty files (HTTP 400).
    4. Validates that the file starts with %PDF- or valid image magic bytes (HTTP 415).
    5. Checks parsing with pikepdf for PDF or Pillow for images; rejects corrupted files (HTTP 422).
    6. Checks encryption requiring a password; rejects without cracking (HTTP 422).
    7. Cleans up the temporary file if any validation step fails.

    Returns:
        tuple of (temporary_file_path, file_size_bytes, sha256_hex, file_type)
        where file_type is 'pdf' or 'image'.
    """
    effective_max_size = max_size_bytes if max_size_bytes is not None else MAX_FILE_SIZE_BYTES

    if file is None or not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Missing or invalid file upload: no file was provided.",
        )

    # Create unpredictable temporary file
    temp_file = tempfile.NamedTemporaryFile(
        delete=False,
        prefix="pdf_forensic_",
        suffix=".bin",
    )
    temp_path = Path(temp_file.name)

    total_bytes = 0
    hasher = hashlib.sha256()

    try:
        with temp_file:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break

                total_bytes += len(chunk)
                if total_bytes > effective_max_size:
                    raise HTTPException(
                        status_code=413,
                        detail=(
                            f"File exceeds maximum allowed size of {effective_max_size} "
                            f"bytes (20 MB)."
                        ),
                    )

                hasher.update(chunk)
                temp_file.write(chunk)

        if total_bytes == 0:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty (0 bytes).",
            )

        # Validate magic bytes within the first 1024 bytes
        with open(temp_path, "rb") as f:
            header_sample = f.read(MAGIC_BYTES_LIMIT)

        is_pdf = PDF_MAGIC_BYTES in header_sample
        is_jpeg = header_sample.startswith(JPEG_MAGIC_BYTES)
        is_png = header_sample.startswith(PNG_MAGIC_BYTES)
        is_webp = header_sample.startswith(b"RIFF") and b"WEBP" in header_sample[:16]
        is_tiff = header_sample.startswith(TIFF_LE_MAGIC) or header_sample.startswith(TIFF_BE_MAGIC)

        if is_pdf:
            file_type = "pdf"
        elif is_jpeg or is_png or is_webp or is_tiff:
            file_type = "image"
        else:
            raise HTTPException(
                status_code=415,
                detail=(
                    "Unsupported media type: file does not contain a valid '%PDF-' "
                    "header or supported image format (JPEG, PNG, WebP, TIFF)."
                ),
            )

        if file_type == "pdf":
            # Validate PDF structure and encryption with pikepdf
            try:
                with pikepdf.open(temp_path) as pdf:
                    _ = len(pdf.pages)
                    _ = pdf.Root
            except pikepdf.PasswordError:
                raise HTTPException(
                    status_code=422,
                    detail="Encrypted PDF: password-protected files cannot be analyzed.",
                )
            except pikepdf.PdfError as e:
                raise HTTPException(
                    status_code=422,
                    detail=f"Corrupted PDF: pikepdf failed to parse file structure ({e}).",
                )
            except Exception as e:
                raise HTTPException(
                    status_code=422,
                    detail=f"Corrupted or unreadable PDF: {e}.",
                )
        else:
            # Validate image structure with Pillow
            try:
                with Image.open(temp_path) as img:
                    img.verify()
            except Exception as e:
                raise HTTPException(
                    status_code=422,
                    detail=f"Corrupted image: failed to parse image structure ({e}).",
                )

        return temp_path, total_bytes, hasher.hexdigest(), file_type

    except Exception:
        # Guarantee removal of temporary file if any validation step fails
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise
