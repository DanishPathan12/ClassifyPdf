"""Analysis API route accepting PDF or image uploads."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from starlette.concurrency import run_in_threadpool

from app.metadata import analyze_image_file
from app.schemas.analysis import UnifiedAnalysisResponse
from app.services.pdf_analysis.orchestrator import run_pdf_analysis
from app.validation import validate_and_save_upload

logger = logging.getLogger("pdf_analyser.api.analyze")
ANALYSIS_TIMEOUT_SECONDS: float = 30.0

router = APIRouter(tags=["Forensics"])


def _analyze_pdf_sync(
    file_path: Path,
    safe_filename: str,
    doc_type: str | None,
    original_bytes: bytes | None = None,
    original_filename: str = "trusted_original.pdf",
    expected_hash: str | None = None,
) -> UnifiedAnalysisResponse:
    """Synchronous worker running in threadpool."""
    return run_pdf_analysis(
        file_path,
        filename=safe_filename,
        doc_type=doc_type,
        original_source=original_bytes,
        original_filename=original_filename,
        expected_hash=expected_hash,
    )


@router.post("/analyze", response_model=UnifiedAnalysisResponse)
async def analyze_document(
    file: UploadFile | None = File(default=None, description="PDF or Image file to analyze"),
    original_file: UploadFile | None = File(default=None, description="Optional trusted reference original PDF"),
    expected_hash: str | None = Form(default=None, description="Optional expected SHA-256 reference hash"),
    doc_type: str | None = Form(default=None, description="Optional document context: 'official' or 'standard'"),
) -> UnifiedAnalysisResponse:
    """Analyze an uploaded PDF or image for forensic editing, metadata, signatures, and revisions."""
    temp_path: Path | None = None

    try:
        temp_path, file_size, sha256_hash, file_type = await validate_and_save_upload(file)
        safe_filename = Path(file.filename or "upload.pdf").name

        orig_bytes: bytes | None = None
        orig_name: str = "trusted_original.pdf"
        if original_file and original_file.filename:
            orig_bytes = await original_file.read()
            orig_name = Path(original_file.filename).name

        logger.info(
            "Analyzing %s: name=%s, size=%d, doc_type=%s, has_original=%s",
            file_type.upper(),
            safe_filename,
            file_size,
            doc_type,
            bool(orig_bytes),
        )

        try:
            if file_type == "image":
                result = await asyncio.wait_for(
                    run_in_threadpool(
                        analyze_image_file,
                        temp_path,
                        safe_filename,
                        file_size,
                        sha256_hash,
                        doc_type,
                    ),
                    timeout=ANALYSIS_TIMEOUT_SECONDS,
                )
            else:
                result = await asyncio.wait_for(
                    run_in_threadpool(
                        _analyze_pdf_sync,
                        temp_path,
                        safe_filename,
                        doc_type,
                        orig_bytes,
                        orig_name,
                        expected_hash,
                    ),
                    timeout=ANALYSIS_TIMEOUT_SECONDS,
                )
        except asyncio.TimeoutError:
            logger.warning("Document analysis timed out after %.1fs", ANALYSIS_TIMEOUT_SECONDS)
            raise HTTPException(
                status_code=504,
                detail=f"Analysis timed out after {ANALYSIS_TIMEOUT_SECONDS} seconds.",
            )

        return result

    finally:
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError as e:
                logger.debug("Failed to delete temp file %s: %s", temp_path, e)

