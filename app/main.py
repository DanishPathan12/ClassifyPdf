"""FastAPI application entrypoint for PDF forensic metadata analysis."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from app.api.routes.analyze import router as analyze_router
from app.metadata import analyze_image_file
from app.models import HealthResponse
from app.schemas.analysis import UnifiedAnalysisResponse
from app.services.pdf_analysis.orchestrator import run_pdf_analysis
from app.validation import validate_and_save_upload

# Configure logging: ensure file contents and metadata values are NEVER logged at INFO level
logger = logging.getLogger("pdf_analyser")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

# Hostile PDF timeout protection (in seconds)
ANALYSIS_TIMEOUT_SECONDS: float = 30.0


def analyze_pdf_file(
    file_path: Path,
    file_name: str,
    file_size: int,
    sha256_hash: str,
    doc_type: str | None = None,
    original_source: bytes | Path | None = None,
    original_filename: str = "trusted_original.pdf",
    expected_hash: str | None = None,
) -> UnifiedAnalysisResponse:
    """Analyze PDF file through the three-layer forensic orchestrator."""
    return run_pdf_analysis(
        file_path,
        filename=file_name,
        doc_type=doc_type,
        original_source=original_source,
        original_filename=original_filename,
        expected_hash=expected_hash,
    )

app = FastAPI(
    title="PDF Forensic Metadata Analysis Service",
    description="High-accuracy PDF metadata extraction and forensic analysis service.",
    version="0.2.0",
)

app.include_router(analyze_router, prefix="/api/v1")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Ensure missing or non-file upload inputs return HTTP 400 as per specification."""
    for error in exc.errors():
        loc = error.get("loc", ())
        if "file" in loc:
            return JSONResponse(
                status_code=400,
                content={"detail": "Missing or invalid file upload: no file was provided."},
            )
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


@app.get("/", response_class=HTMLResponse)
async def index_view() -> HTMLResponse:
    """Serve the simple web interface for summary inspection and PDF/image uploads."""
    template_file = Path(__file__).parent / "templates" / "index.html"
    return HTMLResponse(content=template_file.read_text(encoding="utf-8"))


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return health status."""
    return HealthResponse(status="ok")


@app.post("/analyze", response_model=UnifiedAnalysisResponse)
async def analyze_pdf(
    file: UploadFile | None = File(default=None, description="PDF or Image file to analyze"),
    original_file: UploadFile | None = File(default=None, description="Optional trusted reference original PDF"),
    expected_hash: str | None = Form(default=None, description="Optional expected SHA-256 reference hash"),
    doc_type: str | None = Form(default=None, description="Optional document type: 'official' (bank receipt, invoice, ID) or 'standard' (resume, report)"),
) -> UnifiedAnalysisResponse:
    """Analyze an uploaded PDF or image across structural, visual, and independent verification layers."""
    temp_path: Path | None = None

    try:
        # Validate upload, enforce size limit, and save to secure temporary path
        temp_path, file_size, sha256_hash, file_type = await validate_and_save_upload(file)
        safe_filename = Path(file.filename or "upload.pdf").name

        orig_bytes: bytes | None = None
        orig_name: str = "trusted_original.pdf"
        if original_file and original_file.filename:
            orig_bytes = await original_file.read()
            orig_name = Path(original_file.filename).name

        logger.info(
            "Processing %s upload: filename=%s, size_bytes=%d, doc_type=%s, has_original=%s",
            file_type.upper(),
            safe_filename,
            file_size,
            doc_type,
            bool(orig_bytes),
        )

        try:
            if file_type == "image":
                analysis_result = await asyncio.wait_for(
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
                analysis_result = await asyncio.wait_for(
                    run_in_threadpool(
                        analyze_pdf_file,
                        temp_path,
                        safe_filename,
                        file_size,
                        sha256_hash,
                        doc_type,
                        orig_bytes,
                        orig_name,
                        expected_hash,
                    ),
                    timeout=ANALYSIS_TIMEOUT_SECONDS,
                )
        except asyncio.TimeoutError:
            logger.warning("PDF analysis timed out after %.1fs", ANALYSIS_TIMEOUT_SECONDS)
            raise HTTPException(
                status_code=504,
                detail=f"Analysis timed out after {ANALYSIS_TIMEOUT_SECONDS} seconds.",
            )

        logger.info(
            "Completed PDF analysis: findings_count=%d",
            len(analysis_result.findings),
        )
        return analysis_result

    finally:
        # Ensure temporary file is always deleted
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError as e:
                logger.debug("Failed to delete temp file %s: %s", temp_path, e)
