"""Orchestrator: Executes all edit detection test cases with failure isolation."""

from __future__ import annotations

import logging
from pathlib import Path

from app.metadata import extract_metadata, run_all_checks, standardize_all_dates
from app.models import Finding, MetadataContainer
from app.schemas.analysis import (
    TestCase1IncrementalResult,
    TestCase2SignatureResult,
    TestCase3ResavedResult,
    UnifiedAnalysisResponse,
)
from app.services.pdf_analysis.pdf_loader import LoadedPdf, load_pdf
from app.services.pdf_analysis.result_builder import build_unified_response
from app.services.pdf_analysis.test_case_1_incremental_revisions import analyze_incremental_revisions
from app.services.pdf_analysis.test_case_2_digital_signatures import analyze_digital_signatures
from app.services.pdf_analysis.test_case_3_resaved_pdf import analyze_resaved_pdf

logger = logging.getLogger("pdf_analyser.orchestrator")


def run_pdf_analysis(
    source: bytes | Path,
    filename: str = "document.pdf",
    doc_type: str | None = None,
) -> UnifiedAnalysisResponse:
    """Run full PDF forensic pipeline: metadata extraction, TC1, TC2, and TC3.

    Each test case runs with complete failure isolation.
    """
    # 1. Load and validate PDF
    loaded_pdf = load_pdf(source, filename=filename)

    # 2. Run existing metadata extraction and checks
    metadata_container = MetadataContainer(info={}, xmp={}, dates={})
    metadata_findings: list[Finding] = []

    if loaded_pdf.is_valid:
        try:
            import io
            import pikepdf

            with pikepdf.Pdf.open(io.BytesIO(loaded_pdf.file_bytes)) as pdf:
                parsed_data = extract_metadata(
                    pdf=pdf,
                    file_name=loaded_pdf.filename,
                    file_size=loaded_pdf.file_size,
                    sha256_hash=loaded_pdf.sha256,
                    doc_type=doc_type,
                )
            metadata_findings = run_all_checks(parsed_data)
            metadata_container = MetadataContainer(
                info=parsed_data.info,
                xmp=parsed_data.xmp,
                dates=standardize_all_dates(parsed_data),
            )
        except Exception as meta_err:
            logger.warning("Metadata analysis failed: %s", meta_err)

    # 3. Test Case 1: Incremental Revisions
    try:
        tc1_result = analyze_incremental_revisions(loaded_pdf)
    except Exception as e:
        logger.error("Test Case 1 failed unexpectedly: %s", e, exc_info=True)
        tc1_result = TestCase1IncrementalResult(
            status="inconclusive",
            revision_count=1,
            previous_revision_recovered=False,
            changes=[],
            limitations=[f"Unexpected error in incremental revision analysis: {e}"],
        )

    # 4. Test Case 2: Digital Signatures
    try:
        tc2_result = analyze_digital_signatures(loaded_pdf)
    except Exception as e:
        logger.error("Test Case 2 failed unexpectedly: %s", e, exc_info=True)
        tc2_result = TestCase2SignatureResult(
            status="inconclusive",
            signatures_found=0,
            signature_results=[],
            limitations=[f"Unexpected error in digital signature analysis: {e}"],
        )

    # 5. Test Case 3: Re-saved PDF Analysis
    # Note if historical revision was recovered by TC1
    historical_recovered = tc1_result.previous_revision_recovered
    try:
        tc3_result = analyze_resaved_pdf(loaded_pdf, historical_comparison_available=historical_recovered)
    except Exception as e:
        logger.error("Test Case 3 failed unexpectedly: %s", e, exc_info=True)
        tc3_result = TestCase3ResavedResult(
            status="inconclusive",
            historical_comparison_available=historical_recovered,
            findings=[],
            limitations=[f"Unexpected error in re-saved layout analysis: {e}"],
        )

    # 6. Build unified response
    return build_unified_response(
        loaded_pdf=loaded_pdf,
        metadata_container=metadata_container,
        metadata_findings=metadata_findings,
        tc1_result=tc1_result,
        tc2_result=tc2_result,
        tc3_result=tc3_result,
    )
