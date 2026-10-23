"""Result Builder: Produces a consistent, evidence-based unified analysis response."""

from __future__ import annotations

import logging
from typing import Any

from app.models import FileInfo, Finding, MetadataContainer, Summary
from app.schemas.analysis import (
    TestCase1IncrementalResult,
    TestCase2SignatureResult,
    TestCase3ResavedResult,
    TestCasesContainer,
    UnifiedAnalysisResponse,
    UnifiedSummary,
)
from app.services.pdf_analysis.pdf_loader import LoadedPdf

logger = logging.getLogger("pdf_analyser.result_builder")


def build_unified_response(
    loaded_pdf: LoadedPdf,
    metadata_container: MetadataContainer,
    metadata_findings: list[Finding],
    tc1_result: TestCase1IncrementalResult,
    tc2_result: TestCase2SignatureResult,
    tc3_result: TestCase3ResavedResult,
) -> UnifiedAnalysisResponse:
    """Consolidate file info, metadata findings, and the 3 test case results into a unified response."""
    # 1. Basic File Info
    file_info = FileInfo(
        name=loaded_pdf.filename,
        size_bytes=loaded_pdf.file_size,
        sha256=loaded_pdf.sha256,
        pdf_version=loaded_pdf.pdf_version or "1.7",
        page_count=loaded_pdf.page_count,
    )

    # 2. Group test cases
    test_cases = TestCasesContainer(
        incremental_revisions=tc1_result,
        digital_signatures=tc2_result,
        resaved_pdf_analysis=tc3_result,
    )

    # 3. Calculate confirmed changes & suspicious indicators
    confirmed_changes = 0
    if tc1_result.status == "changes_detected" and tc1_result.previous_revision_recovered:
        confirmed_changes += len(tc1_result.changes)

    if tc2_result.status == "post_signature_changes_detected":
        for sig in tc2_result.signature_results:
            confirmed_changes += len(sig.post_signature_changes)

    suspicious_indicators = 0
    # From metadata checks
    for mf in metadata_findings:
        if mf.category.value == "suspicious":
            suspicious_indicators += 1

    # From Test Case 3 layout anomalies
    if tc3_result.status == "suspicious_indicators_found":
        suspicious_indicators += len(tc3_result.findings)

    # From invalid signatures
    if tc2_result.status == "signature_invalid":
        suspicious_indicators += 1

    # Count confirmed from metadata
    confirmed_meta = sum(1 for f in metadata_findings if f.category.value == "confirmed")
    suspicious_meta = sum(1 for f in metadata_findings if f.category.value == "suspicious")
    inconclusive_meta = sum(1 for f in metadata_findings if f.category.value == "inconclusive")

    # 4. Determine Unified Classification
    if not loaded_pdf.is_valid:
        classification = "inconclusive"
    elif confirmed_changes > 0 or confirmed_meta > 0:
        classification = "confirmed_changes"
    elif suspicious_indicators > 0 or suspicious_meta > 0:
        classification = "suspicious_indicators"
    elif (
        tc1_result.status == "inconclusive"
        and tc2_result.status == "inconclusive"
        and tc3_result.status == "inconclusive"
    ):
        classification = "inconclusive"
    else:
        classification = "no_edit_evidence_found"

    # 5. Collect limitations
    limitations: list[str] = []
    for lim in tc1_result.limitations + tc2_result.limitations + tc3_result.limitations:
        if lim and lim not in limitations:
            limitations.append(lim)

    # 6. Overall neutral summary narrative
    if classification == "confirmed_changes":
        overall = (
            f"{confirmed_changes} confirmed modification indicator(s) found; "
            "these are not proof of tampering."
        )
    elif classification == "suspicious_indicators":
        overall = (
            f"{suspicious_indicators} suspicious indicator(s) found; "
            "these are not proof of tampering."
        )
    elif classification == "no_edit_evidence_found":
        overall = (
            "No evidence of editing found by the implemented revision, signature, or layout checks. "
            "This does not prove the PDF was never modified."
        )
    else:
        overall = "Analysis was inconclusive due to file structure or missing data."

    unified_summary = UnifiedSummary(
        classification=classification,
        confirmed_changes=confirmed_changes + confirmed_meta,
        suspicious_indicators=suspicious_indicators,
        confirmed=confirmed_meta + confirmed_changes,
        suspicious=suspicious_meta + (1 if tc3_result.findings else 0),
        inconclusive=inconclusive_meta,
        overall=overall,
        limitations=limitations,
    )

    return UnifiedAnalysisResponse(
        file=file_info,
        metadata=metadata_container,
        findings=metadata_findings,
        test_cases=test_cases,
        summary=unified_summary,
    )
