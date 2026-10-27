"""Result Builder: Produces a consistent, evidence-based unified analysis response."""

from __future__ import annotations

import logging
from typing import Any

from app.models import FileInfo, Finding, MetadataContainer
from app.schemas.analysis import (
    ForensicFinding,
    TestCase1IncrementalResult,
    TestCase2SignatureResult,
    TestCase3ResavedResult,
    TestCasesContainer,
    UnifiedAnalysisResponse,
    UnifiedSummary,
)
from app.services.pdf_analysis.decision_engine import DecisionOutcome
from app.services.pdf_analysis.pdf_loader import LoadedPdf

logger = logging.getLogger("pdf_analyser.result_builder")


def build_unified_response(
    loaded_pdf: LoadedPdf,
    metadata_container: MetadataContainer,
    metadata_findings: list[Finding],
    tc1_result: TestCase1IncrementalResult,
    tc2_result: TestCase2SignatureResult,
    tc3_result: TestCase3ResavedResult,
    decision: DecisionOutcome | None = None,
    all_forensic_findings: list[ForensicFinding] | None = None,
    checks: dict[str, str] | None = None,
) -> UnifiedAnalysisResponse:
    """Consolidate file info, metadata findings, test cases, and decision engine outcome.

    Preserves both modern Section 5 API attributes and legacy test-case containers.
    """
    file_info = FileInfo(
        name=loaded_pdf.filename,
        size_bytes=loaded_pdf.file_size,
        sha256=loaded_pdf.sha256,
        pdf_version=loaded_pdf.pdf_version or "1.7",
        page_count=loaded_pdf.page_count,
    )

    test_cases = TestCasesContainer(
        incremental_revisions=tc1_result,
        digital_signatures=tc2_result,
        resaved_pdf_analysis=tc3_result,
    )

    # Calculate confirmed changes & suspicious counts for backwards compatibility
    confirmed_changes = 0
    if tc1_result.status == "changes_detected" and tc1_result.previous_revision_recovered:
        confirmed_changes += len(tc1_result.changes)

    if tc2_result.status == "post_signature_changes_detected":
        for sig in tc2_result.signature_results:
            confirmed_changes += len(sig.post_signature_changes)

    suspicious_indicators = 0
    for mf in metadata_findings:
        if getattr(mf.category, "value", str(mf.category)) == "suspicious":
            suspicious_indicators += 1

    if tc3_result.status == "suspicious_indicators_found":
        suspicious_indicators += len(tc3_result.findings)

    if tc2_result.status == "signature_invalid":
        suspicious_indicators += 1

    confirmed_meta = sum(1 for f in metadata_findings if getattr(f.category, "value", str(f.category)) == "confirmed")
    suspicious_meta = sum(1 for f in metadata_findings if getattr(f.category, "value", str(f.category)) == "suspicious")
    inconclusive_meta = sum(1 for f in metadata_findings if getattr(f.category, "value", str(f.category)) == "inconclusive")

    # If decision engine outcome is supplied, use it to populate verdict, edit_detected, confidence, and summary
    if decision is not None:
        verdict = decision.verdict
        edit_detected = decision.edit_detected
        confidence = decision.confidence
        overall = decision.summary
        analysis_status = decision.analysis_status
        module_checks = decision.checks
        limitations = decision.limitations
        findings_list = all_forensic_findings or decision.all_findings

        # Map to legacy classification for backwards compatibility with tests expecting "confirmed_changes"
        if verdict == "likely_edited":
            legacy_classification = "confirmed_changes"
        elif verdict == "suspicious_indicators":
            legacy_classification = "suspicious_indicators"
        elif verdict == "no_edit_evidence_found":
            legacy_classification = "no_edit_evidence_found"
        else:
            legacy_classification = "inconclusive"
    else:
        # Fallback if decision was not run
        if not loaded_pdf.is_valid:
            legacy_classification = "inconclusive"
            verdict = "inconclusive"
            edit_detected = None
            confidence = 0.0
            overall = "Analysis was inconclusive due to file structure or missing data."
        elif confirmed_changes > 0 or confirmed_meta > 0:
            legacy_classification = "confirmed_changes"
            verdict = "likely_edited"
            edit_detected = True
            confidence = 0.85
            overall = f"{confirmed_changes} confirmed modification indicator(s) found; these are not proof of tampering."
        elif suspicious_indicators > 0 or suspicious_meta > 0:
            legacy_classification = "suspicious_indicators"
            verdict = "suspicious_indicators"
            edit_detected = None
            confidence = 0.35
            overall = f"{suspicious_indicators} suspicious indicator(s) found; these are not proof of tampering."
        else:
            legacy_classification = "no_edit_evidence_found"
            verdict = "no_edit_evidence_found"
            edit_detected = False
            confidence = 0.0
            overall = "No evidence of editing found by the implemented revision, signature, or layout checks."

        analysis_status = "completed" if loaded_pdf.is_valid else "inconclusive"
        module_checks = checks or {
            "metadata": "completed",
            "revision_history": "completed",
            "digital_signatures": "completed",
            "content_streams": "completed",
            "layout_analysis": "completed",
        }
        limitations = tc1_result.limitations + tc2_result.limitations + tc3_result.limitations
        findings_list = all_forensic_findings or metadata_findings

    unified_summary = UnifiedSummary(
        verdict=verdict,
        edit_detected=edit_detected,
        confidence=confidence,
        classification=legacy_classification,
        overall=overall,
        confirmed_changes=confirmed_changes + confirmed_meta,
        suspicious_indicators=suspicious_indicators,
        confirmed=confirmed_meta + confirmed_changes,
        suspicious=suspicious_meta + (1 if tc3_result.findings else 0),
        inconclusive=inconclusive_meta,
        limitations=limitations,
    )

    return UnifiedAnalysisResponse(
        file_name=loaded_pdf.filename,
        file_hash_sha256=loaded_pdf.sha256,
        verdict=verdict,
        edit_detected=edit_detected,
        confidence=confidence,
        analysis_status=analysis_status,
        findings=findings_list,
        checks=module_checks,
        limitations=limitations,
        file=file_info,
        metadata=metadata_container,
        test_cases=test_cases,
        summary=unified_summary,
    )
