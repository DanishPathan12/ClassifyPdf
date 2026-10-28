"""Orchestrator: Executes all forensic detection modules with failure isolation and evidence synthesis."""

from __future__ import annotations

import io
import logging
from pathlib import Path
import pikepdf

from app.metadata import (
    extract_metadata,
    log_pdf_metadata,
    run_all_checks,
    standardize_all_dates,
)
from app.models import Finding, MetadataContainer
from app.schemas.analysis import (
    ForensicFinding,
    TestCase1IncrementalResult,
    TestCase2SignatureResult,
    TestCase3ResavedResult,
    UnifiedAnalysisResponse,
)
from app.services.pdf_analysis.decision_engine import evaluate_forensic_evidence
from app.services.pdf_analysis.pdf_loader import LoadedPdf, load_pdf
from app.services.pdf_analysis.result_builder import build_unified_response
from app.services.pdf_analysis.revision_forensics import analyze_revision_structure
from app.services.pdf_analysis.signature_forensics import analyze_digital_signatures_forensics
from app.services.pdf_analysis.structural_analysis import analyze_structural_layer
from app.services.pdf_analysis.structural_forensics import analyze_structural_forensics
from app.services.pdf_analysis.test_case_1_incremental_revisions import analyze_incremental_revisions
from app.services.pdf_analysis.test_case_2_digital_signatures import analyze_digital_signatures
from app.services.pdf_analysis.test_case_3_resaved_pdf import (
    analyze_resaved_pdf,
    resaved_findings_to_forensic,
)
from app.services.pdf_analysis.verification_analysis import analyze_verification_layer
from app.services.pdf_analysis.visual_analysis import analyze_visual_layer

logger = logging.getLogger("pdf_analyser.orchestrator")


def _convert_metadata_finding_to_forensic(f: Finding) -> ForensicFinding:
    """Map metadata Finding model to standard ForensicFinding with calibrated confidence."""
    code = f.id
    cat_val = getattr(f.category, "value", str(f.category))
    sev_val = getattr(f.severity, "value", str(f.severity))

    if code == "META_MODDATE_DIFFERS_CREATION":
        if "red flag" in f.title.lower() or sev_val in ("medium", "high"):
            conf = 0.75
            sev = sev_val
        else:
            conf = 0.20
            sev = "info"
    elif code == "META_MODDATE_BEFORE_CREATION":
        conf = 0.55
        sev = "medium"
    elif code == "META_INFO_XMP_MISMATCH":
        conf = 0.35
        sev = "low"
    elif code == "META_KNOWN_EDITING_TOOL":
        conf = 0.20
        sev = "low"
    elif code == "META_FUTURE_DATE":
        conf = 0.45
        sev = "medium"
    elif cat_val == "suspicious":
        conf = 0.30
        sev = sev_val
    elif cat_val == "confirmed":
        conf = 0.40
        sev = sev_val
    else:
        conf = 0.05
        sev = "info"

    return ForensicFinding(
        code=code,
        category=cat_val,
        domain="metadata",
        severity=sev,
        confidence=conf,
        title=f.title,
        description=f.explanation,
        evidence=f.evidence,
        limitations=[
            "Metadata timestamps can be altered by mail servers, file copying, or non-destructive viewers.",
            "Metadata anomalies alone do not prove document content manipulation.",
        ],
    )


def run_pdf_analysis(
    source: bytes | Path,
    filename: str = "document.pdf",
    doc_type: str | None = None,
    original_source: bytes | Path | None = None,
    original_filename: str = "trusted_original.pdf",
    expected_hash: str | None = None,
) -> UnifiedAnalysisResponse:
    """Run full three-layer PDF forensic pipeline: structural, visual, and independent verification.

    Each module runs with complete failure isolation.
    """
    # 1. Load and validate PDF
    loaded_pdf = load_pdf(source, filename=filename)

    checks: dict[str, str] = {
        "metadata": "skipped",
        "revision_history": "skipped",
        "digital_signatures": "skipped",
        "content_streams": "skipped",
        "layout_analysis": "skipped",
    }
    all_forensic_findings: list[ForensicFinding] = []
    module_limitations: list[str] = []

    # 2. Metadata Extraction and Checks
    metadata_container = MetadataContainer(info={}, xmp={}, dates={})
    metadata_findings: list[Finding] = []

    if loaded_pdf.is_valid:
        try:
            page_text_sample = ""
            try:
                import fitz
                with fitz.open(stream=loaded_pdf.file_bytes, filetype="pdf") as f_doc:
                    if len(f_doc) > 0:
                        page_text_sample = f_doc[0].get_text("text")[:2000].lower()
            except Exception:
                pass

            with pikepdf.Pdf.open(io.BytesIO(loaded_pdf.file_bytes)) as pdf:
                parsed_data = extract_metadata(
                    pdf=pdf,
                    file_name=loaded_pdf.filename,
                    file_size=loaded_pdf.file_size,
                    sha256_hash=loaded_pdf.sha256,
                    doc_type=doc_type,
                    page_text_sample=page_text_sample,
                )
            metadata_findings = run_all_checks(parsed_data)
            metadata_container = MetadataContainer(
                info=parsed_data.info,
                xmp=parsed_data.xmp,
                dates=standardize_all_dates(parsed_data),
            )
            for mf in metadata_findings:
                all_forensic_findings.append(_convert_metadata_finding_to_forensic(mf))
            checks["metadata"] = "completed"

            # Print & log all extracted metadata for inspection/testing
            log_pdf_metadata(
                file_name=loaded_pdf.filename,
                file_size=loaded_pdf.file_size,
                sha256=loaded_pdf.sha256,
                pdf_version=loaded_pdf.pdf_version,
                page_count=loaded_pdf.page_count,
                info=metadata_container.info,
                xmp=metadata_container.xmp,
                dates=metadata_container.dates,
            )
        except Exception as meta_err:
            logger.warning("Metadata analysis failed: %s", meta_err)
            checks["metadata"] = "failed"
            module_limitations.append(f"Metadata extraction failed: {meta_err}")

    # 3. Revision History and Cross-Reference Forensics
    try:
        rev_forensics = analyze_revision_structure(loaded_pdf)
        all_forensic_findings.extend(rev_forensics.findings)
        module_limitations.extend(rev_forensics.limitations)
        tc1_result = analyze_incremental_revisions(loaded_pdf)
        checks["revision_history"] = rev_forensics.module_status
    except Exception as rev_err:
        logger.error("Revision history analysis failed unexpectedly: %s", rev_err, exc_info=True)
        checks["revision_history"] = "failed"
        module_limitations.append(f"Revision history analysis error: {rev_err}")
        tc1_result = TestCase1IncrementalResult(
            status="inconclusive",
            revision_count=1,
            previous_revision_recovered=False,
            changes=[],
            limitations=[f"Unexpected error in revision analysis: {rev_err}"],
        )

    # 4. Digital Signature Forensics
    try:
        sig_forensics = analyze_digital_signatures_forensics(loaded_pdf)
        all_forensic_findings.extend(sig_forensics.findings)
        module_limitations.extend(sig_forensics.limitations)
        tc2_result = analyze_digital_signatures(loaded_pdf)
        checks["digital_signatures"] = sig_forensics.module_status
    except Exception as sig_err:
        logger.error("Digital signature analysis failed unexpectedly: %s", sig_err, exc_info=True)
        checks["digital_signatures"] = "failed"
        module_limitations.append(f"Digital signature analysis error: {sig_err}")
        tc2_result = TestCase2SignatureResult(
            status="inconclusive",
            signatures_found=0,
            signature_results=[],
            limitations=[f"Unexpected error in signature analysis: {sig_err}"],
        )

    # 5. Content-Stream and Structural Forensics
    try:
        structural_forensics = analyze_structural_forensics(loaded_pdf)
        all_forensic_findings.extend(structural_forensics.findings)
        module_limitations.extend(structural_forensics.limitations)
        checks["content_streams"] = structural_forensics.module_status
    except Exception as struct_err:
        logger.error("Structural content-stream forensics failed unexpectedly: %s", struct_err, exc_info=True)
        checks["content_streams"] = "failed"
        module_limitations.append(f"Structural content-stream analysis error: {struct_err}")

    # 6. Layout and Typography Anomaly Analysis
    historical_recovered = tc1_result.previous_revision_recovered
    try:
        tc3_result = analyze_resaved_pdf(loaded_pdf, historical_comparison_available=historical_recovered)
        layout_forensic_findings = resaved_findings_to_forensic(tc3_result)
        all_forensic_findings.extend(layout_forensic_findings)
        module_limitations.extend(tc3_result.limitations)
        checks["layout_analysis"] = "completed" if loaded_pdf.is_valid else "inconclusive"
    except Exception as layout_err:
        logger.error("Layout analysis failed unexpectedly: %s", layout_err, exc_info=True)
        checks["layout_analysis"] = "failed"
        module_limitations.append(f"Layout anomaly scan error: {layout_err}")
        tc3_result = TestCase3ResavedResult(
            status="inconclusive",
            historical_comparison_available=historical_recovered,
            findings=[],
            limitations=[f"Unexpected error in layout analysis: {layout_err}"],
        )

    # 7. Layer 1: Structural Analysis (Deep text spans, whiteouts, images, annotations)
    structural_layer = None
    try:
        structural_layer = analyze_structural_layer(loaded_pdf, original_source=original_source)
        all_forensic_findings.extend(structural_layer.findings)
        module_limitations.extend(structural_layer.limitations)
    except Exception as struct_err:
        logger.error("Structural layer analysis failed: %s", struct_err, exc_info=True)
        module_limitations.append(f"Structural analysis error: {struct_err}")

    # 8. Layer 3: Independent Verification (Signatures, trusted original diff, hash check)
    verification_layer = None
    try:
        orig_bytes = None
        if original_source is not None:
            if isinstance(original_source, Path):
                orig_bytes = original_source.read_bytes()
            else:
                orig_bytes = original_source

        verification_layer = analyze_verification_layer(
            loaded_pdf=loaded_pdf,
            original_bytes=orig_bytes,
            original_filename=original_filename,
            expected_hash=expected_hash,
        )
        all_forensic_findings.extend(verification_layer.findings)
        module_limitations.extend(verification_layer.limitations)
    except Exception as ver_err:
        logger.error("Verification layer analysis failed: %s", ver_err, exc_info=True)
        module_limitations.append(f"Independent verification error: {ver_err}")

    # 9. Layer 2: Visual & Pixel-Level Analysis (DPI rendering, structural overlay, text-edges, whiteouts)
    visual_layer = None
    try:
        # Pass all accumulated structural and verification findings to generate visual overlays
        visual_layer = analyze_visual_layer(
            loaded_pdf,
            structural_findings=list(all_forensic_findings),
        )
        all_forensic_findings.extend(visual_layer.findings)
        module_limitations.extend(visual_layer.limitations)
    except Exception as vis_err:
        logger.error("Visual layer analysis failed: %s", vis_err, exc_info=True)
        module_limitations.append(f"Visual analysis error: {vis_err}")

    # 10. Deduplicate exact duplicate findings
    unique_findings: list[ForensicFinding] = []
    seen_finding_keys = set()
    for f in all_forensic_findings:
        key = (f.code, f.description)
        if key not in seen_finding_keys:
            seen_finding_keys.add(key)
            unique_findings.append(f)
    all_forensic_findings = unique_findings

    # 11. Evaluate Evidence in Decision Engine
    decision = evaluate_forensic_evidence(
        loaded_pdf=loaded_pdf,
        all_findings=all_forensic_findings,
        checks=checks,
        module_limitations=module_limitations,
    )

    # 12. Build Unified Response
    return build_unified_response(
        loaded_pdf=loaded_pdf,
        metadata_container=metadata_container,
        metadata_findings=metadata_findings,
        tc1_result=tc1_result,
        tc2_result=tc2_result,
        tc3_result=tc3_result,
        decision=decision,
        all_forensic_findings=all_forensic_findings,
        checks=checks,
        structural_layer=structural_layer,
        visual_layer=visual_layer,
        verification_layer=verification_layer,
    )
