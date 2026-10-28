"""Result Builder: Produces a consistent, evidence-based unified analysis response."""

from __future__ import annotations

import logging
from typing import Any

from app.models import FileInfo, Finding, MetadataContainer
from app.schemas.analysis import (
    ForensicFinding,
    NonTechnicalCheck,
    NonTechnicalSummary,
    OverallAssessment,
    StructuralAnalysisLayer,
    TestCase1IncrementalResult,
    TestCase2SignatureResult,
    TestCase3ResavedResult,
    TestCasesContainer,
    ThreeLayerAnalyses,
    UnifiedAnalysisResponse,
    UnifiedSummary,
    VerificationAnalysisLayer,
    VisualAnalysisLayer,
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
    structural_layer: Any | None = None,
    visual_layer: Any | None = None,
    verification_layer: Any | None = None,
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

    # Three-Layer Forensic Analyses Construction
    struct_findings = structural_layer.findings if structural_layer else []
    struct_limits = structural_layer.limitations if structural_layer else []
    struct_summary = structural_layer.summary if structural_layer else "Structural analysis completed."
    struct_status = structural_layer.status if structural_layer else "completed"

    visual_findings = visual_layer.findings if visual_layer else []
    visual_limits = visual_layer.limitations if visual_layer else []
    visual_summary = visual_layer.summary if visual_layer else "Visual analysis completed."
    visual_status = visual_layer.status if visual_layer else "completed"
    page_previews: list[dict[str, Any]] = []
    if visual_layer and hasattr(visual_layer, "page_previews"):
        for pv in visual_layer.page_previews:
            page_previews.append(
                {
                    "page_number": pv.page_number,
                    "width_px": pv.width_px,
                    "height_px": pv.height_px,
                    "dpi": pv.dpi,
                    "original_image_base64": pv.original_image_base64,
                    "overlay_image_base64": pv.overlay_image_base64,
                    "suspicious_regions": [
                        {
                            "page": r.page,
                            "bbox_pdf": r.bbox_pdf,
                            "bbox_px": r.bbox_px,
                            "technique": r.technique,
                            "description": r.description,
                            "confidence": r.confidence,
                            "severity": r.severity,
                        }
                        for r in pv.suspicious_regions
                    ],
                }
            )

    verify_sig_results = (
        verification_layer.signature_results if verification_layer else tc2_result.signature_results
    )
    verify_limits = verification_layer.limitations if verification_layer else []
    verify_summary = verification_layer.summary if verification_layer else "Independent verification unavailable."
    verify_status = verification_layer.status if verification_layer else "unavailable"
    orig_comp_dict: dict[str, Any] | None = None
    if verification_layer and verification_layer.original_comparison:
        oc = verification_layer.original_comparison
        orig_comp_dict = {
            "status": oc.status,
            "differences_detected": oc.differences_detected,
            "original_filename": oc.original_filename,
            "original_sha256": oc.original_sha256,
            "page_count_comparison": oc.page_count_comparison,
            "summary": oc.summary,
            "limitations": oc.limitations,
            "page_diffs": [
                {
                    "page_number": pd.page_number,
                    "status": pd.status,
                    "added_text": pd.added_text,
                    "removed_text": pd.removed_text,
                    "changed_pixel_count": pd.changed_pixel_count,
                    "diff_image_base64": pd.diff_image_base64,
                    "bounding_boxes": pd.bounding_boxes,
                }
                for pd in oc.page_diffs
            ],
        }

    hash_dict: dict[str, Any] | None = None
    if verification_layer and verification_layer.hash_verification:
        hv = verification_layer.hash_verification
        hash_dict = {
            "status": hv.status,
            "computed_hash": hv.computed_hash,
            "expected_hash": hv.expected_hash,
            "matches": hv.matches,
            "description": hv.description,
            "limitations": hv.limitations,
        }

    analyses_container = ThreeLayerAnalyses(
        structural=StructuralAnalysisLayer(
            status=struct_status,
            summary=struct_summary,
            findings=struct_findings,
            limitations=struct_limits,
            formatting_anomalies_count=getattr(structural_layer, "formatting_anomalies_count", 0) if structural_layer else 0,
            text_overlaps_count=getattr(structural_layer, "text_overlaps_count", 0) if structural_layer else 0,
            covering_objects_count=getattr(structural_layer, "covering_objects_count", 0) if structural_layer else 0,
            text_replacements_count=getattr(structural_layer, "text_replacements_count", 0) if structural_layer else 0,
            text_insertions_count=getattr(structural_layer, "text_insertions_count", 0) if structural_layer else 0,
            revision_history_available=getattr(structural_layer, "revision_history_available", False) if structural_layer else False,
            historical_comparison_status=getattr(structural_layer, "historical_comparison_status", "unavailable") if structural_layer else "unavailable",
        ),
        visual=VisualAnalysisLayer(
            status=visual_status,
            summary=visual_summary,
            findings=visual_findings,
            page_previews=page_previews,
            limitations=visual_limits,
        ),
        verification=VerificationAnalysisLayer(
            status=verify_status,
            summary=verify_summary,
            signature_results=verify_sig_results,
            original_comparison=orig_comp_dict,
            hash_verification=hash_dict,
            limitations=verify_limits,
        ),
    )

    overall_assess = OverallAssessment(
        status=(
            decision.assessment_status
            if decision
            else ("confirmed_integrity_failure" if verdict == "likely_edited" else "no_suspicious_indicators_detected")
        ),
        summary=overall,
        score=confidence,
        score_explanation=(
            decision.score_explanation
            if (decision and decision.score_explanation)
            else f"Calibrated forensic score: {confidence}"
        ),
    )

    # Key findings: prioritize high and medium severity findings
    key_findings: list[ForensicFinding] = []
    seen_codes: set[str] = set()
    for f in findings_list:
        if isinstance(f, ForensicFinding):
            if f.code not in seen_codes and f.severity in ("high", "medium"):
                seen_codes.add(f.code)
                key_findings.append(f)
    if not key_findings:
        for f in findings_list:
            if isinstance(f, ForensicFinding) and f.code not in seen_codes:
                seen_codes.add(f.code)
                key_findings.append(f)
                if len(key_findings) >= 3:
                    break

    recommended_steps = (
        decision.recommended_next_steps
        if (decision and decision.recommended_next_steps)
        else ["Review detailed structural and visual findings."]
    )

    # Non-Technical Summary for intuitive, conclusive evaluation
    non_tech_summary = build_non_technical_summary(
        verdict=verdict,
        confidence=confidence,
        findings_list=findings_list,
        metadata_container=metadata_container,
        visual_layer=visual_layer,
        verification_layer=verification_layer,
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
        overall_assessment=overall_assess,
        non_technical_summary=non_tech_summary,
        analyses=analyses_container,
        key_findings=key_findings,
        recommended_next_steps=recommended_steps,
    )


def build_non_technical_summary(
    verdict: str,
    confidence: float,
    findings_list: list[ForensicFinding | Finding],
    metadata_container: MetadataContainer,
    visual_layer: Any | None = None,
    verification_layer: Any | None = None,
) -> NonTechnicalSummary:
    """Build a plain-English, non-technical summary enabling a non-technical user to conclusively evaluate if the PDF is proper."""
    finding_codes = {
        getattr(f, "code", getattr(f, "id", ""))
        for f in findings_list
    }

    # 1. Check: Content Alteration & Cover-Ups
    has_white_text = "STRUCT_WHITE_TEXT_LAYER_OVERLAY" in finding_codes or "VISUAL_WHITE_TEXT_LAYER_OVERLAY" in finding_codes
    has_whiteout_rect = "STRUCT_WHITEOUT_RECTANGLE_OVERLAY" in finding_codes or "VISUAL_WHITEOUT_PATCH_DETECTED" in finding_codes
    has_text_replacement = "STRUCT_POSSIBLE_TEXT_REPLACEMENT" in finding_codes or "REV_TEXT_CHANGE_DETECTED" in finding_codes
    has_covering_obj = "STRUCT_POSSIBLE_COVERING_OBJECT" in finding_codes
    has_annot_overlay = "STRUCT_ANNOTATION_OVERLAY" in finding_codes
    has_text_overlap = "STRUCT_TEXT_OVERLAP" in finding_codes or "VISUAL_TEXT_COLLISION_OVERLAY" in finding_codes or "LAYOUT_TEXT_OVERLAP" in finding_codes
    has_text_insertion = "STRUCT_POSSIBLE_TEXT_INSERTION" in finding_codes

    if has_white_text:
        check_content = NonTechnicalCheck(
            name="Content & Text Cover-Ups",
            status="warning",
            headline="White Text Masking Layer Detected",
            detail="Original text (such as heading or figures) was masked using a white font layer and overwritten with altered text.",
        )
    elif has_text_replacement:
        check_content = NonTechnicalCheck(
            name="Content & Text Cover-Ups",
            status="warning",
            headline="Text Replacement Detected",
            detail="Existing text or numbers appear to have been covered, removed, or replaced with altered content.",
        )
    elif has_whiteout_rect or has_covering_obj:
        check_content = NonTechnicalCheck(
            name="Content & Text Cover-Ups",
            status="warning",
            headline="Covering Object / Whiteout Detected",
            detail="An opaque covering object or patch was placed over existing content, obscuring underlying text.",
        )
    elif has_annot_overlay:
        check_content = NonTechnicalCheck(
            name="Content & Text Cover-Ups",
            status="warning",
            headline="Annotation Cover-Up Detected",
            detail="A form field or annotation was placed directly over document text to overwrite original figures.",
        )
    elif has_text_insertion:
        check_content = NonTechnicalCheck(
            name="Content & Text Cover-Ups",
            status="suspicious",
            headline="Unusual Text Insertion",
            detail="Text with differing characteristics appears inserted into an otherwise uniform section.",
        )
    elif has_text_overlap:
        check_content = NonTechnicalCheck(
            name="Content & Text Cover-Ups",
            status="suspicious",
            headline="Overlapping Conflicting Text",
            detail="Multiple text segments collide in the exact same location, indicating possible manual additions.",
        )
    else:
        check_content = NonTechnicalCheck(
            name="Content & Text Cover-Ups",
            status="clean",
            headline="No Cover-Ups Detected",
            detail="Text and numbers appear naturally placed with no signs of whiteout patches, masking layers, or artificial overlays.",
        )

    # 2. Check: Visual Appearance & Page Uniformity
    total_suspicious_regions = 0
    if visual_layer and hasattr(visual_layer, "page_previews"):
        total_suspicious_regions = sum(len(p.suspicious_regions) for p in visual_layer.page_previews)

    if has_white_text or has_whiteout_rect:
        check_visual = NonTechnicalCheck(
            name="Visual Appearance",
            status="warning",
            headline="Visual Anomaly Highlighted",
            detail=f"{total_suspicious_regions} area(s) show artificial visual boundaries or masked overlays requiring review.",
        )
    elif total_suspicious_regions > 0:
        check_visual = NonTechnicalCheck(
            name="Visual Appearance",
            status="suspicious",
            headline="Visual Outliers Detected",
            detail=f"{total_suspicious_regions} region(s) show localized sharpness or texture variations.",
        )
    else:
        check_visual = NonTechnicalCheck(
            name="Visual Appearance",
            status="clean",
            headline="Visually Uniform",
            detail="Rendered page textures, text sharpness, and background contrast appear consistent throughout.",
        )

    # 3. Check: Document History & Timestamps
    has_date_inversion = "META_MODDATE_BEFORE_CREATION" in finding_codes
    has_rev_text_change = "REV_TEXT_CHANGE_DETECTED" in finding_codes
    has_editing_tool = "META_KNOWN_EDITING_TOOL" in finding_codes
    has_orphan_stream = "STREAM_UNREFERENCED_ORPHAN_OBJECTS" in finding_codes

    # Check for official document post-creation modification (Major Red Flag)
    mod_diff_finding = next(
        (f for f in findings_list if getattr(f, "code", getattr(f, "id", "")) == "META_MODDATE_DIFFERS_CREATION"),
        None,
    )
    is_official_mod_flag = False
    diff_human_str = ""
    if mod_diff_finding:
        title_str = getattr(mod_diff_finding, "title", "")
        sev_str = str(getattr(mod_diff_finding, "severity", "")).lower()
        if "red flag" in title_str.lower() or sev_str in ("medium", "high", "severity.medium", "severity.high"):
            is_official_mod_flag = True
            ev = getattr(mod_diff_finding, "evidence", {})
            if isinstance(ev, dict) and "elapsed_time" in ev:
                diff_human_str = str(ev["elapsed_time"])

    if is_official_mod_flag:
        check_dates = NonTechnicalCheck(
            name="Document History & Dates",
            status="warning",
            headline="Post-Creation Modification (Major Red Flag on System Document)",
            detail=(
                f"This system-generated document (such as an invoice, payslip, or statement) was modified after creation "
                f"({diff_human_str or 'subsequent to initial export'}). Automated billing and payroll systems generate completed documents "
                "in a single operation; post-creation modification is concrete evidence of alteration."
            ),
        )
    elif has_rev_text_change:
        check_dates = NonTechnicalCheck(
            name="Document History & Revisions",
            status="warning",
            headline="Content Modified Across Revisions",
            detail="Direct text changes were detected between earlier and later revisions stored inside the PDF.",
        )
    elif has_date_inversion:
        check_dates = NonTechnicalCheck(
            name="Document History & Dates",
            status="warning",
            headline="Inconsistent Timeline",
            detail="File timestamps are conflicting: the modification time precedes the creation time.",
        )
    elif has_editing_tool or has_orphan_stream:
        check_dates = NonTechnicalCheck(
            name="Document History & Dates",
            status="info",
            headline="Re-saved / Post-Processed",
            detail="The document shows indications of being re-saved or processed with an editing application after initial export.",
        )
    else:
        check_dates = NonTechnicalCheck(
            name="Document History & Dates",
            status="clean",
            headline="Consistent Timeline",
            detail="Document timestamps and internal structure are consistent and show no signs of manipulation.",
        )

    # 4. Check: Digital Signatures & Seal
    has_sig_tampered = "SIG_POST_SIGNING_MODIFICATION" in finding_codes or "SIG_CRYPTO_DIGEST_INVALID" in finding_codes
    is_signed = False
    if verification_layer and hasattr(verification_layer, "signature_results"):
        is_signed = len(verification_layer.signature_results) > 0

    if has_sig_tampered:
        check_signature = NonTechnicalCheck(
            name="Digital Seal & Signatures",
            status="warning",
            headline="Digital Seal Broken",
            detail="The document was digitally signed, but changes were made after signing that invalidated the signature.",
        )
    elif is_signed:
        check_signature = NonTechnicalCheck(
            name="Digital Seal & Signatures",
            status="clean",
            headline="Digitally Signed & Valid",
            detail="The document contains an authentic, cryptographically intact digital signature.",
        )
    else:
        check_signature = NonTechnicalCheck(
            name="Digital Seal & Signatures",
            status="info",
            headline="Standard Unsigned Document",
            detail="No digital signature was applied (normal for standard commercial PDFs).",
        )

    checklist = [check_content, check_visual, check_dates, check_signature]

    # Synthesize conclusive plain-English verdict
    if verdict == "likely_edited":
        is_proper = False
        verdict_label = "Potentially Tampered / Altered Document"
        verdict_color = "red"
        headline = "Evidence indicates this document was modified after creation."
        if has_white_text:
            explanation = (
                "This document shows clear signs of post-creation editing. Specifically, an intentional white text "
                "masking layer was placed over a heading or numerical figure, and altered text was typed on top to replace it."
            )
        elif has_text_replacement:
            explanation = (
                "This document shows structural or historical evidence of text replacement. "
                "Existing content appears to have been covered, removed, or overwritten across revisions."
            )
        elif has_whiteout_rect:
            explanation = (
                "This document contains an opaque whiteout patch covering original content, with new text typed over it. "
                "This is a common method used in document alteration."
            )
        elif has_sig_tampered:
            explanation = (
                "This document was digitally signed, but content was modified after signing, breaking the digital authenticity seal."
            )
        elif is_official_mod_flag:
            explanation = (
                f"This document is an official or system-generated record (such as an invoice, payslip, or statement) "
                f"with concrete evidence of post-generation modification ({diff_human_str or 'modified after initial creation'}). "
                "Automated billing and payroll engines produce records in a single step; any post-creation modification "
                "is a major red flag indicating post-export alteration."
            )
        else:
            explanation = (
                "Multiple structural and visual anomalies indicate that portions of this document have been altered "
                "or re-composed using a PDF editing application."
            )
        trust_recommendation = (
            "DO NOT RELY on the key figures, names, or terms in this document. "
            "We strongly recommend requesting an authenticated original directly from the issuing party."
        )

    elif verdict == "suspicious_indicators":
        is_proper = None
        verdict_label = "Caution: Suspicious Inconsistencies Found"
        verdict_color = "amber"
        if is_official_mod_flag:
            headline = "Post-creation modification detected on official record."
            explanation = (
                f"This document is an official record (invoice/payslip/statement) with concrete metadata evidence of modification "
                f"after its creation date ({diff_human_str or 'subsequent to creation'}). "
                "System-generated documents should not be modified after initial creation."
            )
        else:
            headline = "Some unusual formatting or timeline inconsistencies warrant review."
            explanation = (
                "We detected minor anomalies such as overlapping text lines or re-saving traces. "
                "While these can occasionally occur in complex document templates, they may also indicate manual adjustments."
            )
        trust_recommendation = (
            "Review the highlighted areas on the visual page preview. Before taking critical action, "
            "verify key terms or totals with the sender."
        )

    elif verdict == "no_edit_evidence_found":
        is_proper = True
        verdict_label = "Proper & Likely Authentic"
        verdict_color = "green"
        headline = "No evidence of tampering or alteration was detected."
        explanation = (
            "All text placement, visual sharpness, and document structures appear consistent and normal. "
            "The document does not contain covered text, whiteout boxes, or broken signatures."
        )
        trust_recommendation = (
            "This document appears authentic and proper for standard review and archiving."
        )

    else:
        is_proper = None
        verdict_label = "Inconclusive Analysis"
        verdict_color = "gray"
        headline = "The document could not be reliably inspected."
        explanation = (
            "The document is password-protected, encrypted, or corrupted, preventing our tools from inspecting its internal contents."
        )
        trust_recommendation = (
            "Provide an unencrypted, non-password-protected copy of the PDF to perform a complete authenticity check."
        )

    return NonTechnicalSummary(
        is_proper=is_proper,
        verdict_label=verdict_label,
        verdict_color=verdict_color,
        headline=headline,
        explanation=explanation,
        trust_recommendation=trust_recommendation,
        checks=checklist,
    )
