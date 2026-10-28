"""Evidence-Based Decision Engine: Evaluates forensic signals across all modules to determine verdict and confidence."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Any

from app.schemas.analysis import ForensicFinding, ForensicVerdict
from app.services.pdf_analysis.pdf_loader import LoadedPdf

logger = logging.getLogger("pdf_analyser.decision_engine")

# Strong indicators that independently establish credible modification evidence
STRONG_INDICATOR_CODES = frozenset({
    "SIG_POST_SIGNING_MODIFICATION",
    "SIG_CRYPTO_DIGEST_INVALID",
    "REV_CRITICAL_OBJECT_REPLACED",
    "REV_TEXT_CHANGE_DETECTED",
    "VERIFY_ORIGINAL_DIFF_DETECTED",
    "VERIFY_REFERENCE_HASH_MISMATCH",
})

# Moderate indicators that require independent correlation
MODERATE_INDICATOR_CODES = frozenset({
    "META_MODDATE_BEFORE_CREATION",
    "STREAM_UNREFERENCED_ORPHAN_OBJECTS",
    "STREAM_DANGLING_FONT_REFERENCE",
    "REV_XREF_OFFSET_OUT_OF_BOUNDS",
    "STRUCT_WHITEOUT_RECTANGLE_OVERLAY",
    "STRUCT_WHITE_TEXT_LAYER_OVERLAY",
    "STRUCT_ANNOTATION_OVERLAY",
    "STRUCT_POSSIBLE_TEXT_REPLACEMENT",
    "STRUCT_POSSIBLE_COVERING_OBJECT",
    "STRUCT_POSSIBLE_TEXT_INSERTION",
    "VISUAL_WHITEOUT_PATCH_DETECTED",
    "VISUAL_WHITE_TEXT_LAYER_OVERLAY",
    "VISUAL_DUPLICATE_REGION_CANDIDATE",
})

# Weak / supporting indicators that cannot establish manipulation on their own
WEAK_INDICATOR_CODES = frozenset({
    "LAYOUT_TEXT_OVERLAP",
    "LAYOUT_TEXT_OVER_IMAGE",
    "LAYOUT_INCONSISTENT_FONT",
    "LAYOUT_ISOLATED_OVERLAY",
    "STRUCT_TEXT_OVERLAP",
    "STRUCT_TEXT_OVER_IMAGE",
    "STRUCT_INCONSISTENT_FONT_SWITCH",
    "STRUCT_FORMATTING_ANOMALY",
    "STRUCT_UNUSUAL_TEXT_POSITION",
    "STRUCT_INVISIBLE_WHITE_TEXT",
    "VISUAL_HIDDEN_WHITE_TEXT",
    "VISUAL_TEXT_COLLISION_OVERLAY",
    "VISUAL_INCONSISTENT_TEXT_SHARPNESS",
    "VISUAL_ELA_HIGH_COMPRESSION_VARIANCE",
    "STREAM_INVISIBLE_TEXT_OPERATOR",
    "STREAM_MULTIPLE_PAGE_CONTENTS",
    "STREAM_UNBALANCED_GRAPHICS_STATE",
    "META_INFO_XMP_MISMATCH",
    "META_FUTURE_DATE",
    "META_KNOWN_EDITING_TOOL",
    "REV_INCREMENTAL_REVISION_PRESENT",
    "SIG_POST_SIGNING_PERMITTED_APPEND",
})


@dataclass
class DecisionOutcome:
    """The synthesized verdict, confidence, narrative summary, and consolidated limitations."""

    verdict: str  # likely_edited | suspicious_indicators | no_edit_evidence_found | inconclusive
    edit_detected: bool | None  # True | None | False
    confidence: float  # 0.0 to 1.0
    summary: str
    analysis_status: str  # completed | partial | failed | inconclusive
    checks: dict[str, str]
    limitations: list[str]
    all_findings: list[ForensicFinding] = field(default_factory=list)
    assessment_status: str = "no_suspicious_indicators_detected"
    score_explanation: str = ""
    recommended_next_steps: list[str] = field(default_factory=list)



def evaluate_forensic_evidence(
    loaded_pdf: LoadedPdf,
    all_findings: list[ForensicFinding],
    checks: dict[str, str],
    module_limitations: list[str],
) -> DecisionOutcome:
    """Synthesize evidence from all forensic modules using strict independence rules.

    Args:
        loaded_pdf: Safely loaded PDF.
        all_findings: Consolidated findings from metadata, revisions, signatures, content-streams, and layout.
        checks: Execution status of each module.
        module_limitations: Limitations gathered across all modules.

    Returns:
        DecisionOutcome with verdict, edit_detected, confidence, summary, and limitations.
    """
    # Base mandatory limitations
    limitations: list[str] = [
        "Analysis evaluates structural, cryptographic, metadata, and content-stream indicators on a single PDF without a reference copy.",
        "Absence of detected anomalies does not certify document authenticity; a clean resave can discard historical revision traces.",
        "Confidence scores reflect heuristic calibration across observed forensic signals, not statistical probability or legal certification.",
    ]
    for lim in module_limitations:
        if lim and lim not in limitations:
            limitations.append(lim)

    # 1. Handle unparseable / encrypted / invalid documents
    if not loaded_pdf.is_valid:
        if loaded_pdf.is_encrypted:
            return DecisionOutcome(
                verdict=ForensicVerdict.INCONCLUSIVE.value,
                edit_detected=None,
                confidence=0.0,
                summary="The document is password-protected or encrypted; internal structures and content could not be evaluated.",
                analysis_status="inconclusive",
                checks=checks,
                limitations=limitations,
                all_findings=all_findings,
                assessment_status="inconclusive",
                score_explanation="Score 0.0: Encrypted/password-protected PDF cannot be evaluated.",
                recommended_next_steps=[
                    "Provide an unencrypted or non-password-protected copy of the PDF for analysis.",
                ],
            )
        return DecisionOutcome(
            verdict=ForensicVerdict.INCONCLUSIVE.value,
            edit_detected=None,
            confidence=0.0,
            summary=f"Document could not be reliably parsed ({loaded_pdf.error_message or 'corrupted PDF structure'}); analysis inconclusive.",
            analysis_status="inconclusive",
            checks=checks,
            limitations=limitations,
            all_findings=all_findings,
            assessment_status="inconclusive",
            score_explanation="Score 0.0: Corrupted or unparseable document structure.",
            recommended_next_steps=[
                "Re-export or re-scan the document using a standard compliant PDF writer.",
            ],
        )

    # 2. Filter findings into strength tiers and categorize by domain
    strong_findings = [f for f in all_findings if f.code in STRONG_INDICATOR_CODES]
    moderate_findings = [f for f in all_findings if f.code in MODERATE_INDICATOR_CODES]
    weak_findings = [
        f for f in all_findings
        if f.code in WEAK_INDICATOR_CODES or (f.code not in STRONG_INDICATOR_CODES and f.code not in MODERATE_INDICATOR_CODES and f.severity in ("low", "medium"))
    ]

    # Group domains that produced non-info findings
    domains_with_evidence: set[str] = set()
    for f in all_findings:
        f_dom = getattr(f, "domain", getattr(f, "category", "general"))
        if f.severity in ("low", "medium", "high") and f.code not in ("SIG_DOCUMENT_UNSIGNED", "REV_NO_INCREMENTAL_REVISIONS", "REV_LINEARIZED_BENIGN_STRUCTURE"):
            domains_with_evidence.add(f_dom)

    # 3. Decision Rules
    # Rule A: Strong indicator present
    if strong_findings:
        top_strong = strong_findings[0]
        # Calculate calibrated confidence: strong base 0.85 + small boost if multiple domains confirm
        conf = min(0.95, 0.85 + (0.05 if len(domains_with_evidence) > 1 else 0.0) + (0.05 if len(strong_findings) > 1 else 0.0))
        conf = round(conf, 2)
        summary = (
            f"Credible forensic evidence indicates subsequent modification or manipulation: "
            f"{top_strong.description}. "
            "These findings are not proof of tampering."
        )
        return DecisionOutcome(
            verdict=ForensicVerdict.LIKELY_EDITED.value,
            edit_detected=True,
            confidence=conf,
            summary=summary,
            analysis_status="completed",
            checks=checks,
            limitations=limitations,
            all_findings=all_findings,
            assessment_status="confirmed_integrity_failure",
            score_explanation=f"Score {conf}: Strong verifiable finding ({top_strong.code}) establishes that document integrity was breached.",
            recommended_next_steps=[
                "Inspect specific signed byte ranges or modified pages highlighted in the verification report.",
                "Request a freshly issued and digitally signed copy from the authorized originator.",
                "Compare against an authenticated archival record before relying on document contents.",
            ],
        )

    # Rule B: Multiple independent moderate indicators from distinct domains
    moderate_domains = {getattr(f, "domain", getattr(f, "category", "general")) for f in moderate_findings}
    if len(moderate_domains) >= 2:
        conf = min(0.85, 0.70 + (0.05 * len(moderate_domains)))
        conf = round(conf, 2)
        summary = (
            f"Credible forensic evidence indicates subsequent modification: "
            f"independent moderate structural and metadata anomalies were identified "
            f"across {len(moderate_domains)} forensic domains ({', '.join(sorted(moderate_domains))}); "
            "these findings are not proof of tampering."
        )
        return DecisionOutcome(
            verdict=ForensicVerdict.LIKELY_EDITED.value,
            edit_detected=True,
            confidence=conf,
            summary=summary,
            analysis_status="completed",
            checks=checks,
            limitations=limitations,
            all_findings=all_findings,
            assessment_status="suspicious_indicators_detected",
            score_explanation=f"Score {conf}: Independent anomalies across {len(moderate_domains)} distinct forensic domains ({', '.join(sorted(moderate_domains))}) corroborate modification.",
            recommended_next_steps=[
                "Review flagged structural overlay patches and cross-reference revision anomalies.",
                "If available, provide the trusted original PDF for automated pixel and text diff verification.",
                "Independently confirm terms or figures appearing in flagged regions with the issuing party.",
            ],
        )

    # Rule C: Suspicious indicators (moderate indicator in 1 domain, or multiple weak indicators)
    if moderate_findings or len(weak_findings) > 0:
        # Determine calibrated confidence for suspicious tier
        if moderate_findings:
            top_mod = moderate_findings[0]
            conf = min(0.65, top_mod.confidence + (0.05 if weak_findings else 0.0))
            summary = (
                f"Suspicious indicators were detected ({top_mod.description}), "
                f"but the evidence is insufficient to conclude that the PDF was manipulated; "
                "these indicators are not proof of tampering."
            )
            score_expl = f"Score {round(conf, 2)}: Isolated moderate anomaly ({top_mod.code}) warrants visual review but lacks cross-domain corroboration."
        else:
            # Only weak / layout / minor metadata findings
            # Cap confidence at 0.35 max when only layout or weak signals exist
            conf = min(0.35, 0.15 + (0.05 * len(weak_findings)))
            conf = round(conf, 2)
            summary = (
                f"Minor structural or layout anomalies were identified ({len(weak_findings)} indicator(s)), "
                "these indicators are not proof of tampering."
            )
            score_expl = f"Score {conf}: Low-confidence visual/layout anomalies. Normal layout complexity cannot be treated as manipulation."

        return DecisionOutcome(
            verdict=ForensicVerdict.SUSPICIOUS_INDICATORS.value,
            edit_detected=None,
            confidence=round(conf, 2),
            summary=summary,
            analysis_status="completed",
            checks=checks,
            limitations=limitations,
            all_findings=all_findings,
            assessment_status="suspicious_indicators_detected",
            score_explanation=score_expl,
            recommended_next_steps=[
                "Review the highlighted visual overlay previews to inspect flagged text or background regions.",
                "Check whether whiteout rectangles or font switches align with known redaction or document design choices.",
                "Perform reference hash verification or supply an original copy if certainty is required.",
            ],
        )

    # Rule D: No edit evidence found
    summary = (
        "No meaningful evidence of editing or manipulation was identified across revision history, "
        "digital signature, content-stream, metadata, or layout checks. "
        "This analysis cannot prove the document is an untouched original."
    )
    return DecisionOutcome(
        verdict=ForensicVerdict.NO_EDIT_EVIDENCE_FOUND.value,
        edit_detected=False,
        confidence=0.0,
        summary=summary,
        analysis_status="completed",
        checks=checks,
        limitations=limitations,
        all_findings=all_findings,
        assessment_status="no_suspicious_indicators_detected",
        score_explanation="Score 0.0: No structural, visual, cryptographic, or metadata anomalies identified.",
        recommended_next_steps=[
            "Document shows no internal anomalies or traces of manipulation across all three analysis layers.",
            "If absolute authenticity is required, verify external certificate chains or compare against a registered registry hash.",
        ],
    )

