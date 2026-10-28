"""Pydantic schemas for PDF edit detection test cases and unified analysis response."""

from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from app.models import Category, FileInfo, Finding, MetadataContainer, Severity, Summary


class ForensicVerdict(str, Enum):
    """Standardized verdicts for PDF forensic manipulation analysis."""

    LIKELY_EDITED = "likely_edited"
    SUSPICIOUS_INDICATORS = "suspicious_indicators"
    NO_EDIT_EVIDENCE_FOUND = "no_edit_evidence_found"
    INCONCLUSIVE = "inconclusive"


class CheckExecutionStatus(str, Enum):
    """Execution status for an individual forensic analysis check."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class ForensicFinding(BaseModel):
    """An evidence-based forensic finding with standardized attributes."""

    model_config = ConfigDict(extra="ignore")

    code: str = Field(..., description="Stable machine-readable code e.g. SIG_POST_SIGNING_MODIFICATION")
    category: str = Field(
        default="suspicious",
        description="Forensic category classification: confirmed | suspicious | inconclusive",
    )
    domain: str = Field(
        default="general",
        description="Forensic domain: digital_signatures | revision_history | content_stream | metadata | layout_analysis",
    )
    severity: str = Field(..., description="info | low | medium | high")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Calibrated confidence from 0.0 to 1.0")
    description: str = Field(..., description="Plain-English explanation of the observed forensic condition")
    evidence: Any = Field(default_factory=dict, description="Supporting structural/offset/operator evidence")
    limitations: list[str] = Field(default_factory=list, description="Methodological limitations or innocent causes")

    # Compatibility attributes for dashboard and older clients
    id: str | None = Field(default=None, description="Alias for code")
    title: str | None = Field(default=None, description="Human-readable title")
    explanation: str | None = Field(default=None, description="Alias for description")

    def model_post_init(self, __context: Any) -> None:
        if self.id is None:
            self.id = self.code
        if self.title is None:
            self.title = self.code.replace("_", " ").title()
        if self.explanation is None:
            self.explanation = self.description


class ChangeLocation(BaseModel):
    """Bounding box location of an identified change or anomaly on a page."""

    model_config = ConfigDict(extra="ignore")

    bbox: list[float] | None = Field(
        default=None,
        description="Bounding box coordinates [x0, y0, x1, y1] in points",
    )


class RevisionChange(BaseModel):
    """An identified change between recoverable incremental revisions."""

    model_config = ConfigDict(extra="ignore")

    type: str = Field(..., description="Change type: text_added, text_removed, text_changed, page_added, page_removed")
    page: int = Field(..., ge=1, description="1-based page number")
    old_text: str | None = Field(default=None, description="Previous text content if recovered")
    new_text: str | None = Field(default=None, description="New text content")
    location: ChangeLocation | None = Field(default=None, description="Bounding box if available")
    evidence: Any = Field(default="", description="Supporting comparison evidence")


class TestCase1IncrementalResult(BaseModel):
    """Result for Test Case 1: Incremental revision analysis."""

    __test__ = False
    model_config = ConfigDict(extra="ignore")

    test_case: str = Field(default="incremental_revisions")
    status: str = Field(..., description="changes_detected | no_revision_evidence | inconclusive")
    revision_count: int = Field(default=1, ge=1, description="Number of identified revisions")
    previous_revision_recovered: bool = Field(default=False, description="Whether an earlier state was reconstructed")
    changes: list[RevisionChange] = Field(default_factory=list, description="List of detected changes between revisions")
    limitations: list[str] = Field(default_factory=list, description="Methodological limitations")


class PostSignatureChange(BaseModel):
    """A change detected after the signed revision in a digitally signed PDF."""

    model_config = ConfigDict(extra="ignore")

    type: str = Field(..., description="Change type e.g. text_added, form_filled, annotation_added")
    page: int = Field(..., ge=1, description="1-based page number")
    old_text: str | None = Field(default=None)
    new_text: str | None = Field(default=None)
    location: ChangeLocation | None = Field(default=None)


class SignatureValidationResult(BaseModel):
    """Forensic evaluation of an individual digital signature."""

    model_config = ConfigDict(extra="ignore")

    field_name: str = Field(..., description="Signature field identifier")
    cryptographic_integrity: str = Field(..., description="valid | invalid | unknown")
    certificate_trust: str = Field(..., description="trusted | untrusted | not_evaluated")
    covers_current_file: bool = Field(..., description="Whether signature covers the entire file up to EOF")
    later_revision_evidence: bool = Field(..., description="Whether bytes or revisions exist after signed range")
    post_signature_changes: list[PostSignatureChange] = Field(default_factory=list, description="Changes after signing")
    limitations: list[str] = Field(default_factory=list, description="Signature evaluation limitations")


class TestCase2SignatureResult(BaseModel):
    """Result for Test Case 2: Digital signatures and post-signature changes."""

    __test__ = False
    model_config = ConfigDict(extra="ignore")

    test_case: str = Field(default="digital_signatures")
    status: str = Field(
        ...,
        description="post_signature_changes_detected | signed_intact_no_later_changes | no_signatures_found | signature_invalid | inconclusive",
    )
    signatures_found: int = Field(default=0, ge=0, description="Total signatures identified in document")
    signature_results: list[SignatureValidationResult] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ResavedFinding(BaseModel):
    """Suspicious layout or content anomaly in a re-saved PDF without revision history."""

    model_config = ConfigDict(extra="ignore")

    type: str = Field(..., description="Anomaly type: unusual_text_overlap | text_over_image | inconsistent_font_anomaly | isolated_text_overlay")
    page: int = Field(..., ge=1, description="1-based page number")
    description: str = Field(..., description="Clear explanation of the detected anomaly")
    location: ChangeLocation | None = Field(default=None)
    evidence: dict[str, Any] = Field(default_factory=dict)
    confidence: str = Field(default="low", description="low | medium")
    interpretation: str = Field(default="Potential anomaly; not proof of editing")


class TestCase3ResavedResult(BaseModel):
    """Result for Test Case 3: Re-saved PDF analysis without recoverable history."""

    __test__ = False
    model_config = ConfigDict(extra="ignore")

    test_case: str = Field(default="resaved_pdf_analysis")
    status: str = Field(..., description="suspicious_indicators_found | no_anomalies_detected | inconclusive")
    historical_comparison_available: bool = Field(default=False)
    findings: list[ResavedFinding] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class TestCasesContainer(BaseModel):
    """Container grouping all three edit detection test case results."""

    model_config = ConfigDict(extra="ignore")

    incremental_revisions: TestCase1IncrementalResult
    digital_signatures: TestCase2SignatureResult
    resaved_pdf_analysis: TestCase3ResavedResult


class UnifiedSummary(BaseModel):
    """Top-level unified forensic summary with explicit verdict and evidence metrics."""

    model_config = ConfigDict(extra="ignore")

    verdict: str = Field(
        default="inconclusive",
        description="likely_edited | suspicious_indicators | no_edit_evidence_found | inconclusive",
    )
    edit_detected: bool | None = Field(
        default=None,
        description="true when likely_edited, false when no_edit_evidence_found, null when suspicious or inconclusive",
    )
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Calibrated confidence score from 0.0 to 1.0")
    classification: str = Field(
        default="inconclusive",
        description="Legacy classification: confirmed_changes | suspicious_indicators | no_edit_evidence_found | inconclusive",
    )
    overall: str = Field(default="", description="Neutral plain-English summary of forensic analysis")
    confirmed_changes: int = Field(default=0, ge=0)
    suspicious_indicators: int = Field(default=0, ge=0)
    confirmed: int = Field(default=0, ge=0)
    suspicious: int = Field(default=0, ge=0)
    inconclusive: int = Field(default=0, ge=0)
    limitations: list[str] = Field(default_factory=list)


class NonTechnicalCheck(BaseModel):
    """An individual check item for non-technical evaluation."""

    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., description="Check category title e.g. Content & Text Cover-Ups")
    status: str = Field(..., description="clean | suspicious | warning | info")
    headline: str = Field(..., description="Short status description")
    detail: str = Field(..., description="Plain English description of findings")


class NonTechnicalSummary(BaseModel):
    """A shorter, conclusive, plain-English summary without technical jargon so users can decide if the PDF is proper."""

    model_config = ConfigDict(extra="ignore")

    is_proper: bool | None = Field(
        default=None,
        description="True if document appears authentic/proper, False if altered/tampered, None if caution or inconclusive",
    )
    verdict_label: str = Field(default="Authentic & Clean", description="User-friendly status title")
    verdict_color: str = Field(default="green", description="green | amber | red | gray")
    headline: str = Field(default="", description="Concise conclusion statement")
    explanation: str = Field(default="", description="1-3 sentence non-technical explanation")
    trust_recommendation: str = Field(default="", description="Plain-English advice on whether to accept or verify")
    checks: list[NonTechnicalCheck] = Field(default_factory=list, description="4 core non-technical checks")


class UnifiedAnalysisResponse(BaseModel):
    """Unified API response matching the modern forensic specification while preserving backward compatibility."""

    model_config = ConfigDict(extra="ignore")

    # Modern forensic schema fields
    file_name: str = Field(default="document.pdf", description="Uploaded file name")
    file_hash_sha256: str = Field(default="", description="SHA-256 hash of the uploaded file bytes")
    verdict: str = Field(
        default="inconclusive",
        description="likely_edited | suspicious_indicators | no_edit_evidence_found | inconclusive",
    )
    edit_detected: bool | None = Field(
        default=None,
        description="true when likely_edited, false when no_edit_evidence_found, null when ambiguous or inconclusive",
    )
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Calibrated confidence score from 0.0 to 1.0")
    analysis_status: str = Field(default="completed", description="completed | partial | failed | inconclusive")
    findings: list[ForensicFinding | Finding] = Field(
        default_factory=list,
        description="Complete list of evidence-based forensic findings across all checks",
    )
    checks: dict[str, str] = Field(
        default_factory=dict,
        description="Execution status per module: metadata, revision_history, digital_signatures, content_streams, layout_analysis",
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Methodological limitations acknowledging what analysis can and cannot prove",
    )

    # Legacy container fields for backwards compatibility
    file: FileInfo
    metadata: MetadataContainer
    test_cases: TestCasesContainer | None = Field(default=None)
    summary: UnifiedSummary

    # Three-Layer Forensic Schema
    overall_assessment: OverallAssessment | None = Field(
        default=None,
        description="High-level forensic status: confirmed_integrity_failure | suspicious_indicators_detected | inconclusive | no_suspicious_indicators_detected",
    )
    non_technical_summary: NonTechnicalSummary | None = Field(
        default=None,
        description="Shorter, conclusive non-technical summary enabling users to decide if the document is proper",
    )
    analyses: ThreeLayerAnalyses | None = Field(
        default=None,
        description="Detailed findings and limitations across Structural, Visual, and Verification layers",
    )
    key_findings: list[ForensicFinding] = Field(
        default_factory=list,
        description="Prioritized list of key structural, visual, or verification findings",
    )
    recommended_next_steps: list[str] = Field(
        default_factory=list,
        description="Actionable next steps recommended based on forensic assessment",
    )


class OverallAssessment(BaseModel):
    """Overall assessment status and score."""

    model_config = ConfigDict(extra="ignore")

    status: str = Field(
        ...,
        description="confirmed_integrity_failure | suspicious_indicators_detected | inconclusive | no_suspicious_indicators_detected",
    )
    summary: str = Field(..., description="Evidence-based assessment narrative")
    score: float | None = Field(default=None, description="Calibrated confidence score from 0.0 to 1.0")
    score_explanation: str | None = Field(default=None, description="Explanation of score calculation and limitations")


class StructuralAnalysisLayer(BaseModel):
    """Layer 1: Structural Analysis results."""

    model_config = ConfigDict(extra="ignore")

    status: str = Field(default="completed", description="completed | partial | failed | skipped")
    summary: str = Field(default="", description="Structural findings summary")
    findings: list[ForensicFinding] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class VisualAnalysisLayer(BaseModel):
    """Layer 2: Pixel-Level and Visual Analysis results."""

    model_config = ConfigDict(extra="ignore")

    status: str = Field(default="completed", description="completed | partial | failed | skipped")
    summary: str = Field(default="", description="Visual analysis summary")
    findings: list[ForensicFinding] = Field(default_factory=list)
    page_previews: list[dict[str, Any]] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class VerificationAnalysisLayer(BaseModel):
    """Layer 3: Independent Verification results."""

    model_config = ConfigDict(extra="ignore")

    status: str = Field(default="unavailable", description="completed | partial | unavailable | failed")
    summary: str = Field(default="", description="Verification summary")
    signature_results: list[SignatureValidationResult] = Field(default_factory=list)
    original_comparison: dict[str, Any] | None = Field(default=None)
    hash_verification: dict[str, Any] | None = Field(default=None)
    limitations: list[str] = Field(default_factory=list)


class ThreeLayerAnalyses(BaseModel):
    """Container grouping all three forensic analysis layers."""

    model_config = ConfigDict(extra="ignore")

    structural: StructuralAnalysisLayer
    visual: VisualAnalysisLayer
    verification: VerificationAnalysisLayer


UnifiedAnalysisResponse.model_rebuild()


