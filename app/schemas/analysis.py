"""Pydantic schemas for PDF edit detection test cases and unified analysis response."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from app.models import Category, FileInfo, Finding, MetadataContainer, Severity, Summary


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
    """Top-level unified forensic summary with explicit classification."""

    model_config = ConfigDict(extra="ignore")

    classification: str = Field(
        default="inconclusive",
        description="confirmed_changes | suspicious_indicators | no_edit_evidence_found | inconclusive",
    )
    confirmed_changes: int = Field(default=0, ge=0)
    suspicious_indicators: int = Field(default=0, ge=0)
    confirmed: int = Field(default=0, ge=0)
    suspicious: int = Field(default=0, ge=0)
    inconclusive: int = Field(default=0, ge=0)
    overall: str = Field(default="")
    limitations: list[str] = Field(default_factory=list)


class UnifiedAnalysisResponse(BaseModel):
    """Unified API response including file info, metadata findings, test cases, and summary."""

    model_config = ConfigDict(extra="ignore")

    file: FileInfo
    metadata: MetadataContainer
    findings: list[Finding]
    test_cases: TestCasesContainer | None = Field(default=None)
    summary: UnifiedSummary
