"""Pydantic models and schemas for PDF forensic metadata analysis."""

from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class Category(str, Enum):
    """Category classification for forensic findings."""

    CONFIRMED = "confirmed"
    SUSPICIOUS = "suspicious"
    INCONCLUSIVE = "inconclusive"


class Severity(str, Enum):
    """Severity level of a forensic finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Finding(BaseModel):
    """A single metadata forensic check finding."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Stable unique identifier for the check, e.g. META_MODDATE_BEFORE_CREATION")
    title: str = Field(..., description="Short descriptive title of the finding")
    category: Category = Field(..., description="Category classification: confirmed, suspicious, or inconclusive")
    severity: Severity = Field(..., description="Severity level: info, low, medium, or high")
    explanation: str = Field(..., description="Plain-English explanation of what was found and potential innocent explanations")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Supporting evidence including raw strings and parsed values")


class FileInfo(BaseModel):
    """Basic file facts."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Uploaded file name")
    size_bytes: int = Field(..., ge=0, description="File size in bytes")
    sha256: str = Field(..., description="SHA-256 hash of the file bytes")
    pdf_version: str = Field(..., description="PDF specification version, e.g. 1.7")
    page_count: int = Field(..., ge=0, description="Total number of pages in the PDF")


class MetadataContainer(BaseModel):
    """Raw metadata extracted from Info dictionary and XMP stream, plus human-readable dates."""

    model_config = ConfigDict(extra="forbid")

    info: dict[str, Any] = Field(default_factory=dict, description="Raw key-value pairs from the PDF Info dictionary")
    xmp: dict[str, Any] = Field(default_factory=dict, description="Raw key-value pairs extracted from the XMP stream")
    dates: dict[str, str] = Field(
        default_factory=dict,
        description="Clean human-readable dates using AM/PM, day of week, and exact time",
    )


class Summary(BaseModel):
    """Aggregated count of findings and neutral summary statement."""

    model_config = ConfigDict(extra="ignore")

    confirmed: int = Field(default=0, ge=0, description="Count of confirmed findings")
    suspicious: int = Field(default=0, ge=0, description="Count of suspicious findings")
    inconclusive: int = Field(default=0, ge=0, description="Count of inconclusive findings")
    overall: str = Field(..., description="Neutral summary statement; never states whether document is authentic or forged")
    classification: str = Field(default="inconclusive", description="Classification: confirmed_changes | suspicious_indicators | no_edit_evidence_found | inconclusive")
    confirmed_changes: int = Field(default=0, ge=0)
    suspicious_indicators: int = Field(default=0, ge=0)
    limitations: list[str] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    """Top-level response schema for PDF metadata forensic analysis."""

    model_config = ConfigDict(extra="ignore")

    file: FileInfo
    metadata: MetadataContainer
    findings: list[Finding]
    test_cases: Any | None = Field(default=None, description="Detailed results from edit detection test cases")
    summary: Summary


class HealthResponse(BaseModel):
    """Health check response schema."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="ok", description="Service status")

