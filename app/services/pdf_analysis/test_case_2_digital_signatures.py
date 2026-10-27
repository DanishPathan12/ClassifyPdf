"""Test Case 2: Digital Signature and Post-Signature Changes.

Delegates to signature_forensics while preserving the legacy TestCase2SignatureResult.
"""

from __future__ import annotations

import logging

from app.schemas.analysis import (
    SignatureValidationResult,
    TestCase2SignatureResult,
)
from app.services.pdf_analysis.pdf_loader import LoadedPdf
from app.services.pdf_analysis.signature_forensics import analyze_digital_signatures_forensics

logger = logging.getLogger("pdf_analyser.test_case_2")


def analyze_digital_signatures(loaded_pdf: LoadedPdf) -> TestCase2SignatureResult:
    """Inspect and validate digital signatures and identify post-signature changes.

    Args:
        loaded_pdf: The loaded PDF with preserved bytes.

    Returns:
        TestCase2SignatureResult containing signature validation results and post-signing diffs.
    """
    forensics = analyze_digital_signatures_forensics(loaded_pdf)

    return TestCase2SignatureResult(
        status=forensics.legacy_status,
        signatures_found=forensics.signatures_found,
        signature_results=forensics.signature_results,
        limitations=forensics.limitations,
    )
