"""Test Case 1: Incremental Revision Analysis.

Delegates to revision_forensics for xref/structural analysis while preserving the legacy result schema.
"""

from __future__ import annotations

import io
import logging
import pikepdf
from pyhanko.pdf_utils.reader import PdfFileReader

from app.schemas.analysis import (
    ChangeLocation,
    RevisionChange,
    TestCase1IncrementalResult,
)
from app.services.pdf_analysis.pdf_loader import LoadedPdf
from app.services.pdf_analysis.revision_forensics import analyze_revision_structure
from app.services.pdf_analysis.shared_utils import compare_revisions_content, extract_pdf_layout

logger = logging.getLogger("pdf_analyser.test_case_1")


def analyze_incremental_revisions(loaded_pdf: LoadedPdf) -> TestCase1IncrementalResult:
    """Analyze PDF structure for incremental revisions, recover earlier states, and evaluate structural changes.

    Args:
        loaded_pdf: The safely loaded PDF containing preserved bytes.

    Returns:
        TestCase1IncrementalResult detailing revision count, recovered changes, and limitations.
    """
    rev_result = analyze_revision_structure(loaded_pdf)

    # If invalid or inconclusive from loader
    if not loaded_pdf.is_valid or not loaded_pdf.file_bytes:
        return TestCase1IncrementalResult(
            status="inconclusive",
            revision_count=1,
            previous_revision_recovered=False,
            changes=[],
            limitations=rev_result.limitations,
        )

    if not rev_result.has_revisions:
        return TestCase1IncrementalResult(
            status="no_revision_evidence",
            revision_count=1,
            previous_revision_recovered=False,
            changes=[],
            limitations=rev_result.limitations,
        )

    # Reconstruct historical revisions and compare layout if possible for legacy callers
    pdf_bytes = loaded_pdf.file_bytes
    all_changes = list(rev_result.legacy_changes)
    previous_recovered = rev_result.previous_revision_recovered
    limitations = list(rev_result.limitations)

    try:
        reader = PdfFileReader(io.BytesIO(pdf_bytes))
        total_revisions = reader.total_revisions
        if total_revisions > 1:
            sxref = reader.xrefs.get_startxref_for_revision(0)
            eof_pos = pdf_bytes.find(b"%%EOF", sxref)
            if eof_pos != -1:
                rev_slice = pdf_bytes[: eof_pos + 5]
                earliest_layout = extract_pdf_layout(rev_slice)
                latest_layout = extract_pdf_layout(pdf_bytes)
                layout_changes = compare_revisions_content(earliest_layout, latest_layout)
                if layout_changes:
                    all_changes = layout_changes + all_changes
                previous_recovered = True
    except Exception as exc:
        logger.debug("Legacy layout revision comparison note: %s", exc)

    return TestCase1IncrementalResult(
        status=rev_result.legacy_status,
        revision_count=rev_result.revision_count,
        previous_revision_recovered=previous_recovered,
        changes=all_changes,
        limitations=limitations,
    )

