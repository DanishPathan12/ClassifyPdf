"""Test Case 1: Incremental Revision Analysis.

Detects and recovers changes by analyzing previous revisions stored inside the same PDF.
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
from app.services.pdf_analysis.shared_utils import compare_revisions_content, extract_pdf_layout

logger = logging.getLogger("pdf_analyser.test_case_1")


def analyze_incremental_revisions(loaded_pdf: LoadedPdf) -> TestCase1IncrementalResult:
    """Analyze PDF structure for incremental revisions, recover earlier states, and compare content.

    Args:
        loaded_pdf: The safely loaded PDF containing preserved bytes.

    Returns:
        TestCase1IncrementalResult detailing revision count, recovered changes, and limitations.
    """
    pdf_bytes = loaded_pdf.file_bytes
    limitations: list[str] = []

    if not loaded_pdf.is_valid or not pdf_bytes:
        return TestCase1IncrementalResult(
            status="inconclusive",
            revision_count=1,
            previous_revision_recovered=False,
            changes=[],
            limitations=[loaded_pdf.error_message or "PDF is invalid or unreadable."],
        )

    # Inspect total revisions using pyHanko's structural xref parser
    try:
        reader = PdfFileReader(io.BytesIO(pdf_bytes))
        total_revisions = reader.total_revisions
    except Exception as e:
        logger.warning("Failed to parse PDF xref structure with pyHanko: %s", e)
        return TestCase1IncrementalResult(
            status="inconclusive",
            revision_count=1,
            previous_revision_recovered=False,
            changes=[],
            limitations=[f"Unable to parse cross-reference structure reliably: {e}"],
        )

    # Also inspect trailer /Prev using pikepdf
    trailer_has_prev = False
    try:
        with pikepdf.Pdf.open(io.BytesIO(pdf_bytes)) as pike:
            if hasattr(pike, "trailer") and "/Prev" in pike.trailer:
                trailer_has_prev = True
    except Exception:
        pass

    if total_revisions <= 1 and not trailer_has_prev:
        return TestCase1IncrementalResult(
            status="no_revision_evidence",
            revision_count=1,
            previous_revision_recovered=False,
            changes=[],
            limitations=["No previous incremental revision history exists in this document."],
        )

    # Reconstruct historical revisions
    recovered_bytes: list[bytes] = []
    try:
        for rev_idx in range(total_revisions - 1):
            sxref = reader.xrefs.get_startxref_for_revision(rev_idx)
            # Find %%EOF marker after this revision's startxref
            eof_pos = pdf_bytes.find(b"%%EOF", sxref)
            if eof_pos == -1:
                limitations.append(f"Could not locate valid %%EOF for revision {rev_idx + 1}.")
                continue

            rev_end = eof_pos + 5
            rev_slice = pdf_bytes[:rev_end]

            # Validate that the slice is a structurally complete PDF
            try:
                with pikepdf.Pdf.open(io.BytesIO(rev_slice)) as test_pdf:
                    _ = len(test_pdf.pages)
                recovered_bytes.append(rev_slice)
            except Exception as parse_err:
                limitations.append(
                    f"Recovered revision {rev_idx + 1} failed structural validation: {parse_err}"
                )
    except Exception as exc:
        logger.warning("Error recovering revision byte slices: %s", exc)
        limitations.append(f"Revision reconstruction encountered an error: {exc}")

    if not recovered_bytes:
        return TestCase1IncrementalResult(
            status="inconclusive",
            revision_count=total_revisions,
            previous_revision_recovered=False,
            changes=[],
            limitations=limitations
            or ["Incremental revisions detected, but earlier revisions could not be safely validated."],
        )

    # Compare the earliest recovered revision against the latest file state
    all_changes: list[RevisionChange] = []
    try:
        earliest_layout = extract_pdf_layout(recovered_bytes[0])
        latest_layout = extract_pdf_layout(pdf_bytes)
        all_changes = compare_revisions_content(earliest_layout, latest_layout)
    except Exception as cmp_err:
        logger.warning("Error extracting or comparing revision layouts: %s", cmp_err)
        limitations.append(f"Content extraction comparison encountered an error: {cmp_err}")

    # Inspect object differences if text comparison found 0 changes but multiple revisions exist
    if not all_changes and total_revisions > 1:
        try:
            # Check what objects were modified in later revisions
            for rev_idx in range(1, total_revisions):
                res = reader.get_historical_resolver(rev_idx)
                explicit_refs = getattr(res, "explicit_refs_in_revision", set())
                freed_refs = getattr(res, "refs_freed_in_revision", set())
                if explicit_refs or freed_refs:
                    all_changes.append(
                        RevisionChange(
                            type="objects_modified",
                            page=1,
                            old_text=None,
                            new_text=f"{len(explicit_refs)} objects modified, {len(freed_refs)} objects freed in revision {rev_idx + 1}",
                            location=None,
                            evidence=f"Cross-reference table records modifications in revision {rev_idx + 1}",
                        )
                    )
        except Exception:
            pass

    status = "changes_detected" if (all_changes or total_revisions > 1) else "no_revision_evidence"

    return TestCase1IncrementalResult(
        status=status,
        revision_count=total_revisions,
        previous_revision_recovered=True,
        changes=all_changes,
        limitations=limitations,
    )

