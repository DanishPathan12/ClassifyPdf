"""Revision Forensics: Analyzes cross-reference tables, revision chains, and structural modifications."""

from __future__ import annotations

from dataclasses import dataclass, field
import io
import logging
from typing import Any
import pikepdf
from pyhanko.pdf_utils.reader import PdfFileReader

from app.schemas.analysis import (
    ChangeLocation,
    ForensicFinding,
    RevisionChange,
    TestCase1IncrementalResult,
)
from app.services.pdf_analysis.pdf_loader import LoadedPdf

logger = logging.getLogger("pdf_analyser.revision_forensics")


@dataclass
class RevisionForensicsResult:
    """Detailed structural findings from incremental revision and xref analysis."""

    module_status: str  # completed | partial | failed | inconclusive
    revision_count: int
    has_revisions: bool
    is_linearized: bool
    has_hybrid_xref: bool
    is_chain_consistent: bool
    findings: list[ForensicFinding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    # Legacy compatibility fields
    legacy_status: str = "no_revision_evidence"
    previous_revision_recovered: bool = False
    legacy_changes: list[RevisionChange] = field(default_factory=list)


def analyze_revision_structure(loaded_pdf: LoadedPdf) -> RevisionForensicsResult:
    """Perform independent structural and cross-reference forensics on a single PDF.

    Args:
        loaded_pdf: Safely loaded PDF with preserved bytes.

    Returns:
        RevisionForensicsResult with standardized findings and compatibility data.
    """
    pdf_bytes = loaded_pdf.file_bytes
    file_len = len(pdf_bytes)
    limitations: list[str] = [
        "Absence of incremental revision history does not prove a document is an unedited original; "
        "a fully re-saved PDF discards prior revision chains.",
        "Incremental saves are standard in legitimate PDF software (e.g. Acrobat form saving, comments, digital signatures).",
    ]

    if not loaded_pdf.is_valid or file_len == 0:
        return RevisionForensicsResult(
            module_status="inconclusive",
            revision_count=1,
            has_revisions=False,
            is_linearized=False,
            has_hybrid_xref=False,
            is_chain_consistent=False,
            findings=[],
            limitations=[loaded_pdf.error_message or "PDF is empty or unreadable."],
            legacy_status="inconclusive",
            previous_revision_recovered=False,
            legacy_changes=[],
        )

    # 1. Physical EOF marker count and startxref positions
    eof_positions: list[int] = []
    idx = 0
    while True:
        pos = pdf_bytes.find(b"%%EOF", idx)
        if pos == -1:
            break
        eof_positions.append(pos)
        idx = pos + 5

    startxref_positions: list[int] = []
    idx = 0
    while True:
        pos = pdf_bytes.find(b"startxref", idx)
        if pos == -1:
            break
        startxref_positions.append(pos)
        idx = pos + 9

    # 2. Check for Linearization
    is_linearized = False
    try:
        first_kb = pdf_bytes[:2048]
        if b"/Linearized" in first_kb:
            is_linearized = True
    except Exception:
        pass

    # 3. pyHanko structural xref inspection
    reader: PdfFileReader | None = None
    total_revisions = 1
    has_hybrid = False
    chain_consistent = True
    findings: list[ForensicFinding] = []

    try:
        reader = PdfFileReader(io.BytesIO(pdf_bytes))
        total_revisions = reader.total_revisions
    except Exception as parse_err:
        logger.warning("pyHanko xref parsing error: %s", parse_err)
        # Fall back to physical markers count
        total_revisions = max(1, len(eof_positions), len(startxref_positions))

    # 4. Trailer /Prev chain consistency check
    trailer_has_prev = False
    prev_chain_offsets: list[int] = []
    try:
        with pikepdf.Pdf.open(io.BytesIO(pdf_bytes)) as pike:
            if hasattr(pike, "trailer"):
                trailer = pike.trailer
                if "/Prev" in trailer:
                    trailer_has_prev = True
                    # Trace /Prev chain
                    curr_prev = int(trailer["/Prev"])
                    seen_prevs: set[int] = set()
                    while curr_prev > 0 and curr_prev not in seen_prevs:
                        seen_prevs.add(curr_prev)
                        prev_chain_offsets.append(curr_prev)
                        if curr_prev >= file_len:
                            chain_consistent = False
                            findings.append(
                                ForensicFinding(
                                    code="REV_XREF_OFFSET_OUT_OF_BOUNDS",
                                    category="revision_history",
                                    severity="high",
                                    confidence=0.85,
                                    description="Cross-reference /Prev pointer references byte offset outside file bounds",
                                    evidence={"target_offset": curr_prev, "file_size": file_len},
                                    limitations=["Corrupted or truncated file transfer can produce invalid offsets."],
                                )
                            )
                            break
                        # Find previous /Prev in file slice if any
                        prev_pos = pdf_bytes.rfind(b"/Prev", 0, curr_prev)
                        if prev_pos != -1:
                            # Read integer following /Prev
                            slice_text = pdf_bytes[prev_pos : prev_pos + 40]
                            tokens = slice_text.split()
                            if len(tokens) >= 2 and tokens[1].isdigit():
                                curr_prev = int(tokens[1])
                            else:
                                break
                        else:
                            break
    except Exception as pike_err:
        logger.debug("pikepdf trailer inspection note: %s", pike_err)

    # 5. Hybrid xref detection (both table and stream)
    has_xref_stream = (b"/Type /XRef" in pdf_bytes) or (b"/Type/XRef" in pdf_bytes)
    has_xref_table = b"\nxref\n" in pdf_bytes or b"\rxref\r" in pdf_bytes or b"\r\nxref\r\n" in pdf_bytes
    if has_xref_stream and has_xref_table:
        has_hybrid = True

    # 6. Evaluate revision presence & nature
    has_revisions = total_revisions > 1 or len(eof_positions) > 1 or trailer_has_prev

    legacy_changes: list[RevisionChange] = []
    recovered_revision_ok = False

    if has_revisions:
        # Check modified objects in each revision if reader is available
        suspicious_structural_replacement = False
        objects_modified_count = 0
        replaced_critical_keys: list[str] = []

        if reader is not None:
            try:
                for rev_idx in range(1, total_revisions):
                    res = reader.get_historical_resolver(rev_idx)
                    explicit_refs_callable = getattr(res, "explicit_refs_in_revision", None)
                    explicit_refs = explicit_refs_callable() if callable(explicit_refs_callable) else set()
                    objects_modified_count += len(explicit_refs)

                    # Check what kinds of objects were updated
                    has_sig_in_rev = False
                    for ref in explicit_refs:
                        try:
                            obj = res.get_object(ref)
                            if hasattr(obj, "keys"):
                                obj_keys = [str(k) for k in obj.keys()]
                                if "/ByteRange" in obj_keys or "/SubFilter" in obj_keys:
                                    has_sig_in_rev = True
                                # If the page tree root itself (/Type /Pages) was replaced
                                if "/Type" in obj_keys and str(obj.get("/Type")) == "/Pages" and "/Kids" in obj_keys:
                                    # If page tree is replaced in a revision without signatures
                                    suspicious_structural_replacement = True
                                    replaced_critical_keys.extend(obj_keys)
                        except Exception:
                            pass

                    # If catalog was updated without adding AcroForm or signature
                    if not has_sig_in_rev:
                        for ref in explicit_refs:
                            try:
                                obj = res.get_object(ref)
                                if hasattr(obj, "keys"):
                                    obj_keys = [str(k) for k in obj.keys()]
                                    if "/Type" in obj_keys and str(obj.get("/Type")) == "/Catalog":
                                        if "/AcroForm" not in obj_keys and "/Metadata" not in obj_keys:
                                            suspicious_structural_replacement = True
                                            replaced_critical_keys.extend(obj_keys)
                            except Exception:
                                pass

                    if explicit_refs:
                        legacy_changes.append(
                            RevisionChange(
                                type="objects_modified",
                                page=1,
                                old_text=None,
                                new_text=f"{len(explicit_refs)} objects updated in revision {rev_idx + 1}",
                                location=None,
                                evidence=f"Cross-reference table records modifications in revision {rev_idx + 1}",
                            )
                        )
            except Exception as hist_err:
                logger.debug("Historical resolver inspection note: %s", hist_err)

        # Attempt to validate earlier revision bytes
        if reader is not None and total_revisions > 1:
            try:
                sxref = reader.xrefs.get_startxref_for_revision(0)
                eof_pos = pdf_bytes.find(b"%%EOF", sxref)
                if eof_pos != -1:
                    slice_0 = pdf_bytes[: eof_pos + 5]
                    with pikepdf.Pdf.open(io.BytesIO(slice_0)) as test_p:
                        if len(test_p.pages) > 0:
                            recovered_revision_ok = True
            except Exception:
                pass

        # Distinguish suspicious structural replacement from benign incremental updates
        if suspicious_structural_replacement:
            findings.append(
                ForensicFinding(
                    code="REV_CRITICAL_OBJECT_REPLACED",
                    category="confirmed",
                    domain="revision_history",
                    severity="high",
                    confidence=0.80,
                    description="An incremental revision replaced critical document root or page-tree structures",
                    evidence={
                        "revision_count": total_revisions,
                        "critical_keys_modified": replaced_critical_keys,
                        "modified_objects_count": objects_modified_count,
                    },
                    limitations=["Complex page merging or digital form insertion can legitimately touch page trees."],
                )
            )
        elif is_linearized and total_revisions == 2:
            findings.append(
                ForensicFinding(
                    code="REV_LINEARIZED_BENIGN_STRUCTURE",
                    category="inconclusive",
                    domain="revision_history",
                    severity="info",
                    confidence=0.10,
                    description="Document uses Linearized (Fast Web View) structure with standard dual revisions",
                    evidence={"linearized": True, "revision_count": total_revisions},
                    limitations=["Linearization is standard behavior for web-optimized PDFs."],
                )
            )
        elif reader is not None and len(reader.embedded_signatures) > 0 and (total_revisions <= len(reader.embedded_signatures) + 1):
            # Check if all signatures cover their respective revisions without subsequent unverified revisions
            findings.append(
                ForensicFinding(
                    code="REV_SIGNATURE_INCREMENTAL_REVISION",
                    category="inconclusive",
                    domain="revision_history",
                    severity="info",
                    confidence=0.05,
                    description=f"Document contains {total_revisions} revision(s) corresponding to the application of {len(reader.embedded_signatures)} digital signature(s)",
                    evidence={"revision_count": total_revisions, "signatures_count": len(reader.embedded_signatures)},
                    limitations=["Digital signatures are standardly appended as incremental revisions per ISO 32000-1."],
                )
            )
        else:
            findings.append(
                ForensicFinding(
                    code="REV_INCREMENTAL_REVISION_PRESENT",
                    category="suspicious",
                    domain="revision_history",
                    severity="low",
                    confidence=0.25,
                    description=f"Document contains {total_revisions} incremental revision(s) recorded in cross-reference tables",
                    evidence={
                        "revision_count": total_revisions,
                        "eof_markers_count": len(eof_positions),
                        "startxref_count": len(startxref_positions),
                        "trailer_has_prev": trailer_has_prev,
                        "total_modified_objects": objects_modified_count,
                    },
                    limitations=[
                        "Incremental revisions are standard for normal PDF editing, form filling, annotations, or signing.",
                        "Presence of incremental revisions alone does not establish malicious manipulation.",
                    ],
                )
            )

        legacy_status = "changes_detected"
    else:
        findings.append(
            ForensicFinding(
                code="REV_NO_INCREMENTAL_REVISIONS",
                category="inconclusive",
                domain="revision_history",
                severity="info",
                confidence=0.05,
                description="No incremental revision history detected; document is stored in a single cross-reference revision",
                evidence={"revision_count": 1, "trailer_has_prev": False},
                limitations=[
                    "Lack of revision history is normal for newly exported or fully re-saved PDFs.",
                    "This does not establish that the document has never been modified.",
                ],
            )
        )
        legacy_status = "no_revision_evidence"

    return RevisionForensicsResult(
        module_status="completed",
        revision_count=total_revisions,
        has_revisions=has_revisions,
        is_linearized=is_linearized,
        has_hybrid_xref=has_hybrid,
        is_chain_consistent=chain_consistent,
        findings=findings,
        limitations=limitations,
        legacy_status=legacy_status,
        previous_revision_recovered=recovered_revision_ok,
        legacy_changes=legacy_changes,
    )
