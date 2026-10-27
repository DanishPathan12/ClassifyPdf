"""Structural Forensics: Content streams, font resource consistency, and object-level anomalies."""

from __future__ import annotations

from dataclasses import dataclass, field
import io
import logging
import re
from typing import Any
import pikepdf

from app.schemas.analysis import ForensicFinding
from app.services.pdf_analysis.pdf_loader import LoadedPdf

logger = logging.getLogger("pdf_analyser.structural_forensics")


@dataclass
class StructuralForensicsResult:
    """Findings from content-stream, resource-mapping, and object graph analysis."""

    module_status: str  # completed | partial | failed | inconclusive
    unreferenced_objects_count: int = 0
    multiple_content_streams_pages: list[int] = field(default_factory=list)
    dangling_font_references: list[dict[str, Any]] = field(default_factory=list)
    invisible_text_pages: list[int] = field(default_factory=list)
    unbalanced_graphics_state_pages: list[int] = field(default_factory=list)
    findings: list[ForensicFinding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def analyze_structural_forensics(loaded_pdf: LoadedPdf) -> StructuralForensicsResult:
    """Inspect PDF objects, streams, operator sequences, and resource consistency.

    Args:
        loaded_pdf: Safely loaded PDF with preserved bytes.

    Returns:
        StructuralForensicsResult with standardized forensic findings.
    """
    pdf_bytes = loaded_pdf.file_bytes
    limitations: list[str] = [
        "Modern PDF creators and design tools legitimately use multiple content streams, XObjects, or font subsets.",
        "Invisible text (rendering mode 3 Tr) is commonly and legitimately used in OCR layers behind scanned documents.",
        "Structural anomalies provide forensic signals that require correlation with revision or metadata evidence.",
    ]

    if not loaded_pdf.is_valid or not pdf_bytes:
        return StructuralForensicsResult(
            module_status="inconclusive",
            findings=[],
            limitations=[loaded_pdf.error_message or "PDF is invalid or unreadable."],
        )

    findings: list[ForensicFinding] = []
    unreferenced_count = 0
    multiple_streams_pages: list[int] = []
    dangling_fonts: list[dict[str, Any]] = []
    invisible_text_pages: list[int] = []
    unbalanced_gs_pages: list[int] = []

    try:
        with pikepdf.Pdf.open(io.BytesIO(pdf_bytes)) as pdf:
            # 1. Reachability & Orphan Object Inspection
            unreferenced_count = _inspect_unreferenced_objects(pdf, findings)

            # 2. Page Content Stream and Resource Inspections
            for p_idx, page in enumerate(pdf.pages, start=1):
                _inspect_page_streams(
                    page=page,
                    page_num=p_idx,
                    multiple_streams_pages=multiple_streams_pages,
                    dangling_fonts=dangling_fonts,
                    invisible_text_pages=invisible_text_pages,
                    unbalanced_gs_pages=unbalanced_gs_pages,
                    findings=findings,
                )

    except Exception as exc:
        logger.warning("Structural forensics encountered an error: %s", exc)
        return StructuralForensicsResult(
            module_status="partial" if findings else "failed",
            unreferenced_objects_count=unreferenced_count,
            multiple_content_streams_pages=multiple_streams_pages,
            dangling_font_references=dangling_fonts,
            invisible_text_pages=invisible_text_pages,
            unbalanced_graphics_state_pages=unbalanced_gs_pages,
            findings=findings,
            limitations=[f"Structural inspection encountered an exception: {exc}"] + limitations,
        )

    return StructuralForensicsResult(
        module_status="completed",
        unreferenced_objects_count=unreferenced_count,
        multiple_content_streams_pages=multiple_streams_pages,
        dangling_font_references=dangling_fonts,
        invisible_text_pages=invisible_text_pages,
        unbalanced_graphics_state_pages=unbalanced_gs_pages,
        findings=findings,
        limitations=limitations,
    )


def _inspect_unreferenced_objects(pdf: pikepdf.Pdf, findings: list[ForensicFinding]) -> int:
    """Traverse PDF object graph from Root and trailer to discover unreferenced orphan objects."""
    visited_oids: set[tuple[int, int]] = set()

    def _traverse(obj: Any) -> None:
        if isinstance(obj, pikepdf.Object):
            oid = getattr(obj, "objgen", None)
            if oid:
                if oid in visited_oids:
                    return
                visited_oids.add(oid)
            if isinstance(obj, pikepdf.Dictionary):
                for v in obj.values():
                    _traverse(v)
            elif isinstance(obj, pikepdf.Array):
                for item in obj:
                    _traverse(item)

    try:
        _traverse(pdf.Root)
        if hasattr(pdf, "trailer"):
            _traverse(pdf.trailer)

        all_oids = {o.objgen for o in pdf.objects if getattr(o, "objgen", None)}
        # Filter standard free-list head object (0, 65535)
        orphans = {oid for oid in (all_oids - visited_oids) if oid[0] != 0 and oid[1] != 65535}

        # Check if any orphan objects contain actual streams or page/xobject definitions
        orphan_streams = 0
        orphan_pages = 0
        for oid in orphans:
            try:
                raw_obj = pdf.get_object(oid)
                if isinstance(raw_obj, pikepdf.Stream):
                    orphan_streams += 1
                elif isinstance(raw_obj, pikepdf.Dictionary):
                    obj_type = str(raw_obj.get("/Type", ""))
                    if obj_type in ("/Page", "/Pages", "/XObject"):
                        orphan_pages += 1
            except Exception:
                pass

        # Only flag if there are meaningful orphan content streams or page objects
        if orphan_streams > 0 or orphan_pages > 0:
            findings.append(
                ForensicFinding(
                    code="STREAM_UNREFERENCED_ORPHAN_OBJECTS",
                    category="suspicious",
                    domain="content_stream",
                    severity="medium",
                    confidence=0.55,
                    description=(
                        f"Document contains {len(orphans)} unreferenced orphan object(s) "
                        f"including {orphan_streams} stream(s) and {orphan_pages} page/xobject structure(s) "
                        "not reachable from the document catalog or trailer"
                    ),
                    evidence={
                        "orphan_count": len(orphans),
                        "orphan_streams": orphan_streams,
                        "orphan_pages": orphan_pages,
                        "sample_orphan_ids": [f"{o[0]} {o[1]} R" for o in list(orphans)[:5]],
                    },
                    limitations=[
                        "Incomplete PDF generation or optimization stripping can leave orphan objects without malicious intent.",
                        "Incremental resaving by some tools leaves superseded objects in the file.",
                    ],
                )
            )
        return len(orphans)
    except Exception as e:
        logger.debug("Orphan object inspection note: %s", e)
        return 0


def _inspect_page_streams(
    page: pikepdf.Page,
    page_num: int,
    multiple_streams_pages: list[int],
    dangling_fonts: list[dict[str, Any]],
    invisible_text_pages: list[int],
    unbalanced_gs_pages: list[int],
    findings: list[ForensicFinding],
) -> None:
    """Inspect page /Contents, /Resources, operator syntax, and graphics state."""
    raw_contents = page.get("/Contents")
    if raw_contents is None:
        return

    # Extract all stream byte chunks for this page
    streams_bytes: list[bytes] = []
    if isinstance(raw_contents, pikepdf.Stream):
        try:
            streams_bytes.append(raw_contents.read_bytes())
        except Exception:
            pass
    elif isinstance(raw_contents, pikepdf.Array):
        multiple_streams_pages.append(page_num)
        for s in raw_contents:
            if isinstance(s, pikepdf.Stream):
                try:
                    streams_bytes.append(s.read_bytes())
                except Exception:
                    pass

    if len(streams_bytes) > 1:
        # Flag multiple content streams as an informational/low structural note
        findings.append(
            ForensicFinding(
                code="STREAM_MULTIPLE_PAGE_CONTENTS",
                category="content_stream",
                severity="low",
                confidence=0.20,
                description=f"Page {page_num} uses multiple ({len(streams_bytes)}) content streams; often used for layered content, watermarks, or appended edits",
                evidence={"page": page_num, "stream_count": len(streams_bytes)},
                limitations=[
                    "PDF generators commonly split headers, footers, watermarks, and background forms into separate streams.",
                    "Not proof of unauthorized modification.",
                ],
            )
        )

    # Collect declared font resource names on the page
    declared_font_names: set[str] = set()
    try:
        res = page.get("/Resources")
        if res and "/Font" in res:
            font_dict = res["/Font"]
            if hasattr(font_dict, "keys"):
                for k in font_dict.keys():
                    declared_font_names.add(str(k))
    except Exception:
        pass

    # Inspect operator tokens in streams
    tf_pattern = re.compile(rb"(/[\w\.\-]+)\s+([\d\.]+)\s+Tf")
    tr_pattern = re.compile(rb"(\d+)\s+Tr")
    q_push_pattern = re.compile(rb"\bq\b")
    q_pop_pattern = re.compile(rb"\bQ\b")

    for s_idx, s_bytes in enumerate(streams_bytes, start=1):
        # 1. Unbalanced graphics state q/Q
        q_count = len(q_push_pattern.findall(s_bytes))
        q_pop_count = len(q_pop_pattern.findall(s_bytes))
        if q_count != q_pop_count:
            unbalanced_gs_pages.append(page_num)
            findings.append(
                ForensicFinding(
                    code="STREAM_UNBALANCED_GRAPHICS_STATE",
                    category="content_stream",
                    severity="low",
                    confidence=0.30,
                    description=f"Page {page_num} stream {s_idx} contains unbalanced graphics state push/pop operators (q={q_count}, Q={q_pop_count})",
                    evidence={"page": page_num, "stream_index": s_idx, "q_count": q_count, "Q_count": q_pop_count},
                    limitations=["Malformed PDF generators can produce unbalanced graphics states without malice."],
                )
            )

        # 2. Invisible text rendering mode 3 Tr
        tr_matches = tr_pattern.findall(s_bytes)
        if b"3" in tr_matches:
            invisible_text_pages.append(page_num)
            findings.append(
                ForensicFinding(
                    code="STREAM_INVISIBLE_TEXT_OPERATOR",
                    category="content_stream",
                    severity="low",
                    confidence=0.30,
                    description=f"Page {page_num} uses invisible text rendering mode (3 Tr); often used for OCR text layers, hidden overlays, or watermarks",
                    evidence={"page": page_num, "stream_index": s_idx, "render_mode": 3},
                    limitations=[
                        "OCR scanned documents legitimately employ 3 Tr invisible text overlaid on images for searchability.",
                        "Inspect image background to distinguish standard OCR from hidden textual overrides.",
                    ],
                )
            )

        # 3. Dangling font references: /F... Tf used but not in page /Resources /Font
        if declared_font_names:
            tf_matches = tf_pattern.findall(s_bytes)
            for font_tag_bytes, font_size_bytes in tf_matches:
                font_tag = font_tag_bytes.decode("ascii", errors="ignore")
                if font_tag not in declared_font_names:
                    dangling_record = {
                        "page": page_num,
                        "stream_index": s_idx,
                        "font_tag": font_tag,
                        "declared_fonts": list(declared_font_names),
                    }
                    dangling_fonts.append(dangling_record)
                    findings.append(
                        ForensicFinding(
                            code="STREAM_DANGLING_FONT_REFERENCE",
                            category="content_stream",
                            severity="medium",
                            confidence=0.60,
                            description=f"Page {page_num} content stream references font '{font_tag}' which is missing from the page's declared /Font resources",
                            evidence=dangling_record,
                            limitations=[
                                "Font may be inherited from parent /Pages tree or global resource dictionary.",
                                "Some PDF editors fail to register newly typed fonts into the page resource dictionary properly.",
                            ],
                        )
                    )
                    break
