"""Test Suite: Content Stream Mapping, Stream-Origin Heuristic, Line Fragmentation,
Producer/Metadata Check, Object-Number Analysis, and Signal Escalation.
"""

from __future__ import annotations

import io
import fitz
import pikepdf
import pytest

from app.schemas.analysis import ForensicVerdict
from app.services.pdf_analysis.orchestrator import run_pdf_analysis
from app.services.pdf_analysis.pdf_loader import load_pdf
from app.services.pdf_analysis.structural_analysis import analyze_structural_layer
from app.services.pdf_analysis.visual_analysis import analyze_visual_layer


def _make_multi_stream_pdf_with_baseline_insertion() -> bytes:
    """Create a PDF with 5 content streams:
    Stream 1: 'Invoice document1 '
    Stream 2: 'Due Date: Nov 15'
    Stream 3: 'Appended note in stream 3'
    Stream 4: '23.' on same baseline (y=700) as 'document1 '
    Stream 5: 'Appended stamp in stream 5'
    """
    pdf = pikepdf.new()
    p = pdf.add_blank_page(page_size=(612, 792))
    font = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name.Font,
            Subtype=pikepdf.Name.Type1,
            BaseFont=pikepdf.Name.Helvetica,
        )
    )
    p.Resources = pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font))

    s1 = pdf.make_stream(b"BT /F1 12 Tf 72 700 Td (Invoice document1 ) Tj ET")
    s2 = pdf.make_stream(b"BT /F1 12 Tf 72 650 Td (Due Date: Nov 15) Tj ET")
    s3 = pdf.make_stream(b"BT /F1 12 Tf 72 600 Td (Appended note in stream 3) Tj ET")
    s4 = pdf.make_stream(b"BT /F1 12 Tf 180 700 Td (23.) Tj ET")
    s5 = pdf.make_stream(b"BT /F1 12 Tf 72 550 Td (Appended stamp in stream 5) Tj ET")

    p.Contents = pdf.make_indirect(pikepdf.Array([s1, s2, s3, s4, s5]))
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def _make_pdf_with_editor_producer_and_appended_stream() -> bytes:
    """Create a PDF with Sejda producer string and an appended content stream."""
    pdf = pikepdf.new()
    p = pdf.add_blank_page(page_size=(612, 792))
    font = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name.Font,
            Subtype=pikepdf.Name.Type1,
            BaseFont=pikepdf.Name.Helvetica,
        )
    )
    p.Resources = pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font))

    s1 = pdf.make_stream(b"BT /F1 12 Tf 72 700 Td (Original Document Agreement) Tj ET")
    s2 = pdf.make_stream(b"BT /F1 12 Tf 72 650 Td (Modified via Sejda Editor) Tj ET")
    p.Contents = pdf.make_indirect(pikepdf.Array([s1, s2]))

    pdf.docinfo["/Producer"] = "Sejda PDF Desktop 7.5"
    pdf.docinfo["/Creator"] = "Sejda"

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def _make_pdf_with_orphans_late_stream_and_baseline_insertion() -> bytes:
    """Create a PDF combining all 3 independent structural signals:
    1. Orphan objects (unreferenced streams/dictionaries)
    2. Appended secondary content stream with large object-number gap
    3. Stream-origin text insertion on the same baseline as stream 1
    """
    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    base = pikepdf.new()
    p = base.add_blank_page(page_size=(612, 792))
    font = base.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name.Font,
            Subtype=pikepdf.Name.Type1,
            BaseFont=pikepdf.Name.Helvetica,
        )
    )
    p.Resources = pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font))
    s1 = base.make_stream(b"BT /F1 12 Tf 72 700 Td (Account document1 ) Tj ET")
    p.Contents = s1
    buf1 = io.BytesIO()
    base.save(buf1)

    writer = IncrementalPdfFileWriter(io.BytesIO(buf1.getvalue()))
    for i in range(10):
        writer.add_object(generic.DictionaryObject({generic.pdf_name("/Dummy"): generic.NumberObject(i)}))

    writer.add_object(generic.StreamObject(stream_data=b"orphan unreferenced stream data"))
    app_s = writer.add_object(generic.StreamObject(stream_data=b"BT /F1 12 Tf 200 700 Td (23.) Tj ET"))
    writer.add_stream_to_page(0, app_s)

    buf2 = io.BytesIO()
    writer.write(buf2)
    return buf2.getvalue()


# ==============================================================================
# Tests
# ==============================================================================

def test_map_content_streams_to_text_spans_and_draw_boxes() -> None:
    """Requirement 1: Parse content streams separately, extract text operators (Tj, TJ) per stream,
    flag exact strings coming from appended streams (streams 3, 4, 5), and draw boxes around them.
    """
    pdf_bytes = _make_multi_stream_pdf_with_baseline_insertion()
    loaded = load_pdf(pdf_bytes, filename="five_streams.pdf")

    # Layer 1: Structural Analysis
    struct = analyze_structural_layer(loaded)
    appended_span_findings = [f for f in struct.findings if f.code == "STREAM_APPENDED_STREAM_TEXT_SPAN"]
    assert len(appended_span_findings) >= 3

    # Check exact strings from streams 3, 4, 5 are flagged
    flagged_texts = [f.evidence["text"] for f in appended_span_findings]
    assert any("stream 3" in t for t in flagged_texts)
    assert any("23." in t for t in flagged_texts)
    assert any("stream 5" in t for t in flagged_texts)

    # Check that stream index is recorded in evidence
    stream_indices = [f.evidence["stream_index"] for f in appended_span_findings]
    assert 3 in stream_indices
    assert 4 in stream_indices
    assert 5 in stream_indices

    # Layer 2: Visual Analysis draws boxes around them
    vis = analyze_visual_layer(loaded, dpi=120, structural_findings=struct.findings)
    assert len(vis.page_previews) >= 1
    preview = vis.page_previews[0]

    # Verify suspicious regions include appended_stream_text with bboxes
    appended_regions = [r for r in preview.suspicious_regions if r.technique in ("appended_stream_text", "stream_insertion")]
    assert len(appended_regions) >= 2
    for r in appended_regions:
        assert len(r.bbox_pdf) == 4
        assert len(r.bbox_px) == 4
        assert r.severity == "high"


def test_stream_origin_heuristic_baseline_insertion() -> None:
    """Requirement 2: Stream-origin heuristic flags text in a later stream sitting
    on the same baseline as stream 1 text (e.g. 'document1' in stream 1 and '23.' in stream 4).
    """
    pdf_bytes = _make_multi_stream_pdf_with_baseline_insertion()
    loaded = load_pdf(pdf_bytes, filename="baseline_insertion.pdf")

    struct = analyze_structural_layer(loaded)
    baseline_findings = [f for f in struct.findings if f.code == "STREAM_TEXT_INSERTION_ON_BASELINE"]
    assert len(baseline_findings) >= 1

    bf = baseline_findings[0]
    assert bf.severity == "high"
    assert bf.confidence >= 0.85
    assert bf.evidence["inserted_text"] == "23."
    assert "document1" in bf.evidence["stream1_text"]
    assert bf.evidence["stream_index"] == 4

    # Visual analysis maps this to stream_insertion with high severity
    vis = analyze_visual_layer(loaded, dpi=120, structural_findings=struct.findings)
    stream_ins_regions = [r for r in vis.page_previews[0].suspicious_regions if r.technique == "stream_insertion"]
    assert len(stream_ins_regions) >= 1
    assert "23." in stream_ins_regions[0].description


def test_line_fragmentation_check() -> None:
    """Requirement 3: Check for line fragmentation when a line is split into multiple runs
    with slight x-offsets or kerning / cross-stream differences.
    """
    pdf_bytes = _make_multi_stream_pdf_with_baseline_insertion()
    loaded = load_pdf(pdf_bytes, filename="fragmented.pdf")

    struct = analyze_structural_layer(loaded)
    frag_findings = [f for f in struct.findings if f.code == "STRUCT_LINE_FRAGMENTATION"]
    assert len(frag_findings) >= 1

    ff = frag_findings[0]
    assert "gap" in ff.evidence
    assert "fragment" in ff.evidence


def test_check_producer_and_metadata_with_appended_stream() -> None:
    """Requirement 4: An editor-specific producer string (e.g. 'Sejda', 'iLovePDF')
    combined with an appended content stream strengthens the tampering case.
    """
    pdf_bytes = _make_pdf_with_editor_producer_and_appended_stream()
    loaded = load_pdf(pdf_bytes, filename="sejda_edit.pdf")

    struct = analyze_structural_layer(loaded)
    producer_findings = [f for f in struct.findings if f.code == "META_EDITOR_PRODUCER_WITH_APPENDED_STREAM"]
    assert len(producer_findings) >= 1

    pf = producer_findings[0]
    assert pf.severity == "high"
    assert pf.confidence >= 0.80
    assert pf.evidence["detected_editor"] == "sejda"


def test_object_number_analysis_late_addition() -> None:
    """Requirement 5: Orphan objects plus a higher-numbered content stream attached to a page
    whose base stream is lower-numbered indicates late additions.
    """
    pdf_bytes = _make_pdf_with_orphans_late_stream_and_baseline_insertion()
    loaded = load_pdf(pdf_bytes, filename="late_addition.pdf")

    struct = analyze_structural_layer(loaded)
    late_findings = [f for f in struct.findings if f.code == "STRUCT_LATE_ADDITION_OBJECT_NUMBER"]
    assert len(late_findings) >= 1

    lf = late_findings[0]
    assert lf.severity == "high"
    assert lf.evidence["gap"] >= 5
    assert lf.evidence["orphan_count"] >= 1


def test_escalate_by_combining_signals() -> None:
    """Requirement 6: Orphans (47%) + appended text streams (60%) + text insertion indicator
    are independent and mutually reinforcing, raising the score to >= 0.85 and likely_edited.
    """
    pdf_bytes = _make_pdf_with_orphans_late_stream_and_baseline_insertion()
    res = run_pdf_analysis(pdf_bytes, filename="escalated.pdf")

    # Mutually reinforcing signals must elevate verdict to likely_edited
    assert res.verdict == ForensicVerdict.LIKELY_EDITED.value
    assert res.edit_detected is True
    assert res.confidence >= 0.85
    summary_text = getattr(res.summary, "summary_text", str(res.summary))
    assert "mutually reinforcing" in summary_text.lower() or "structural" in summary_text.lower() or "modification" in summary_text.lower()
    score_expl = getattr(res.overall_assessment, "score_explanation", "")
    assert "0.88" in score_expl or res.confidence >= 0.85

    # Visual analysis must display page previews with drawn boxes around inserted regions
    assert len(res.analyses.visual.page_previews) >= 1
    preview = res.analyses.visual.page_previews[0]
    regions = preview["suspicious_regions"] if isinstance(preview, dict) else preview.suspicious_regions
    assert len(regions) >= 1
    technique_list = [r["technique"] if isinstance(r, dict) else r.technique for r in regions]
    assert any(t in ("stream_insertion", "appended_stream_text", "text_added") for t in technique_list)
