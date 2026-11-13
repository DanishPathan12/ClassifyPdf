"""Regression tests for legitimate filler versus isolated placeholder residue."""

import fitz

from app.services.pdf_analysis.orchestrator import run_pdf_analysis


def _pdf_with_lines(lines: list[str]) -> bytes:
    doc = fitz.open()
    page = doc.new_page()
    for index, text in enumerate(lines):
        page.insert_text((72, 72 + index * 24), text, fontsize=10)
    result = doc.tobytes()
    doc.close()
    return result


def test_repeated_lorem_is_info_only_and_aggregated() -> None:
    pdf = _pdf_with_lines([
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    ])
    result = run_pdf_analysis(pdf, filename="sample5.pdf")
    findings = [f for f in result.findings if f.code == "STRUCT_EDITOR_PLACEHOLDER_TEXT"]
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].evidence["occurrence_count"] == 5
    assert result.overall_assessment is None or result.overall_assessment.status != "suspicious_indicators_detected"


def test_isolated_lorem_is_reported_without_false_confirmation() -> None:
    pdf = _pdf_with_lines([
        "Normal report text with no editing instructions.",
        "Lorem ipsum dolor sit amet",
    ])
    result = run_pdf_analysis(pdf, filename="isolated_lorem.pdf")
    findings = [f for f in result.findings if f.code == "STRUCT_EDITOR_PLACEHOLDER_TEXT"]
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].evidence["occurrence_count"] == 1

