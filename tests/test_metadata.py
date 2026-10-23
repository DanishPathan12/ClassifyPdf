"""Tests for metadata extraction, robust date parsing, and forensic checks."""

from __future__ import annotations

from datetime import datetime, timezone
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.metadata import (
    parse_date,
    run_all_checks,
    extract_metadata,
    build_summary,
    check_moddate_before_creation,
    check_date_in_future,
    check_moddate_differs_creation,
    check_info_xmp_disagreement,
    check_known_editing_tools_and_mismatch,
    check_metadata_containers_missing,
    check_xmp_history_present,
    check_document_instance_id_differs,
    check_malformed_dates,
    check_timezone_oddities,
    check_identical_timestamps_with_editing_tool,
    check_custom_info_keys,
    ParsedMetadata,
)
from app.models import Category, FileInfo, Severity
from tests.fixtures.pdf_generators import (
    make_custom_info_keys_pdf,
    make_future_date_pdf,
    make_identical_timestamps_tool_pdf,
    make_info_xmp_mismatch_pdf,
    make_malformed_date_pdf,
    make_missing_metadata_pdf,
    make_moddate_before_creation_pdf,
    make_timezone_oddity_pdf,
    make_valid_pdf,
    make_xmp_history_pdf,
)

client = TestClient(app)


# ------------------------------------------------------------------------------
# Robust Date Parsing Tests
# ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_str,expected_iso,expected_offset",
    [
        ("D:20230501143000Z", "2023-05-01T14:30:00+00:00", 0.0),
        ("D:20230501143000+02'00'", "2023-05-01T12:30:00+00:00", 120.0),
        ("D:20230501143000-05'00'", "2023-05-01T19:30:00+00:00", -300.0),
        ("D:20230501143000+05'30", "2023-05-01T09:00:00+00:00", 330.0),
        ("D:20230501143000+0530", "2023-05-01T09:00:00+00:00", 330.0),
        ("D:20230501", "2023-05-01T00:00:00+00:00", None),
        ("D:2023", "2023-01-01T00:00:00+00:00", None),
        ("20230501143000Z", "2023-05-01T14:30:00+00:00", 0.0),
        ("2023-05-01T14:30:00Z", "2023-05-01T14:30:00+00:00", 0.0),
        ("2023-05-01T16:30:00+02:00", "2023-05-01T14:30:00+00:00", 120.0),
    ],
)
def test_parse_date_valid(raw_str: str, expected_iso: str, expected_offset: float | None) -> None:
    """Date parser must correctly handle various PDF and ISO 8601 timestamps."""
    result = parse_date(raw_str)
    assert result.error is None
    assert result.dt_utc is not None
    assert result.dt_utc.isoformat() == expected_iso
    assert result.tz_offset_minutes == expected_offset


def test_parse_date_malformed() -> None:
    """Invalid or impossible dates must return a structured error without crashing."""
    res1 = parse_date("not-a-date")
    assert res1.error is not None
    assert res1.dt_utc is None

    res2 = parse_date("D:20231301000000Z")  # Month 13
    assert res2.error is not None
    assert "month" in res2.error.lower()

    res3 = parse_date(None)
    assert res3.error is not None


# ------------------------------------------------------------------------------
# Integration Tests on Forensic Checks via Endpoint
# ------------------------------------------------------------------------------


def test_standardized_dates_in_response() -> None:
    """Analysis response must include clean, single human-readable dates with day of week, AM/PM, and exact time."""
    pdf_bytes = make_valid_pdf(
        creation_date="D:20261022140547+00'00'",
        mod_date="D:20261022083806Z",
    )
    response = client.post(
        "/analyze",
        files={"file": ("dates_test.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    assert "dates" in data["metadata"]
    dates = data["metadata"]["dates"]

    assert "creation_date" in dates
    assert isinstance(dates["creation_date"], str)
    assert "Thursday, October 22, 2026 at 02:05:47 PM UTC" in dates["creation_date"]

    assert "modification_date" in dates
    assert isinstance(dates["modification_date"], str)
    assert "Thursday, October 22, 2026 at 08:38:06 AM UTC" in dates["modification_date"]


def test_check_moddate_before_creation() -> None:
    """Check 1: Flag when ModDate is earlier than CreationDate."""
    pdf_bytes = make_moddate_before_creation_pdf()
    response = client.post(
        "/analyze",
        files={"file": ("inverted_date.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    finding_ids = [f["id"] for f in data["findings"]]
    assert "META_MODDATE_BEFORE_CREATION" in finding_ids

    finding = next(f for f in data["findings"] if f["id"] == "META_MODDATE_BEFORE_CREATION")
    assert finding["category"] == Category.SUSPICIOUS.value
    assert finding["severity"] == Severity.MEDIUM.value
    assert "delta_seconds" in finding["evidence"]


def test_check_future_date() -> None:
    """Check 2: Flag timestamps set in the future."""
    pdf_bytes = make_future_date_pdf()
    response = client.post(
        "/analyze",
        files={"file": ("future.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    finding_ids = [f["id"] for f in data["findings"]]
    assert "META_DATE_IN_FUTURE" in finding_ids

    finding = next(f for f in data["findings"] if f["id"] == "META_DATE_IN_FUTURE")
    assert finding["category"] == Category.SUSPICIOUS.value
    assert finding["severity"] == Severity.MEDIUM.value


def test_check_moddate_differs_creation() -> None:
    """Check 3: Flag when ModDate differs from CreationDate (info level for standard docs)."""
    # CreationDate in morning, ModDate in afternoon
    pdf_bytes = make_valid_pdf(
        creation_date="D:20230501100000Z",
        mod_date="D:20230501150000Z",
    )
    response = client.post(
        "/analyze",
        files={"file": ("modified_later.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    finding_ids = [f["id"] for f in data["findings"]]
    assert "META_MODDATE_DIFFERS_CREATION" in finding_ids

    finding = next(f for f in data["findings"] if f["id"] == "META_MODDATE_DIFFERS_CREATION")
    assert finding["severity"] == Severity.INFO.value
    assert "resume" in finding["explanation"].lower()


def test_check_moddate_differs_official_receipt_red_flag() -> None:
    """Check 3: Flag ModDate > CreationDate as a Red Flag (suspicious) on official receipts / IDs."""
    pdf_bytes = make_valid_pdf(
        creation_date="D:20230501100000Z",
        mod_date="D:20230501150000Z",
    )
    # Test via filename keyword 'bank_receipt.pdf'
    response = client.post(
        "/analyze",
        files={"file": ("bank_receipt.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    finding = next(f for f in data["findings"] if f["id"] == "META_MODDATE_DIFFERS_CREATION")
    assert finding["category"] == Category.SUSPICIOUS.value
    assert finding["severity"] == Severity.MEDIUM.value
    assert "Red Flag" in finding["title"]

    # Test via explicit doc_type='official'
    response2 = client.post(
        "/analyze",
        files={"file": ("document.pdf", pdf_bytes, "application/pdf")},
        data={"doc_type": "official"},
    )
    assert response2.status_code == 200
    finding2 = next(f for f in response2.json()["findings"] if f["id"] == "META_MODDATE_DIFFERS_CREATION")
    assert finding2["category"] == Category.SUSPICIOUS.value
    assert finding2["severity"] == Severity.MEDIUM.value


def test_check_info_xmp_mismatch() -> None:
    """Check 4: Flag disagreement between Info dictionary and XMP stream."""
    pdf_bytes = make_info_xmp_mismatch_pdf()
    response = client.post(
        "/analyze",
        files={"file": ("mismatch.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    mismatch_findings = [f for f in data["findings"] if f["id"] == "META_INFO_XMP_DISAGREEMENT"]
    assert len(mismatch_findings) >= 1

    # Should flag disagreement in title, producer, creator, or dates
    disagreed_fields = [f["evidence"]["field"] for f in mismatch_findings]
    assert any("Title" in field for field in disagreed_fields)


def test_check_known_tool_and_mismatch() -> None:
    """Check 5: Flag known editing tool and Creator/Producer origin mismatch."""
    pdf_bytes = make_valid_pdf(
        creator="Microsoft Word for Office 365",
        producer="iLovePDF Online Compressor",
    )
    response = client.post(
        "/analyze",
        files={"file": ("word_ilovepdf.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    finding_ids = [f["id"] for f in data["findings"]]
    assert "META_KNOWN_EDITING_TOOL" in finding_ids
    assert "META_CREATOR_PRODUCER_MISMATCH" in finding_ids


def test_check_missing_metadata() -> None:
    """Check 6: Flag missing metadata containers as inconclusive."""
    # Strip both Info and XMP
    pdf_bytes = make_missing_metadata_pdf(remove_info=True, remove_xmp=True)
    response = client.post(
        "/analyze",
        files={"file": ("stripped.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    finding_ids = [f["id"] for f in data["findings"]]
    assert "META_CONTAINER_MISSING" in finding_ids

    finding = next(f for f in data["findings"] if f["id"] == "META_CONTAINER_MISSING")
    assert finding["category"] == Category.INCONCLUSIVE.value


def test_check_xmp_history() -> None:
    """Check 7: Flag xmpMM:History records as confirmed modification."""
    pdf_bytes = make_xmp_history_pdf()
    response = client.post(
        "/analyze",
        files={"file": ("history.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    finding_ids = [f["id"] for f in data["findings"]]
    assert "META_XMP_HISTORY_PRESENT" in finding_ids

    finding = next(f for f in data["findings"] if f["id"] == "META_XMP_HISTORY_PRESENT")
    assert finding["category"] == Category.CONFIRMED.value
    assert finding["evidence"]["event_count"] == 2


def test_check_doc_instance_id_differs() -> None:
    """Check 8: Flag difference between DocumentID and InstanceID."""
    pdf_bytes = make_xmp_history_pdf()  # Contains doc-1 and inst-2
    response = client.post(
        "/analyze",
        files={"file": ("doc_inst_diff.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    finding_ids = [f["id"] for f in data["findings"]]
    assert "META_DOC_INSTANCE_ID_DIFFERS" in finding_ids

    finding = next(f for f in data["findings"] if f["id"] == "META_DOC_INSTANCE_ID_DIFFERS")
    assert finding["severity"] == Severity.LOW.value


def test_check_malformed_date() -> None:
    """Check 9: Flag malformed or unparseable date strings."""
    pdf_bytes = make_malformed_date_pdf()
    response = client.post(
        "/analyze",
        files={"file": ("bad_date.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    finding_ids = [f["id"] for f in data["findings"]]
    assert "META_MALFORMED_DATE" in finding_ids

    finding = next(f for f in data["findings"] if f["id"] == "META_MALFORMED_DATE")
    assert finding["category"] == Category.INCONCLUSIVE.value


def test_check_custom_info_keys() -> None:
    """Check 12: Flag non-standard keys in Info dictionary."""
    pdf_bytes = make_custom_info_keys_pdf()
    response = client.post(
        "/analyze",
        files={"file": ("custom_keys.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    finding_ids = [f["id"] for f in data["findings"]]
    assert "META_CUSTOM_INFO_KEYS" in finding_ids

    finding = next(f for f in data["findings"] if f["id"] == "META_CUSTOM_INFO_KEYS")
    assert finding["severity"] == Severity.INFO.value
    assert "PTEX.Fullbanner" in finding["evidence"]["custom_keys"]


def test_check_identical_timestamps_with_editing_tool() -> None:
    """Check 11: Flag identical creation/mod timestamps combined with editing tool."""
    pdf_bytes = make_identical_timestamps_tool_pdf(tool_name="iLovePDF")
    response = client.post(
        "/analyze",
        files={"file": ("tool_identical.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    finding_ids = [f["id"] for f in data["findings"]]
    assert "META_IDENTICAL_TIMESTAMPS_EDITING_TOOL" in finding_ids


def test_check_timezone_oddity() -> None:
    """Check 10: Flag timezone differences and oddities."""
    pdf_bytes = make_timezone_oddity_pdf()
    response = client.post(
        "/analyze",
        files={"file": ("timezone.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    finding_ids = [f["id"] for f in data["findings"]]
    assert "META_TIMEZONE_ODDITY" in finding_ids


# ------------------------------------------------------------------------------
# Unit Tests for Summary and Error Resilience
# ------------------------------------------------------------------------------


def test_check_missing_info_with_xmp_present() -> None:
    """Check 6: Flag Info missing while XMP is present."""
    pdf_bytes = make_missing_metadata_pdf(remove_info=True, remove_xmp=False)
    response = client.post(
        "/analyze",
        files={"file": ("no_info_has_xmp.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()
    finding = next(f for f in data["findings"] if f["id"] == "META_CONTAINER_MISSING")
    assert "Info dictionary is missing" in finding["title"]
    assert finding["category"] == Category.INCONCLUSIVE.value


def test_check_xmp_moddate_before_creation() -> None:
    """Check 1: Flag when XMP ModifyDate is earlier than CreateDate."""
    xmp_inverted = b"""<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:xmp="http://ns.adobe.com/xap/1.0/">
   <xmp:CreateDate>2023-05-15T10:00:00Z</xmp:CreateDate>
   <xmp:ModifyDate>2023-05-01T10:00:00Z</xmp:ModifyDate>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""
    pdf_bytes = make_valid_pdf(xmp_xml=xmp_inverted)
    response = client.post(
        "/analyze",
        files={"file": ("xmp_inverted.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    findings = [f for f in response.json()["findings"] if f["id"] == "META_MODDATE_BEFORE_CREATION"]
    assert any("XMP" in f["title"] for f in findings)


def test_check_xmp_future_date() -> None:
    """Check 2: Flag future date when present in XMP."""
    xmp_future = b"""<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:xmp="http://ns.adobe.com/xap/1.0/">
   <xmp:CreateDate>2040-01-01T00:00:00Z</xmp:CreateDate>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""
    pdf_bytes = make_valid_pdf(xmp_xml=xmp_future)
    response = client.post(
        "/analyze",
        files={"file": ("xmp_future.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    findings = [f for f in response.json()["findings"] if f["id"] == "META_DATE_IN_FUTURE"]
    assert len(findings) >= 1


def test_check_summary_neutrality() -> None:
    """Summary overall message must be neutral and never state authentic or forged."""
    # No findings
    s1 = build_summary([])
    assert "No metadata inconsistencies detected" in s1.overall
    assert "authentic" not in s1.overall.lower()
    assert "forged" not in s1.overall.lower()

    # Some suspicious and confirmed findings
    sample_pdf = make_moddate_before_creation_pdf()
    response = client.post(
        "/analyze",
        files={"file": ("test.pdf", sample_pdf, "application/pdf")},
    )
    summary = response.json()["summary"]
    assert "not proof of tampering" in summary["overall"]
    assert "authentic" not in summary["overall"].lower()
    assert "forged" not in summary["overall"].lower()


def test_check_execution_error_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    """If a single check raises an unexpected exception, analysis must still complete."""
    import app.metadata as meta_mod

    def broken_check(_data: ParsedMetadata) -> list[any]:
        raise RuntimeError("Simulated internal check failure")

    original_checks = list(meta_mod.ALL_CHECKS)
    monkeypatch.setattr(meta_mod, "ALL_CHECKS", [broken_check] + original_checks)

    pdf_bytes = make_valid_pdf()
    response = client.post(
        "/analyze",
        files={"file": ("safe.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    finding_ids = [f["id"] for f in data["findings"]]
    assert "META_CHECK_EXECUTION_ERROR" in finding_ids
    error_finding = next(f for f in data["findings"] if f["id"] == "META_CHECK_EXECUTION_ERROR")
    assert error_finding["category"] == Category.INCONCLUSIVE.value
    assert "Simulated internal check failure" in error_finding["evidence"]["error"]
