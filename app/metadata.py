"""Metadata extraction and forensic checks for PDF files."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import defusedxml.ElementTree as ET
import pikepdf
from PIL import ExifTags, Image

from app.models import (
    AnalysisResponse,
    Category,
    FileInfo,
    Finding,
    MetadataContainer,
    Severity,
    Summary,
)

logger = logging.getLogger("pdf_analyser.metadata")

# Standard Info dictionary keys according to the PDF 1.7/2.0 specifications
STANDARD_INFO_KEYS: frozenset[str] = frozenset({
    "title",
    "author",
    "subject",
    "keywords",
    "creator",
    "producer",
    "creationdate",
    "moddate",
    "trapped",
})

# Configurable list of software known for editing or converting PDFs
KNOWN_EDITING_TOOLS: tuple[str, ...] = (
    "photoshop",
    "illustrator",
    "acrobat",
    "ilovepdf",
    "smallpdf",
    "sejda",
    "pdfescape",
    "foxit",
    "nitro",
    "canva",
    "libreoffice",
    "word",
    "indesign",
    "coreldraw",
    "pdf24",
    "pdffiller",
    "cutepdf",
    "pdfcreator",
    "inkscape",
    "gimp",
    "preview",
)

# XML namespace mapping for XMP metadata parsing
XMP_NAMESPACES: dict[str, str] = {
    "http://ns.adobe.com/xap/1.0/": "xmp",
    "http://ns.adobe.com/pdf/1.3/": "pdf",
    "http://purl.org/dc/elements/1.1/": "dc",
    "http://ns.adobe.com/xap/1.0/mm/": "xmpMM",
    "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#": "stEvt",
    "http://www.w3.org/1999/02/22-rdf-syntax-ns#": "rdf",
}


@dataclass
class ParsedDateResult:
    """Outcome of parsing a date string."""

    raw_value: str
    dt_utc: datetime | None = None
    tz_offset_minutes: float | None = None
    error: str | None = None


def format_seconds_human(seconds: float) -> str:
    """Format a duration in seconds into a human-friendly string (e.g. 5 hours, 27 minutes)."""
    secs = int(abs(seconds))
    hours, remainder = divmod(secs, 3600)
    minutes, s = divmod(remainder, 60)
    parts: list[str] = []
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if s > 0 or not parts:
        parts.append(f"{s} second{'s' if s != 1 else ''}")
    return ", ".join(parts)


def format_human_date(pdate: ParsedDateResult) -> str:
    """Format a parsed date into a single clean human-readable string with day, AM/PM, and exact time."""
    if pdate.error or pdate.dt_utc is None:
        return f"Unparseable date: {pdate.raw_value}" if pdate.raw_value else "Date missing"

    dt = pdate.dt_utc
    # Format: Thursday, October 22, 2026 at 02:05:47 PM UTC
    base = dt.strftime("%A, %B %d, %Y at %I:%M:%S %p UTC")
    if pdate.tz_offset_minutes is not None and pdate.tz_offset_minutes != 0.0:
        sign = "+" if pdate.tz_offset_minutes >= 0 else "-"
        total_m = abs(int(pdate.tz_offset_minutes))
        h, m = divmod(total_m, 60)
        base += f" (orig {sign}{h:02d}:{m:02d})"
    return base


def standardize_all_dates(parsed_data: ParsedMetadata) -> dict[str, str]:
    """Produce clean human-readable date strings for all detected timestamps."""
    dates: dict[str, str] = {}
    mapping = {
        "info:CreationDate": "creation_date",
        "info:ModDate": "modification_date",
        "xmp:CreateDate": "xmp_create_date",
        "xmp:ModifyDate": "xmp_modify_date",
        "xmp:MetadataDate": "xmp_metadata_date",
    }
    for source_key, target_key in mapping.items():
        if source_key in parsed_data.parsed_dates:
            dates[target_key] = format_human_date(parsed_data.parsed_dates[source_key])
    return dates


@dataclass
class ParsedMetadata:
    """Structured intermediate metadata representation passed to forensic checks."""

    file_info: FileInfo
    info: dict[str, Any]
    xmp: dict[str, Any]
    has_info: bool
    has_xmp: bool
    parsed_dates: dict[str, ParsedDateResult] = field(default_factory=dict)
    doc_type: str | None = None


def parse_date(val: Any) -> ParsedDateResult:
    """Parse a PDF or ISO 8601 date string into a UTC datetime and timezone offset.

    Supports:
    - PDF date strings: D:YYYYMMDDHHmmSS[OHH'mm'] (and without D:)
    - Partial PDF dates: D:YYYY, D:YYYYMM, D:YYYYMMDD, D:YYYYMMDDHH, D:YYYYMMDDHHmm
    - Flexible timezone formats: Z, +HH'mm', -HH'mm', +HH'mm, +HHmm, +HH, -HH
    - ISO 8601 date strings: YYYY-MM-DDTHH:MM:SSZ, YYYY-MM-DDTHH:MM:SS+HH:MM, etc.
    """
    if val is None:
        return ParsedDateResult(raw_value="", error="Date value is None")

    raw_str = str(val).strip()
    s = raw_str
    if s.startswith("(") and s.endswith(")"):
        s = s[1:-1].strip()
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1].strip()
    if not s:
        return ParsedDateResult(raw_value=raw_str, error="Empty date string")

    # 1. Attempt ISO 8601 parsing if standard separators are present
    if "-" in s[:10] or "T" in s:
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is not None:
                offset_sec = dt.utcoffset().total_seconds() if dt.utcoffset() else 0.0
                offset_min = offset_sec / 60.0
                dt_utc = dt.astimezone(timezone.utc)
                return ParsedDateResult(
                    raw_value=raw_str,
                    dt_utc=dt_utc,
                    tz_offset_minutes=offset_min,
                )
            # Naive ISO date: treat as UTC for comparison, record no offset
            return ParsedDateResult(
                raw_value=raw_str,
                dt_utc=dt.replace(tzinfo=timezone.utc),
                tz_offset_minutes=None,
            )
        except Exception:
            pass

    # 2. Attempt EXIF date format parsing: YYYY:MM:DD HH:MM:SS[Z | [+-]HH[:mm]]
    m_exif = re.match(
        r"^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})"
        r"(?:(Z)|([+-])(\d{1,2})(?::?(\d{2}))?)?$",
        s,
    )
    if m_exif:
        year = int(m_exif.group(1))
        month = int(m_exif.group(2))
        day = int(m_exif.group(3))
        hour = int(m_exif.group(4))
        minute = int(m_exif.group(5))
        second = int(m_exif.group(6))

        tz_z = m_exif.group(7)
        tz_sign = m_exif.group(8)
        tz_h = m_exif.group(9)
        tz_m = m_exif.group(10)

        offset_min: float | None = None
        tz: timezone | None = None

        if tz_z:
            offset_min = 0.0
            tz = timezone.utc
        elif tz_sign and tz_h:
            h = int(tz_h)
            mins = int(tz_m) if tz_m else 0
            total_m = (h * 60 + mins) * (1 if tz_sign == "+" else -1)
            offset_min = float(total_m)
            tz = timezone(timedelta(minutes=total_m))

        try:
            if tz is not None:
                dt = datetime(year, month, day, hour, minute, second, tzinfo=tz)
                dt_utc = dt.astimezone(timezone.utc)
            else:
                dt_utc = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
            return ParsedDateResult(
                raw_value=raw_str,
                dt_utc=dt_utc,
                tz_offset_minutes=offset_min,
            )
        except ValueError as e:
            return ParsedDateResult(
                raw_value=raw_str,
                error=f"Invalid date values in EXIF timestamp: {e}",
            )

    # 3. Attempt PDF date format parsing: D:YYYYMMDDHHmmSS[OHH'mm']
    s_pdf = s
    if s_pdf.startswith("D:"):
        s_pdf = s_pdf[2:]

    pattern = re.compile(
        r"^(\d{4})"                             # YYYY (required)
        r"(?:(\d{2})"                           # MM (optional)
        r"(?:(\d{2})"                           # DD (optional)
        r"(?:(\d{2})"                           # HH (optional)
        r"(?:(\d{2})"                           # mm (optional)
        r"(?:(\d{2}))?"                         # SS (optional)
        r")?)?)?)?"
        r"(?:(Z)|([+-])(\d{1,2})(?:\'?(\d{2})\'?)?)?$"  # Timezone offset
    )
    m = pattern.match(s_pdf)
    if not m:
        return ParsedDateResult(
            raw_value=raw_str,
            error=f"String does not conform to PDF or ISO date specifications: {s}",
        )

    year = int(m.group(1))
    month = int(m.group(2)) if m.group(2) else 1
    day = int(m.group(3)) if m.group(3) else 1
    hour = int(m.group(4)) if m.group(4) else 0
    minute = int(m.group(5)) if m.group(5) else 0
    second = int(m.group(6)) if m.group(6) else 0

    tz_z = m.group(7)
    tz_sign = m.group(8)
    tz_h = m.group(9)
    tz_m = m.group(10)

    offset_min: float | None = None
    tz: timezone | None = None

    if tz_z:
        offset_min = 0.0
        tz = timezone.utc
    elif tz_sign and tz_h:
        h = int(tz_h)
        mins = int(tz_m) if tz_m else 0
        total_m = (h * 60 + mins) * (1 if tz_sign == "+" else -1)
        offset_min = float(total_m)
        tz = timezone(timedelta(minutes=total_m))

    try:
        if tz is not None:
            dt = datetime(year, month, day, hour, minute, second, tzinfo=tz)
            dt_utc = dt.astimezone(timezone.utc)
            return ParsedDateResult(
                raw_value=raw_str,
                dt_utc=dt_utc,
                tz_offset_minutes=offset_min,
            )
        dt_utc = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
        return ParsedDateResult(
            raw_value=raw_str,
            dt_utc=dt_utc,
            tz_offset_minutes=None,
        )
    except ValueError as e:
        return ParsedDateResult(
            raw_value=raw_str,
            error=f"Invalid date values: {e}",
        )


def _clean_xmp_tag(tag: str) -> str:
    """Convert XML namespace URI to a short prefix, e.g. {http://...}CreateDate -> xmp:CreateDate."""
    if tag.startswith("{"):
        ns, local = tag[1:].split("}", 1)
        prefix = XMP_NAMESPACES.get(ns)
        if prefix:
            return f"{prefix}:{local}"
        return local
    return tag


def parse_xmp_metadata(raw_bytes: bytes) -> dict[str, Any]:
    """Parse XMP metadata bytes securely using defusedxml.

    Safeguards against XML entity expansion (Billion Laughs) and XXE attacks.
    Extracts standard XMP fields, dublin core fields, document IDs, and history.
    """
    if not raw_bytes:
        return {}

    try:
        root = ET.fromstring(raw_bytes)
    except Exception as e:
        return {"_xmp_parse_error": f"Failed to parse XMP XML: {e}"}

    result: dict[str, Any] = {}
    history_entries: list[dict[str, Any]] = []

    for desc in root.iter():
        tag = _clean_xmp_tag(desc.tag)

        # Attribute-based properties on Description elements
        if tag in ("rdf:Description", "Description"):
            for attr_name, attr_val in desc.attrib.items():
                c_name = _clean_xmp_tag(attr_name)
                if c_name in [
                    "xmp:CreateDate",
                    "xmp:ModifyDate",
                    "xmp:MetadataDate",
                    "xmp:CreatorTool",
                    "pdf:Producer",
                    "xmpMM:DocumentID",
                    "xmpMM:InstanceID",
                ]:
                    result[c_name] = str(attr_val).strip()

        # Element-based properties
        if tag in [
            "xmp:CreateDate",
            "xmp:ModifyDate",
            "xmp:MetadataDate",
            "xmp:CreatorTool",
            "pdf:Producer",
            "xmpMM:DocumentID",
            "xmpMM:InstanceID",
        ]:
            if desc.text and desc.text.strip():
                result[tag] = desc.text.strip()

        elif tag == "dc:title":
            lis = [li.text.strip() for li in desc.iter() if _clean_xmp_tag(li.tag) == "rdf:li" and li.text]
            if lis:
                result["dc:title"] = lis[0]
            elif desc.text and desc.text.strip():
                result["dc:title"] = desc.text.strip()

        elif tag == "dc:creator":
            lis = [li.text.strip() for li in desc.iter() if _clean_xmp_tag(li.tag) == "rdf:li" and li.text]
            if lis:
                result["dc:creator"] = lis if len(lis) > 1 else lis[0]
            elif desc.text and desc.text.strip():
                result["dc:creator"] = desc.text.strip()

        elif tag == "xmpMM:History":
            for li in desc.iter():
                if _clean_xmp_tag(li.tag) == "rdf:li":
                    entry: dict[str, Any] = {}
                    sub_desc = None
                    for child in li:
                        if _clean_xmp_tag(child.tag) in ("rdf:Description", "Description"):
                            sub_desc = child
                            break
                    source_elem = sub_desc if sub_desc is not None else li

                    for k, v in source_elem.attrib.items():
                        ck = _clean_xmp_tag(k)
                        field_name = ck.split(":", 1)[1] if ":" in ck else ck
                        entry[field_name] = str(v).strip()

                    for child in source_elem:
                        ck = _clean_xmp_tag(child.tag)
                        field_name = ck.split(":", 1)[1] if ":" in ck else ck
                        if child.text and child.text.strip():
                            entry[field_name] = child.text.strip()

                    if entry:
                        history_entries.append(entry)

    if history_entries:
        result["xmpMM:History"] = history_entries

    return result


def extract_info_dict(pdf: pikepdf.Pdf) -> dict[str, Any]:
    """Extract raw key-value pairs from the PDF Info dictionary unmodified."""
    info_dict: dict[str, Any] = {}
    try:
        if pdf.docinfo:
            for k, v in pdf.docinfo.items():
                key_str = str(k).lstrip("/")
                val_str = str(v)
                info_dict[key_str] = val_str
    except Exception:
        pass
    return info_dict


def extract_metadata(
    pdf: pikepdf.Pdf,
    file_name: str,
    file_size: int,
    sha256_hash: str,
    doc_type: str | None = None,
) -> ParsedMetadata:
    """Extract basic facts, Info dict, and XMP stream, and parse timestamps."""
    pdf_version = str(pdf.pdf_version)
    page_count = len(pdf.pages)

    file_info = FileInfo(
        name=file_name,
        size_bytes=file_size,
        sha256=sha256_hash,
        pdf_version=pdf_version,
        page_count=page_count,
    )

    info_dict = extract_info_dict(pdf)
    has_info = bool(info_dict)

    xmp_dict: dict[str, Any] = {}
    has_xmp = False
    try:
        if "/Metadata" in pdf.Root:
            metadata_stream = pdf.Root.Metadata
            raw_bytes = bytes(metadata_stream.read_bytes())
            xmp_dict = parse_xmp_metadata(raw_bytes)
            has_xmp = bool(xmp_dict) and ("_xmp_parse_error" not in xmp_dict)
    except Exception:
        has_xmp = False

    parsed_dates: dict[str, ParsedDateResult] = {}

    # Parse Info dates
    if "CreationDate" in info_dict:
        parsed_dates["info:CreationDate"] = parse_date(info_dict["CreationDate"])
    if "ModDate" in info_dict:
        parsed_dates["info:ModDate"] = parse_date(info_dict["ModDate"])

    # Parse XMP dates
    if "xmp:CreateDate" in xmp_dict:
        parsed_dates["xmp:CreateDate"] = parse_date(xmp_dict["xmp:CreateDate"])
    if "xmp:ModifyDate" in xmp_dict:
        parsed_dates["xmp:ModifyDate"] = parse_date(xmp_dict["xmp:ModifyDate"])
    if "xmp:MetadataDate" in xmp_dict:
        parsed_dates["xmp:MetadataDate"] = parse_date(xmp_dict["xmp:MetadataDate"])

    return ParsedMetadata(
        file_info=file_info,
        info=info_dict,
        xmp=xmp_dict,
        has_info=has_info,
        has_xmp=has_xmp,
        parsed_dates=parsed_dates,
        doc_type=doc_type,
    )


# ==============================================================================
# The 12 Forensic Checks
# ==============================================================================


def check_moddate_before_creation(data: ParsedMetadata) -> list[Finding]:
    """Check 1: Flag if ModDate is earlier than CreationDate."""
    findings: list[Finding] = []

    # Check within Info
    info_c = data.parsed_dates.get("info:CreationDate")
    info_m = data.parsed_dates.get("info:ModDate")
    if (
        info_c
        and info_m
        and info_c.dt_utc
        and info_m.dt_utc
        and info_m.dt_utc < info_c.dt_utc - timedelta(seconds=1)
    ):
        diff_sec = (info_c.dt_utc - info_m.dt_utc).total_seconds()
        diff_human = format_seconds_human(diff_sec)
        findings.append(
            Finding(
                id="META_MODDATE_BEFORE_CREATION",
                title="Modification date is earlier than creation date in Info dictionary",
                category=Category.SUSPICIOUS,
                severity=Severity.MEDIUM,
                explanation=(
                    "The document modification date is recorded as earlier than the creation "
                    "date in the Info dictionary. A common cause is an authoring tool writing local "
                    "time but labeling the offset as UTC (+00:00). It can also indicate metadata "
                    "alteration, manual clock changes, or improper document merging."
                ),
                evidence={
                    "container": "info",
                    "creation_date": format_human_date(info_c),
                    "mod_date": format_human_date(info_m),
                    "difference": f"{diff_human} earlier than creation",
                    "delta_seconds": diff_sec,
                },
            )
        )

    # Check within XMP
    xmp_c = data.parsed_dates.get("xmp:CreateDate")
    xmp_m = data.parsed_dates.get("xmp:ModifyDate")
    if (
        xmp_c
        and xmp_m
        and xmp_c.dt_utc
        and xmp_m.dt_utc
        and xmp_m.dt_utc < xmp_c.dt_utc - timedelta(seconds=1)
    ):
        diff_sec = (xmp_c.dt_utc - xmp_m.dt_utc).total_seconds()
        diff_human = format_seconds_human(diff_sec)
        findings.append(
            Finding(
                id="META_MODDATE_BEFORE_CREATION",
                title="Modification date is earlier than creation date in XMP metadata",
                category=Category.SUSPICIOUS,
                severity=Severity.MEDIUM,
                explanation=(
                    "The XMP modify date is earlier than the XMP create date. This chronological "
                    "inversion often arises when documents are retroactively edited, backdated, "
                    "or processed by tools with unaligned system times."
                ),
                evidence={
                    "container": "xmp",
                    "create_date": format_human_date(xmp_c),
                    "modify_date": format_human_date(xmp_m),
                    "difference": f"{diff_human} earlier than creation",
                    "delta_seconds": diff_sec,
                },
            )
        )

    return findings


def check_date_in_future(data: ParsedMetadata) -> list[Finding]:
    """Check 2: Flag timestamps that are in the future relative to analysis time."""
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)
    tolerance = timedelta(minutes=5)  # 5-minute tolerance for reasonable clock drift

    for key, pdate in data.parsed_dates.items():
        if pdate.dt_utc and pdate.dt_utc > now + tolerance:
            diff_future = (pdate.dt_utc - now).total_seconds()
            diff_human = format_seconds_human(diff_future)
            now_res = ParsedDateResult(raw_value="", dt_utc=now, tz_offset_minutes=0.0)
            findings.append(
                Finding(
                    id="META_DATE_IN_FUTURE",
                    title=f"Metadata timestamp in {key} is in the future",
                    category=Category.SUSPICIOUS,
                    severity=Severity.MEDIUM,
                    explanation=(
                        f"The timestamp in '{key}' is set in the future relative to current analysis "
                        "time. Frequently, this is caused by an authoring tool recording local machine "
                        "time while defaulting the timezone offset to UTC (+00:00)."
                    ),
                    evidence={
                        "field": key,
                        "timestamp": format_human_date(pdate),
                        "analysis_time": format_human_date(now_res),
                        "difference": f"{diff_human} ahead of analysis time",
                    },
                )
            )

    return findings


def _is_official_document(data: ParsedMetadata) -> bool:
    """Determine whether the document represents an official record where post-creation modification is a red flag."""
    if data.doc_type:
        dt = data.doc_type.lower().strip()
        if dt in ("official", "receipt", "bank", "invoice", "statement", "id", "bill", "certificate", "government"):
            return True
        if dt in ("standard", "resume", "cv", "draft", "report"):
            return False

    fname = data.file_info.name.lower()
    official_keywords = (
        "receipt", "invoice", "statement", "bill", "bank", "payslip",
        "salary", "certificate", "tax", "govt", "passport", "license", "challan"
    )
    return any(kw in fname for kw in official_keywords)


def check_moddate_differs_creation(data: ParsedMetadata) -> list[Finding]:
    """Check 3: Flag when ModDate differs from CreationDate.

    Dual-case assessment:
    - Normal working documents (resumes, contract drafts, internal reports): 100% normal lifecycle (info severity).
    - Official / system-generated documents (bank receipts, invoices, IDs): red flag (medium/high severity).
    """
    findings: list[Finding] = []
    is_official = _is_official_document(data)

    # Check Info
    info_c = data.parsed_dates.get("info:CreationDate")
    info_m = data.parsed_dates.get("info:ModDate")
    if (
        info_c
        and info_m
        and info_c.dt_utc
        and info_m.dt_utc
        and info_m.dt_utc > info_c.dt_utc + timedelta(seconds=1)
    ):
        diff_sec = (info_m.dt_utc - info_c.dt_utc).total_seconds()
        diff_human = format_seconds_human(diff_sec)

        if is_official:
            findings.append(
                Finding(
                    id="META_MODDATE_DIFFERS_CREATION",
                    title="Post-creation modification on official record (Red Flag: ModDate > CreationDate)",
                    category=Category.SUSPICIOUS,
                    severity=Severity.MEDIUM,
                    explanation=(
                        f"The modification date is {diff_human} later than the creation date on an official "
                        "record (bank receipt, invoice, or ID). Official documents should be generated once by "
                        "an automated system and never re-saved. Any post-creation edit on this document type is "
                        "a significant red flag."
                    ),
                    evidence={
                        "container": "info",
                        "creation_date": format_human_date(info_c),
                        "mod_date": format_human_date(info_m),
                        "elapsed_time": f"Modified {diff_human} after creation",
                        "document_type": "official_record",
                        "verdict_context": "Red flag: official records, receipts, and IDs should not be modified after creation.",
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    id="META_MODDATE_DIFFERS_CREATION",
                    title="Document was edited after initial creation (ModDate > CreationDate)",
                    category=Category.CONFIRMED,
                    severity=Severity.INFO,
                    explanation=(
                        f"The modification date is {diff_human} later than the creation date, confirming the document "
                        "was edited or re-saved after initial creation. "
                        "Forensic context: (1) For resumes, contract drafts, or internal reports, this is 100% normal "
                        "document workflow. (2) For bank receipts, invoices, or government IDs, any post-creation "
                        "modification is a red flag."
                    ),
                    evidence={
                        "container": "info",
                        "creation_date": format_human_date(info_c),
                        "mod_date": format_human_date(info_m),
                        "elapsed_time": f"Modified {diff_human} after creation",
                        "forensic_context": {
                            "resume_or_draft": "100% normal document workflow",
                            "bank_receipt_or_id": "Red flag: official records should not be modified after creation",
                        },
                    },
                )
            )

    # Check XMP
    xmp_c = data.parsed_dates.get("xmp:CreateDate")
    xmp_m = data.parsed_dates.get("xmp:ModifyDate")
    if (
        xmp_c
        and xmp_m
        and xmp_c.dt_utc
        and xmp_m.dt_utc
        and xmp_m.dt_utc > xmp_c.dt_utc + timedelta(seconds=1)
    ):
        diff_sec = (xmp_m.dt_utc - xmp_c.dt_utc).total_seconds()
        diff_human = format_seconds_human(diff_sec)

        if is_official:
            findings.append(
                Finding(
                    id="META_MODDATE_DIFFERS_CREATION",
                    title="Post-creation modification on official record in XMP (Red Flag: ModifyDate > CreateDate)",
                    category=Category.SUSPICIOUS,
                    severity=Severity.MEDIUM,
                    explanation=(
                        f"The XMP ModifyDate is {diff_human} later than the CreateDate on an official record. "
                        "Official documents should not have post-creation modifications recorded in XMP metadata."
                    ),
                    evidence={
                        "container": "xmp",
                        "create_date": format_human_date(xmp_c),
                        "modify_date": format_human_date(xmp_m),
                        "elapsed_time": f"Modified {diff_human} after creation",
                        "document_type": "official_record",
                        "verdict_context": "Red flag: official records, receipts, and IDs should not be modified after creation.",
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    id="META_MODDATE_DIFFERS_CREATION",
                    title="Document was edited after initial creation in XMP metadata",
                    category=Category.CONFIRMED,
                    severity=Severity.INFO,
                    explanation=(
                        f"The XMP ModifyDate is {diff_human} later than the CreateDate, confirming the document was "
                        "edited after creation. "
                        "Forensic context: (1) For resumes, contract drafts, or internal reports, this is 100% normal. "
                        "(2) For bank receipts, invoices, or government IDs, any post-creation modification is a red flag."
                    ),
                    evidence={
                        "container": "xmp",
                        "create_date": format_human_date(xmp_c),
                        "modify_date": format_human_date(xmp_m),
                        "elapsed_time": f"Modified {diff_human} after creation",
                        "forensic_context": {
                            "resume_or_draft": "100% normal document workflow",
                            "bank_receipt_or_id": "Red flag: official records should not be modified after creation",
                        },
                    },
                )
            )

    return findings


def check_info_xmp_disagreement(data: ParsedMetadata) -> list[Finding]:
    """Check 4: Disagreement between Info and XMP on dates, producer, creator, or title."""
    findings: list[Finding] = []

    # 1. Creation Date disagreement
    info_c = data.parsed_dates.get("info:CreationDate")
    xmp_c = data.parsed_dates.get("xmp:CreateDate")
    if (
        info_c
        and xmp_c
        and info_c.dt_utc
        and xmp_c.dt_utc
        and abs((info_c.dt_utc - xmp_c.dt_utc).total_seconds()) > 1.0
    ):
        findings.append(
            Finding(
                id="META_INFO_XMP_DISAGREEMENT",
                title="Disagreement between Info and XMP creation dates",
                category=Category.SUSPICIOUS,
                severity=Severity.MEDIUM,
                explanation=(
                    "The creation dates in the Info dictionary and XMP metadata stream do not match. "
                    "This discrepancy often occurs when an editing application updates only one of "
                    "the two metadata structures."
                ),
                evidence={
                    "field": "CreationDate / xmp:CreateDate",
                    "info_value": info_c.raw_value,
                    "xmp_value": xmp_c.raw_value,
                    "delta_seconds": abs((info_c.dt_utc - xmp_c.dt_utc).total_seconds()),
                },
            )
        )

    # 2. Modification Date disagreement
    info_m = data.parsed_dates.get("info:ModDate")
    xmp_m = data.parsed_dates.get("xmp:ModifyDate")
    if (
        info_m
        and xmp_m
        and info_m.dt_utc
        and xmp_m.dt_utc
        and abs((info_m.dt_utc - xmp_m.dt_utc).total_seconds()) > 1.0
    ):
        findings.append(
            Finding(
                id="META_INFO_XMP_DISAGREEMENT",
                title="Disagreement between Info and XMP modification dates",
                category=Category.SUSPICIOUS,
                severity=Severity.MEDIUM,
                explanation=(
                    "The modification dates in the Info dictionary and XMP metadata stream disagree. "
                    "This is a common signature of third-party modifications where only one metadata "
                    "store is refreshed."
                ),
                evidence={
                    "field": "ModDate / xmp:ModifyDate",
                    "info_value": info_m.raw_value,
                    "xmp_value": xmp_m.raw_value,
                    "delta_seconds": abs((info_m.dt_utc - xmp_m.dt_utc).total_seconds()),
                },
            )
        )

    # 3. Producer disagreement
    info_prod = data.info.get("Producer")
    xmp_prod = data.xmp.get("pdf:Producer")
    if (
        info_prod is not None
        and xmp_prod is not None
        and str(info_prod).strip() != str(xmp_prod).strip()
    ):
        findings.append(
            Finding(
                id="META_INFO_XMP_DISAGREEMENT",
                title="Disagreement between Info Producer and XMP Producer",
                category=Category.SUSPICIOUS,
                severity=Severity.MEDIUM,
                explanation=(
                    "The Producer field differs between the Info dictionary and XMP metadata. "
                    "This indicates that different software components or post-processing tools "
                    "touched the document without synchronizing metadata stores."
                ),
                evidence={
                    "field": "Producer / pdf:Producer",
                    "info_value": str(info_prod).strip(),
                    "xmp_value": str(xmp_prod).strip(),
                },
            )
        )

    # 4. Creator / CreatorTool disagreement
    info_creat = data.info.get("Creator")
    xmp_creat = data.xmp.get("xmp:CreatorTool")
    if (
        info_creat is not None
        and xmp_creat is not None
        and str(info_creat).strip() != str(xmp_creat).strip()
    ):
        findings.append(
            Finding(
                id="META_INFO_XMP_DISAGREEMENT",
                title="Disagreement between Info Creator and XMP CreatorTool",
                category=Category.SUSPICIOUS,
                severity=Severity.MEDIUM,
                explanation=(
                    "The Creator field in the Info dictionary does not match the XMP CreatorTool. "
                    "This often arises when an editor updates the XMP schema without touching "
                    "legacy Info fields."
                ),
                evidence={
                    "field": "Creator / xmp:CreatorTool",
                    "info_value": str(info_creat).strip(),
                    "xmp_value": str(xmp_creat).strip(),
                },
            )
        )

    # 5. Title disagreement
    info_title = data.info.get("Title")
    xmp_title = data.xmp.get("dc:title")
    if (
        info_title is not None
        and xmp_title is not None
        and str(info_title).strip() != str(xmp_title).strip()
    ):
        findings.append(
            Finding(
                id="META_INFO_XMP_DISAGREEMENT",
                title="Disagreement between Info Title and XMP title",
                category=Category.SUSPICIOUS,
                severity=Severity.MEDIUM,
                explanation=(
                    "The document title in the Info dictionary differs from the title in XMP metadata. "
                    "This suggests one metadata container was updated independently of the other."
                ),
                evidence={
                    "field": "Title / dc:title",
                    "info_value": str(info_title).strip(),
                    "xmp_value": str(xmp_title).strip(),
                },
            )
        )

    return findings


def check_known_editing_tools_and_mismatch(data: ParsedMetadata) -> list[Finding]:
    """Check 5: Flag producer/creator matching known editing tools and creator/producer origin mismatch."""
    findings: list[Finding] = []

    # Fields to inspect for known tools
    targets = [
        ("Info Producer", data.info.get("Producer")),
        ("Info Creator", data.info.get("Creator")),
        ("XMP Producer", data.xmp.get("pdf:Producer")),
        ("XMP CreatorTool", data.xmp.get("xmp:CreatorTool")),
    ]

    matched_tools_seen: set[str] = set()

    for label, val in targets:
        if not val:
            continue
        val_str = str(val).lower()
        for tool in KNOWN_EDITING_TOOLS:
            if tool in val_str and tool not in matched_tools_seen:
                matched_tools_seen.add(tool)
                findings.append(
                    Finding(
                        id="META_KNOWN_EDITING_TOOL",
                        title=f"Metadata {label} indicates use of known editing or conversion tool",
                        category=Category.SUSPICIOUS,
                        severity=Severity.LOW,
                        explanation=(
                            f"The document metadata references '{tool}', a known editing, conversion, "
                            "or publishing utility. While widely used in legitimate document workflows, "
                            "such software also enables arbitrary content and timestamp modification."
                        ),
                        evidence={
                            "field": label,
                            "value": str(val),
                            "matched_tool": tool,
                        },
                    )
                )

    # Check for Creator and Producer suggesting different origins
    creator = data.info.get("Creator") or data.xmp.get("xmp:CreatorTool")
    producer = data.info.get("Producer") or data.xmp.get("pdf:Producer")

    if creator and producer:
        c_str = str(creator).strip()
        p_str = str(producer).strip()
        c_low = c_str.lower()
        p_low = p_str.lower()

        # Flag when neither string contains or mirrors the other
        if c_low != p_low and c_low not in p_low and p_low not in c_low:
            findings.append(
                Finding(
                    id="META_CREATOR_PRODUCER_MISMATCH",
                    title="Creator and Producer suggest different software origins",
                    category=Category.SUSPICIOUS,
                    severity=Severity.LOW,
                    explanation=(
                        f"The Creator field ('{c_str}') and Producer field ('{p_str}') reference "
                        "different software environments. This is common when a document generated in one "
                        "application is printed to PDF or re-saved using a different utility."
                    ),
                    evidence={
                        "creator": c_str,
                        "producer": p_str,
                    },
                )
            )

    return findings


def check_metadata_containers_missing(data: ParsedMetadata) -> list[Finding]:
    """Check 6: Flag when metadata is missing entirely or asymmetric between Info and XMP."""
    findings: list[Finding] = []

    if not data.has_info and not data.has_xmp:
        findings.append(
            Finding(
                id="META_CONTAINER_MISSING",
                title="Metadata missing entirely (no Info dictionary or XMP stream)",
                category=Category.INCONCLUSIVE,
                severity=Severity.LOW,
                explanation=(
                    "Neither a PDF Info dictionary nor an XMP metadata stream was detected. "
                    "This may indicate aggressive privacy scrubbing, stripped metadata, or "
                    "generation by a minimal PDF library."
                ),
                evidence={"has_info": False, "has_xmp": False},
            )
        )
    elif data.has_info and not data.has_xmp:
        findings.append(
            Finding(
                id="META_CONTAINER_MISSING",
                title="XMP metadata stream is missing (Info dictionary present)",
                category=Category.INCONCLUSIVE,
                severity=Severity.INFO,
                explanation=(
                    "The document contains an Info dictionary but lacks an XMP metadata stream. "
                    "This is common in older PDF specifications (PDF 1.3 or earlier) or lightweight "
                    "PDF utilities."
                ),
                evidence={"has_info": True, "has_xmp": False},
            )
        )
    elif not data.has_info and data.has_xmp:
        findings.append(
            Finding(
                id="META_CONTAINER_MISSING",
                title="Info dictionary is missing (XMP metadata present)",
                category=Category.INCONCLUSIVE,
                severity=Severity.INFO,
                explanation=(
                    "The document contains an XMP metadata stream but no Info dictionary. "
                    "PDF 2.0 deprecates the Info dictionary in favor of XMP, though legacy readers "
                    "still expect it."
                ),
                evidence={"has_info": False, "has_xmp": True},
            )
        )

    return findings


def check_xmp_history_present(data: ParsedMetadata) -> list[Finding]:
    """Check 7: Flag presence of xmpMM:History entries detailing past modification events."""
    findings: list[Finding] = []
    history = data.xmp.get("xmpMM:History")

    if isinstance(history, list) and history:
        severity = Severity.MEDIUM if len(history) > 1 else Severity.LOW
        findings.append(
            Finding(
                id="META_XMP_HISTORY_PRESENT",
                title=f"XMP history contains {len(history)} recorded modification event(s)",
                category=Category.CONFIRMED,
                severity=severity,
                explanation=(
                    "The document's XMP metadata includes a recorded change history (xmpMM:History). "
                    "This objectively confirms past save, conversion, or edit operations, detailing "
                    "software agents and timestamps."
                ),
                evidence={
                    "event_count": len(history),
                    "events": history,
                },
            )
        )

    return findings


def check_document_instance_id_differs(data: ParsedMetadata) -> list[Finding]:
    """Check 8: Flag difference between xmpMM:DocumentID and xmpMM:InstanceID."""
    findings: list[Finding] = []
    doc_id = data.xmp.get("xmpMM:DocumentID")
    inst_id = data.xmp.get("xmpMM:InstanceID")

    if doc_id and inst_id:
        doc_str = str(doc_id).strip()
        inst_str = str(inst_id).strip()
        if doc_str != inst_str:
            findings.append(
                Finding(
                    id="META_DOC_INSTANCE_ID_DIFFERS",
                    title="XMP DocumentID and InstanceID differ",
                    category=Category.SUSPICIOUS,
                    severity=Severity.LOW,
                    explanation=(
                        "The XMP DocumentID and InstanceID differ. In XMP architecture, DocumentID "
                        "identifies the document lifecycle ancestor, while InstanceID updates on every "
                        "save or edit. This difference is normal for edited or revised documents."
                    ),
                    evidence={
                        "document_id": doc_str,
                        "instance_id": inst_str,
                    },
                )
            )

    return findings


def check_malformed_dates(data: ParsedMetadata) -> list[Finding]:
    """Check 9: Flag any date strings in Info or XMP that failed standard parsing."""
    findings: list[Finding] = []

    for field_name, pdate in data.parsed_dates.items():
        if pdate.error:
            findings.append(
                Finding(
                    id="META_MALFORMED_DATE",
                    title=f"Malformed or unparseable date in {field_name}",
                    category=Category.INCONCLUSIVE,
                    severity=Severity.LOW,
                    explanation=(
                        f"The date string in '{field_name}' could not be parsed according to the "
                        "PDF (D:YYYYMMDDHHmmSSOHH'mm') or ISO 8601 specification. Malformed dates "
                        "frequently arise from non-compliant custom generators or damaged metadata."
                    ),
                    evidence={
                        "field": field_name,
                        "raw_value": pdate.raw_value,
                        "error": pdate.error,
                    },
                )
            )

    return findings


def check_timezone_oddities(data: ParsedMetadata) -> list[Finding]:
    """Check 10: Flag timezone discrepancies between Info and XMP, or between Creation and Mod dates."""
    findings: list[Finding] = []

    # 1. Compare Info CreationDate offset vs XMP CreateDate offset
    info_c = data.parsed_dates.get("info:CreationDate")
    xmp_c = data.parsed_dates.get("xmp:CreateDate")
    if (
        info_c
        and xmp_c
        and info_c.tz_offset_minutes is not None
        and xmp_c.tz_offset_minutes is not None
        and info_c.tz_offset_minutes != xmp_c.tz_offset_minutes
    ):
        findings.append(
            Finding(
                id="META_TIMEZONE_ODDITY",
                title="Timezone offset disagreement between Info and XMP creation dates",
                category=Category.SUSPICIOUS,
                severity=Severity.LOW,
                explanation=(
                    "The UTC timezone offset in Info CreationDate differs from XMP CreateDate. "
                    "This discrepancy can happen if tools operating in different time zones or "
                    "locales updated the metadata structures independently."
                ),
                evidence={
                    "info_creation_offset_minutes": info_c.tz_offset_minutes,
                    "xmp_create_offset_minutes": xmp_c.tz_offset_minutes,
                },
            )
        )

    # 2. Compare Info ModDate offset vs XMP ModifyDate offset
    info_m = data.parsed_dates.get("info:ModDate")
    xmp_m = data.parsed_dates.get("xmp:ModifyDate")
    if (
        info_m
        and xmp_m
        and info_m.tz_offset_minutes is not None
        and xmp_m.tz_offset_minutes is not None
        and info_m.tz_offset_minutes != xmp_m.tz_offset_minutes
    ):
        findings.append(
            Finding(
                id="META_TIMEZONE_ODDITY",
                title="Timezone offset disagreement between Info and XMP modification dates",
                category=Category.SUSPICIOUS,
                severity=Severity.LOW,
                explanation=(
                    "The UTC timezone offset in Info ModDate differs from XMP ModifyDate, suggesting "
                    "inconsistent timezone handling during file modification."
                ),
                evidence={
                    "info_mod_offset_minutes": info_m.tz_offset_minutes,
                    "xmp_modify_offset_minutes": xmp_m.tz_offset_minutes,
                },
            )
        )

    # 3. Compare CreationDate offset vs ModDate offset within Info
    if (
        info_c
        and info_m
        and info_c.tz_offset_minutes is not None
        and info_m.tz_offset_minutes is not None
        and info_c.tz_offset_minutes != info_m.tz_offset_minutes
    ):
        findings.append(
            Finding(
                id="META_TIMEZONE_ODDITY",
                title="Timezone offset change between creation and modification in Info dictionary",
                category=Category.SUSPICIOUS,
                severity=Severity.LOW,
                explanation=(
                    "The document creation date and modification date in the Info dictionary have different "
                    "UTC timezone offsets. This can occur legitimately when a user travels or edits "
                    "across daylight saving time changes, or during remote collaboration."
                ),
                evidence={
                    "creation_offset_minutes": info_c.tz_offset_minutes,
                    "mod_offset_minutes": info_m.tz_offset_minutes,
                },
            )
        )

    # 4. Check for unusual offsets (outside -12:00 to +14:00 or not divisible by 15 minutes)
    for key, pdate in data.parsed_dates.items():
        if pdate.tz_offset_minutes is not None:
            off = pdate.tz_offset_minutes
            if off < -720 or off > 840 or (off % 15 != 0):
                findings.append(
                    Finding(
                        id="META_TIMEZONE_ODDITY",
                        title=f"Unusual timezone offset in {key}",
                        category=Category.SUSPICIOUS,
                        severity=Severity.LOW,
                        explanation=(
                            f"The timezone offset of {off} minutes in '{key}' is unusual or non-standard. "
                            "Standard time zones are typically bounded between UTC-12 and UTC+14 and aligned "
                            "to 15-minute intervals."
                        ),
                        evidence={
                            "field": key,
                            "offset_minutes": off,
                            "raw_value": pdate.raw_value,
                        },
                    )
                )

    return findings


def check_identical_timestamps_with_editing_tool(data: ParsedMetadata) -> list[Finding]:
    """Check 11: Identical Creation and Mod timestamps down to the second combined with an editing tool."""
    findings: list[Finding] = []

    info_c = data.parsed_dates.get("info:CreationDate")
    info_m = data.parsed_dates.get("info:ModDate")

    if (
        info_c
        and info_m
        and info_c.dt_utc
        and info_m.dt_utc
        and abs((info_c.dt_utc - info_m.dt_utc).total_seconds()) < 1.0
    ):
        producer = str(data.info.get("Producer") or data.xmp.get("pdf:Producer") or "").lower()
        creator = str(data.info.get("Creator") or data.xmp.get("xmp:CreatorTool") or "").lower()

        matched_tool: str | None = None
        for tool in KNOWN_EDITING_TOOLS:
            if tool in producer or tool in creator:
                matched_tool = tool
                break

        if matched_tool:
            findings.append(
                Finding(
                    id="META_IDENTICAL_TIMESTAMPS_EDITING_TOOL",
                    title="Suspiciously identical Creation and Mod timestamps with editing tool",
                    category=Category.SUSPICIOUS,
                    severity=Severity.LOW,
                    explanation=(
                        f"Creation and modification timestamps are identical down to the second while "
                        f"the document producer or creator references '{matched_tool}'. Certain online converters "
                        "or re-saving utilities reset both timestamps to the identical instant when exporting."
                    ),
                    evidence={
                        "timestamp": info_c.raw_value,
                        "producer": data.info.get("Producer") or data.xmp.get("pdf:Producer"),
                        "creator": data.info.get("Creator") or data.xmp.get("xmp:CreatorTool"),
                        "matched_tool": matched_tool,
                    },
                )
            )

    return findings


def check_custom_info_keys(data: ParsedMetadata) -> list[Finding]:
    """Check 12: Custom or unusual Info dictionary keys that look like leftover tool metadata."""
    findings: list[Finding] = []
    custom_keys: dict[str, Any] = {}

    for k, v in data.info.items():
        if k.lower() not in STANDARD_INFO_KEYS:
            custom_keys[k] = v

    if custom_keys:
        findings.append(
            Finding(
                id="META_CUSTOM_INFO_KEYS",
                title=f"Custom or non-standard Info dictionary keys present ({len(custom_keys)} found)",
                category=Category.CONFIRMED,
                severity=Severity.INFO,
                explanation=(
                    "The Info dictionary contains non-standard metadata keys. These often persist as "
                    "traces from specific publishing pipelines, TeX/LaTeX processors, or enterprise "
                    "content management systems."
                ),
                evidence={"custom_keys": custom_keys},
            )
        )

    return findings


# Registry of all metadata checks
ALL_CHECKS: list[Callable[[ParsedMetadata], list[Finding]]] = [
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
]


def run_all_checks(parsed: ParsedMetadata) -> list[Finding]:
    """Run all forensic checks with per-check exception isolation."""
    findings: list[Finding] = []

    for check_fn in ALL_CHECKS:
        try:
            results = check_fn(parsed)
            findings.extend(results)
        except Exception as e:
            findings.append(
                Finding(
                    id="META_CHECK_EXECUTION_ERROR",
                    title=f"Check {check_fn.__name__} failed to run",
                    category=Category.INCONCLUSIVE,
                    severity=Severity.LOW,
                    explanation=(
                        f"An unexpected internal error occurred while executing metadata check "
                        f"'{check_fn.__name__}'. The check was aborted."
                    ),
                    evidence={"check": check_fn.__name__, "error": str(e)},
                )
            )

    return findings


def build_summary(findings: list[Finding]) -> Summary:
    """Generate counts and a neutral summary statement that never states authenticity or forgery."""
    confirmed = sum(1 for f in findings if f.category == Category.CONFIRMED)
    suspicious = sum(1 for f in findings if f.category == Category.SUSPICIOUS)
    inconclusive = sum(1 for f in findings if f.category == Category.INCONCLUSIVE)

    if confirmed == 0 and suspicious == 0 and inconclusive == 0:
        overall = "No metadata inconsistencies detected."
    else:
        parts: list[str] = []
        if suspicious > 0:
            parts.append(f"{suspicious} suspicious indicator{'s' if suspicious != 1 else ''}")
        if confirmed > 0:
            parts.append(f"{confirmed} confirmed modification indicator{'s' if confirmed != 1 else ''}")
        if inconclusive > 0:
            parts.append(f"{inconclusive} inconclusive finding{'s' if inconclusive != 1 else ''}")

        joined_parts = ", ".join(parts)
        overall = f"{joined_parts} found; these are not proof of tampering."

    return Summary(
        confirmed=confirmed,
        suspicious=suspicious,
        inconclusive=inconclusive,
        overall=overall,
    )


def log_pdf_metadata(
    file_name: str,
    file_size: int,
    sha256: str,
    pdf_version: str,
    page_count: int,
    info: dict[str, Any],
    xmp: dict[str, Any],
    dates: dict[str, Any] | None = None,
) -> str:
    """Format and log/print all extracted PDF metadata for inspection and testing."""
    info_json = json.dumps(info, indent=2, default=str) if info else "{}"
    xmp_json = json.dumps(xmp, indent=2, default=str) if xmp else "{}"
    dates_json = json.dumps(dates, indent=2, default=str) if dates else "{}"

    output = (
        "\n"
        + "=" * 80 + "\n"
        + " " * 26 + "[PDF METADATA INSPECTION]\n"
        + "=" * 80 + "\n"
        + f"File Name:      {file_name}\n"
        + f"File Size:      {file_size:,} bytes\n"
        + f"SHA-256:        {sha256}\n"
        + f"PDF Version:    {pdf_version}\n"
        + f"Page Count:     {page_count}\n\n"
        + "--- [1] PDF Info Dictionary ---\n"
        + f"{info_json}\n\n"
        + "--- [2] XMP Metadata Stream ---\n"
        + f"{xmp_json}\n\n"
        + "--- [3] Standardized Dates ---\n"
        + f"{dates_json}\n"
        + "=" * 80 + "\n"
    )
    logger.info("%s", output)
    print(output)
    return output


def analyze_pdf_file(
    file_path: Path,
    file_name: str,
    file_size: int,
    sha256_hash: str,
    doc_type: str | None = None,
) -> AnalysisResponse:
    """Execute complete metadata extraction and forensic analysis on a PDF file."""
    with pikepdf.open(file_path) as pdf:
        parsed_data = extract_metadata(
            pdf=pdf,
            file_name=file_name,
            file_size=file_size,
            sha256_hash=sha256_hash,
            doc_type=doc_type,
        )

    findings = run_all_checks(parsed_data)
    summary = build_summary(findings)
    dates_std = standardize_all_dates(parsed_data)

    log_pdf_metadata(
        file_name=file_name,
        file_size=file_size,
        sha256=sha256_hash,
        pdf_version=parsed_data.file_info.pdf_version,
        page_count=parsed_data.file_info.page_count,
        info=parsed_data.info,
        xmp=parsed_data.xmp,
        dates=dates_std,
    )

    return AnalysisResponse(
        file=parsed_data.file_info,
        metadata=MetadataContainer(
            info=parsed_data.info,
            xmp=parsed_data.xmp,
            dates=dates_std,
        ),
        findings=findings,
        summary=summary,
    )


def extract_image_metadata(
    image_path: Path,
    file_name: str,
    file_size: int,
    sha256_hash: str,
    doc_type: str | None = None,
) -> ParsedMetadata:
    """Extract EXIF and image metadata from an uploaded image file."""
    with Image.open(image_path) as img:
        fmt = img.format or "IMAGE"
        w, h = img.size
        raw_exif = img.getexif()

        info_dict: dict[str, Any] = {
            "Format": fmt,
            "Dimensions": f"{w}x{h}",
        }

        # Read base EXIF tags
        if raw_exif:
            for k, v in raw_exif.items():
                tag_name = ExifTags.TAGS.get(k, str(k))
                info_dict[tag_name] = str(v)

            # Read Exif sub-IFD (0x8769) for DateTimeOriginal and DateTimeDigitized
            try:
                sub_exif = raw_exif.get_ifd(0x8769)
                for k, v in sub_exif.items():
                    tag_name = ExifTags.TAGS.get(k, str(k))
                    info_dict[tag_name] = str(v)
            except Exception:
                pass

        # Standard aliases for uniform forensic checks
        if "DateTimeOriginal" in info_dict:
            info_dict["CreationDate"] = info_dict["DateTimeOriginal"]
        elif "DateTimeDigitized" in info_dict:
            info_dict["CreationDate"] = info_dict["DateTimeDigitized"]
        elif "DateTime" in info_dict:
            info_dict["CreationDate"] = info_dict["DateTime"]

        if "DateTime" in info_dict:
            info_dict["ModDate"] = info_dict["DateTime"]

        if "Software" in info_dict:
            info_dict["Producer"] = info_dict["Software"]
            info_dict["Creator"] = info_dict["Software"]

        xmp_dict: dict[str, Any] = {}
        has_xmp = False
        # Extract embedded XMP if present
        for xmp_key in ("xmp", "XML:com.adobe.xmp"):
            if xmp_key in img.info:
                try:
                    val = img.info[xmp_key]
                    xmp_bytes = val.encode("utf-8") if isinstance(val, str) else bytes(val)
                    xmp_dict = parse_xmp_metadata(xmp_bytes)
                    has_xmp = bool(xmp_dict) and ("_xmp_parse_error" not in xmp_dict)
                    break
                except Exception:
                    pass

    has_info = bool(raw_exif)
    file_info = FileInfo(
        name=file_name,
        size_bytes=file_size,
        sha256=sha256_hash,
        pdf_version=f"Image ({fmt})",
        page_count=1,
    )

    parsed_dates: dict[str, ParsedDateResult] = {}
    if "CreationDate" in info_dict:
        parsed_dates["info:CreationDate"] = parse_date(info_dict["CreationDate"])
    if "ModDate" in info_dict:
        parsed_dates["info:ModDate"] = parse_date(info_dict["ModDate"])

    if "xmp:CreateDate" in xmp_dict:
        parsed_dates["xmp:CreateDate"] = parse_date(xmp_dict["xmp:CreateDate"])
    if "xmp:ModifyDate" in xmp_dict:
        parsed_dates["xmp:ModifyDate"] = parse_date(xmp_dict["xmp:ModifyDate"])
    if "xmp:MetadataDate" in xmp_dict:
        parsed_dates["xmp:MetadataDate"] = parse_date(xmp_dict["xmp:MetadataDate"])

    return ParsedMetadata(
        file_info=file_info,
        info=info_dict,
        xmp=xmp_dict,
        has_info=has_info,
        has_xmp=has_xmp,
        parsed_dates=parsed_dates,
        doc_type=doc_type,
    )


def analyze_image_file(
    file_path: Path,
    file_name: str,
    file_size: int,
    sha256_hash: str,
    doc_type: str | None = None,
) -> AnalysisResponse:
    """Execute complete metadata extraction and forensic analysis on an image file."""
    parsed_data = extract_image_metadata(
        image_path=file_path,
        file_name=file_name,
        file_size=file_size,
        sha256_hash=sha256_hash,
        doc_type=doc_type,
    )

    findings = run_all_checks(parsed_data)
    summary = build_summary(findings)

    return AnalysisResponse(
        file=parsed_data.file_info,
        metadata=MetadataContainer(
            info=parsed_data.info,
            xmp=parsed_data.xmp,
            dates=standardize_all_dates(parsed_data),
        ),
        findings=findings,
        summary=summary,
    )


def analyze_file(
    file_path: Path,
    file_name: str,
    file_size: int,
    sha256_hash: str,
    doc_type: str | None = None,
    file_type: str = "pdf",
) -> AnalysisResponse:
    """Unified entrypoint: analyze PDF or Image file based on detected file type."""
    if file_type == "image":
        return analyze_image_file(
            file_path=file_path,
            file_name=file_name,
            file_size=file_size,
            sha256_hash=sha256_hash,
            doc_type=doc_type,
        )
    return analyze_pdf_file(
        file_path=file_path,
        file_name=file_name,
        file_size=file_size,
        sha256_hash=sha256_hash,
        doc_type=doc_type,
    )

