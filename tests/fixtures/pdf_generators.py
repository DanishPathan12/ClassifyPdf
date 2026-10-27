"""Programmatic PDF and Image generation fixtures for tests."""

from __future__ import annotations

import io
from typing import Any
import pikepdf
from PIL import Image


def make_valid_pdf(
    title: str = "Quarterly Financial Analysis",
    author: str = "Jane Doe",
    creator: str = "Enterprise Report Generator",
    producer: str = "ReportEngine v2.0",
    creation_date: str = "D:20230501100000Z",
    mod_date: str = "D:20230501100000Z",
    xmp_xml: bytes | None = None,
) -> bytes:
    """Generate a clean, structurally valid PDF with matching Info and XMP."""
    pdf = pikepdf.new()
    pdf.add_blank_page()

    # Clear default pikepdf docinfo tags
    for k in list(pdf.docinfo.keys()):
        del pdf.docinfo[k]

    pdf.docinfo["/Title"] = title
    pdf.docinfo["/Author"] = author
    pdf.docinfo["/Creator"] = creator
    pdf.docinfo["/Producer"] = producer
    pdf.docinfo["/CreationDate"] = creation_date
    pdf.docinfo["/ModDate"] = mod_date

    if xmp_xml is None:
        # Default synchronized XMP
        xmp_xml = f"""<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:xmp="http://ns.adobe.com/xap/1.0/"
    xmlns:pdf="http://ns.adobe.com/pdf/1.3/"
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/">
   <xmp:CreateDate>2023-05-01T10:00:00Z</xmp:CreateDate>
   <xmp:ModifyDate>2023-05-01T10:00:00Z</xmp:ModifyDate>
   <xmp:CreatorTool>{creator}</xmp:CreatorTool>
   <pdf:Producer>{producer}</pdf:Producer>
   <dc:title><rdf:Alt><rdf:li xml:lang="x-default">{title}</rdf:li></rdf:Alt></dc:title>
   <dc:creator><rdf:Seq><rdf:li>{author}</rdf:li></rdf:Seq></dc:creator>
   <xmpMM:DocumentID>uuid:doc-1001</xmpMM:DocumentID>
   <xmpMM:InstanceID>uuid:doc-1001</xmpMM:InstanceID>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>""".encode("utf-8")

    stream = pdf.make_stream(xmp_xml)
    stream["/Type"] = pikepdf.Name("/Metadata")
    stream["/Subtype"] = pikepdf.Name("/XML")
    pdf.Root["/Metadata"] = stream

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_encrypted_pdf(user_pw: str = "usersecret", owner_pw: str = "ownersecret") -> bytes:
    """Generate an encrypted PDF requiring a password to open."""
    pdf = pikepdf.new()
    pdf.add_blank_page()
    buf = io.BytesIO()
    pdf.save(buf, encryption=pikepdf.Encryption(owner=owner_pw, user=user_pw, R=4))
    return buf.getvalue()


def make_corrupted_pdf() -> bytes:
    """Generate a file that starts with %PDF- but contains corrupted structure."""
    return b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\ncorrupted trailer invalid"


def make_non_pdf(content: bytes = b"This is a plain text file without PDF magic bytes.\n") -> bytes:
    """Generate non-PDF content."""
    return content


def make_moddate_before_creation_pdf() -> bytes:
    """Generate a PDF where ModDate is earlier than CreationDate."""
    pdf = pikepdf.new()
    pdf.add_blank_page()
    for k in list(pdf.docinfo.keys()):
        del pdf.docinfo[k]

    pdf.docinfo["/Title"] = "Chronologically Inverted PDF"
    pdf.docinfo["/CreationDate"] = "D:20230510120000Z"
    pdf.docinfo["/ModDate"] = "D:20230501120000Z"  # 9 days earlier!

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_future_date_pdf() -> bytes:
    """Generate a PDF with timestamps set far in the future."""
    pdf = pikepdf.new()
    pdf.add_blank_page()
    for k in list(pdf.docinfo.keys()):
        del pdf.docinfo[k]

    pdf.docinfo["/Title"] = "Future Date Document"
    pdf.docinfo["/CreationDate"] = "D:20390101000000Z"
    pdf.docinfo["/ModDate"] = "D:20390101000000Z"

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_info_xmp_mismatch_pdf() -> bytes:
    """Generate a PDF where Info dictionary and XMP disagree on dates, title, and tools."""
    pdf = pikepdf.new()
    pdf.add_blank_page()
    for k in list(pdf.docinfo.keys()):
        del pdf.docinfo[k]

    pdf.docinfo["/Title"] = "Title in Info"
    pdf.docinfo["/Producer"] = "Info Producer Alpha"
    pdf.docinfo["/Creator"] = "Info Creator Alpha"
    pdf.docinfo["/CreationDate"] = "D:20230101120000Z"
    pdf.docinfo["/ModDate"] = "D:20230101120000Z"

    xmp = b"""<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:xmp="http://ns.adobe.com/xap/1.0/"
    xmlns:pdf="http://ns.adobe.com/pdf/1.3/"
    xmlns:dc="http://purl.org/dc/elements/1.1/">
   <xmp:CreateDate>2023-06-01T14:00:00Z</xmp:CreateDate>
   <xmp:ModifyDate>2023-06-02T15:00:00Z</xmp:ModifyDate>
   <xmp:CreatorTool>XMP Tool Beta</xmp:CreatorTool>
   <pdf:Producer>XMP Producer Beta</pdf:Producer>
   <dc:title><rdf:Alt><rdf:li xml:lang="x-default">Different Title in XMP</rdf:li></rdf:Alt></dc:title>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""

    stream = pdf.make_stream(xmp)
    stream["/Type"] = pikepdf.Name("/Metadata")
    stream["/Subtype"] = pikepdf.Name("/XML")
    pdf.Root["/Metadata"] = stream

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_missing_metadata_pdf(remove_info: bool = True, remove_xmp: bool = True) -> bytes:
    """Generate a PDF stripped of Info dictionary and/or XMP metadata."""
    pdf = pikepdf.new()
    pdf.add_blank_page()

    if remove_info:
        for k in list(pdf.docinfo.keys()):
            del pdf.docinfo[k]
        if "/Info" in pdf.trailer:
            del pdf.trailer["/Info"]

    if remove_xmp:
        if "/Metadata" in pdf.Root:
            del pdf.Root["/Metadata"]
    else:
        # Explicitly ensure XMP metadata stream exists
        xmp_xml = b"""<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">
   <dc:title><rdf:Alt><rdf:li xml:lang="x-default">Document With XMP Only</rdf:li></rdf:Alt></dc:title>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""
        stream = pdf.make_stream(xmp_xml)
        stream["/Type"] = pikepdf.Name("/Metadata")
        stream["/Subtype"] = pikepdf.Name("/XML")
        pdf.Root["/Metadata"] = stream

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_malformed_date_pdf() -> bytes:
    """Generate a PDF with malformed date strings in the Info dictionary."""
    pdf = pikepdf.new()
    pdf.add_blank_page()
    for k in list(pdf.docinfo.keys()):
        del pdf.docinfo[k]

    pdf.docinfo["/Title"] = "Malformed Date Test"
    pdf.docinfo["/CreationDate"] = "D:INVALID_NON_NUMERIC_DATE"
    pdf.docinfo["/ModDate"] = "D:20231332999999Z"  # Month 13, Day 32

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_xmp_history_pdf() -> bytes:
    """Generate a PDF with xmpMM:History records documenting edit/convert events."""
    pdf = pikepdf.new()
    pdf.add_blank_page()

    xmp = b"""<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"
    xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#">
   <xmpMM:DocumentID>uuid:orig-doc-1</xmpMM:DocumentID>
   <xmpMM:InstanceID>uuid:revised-inst-2</xmpMM:InstanceID>
   <xmpMM:History>
    <rdf:Seq>
     <rdf:li stEvt:action="created" stEvt:instanceID="uuid:revised-inst-1" stEvt:when="2023-01-01T10:00:00Z" stEvt:softwareAgent="Adobe InDesign"/>
     <rdf:li stEvt:action="converted" stEvt:instanceID="uuid:revised-inst-2" stEvt:when="2023-01-02T12:00:00Z" stEvt:softwareAgent="Adobe Acrobat Pro"/>
    </rdf:Seq>
   </xmpMM:History>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""

    stream = pdf.make_stream(xmp)
    stream["/Type"] = pikepdf.Name("/Metadata")
    stream["/Subtype"] = pikepdf.Name("/XML")
    pdf.Root["/Metadata"] = stream

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_custom_info_keys_pdf() -> bytes:
    """Generate a PDF with non-standard Info dictionary keys."""
    pdf = pikepdf.new()
    pdf.add_blank_page()
    for k in list(pdf.docinfo.keys()):
        del pdf.docinfo[k]

    pdf.docinfo["/Title"] = "Standard Title"
    pdf.docinfo["/PTEX.Fullbanner"] = "This is pdfTeX, Version 3.14159265"
    pdf.docinfo["/GTS_PDFXVersion"] = "PDF/X-1:2001"
    pdf.docinfo["/CustomInternalWorkflowID"] = "WF-99823"

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_identical_timestamps_tool_pdf(tool_name: str = "iLovePDF") -> bytes:
    """Generate a PDF with identical creation and mod timestamps and a known tool producer."""
    pdf = pikepdf.new()
    pdf.add_blank_page()
    for k in list(pdf.docinfo.keys()):
        del pdf.docinfo[k]

    ts = "D:20230501140000Z"
    pdf.docinfo["/Title"] = "Identical Timestamps Document"
    pdf.docinfo["/CreationDate"] = ts
    pdf.docinfo["/ModDate"] = ts
    pdf.docinfo["/Producer"] = tool_name

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_timezone_oddity_pdf() -> bytes:
    """Generate a PDF with mismatched timezone offsets between Info and XMP."""
    pdf = pikepdf.new()
    pdf.add_blank_page()
    for k in list(pdf.docinfo.keys()):
        del pdf.docinfo[k]

    pdf.docinfo["/Title"] = "Timezone Discrepancy Doc"
    pdf.docinfo["/CreationDate"] = "D:20230501140000+02'00'"
    pdf.docinfo["/ModDate"] = "D:20230501140000-05'00'"

    xmp = b"""<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:xmp="http://ns.adobe.com/xap/1.0/">
   <xmp:CreateDate>2023-05-01T14:00:00+08:00</xmp:CreateDate>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""

    stream = pdf.make_stream(xmp)
    stream["/Type"] = pikepdf.Name("/Metadata")
    stream["/Subtype"] = pikepdf.Name("/XML")
    pdf.Root["/Metadata"] = stream

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_valid_image_with_exif(
    date_created: str = "2026:10:22 14:05:47",
    date_modified: str = "2026:10:22 08:38:06",
    software: str = "Adobe Photoshop 2024",
) -> bytes:
    """Generate a JPEG image with valid EXIF timestamps and software tags."""
    img = Image.new("RGB", (120, 80), color="blue")
    exif = img.getexif()
    exif[306] = date_modified
    exif[305] = software
    exif[271] = "Apple"
    exif[272] = "iPhone 15 Pro"

    sub_ifd = exif.get_ifd(0x8769)
    sub_ifd[36867] = date_created
    sub_ifd[36868] = date_created

    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif)
    return buf.getvalue()


def make_corrupted_image() -> bytes:
    """Generate a file with JPEG magic bytes but corrupted payload."""
    return b"\xFF\xD8\xFF\xE0" + b"broken jpeg stream invalid"


def make_normal_pdf(text: str = "Quarterly Business Review") -> bytes:
    """Generate a clean single-revision PDF with no signatures and standard typography."""
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(300, 300))
    font = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Helvetica"),
    }))
    page.Resources = pikepdf.Dictionary({
        "/Font": pikepdf.Dictionary({"/F1": font}),
    })
    page.Contents = pdf.make_stream(f"BT /F1 12 Tf 50 200 Td ({text}) Tj ET".encode("ascii"))
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_incremental_pdf(
    original_text: str = "Initial Balance: $100",
    appended_text: str = "Modified Balance: $900",
) -> bytes:
    """Generate a PDF with a true appended incremental update modifying text."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils import generic

    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(300, 300))
    font = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Helvetica"),
    }))
    page.Resources = pikepdf.Dictionary({
        "/Font": pikepdf.Dictionary({"/F1": font}),
    })
    page.Contents = pdf.make_stream(f"BT /F1 12 Tf 50 200 Td ({original_text}) Tj ET".encode("ascii"))
    buf1 = io.BytesIO()
    pdf.save(buf1)
    buf1.seek(0)

    # Append incremental revision
    w = IncrementalPdfFileWriter(buf1)
    stream = generic.StreamObject(
        stream_data=f"BT /F1 12 Tf 50 150 Td ({appended_text}) Tj ET".encode("ascii")
    )
    stream_ref = w.add_object(stream)
    w.add_stream_to_page(0, stream_ref)
    buf2 = io.BytesIO()
    w.write(buf2)
    return buf2.getvalue()


def _generate_test_cert_and_key() -> tuple[str, str]:
    """Helper to generate a self-signed key and cert PEM for testing signatures."""
    import datetime
    import tempfile
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Signer")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10))
        .sign(key, hashes.SHA256())
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf, tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
        kf.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cf.write(cert.public_bytes(serialization.Encoding.PEM))
        return kf.name, cf.name


def make_signed_pdf_intact(text: str = "Authorized Contract Agreement") -> bytes:
    """Generate a digitally signed PDF with pyHanko where signature covers entire file."""
    import os
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields, signers

    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(300, 300))
    font = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Helvetica"),
    }))
    page.Resources = pikepdf.Dictionary({
        "/Font": pikepdf.Dictionary({"/F1": font}),
    })
    page.Contents = pdf.make_stream(f"BT /F1 12 Tf 50 200 Td ({text}) Tj ET".encode("ascii"))
    buf = io.BytesIO()
    pdf.save(buf)
    buf.seek(0)

    kf_path, cf_path = _generate_test_cert_and_key()
    try:
        signer = signers.SimpleSigner.load(key_file=kf_path, cert_file=cf_path)
        signed_buf = io.BytesIO()
        w = IncrementalPdfFileWriter(buf)
        fields.append_signature_field(w, sig_field_spec=fields.SigFieldSpec(sig_field_name="Sig1"))
        signers.sign_pdf(w, signers.PdfSignatureMetadata(field_name="Sig1"), signer=signer, output=signed_buf)
        return signed_buf.getvalue()
    finally:
        os.unlink(kf_path)
        os.unlink(cf_path)


def make_signed_pdf_with_appended_revision(
    original_text: str = "Approved Grant: $10,000",
    appended_text: str = "Modified Grant: $99,000",
) -> bytes:
    """Generate a signed PDF, then append an incremental update after signing."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils import generic

    signed_bytes = make_signed_pdf_intact(text=original_text)

    # Append revision after signing
    w2 = IncrementalPdfFileWriter(io.BytesIO(signed_bytes))
    stream = generic.StreamObject(
        stream_data=f"BT /F1 12 Tf 50 120 Td ({appended_text}) Tj ET".encode("ascii")
    )
    stream_ref = w2.add_object(stream)
    w2.add_stream_to_page(0, stream_ref)
    out = io.BytesIO()
    w2.write(out)
    return out.getvalue()


def make_resaved_pdf_with_overlap() -> bytes:
    """Generate a single-revision PDF containing conflicting text lines in overlapping bounding boxes."""
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(300, 300))
    font = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Helvetica"),
    }))
    page.Resources = pikepdf.Dictionary({
        "/Font": pikepdf.Dictionary({"/F1": font}),
    })
    # Two distinct strings positioned at (50, 200)
    page.Contents = pdf.make_stream(b"BT /F1 12 Tf 50 200 Td (First Line Total $100) Tj ET\nBT /F1 12 Tf 50 200 Td (Second Conflicting Total $900) Tj ET")
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_resaved_pdf_with_font_anomaly() -> bytes:
    """Generate a single-revision PDF with an isolated word using an anomalous font and size on a line."""
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(400, 300))
    f1 = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Helvetica"),
    }))
    f2 = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Courier"),
    }))
    page.Resources = pikepdf.Dictionary({
        "/Font": pikepdf.Dictionary({"/F1": f1, "/F2": f2}),
    })
    stream_data = b"""BT
/F1 12 Tf 50 200 Td (Invoice) Tj
60 0 Td (total) Tj
50 0 Td (is) Tj
/F2 16 Tf 30 0 Td (90000) Tj
ET"""
    page.Contents = pdf.make_stream(stream_data)
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_resaved_pdf_with_text_over_image() -> bytes:
    """Generate a PDF where sparse digital text is overlaid directly on top of a scanned raster image."""
    img = Image.new("RGB", (100, 100), color="lightgray")
    ibuf = io.BytesIO()
    img.save(ibuf, format="JPEG")

    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(300, 300))
    pike_img = pdf.make_stream(ibuf.getvalue())
    pike_img["/Type"] = pikepdf.Name("/XObject")
    pike_img["/Subtype"] = pikepdf.Name("/Image")
    pike_img["/Width"] = 100
    pike_img["/Height"] = 100
    pike_img["/ColorSpace"] = pikepdf.Name("/DeviceRGB")
    pike_img["/BitsPerComponent"] = 8
    pike_img["/Filter"] = pikepdf.Name("/DCTDecode")

    font = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Helvetica"),
    }))
    page.Resources = pikepdf.Dictionary({
        "/XObject": pikepdf.Dictionary({"/Im1": pike_img}),
        "/Font": pikepdf.Dictionary({"/F1": font}),
    })
    page.Contents = pdf.make_stream(b"""q
250 0 0 250 25 25 cm
/Im1 Do
Q
BT
/F1 14 Tf 80 120 Td (Altered Value) Tj
ET""")
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_legitimate_mixed_font_pdf() -> bytes:
    """Generate a standard multi-font document with legitimate heading and body fonts."""
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(400, 400))
    f_bold = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Helvetica-Bold"),
    }))
    f_body = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Helvetica"),
    }))
    page.Resources = pikepdf.Dictionary({
        "/Font": pikepdf.Dictionary({"/FHeading": f_bold, "/FBody": f_body}),
    })
    # Heading at y=320, body paragraph at y=250
    stream = b"""BT
/FHeading 18 Tf 50 320 Td (Monthly Financial Report) Tj
ET
BT
/FBody 12 Tf 50 250 Td (All figures reported are standard and verified.) Tj
ET"""
    page.Contents = pdf.make_stream(stream)
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_multi_column_newsletter_pdf() -> bytes:
    """Generate a multi-column newsletter PDF with headings, multi-column body, and diverse fonts."""
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(612, 792))
    f_title = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Helvetica-Bold"),
    }))
    f_body = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Times-Roman"),
    }))
    page.Resources = pikepdf.Dictionary({
        "/Font": pikepdf.Dictionary({"/F1": f_title, "/F2": f_body}),
    })
    # Title across top, Column 1 at x=54, Column 2 at x=320
    stream = b"""BT
/F1 20 Tf 54 730 Td (Community Newsletter Q3) Tj
ET
BT
/F2 10 Tf 54 680 Td (Column one reports on community events, parks development,) Tj
0 -14 Td (and neighborhood library programs over the past quarter.) Tj
ET
BT
/F2 10 Tf 320 680 Td (Column two highlights local business partnerships, schools,) Tj
0 -14 Td (and public transportation improvements across the city.) Tj
ET"""
    page.Contents = pdf.make_stream(stream)
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_watermarked_pdf() -> bytes:
    """Generate a legitimate document with a diagonal transparent background watermark."""
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(612, 792))
    f_watermark = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Helvetica-Bold"),
    }))
    f_text = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Helvetica"),
    }))
    page.Resources = pikepdf.Dictionary({
        "/Font": pikepdf.Dictionary({"/FW": f_watermark, "/FT": f_text}),
    })
    # Watermark drawn first, then normal text lines
    stream = b"""q
0.9 0.9 0.9 rg
BT
/FW 54 Tf 150 400 Td (DRAFT) Tj
ET
Q
BT
/FT 12 Tf 72 700 Td (Confidential Internal Project Proposal) Tj
0 -20 Td (This document contains initial concepts for review.) Tj
ET"""
    page.Contents = pdf.make_stream(stream)
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_scanned_document_with_ocr_pdf() -> bytes:
    """Generate a scanned document with an image background and legitimate full-page OCR invisible text (3 Tr)."""
    img = Image.new("RGB", (600, 800), color="white")
    ibuf = io.BytesIO()
    img.save(ibuf, format="JPEG")

    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(612, 792))
    pike_img = pdf.make_stream(ibuf.getvalue())
    pike_img["/Type"] = pikepdf.Name("/XObject")
    pike_img["/Subtype"] = pikepdf.Name("/Image")
    pike_img["/Width"] = 600
    pike_img["/Height"] = 800
    pike_img["/ColorSpace"] = pikepdf.Name("/DeviceRGB")
    pike_img["/BitsPerComponent"] = 8
    pike_img["/Filter"] = pikepdf.Name("/DCTDecode")

    f_ocr = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Helvetica"),
    }))
    page.Resources = pikepdf.Dictionary({
        "/XObject": pikepdf.Dictionary({"/ImScan": pike_img}),
        "/Font": pikepdf.Dictionary({"/FOcr": f_ocr}),
    })
    # Scanned image covering page + full OCR paragraph in 3 Tr
    stream = b"""q
612 0 0 792 0 0 cm
/ImScan Do
Q
BT
/FOcr 11 Tf 3 Tr 54 700 Td (This is searchable OCR text rendered invisibly over the scanned document.) Tj
0 -15 Td (Standard scanners create this structure for searchability without modifying raster pixels.) Tj
ET"""
    page.Contents = pdf.make_stream(stream)
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_dangling_font_manipulated_pdf() -> bytes:
    """Generate a single-revision PDF where text is typed using a dangling /F_Unregistered font."""
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(400, 300))
    f_normal = pdf.make_indirect(pikepdf.Dictionary({
        "/Type": pikepdf.Name("/Font"),
        "/Subtype": pikepdf.Name("/Type1"),
        "/BaseFont": pikepdf.Name("/Helvetica"),
    }))
    page.Resources = pikepdf.Dictionary({
        "/Font": pikepdf.Dictionary({"/F1": f_normal}),
    })
    # Content stream uses /F_Tampered which is absent from /Resources
    stream = b"""BT
/F1 12 Tf 50 200 Td (Original Approved Statement) Tj
ET
BT
/F_Tampered 14 Tf 50 150 Td (Unauthorized Added Paragraph) Tj
ET"""
    page.Contents = pdf.make_stream(stream)
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_orphan_stream_resaved_pdf() -> bytes:
    """Generate a PDF containing an unreferenced orphan stream object in its cross-reference table."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils import generic

    base = make_normal_pdf()
    w = IncrementalPdfFileWriter(io.BytesIO(base))
    s = generic.StreamObject(stream_data=b"BT /F1 12 Tf 50 100 Td (Old Deleted Sensitive Clause) Tj ET")
    s[generic.pdf_name("/Type")] = generic.pdf_name("/XObject")
    s[generic.pdf_name("/Subtype")] = generic.pdf_name("/Form")
    w.add_object(s)
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def make_multi_domain_manipulated_pdf() -> bytes:
    """Generate a PDF exhibiting anomalies across distinct domains: inverted metadata + orphan stream."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils import generic

    base = make_moddate_before_creation_pdf()
    w = IncrementalPdfFileWriter(io.BytesIO(base))
    s = generic.StreamObject(stream_data=b"BT /F1 12 Tf 50 100 Td (Replaced Text Clause) Tj ET")
    s[generic.pdf_name("/Type")] = generic.pdf_name("/XObject")
    s[generic.pdf_name("/Subtype")] = generic.pdf_name("/Form")
    w.add_object(s)
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def make_tampered_signature_bytes_pdf() -> bytes:
    """Generate a signed PDF where bytes inside the signed ByteRange are tampered."""
    signed_bytes = bytearray(make_signed_pdf_intact(text="Initial Legitimate Text $1,000"))
    # Corrupt byte at offset 50 inside the signed byte range to invalidate the cryptographic digest
    signed_bytes[50] ^= 0xFF
    return bytes(signed_bytes)


