"""Test Case 2: Digital Signature and Post-Signature Changes.

Validates digital signatures, checks byte range coverage, and inspects post-signature modifications.
"""

from __future__ import annotations

import io
import logging
import pikepdf
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature

from app.schemas.analysis import (
    ChangeLocation,
    PostSignatureChange,
    SignatureValidationResult,
    TestCase2SignatureResult,
)
from app.services.pdf_analysis.pdf_loader import LoadedPdf
from app.services.pdf_analysis.shared_utils import compare_revisions_content, extract_pdf_layout

logger = logging.getLogger("pdf_analyser.test_case_2")


def analyze_digital_signatures(loaded_pdf: LoadedPdf) -> TestCase2SignatureResult:
    """Inspect and validate digital signatures and identify post-signature changes.

    Args:
        loaded_pdf: The loaded PDF with preserved bytes.

    Returns:
        TestCase2SignatureResult containing signature validation results and post-signing diffs.
    """
    pdf_bytes = loaded_pdf.file_bytes
    file_len = len(pdf_bytes)

    if not loaded_pdf.is_valid or file_len == 0:
        return TestCase2SignatureResult(
            status="inconclusive",
            signatures_found=0,
            signature_results=[],
            limitations=[loaded_pdf.error_message or "PDF is invalid or unreadable."],
        )

    # Open reader to discover signatures
    try:
        reader = PdfFileReader(io.BytesIO(pdf_bytes))
        embedded_sigs = reader.embedded_signatures
    except Exception as e:
        logger.warning("Error reading PDF signatures with pyHanko: %s", e)
        return TestCase2SignatureResult(
            status="inconclusive",
            signatures_found=0,
            signature_results=[],
            limitations=[f"Failed to inspect digital signatures: {e}"],
        )

    # Unsigned document
    if not embedded_sigs:
        return TestCase2SignatureResult(
            status="no_signatures_found",
            signatures_found=0,
            signature_results=[],
            limitations=["Document is unsigned; no digital signatures found."],
        )

    sig_results: list[SignatureValidationResult] = []
    has_post_sig_changes = False
    has_invalid_sig = False

    for sig in embedded_sigs:
        field_name = str(sig.field_name or "Signature")
        sig_limits: list[str] = [
            "Certificate trust was not evaluated against a local/OS root certificate store.",
            "Online revocation checking (CRL/OCSP) was not evaluated.",
        ]

        # 1. ByteRange evaluation
        covers_current_file = False
        later_revision_evidence = False
        signed_end_offset = file_len

        try:
            sig_obj = sig.sig_object
            if "/ByteRange" in sig_obj:
                br = [int(x) for x in sig_obj["/ByteRange"]]
                if len(br) == 4:
                    signed_end_offset = br[2] + br[3]
                    if signed_end_offset < file_len:
                        covers_current_file = False
                        later_revision_evidence = True
                    else:
                        covers_current_file = True
                        later_revision_evidence = False
        except Exception as br_err:
            sig_limits.append(f"Error parsing /ByteRange dictionary: {br_err}")

        # Check total revisions vs signed revision in reader (0-indexed)
        try:
            if hasattr(sig, "signed_revision") and sig.signed_revision is not None:
                if sig.signed_revision < (reader.total_revisions - 1):
                    later_revision_evidence = True
                    covers_current_file = False
        except Exception:
            pass

        # 2. Cryptographic validation using pyHanko
        crypto_status = "unknown"
        try:
            val_status = validate_pdf_signature(sig)
            if val_status.intact:
                crypto_status = "valid"
            else:
                crypto_status = "invalid"
                has_invalid_sig = True
        except Exception as val_err:
            logger.warning("Cryptographic validation error for %s: %s", field_name, val_err)
            sig_limits.append(f"Cryptographic validation encountered an error: {val_err}")
            crypto_status = "unknown"

        # 3. Detect changes made after the signed revision
        post_changes: list[PostSignatureChange] = []
        if later_revision_evidence and signed_end_offset < file_len:
            try:
                signed_slice = pdf_bytes[:signed_end_offset]
                # Validate signed slice
                with pikepdf.Pdf.open(io.BytesIO(signed_slice)) as _:
                    pass
                signed_layout = extract_pdf_layout(signed_slice)
                current_layout = extract_pdf_layout(pdf_bytes)

                diffs = compare_revisions_content(signed_layout, current_layout)
                for d in diffs:
                    post_changes.append(
                        PostSignatureChange(
                            type=d.type,
                            page=d.page,
                            old_text=d.old_text,
                            new_text=d.new_text,
                            location=d.location,
                        )
                    )
            except Exception as diff_err:
                logger.warning("Error computing post-signature differences: %s", diff_err)
                sig_limits.append(f"Could not extract signed revision for layout diff: {diff_err}")

            if post_changes or later_revision_evidence:
                has_post_sig_changes = True

        sig_results.append(
            SignatureValidationResult(
                field_name=field_name,
                cryptographic_integrity=crypto_status,
                certificate_trust="not_evaluated",
                covers_current_file=covers_current_file,
                later_revision_evidence=later_revision_evidence,
                post_signature_changes=post_changes,
                limitations=sig_limits,
            )
        )

    # Determine overall status
    if has_post_sig_changes:
        status = "post_signature_changes_detected"
    elif has_invalid_sig:
        status = "signature_invalid"
    else:
        status = "signed_intact_no_later_changes"

    return TestCase2SignatureResult(
        status=status,
        signatures_found=len(sig_results),
        signature_results=sig_results,
        limitations=[],
    )
