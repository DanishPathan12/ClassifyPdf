"""Digital Signature Forensics: Analyzes signature coverage, cryptographic integrity, and post-signing alterations."""

from __future__ import annotations

from dataclasses import dataclass, field
import io
import logging
from typing import Any
import pikepdf
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis.policy_api import SuspiciousModification
from pyhanko.sign.validation import validate_pdf_signature

from app.schemas.analysis import (
    ForensicFinding,
    PostSignatureChange,
    SignatureValidationResult,
    TestCase2SignatureResult,
)
from app.services.pdf_analysis.pdf_loader import LoadedPdf
from app.services.pdf_analysis.shared_utils import compare_revisions_content, extract_pdf_layout

logger = logging.getLogger("pdf_analyser.signature_forensics")


@dataclass
class SignatureForensicsResult:
    """Forensic evaluation outcome for all embedded digital signatures in a PDF."""

    module_status: str  # completed | partial | failed | inconclusive
    signatures_found: int
    has_signatures: bool
    has_post_signature_changes: bool
    has_invalid_signatures: bool
    signature_results: list[SignatureValidationResult] = field(default_factory=list)
    findings: list[ForensicFinding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    legacy_status: str = "no_signatures_found"


def analyze_digital_signatures_forensics(loaded_pdf: LoadedPdf) -> SignatureForensicsResult:
    """Inspect and validate digital signatures with failure isolation and strict permission checks.

    Args:
        loaded_pdf: Safely loaded PDF with preserved bytes.

    Returns:
        SignatureForensicsResult containing forensic findings, limitations, and validation records.
    """
    pdf_bytes = loaded_pdf.file_bytes
    file_len = len(pdf_bytes)

    limitations: list[str] = [
        "Absence of digital signatures is normal for standard documents and does not imply editing.",
        "Certificate trust validation against an OS or commercial trust anchor was not conducted.",
        "Online revocation checking (OCSP / CRL) was not queried in this offline inspection.",
    ]

    if not loaded_pdf.is_valid or file_len == 0:
        return SignatureForensicsResult(
            module_status="inconclusive",
            signatures_found=0,
            has_signatures=False,
            has_post_signature_changes=False,
            has_invalid_signatures=False,
            signature_results=[],
            findings=[],
            limitations=[loaded_pdf.error_message or "PDF is invalid or unreadable."],
            legacy_status="inconclusive",
        )

    # 1. Discover embedded signatures via pyHanko
    try:
        reader = PdfFileReader(io.BytesIO(pdf_bytes))
        embedded_sigs = reader.embedded_signatures
    except Exception as parse_err:
        logger.warning("Error reading PDF signatures with pyHanko: %s", parse_err)
        return SignatureForensicsResult(
            module_status="failed",
            signatures_found=0,
            has_signatures=False,
            has_post_signature_changes=False,
            has_invalid_signatures=False,
            signature_results=[],
            findings=[
                ForensicFinding(
                    code="SIG_PARSING_FAILED",
                    category="digital_signatures",
                    severity="low",
                    confidence=0.10,
                    description=f"Signature catalog parsing encountered an error: {parse_err}",
                    evidence={"error": str(parse_err)},
                    limitations=["Corrupted or non-standard signature dict format."],
                )
            ],
            limitations=[f"Failed to inspect digital signatures: {parse_err}"] + limitations,
            legacy_status="inconclusive",
        )

    # 2. Unsigned document check
    if not embedded_sigs:
        unsigned_limits = ["Document is unsigned; no digital signatures found."] + limitations
        findings = [
            ForensicFinding(
                code="SIG_DOCUMENT_UNSIGNED",
                category="digital_signatures",
                severity="info",
                confidence=0.0,
                description="Document contains no embedded digital signatures; standard for ordinary PDFs",
                evidence={"signatures_found": 0},
                limitations=["Most legitimate PDFs are unsigned; absence of signature is not evidence of tampering."],
            )
        ]
        return SignatureForensicsResult(
            module_status="completed",
            signatures_found=0,
            has_signatures=False,
            has_post_signature_changes=False,
            has_invalid_signatures=False,
            signature_results=[],
            findings=findings,
            limitations=unsigned_limits,
            legacy_status="no_signatures_found",
        )

    # 3. Analyze each signature
    findings: list[ForensicFinding] = []
    sig_results: list[SignatureValidationResult] = []
    has_post_sig_changes = False
    has_invalid_sig = False

    for sig in embedded_sigs:
        field_name = str(sig.field_name or "Signature")
        sig_limits: list[str] = [
            "Certificate trust was not evaluated against a local/OS root certificate store.",
            "Online revocation checking (CRL/OCSP) was not evaluated.",
        ]

        # ByteRange & file coverage evaluation
        covers_current_file = False
        later_revision_evidence = False
        signed_end_offset = file_len
        byte_range_list: list[int] = []

        try:
            sig_obj = sig.sig_object
            if "/ByteRange" in sig_obj:
                br = [int(x) for x in sig_obj["/ByteRange"]]
                byte_range_list = br
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

        # Check signed revision index vs total revisions
        try:
            if hasattr(sig, "signed_revision") and sig.signed_revision is not None:
                if sig.signed_revision < (reader.total_revisions - 1):
                    later_revision_evidence = True
                    covers_current_file = False
        except Exception:
            pass

        # Check DocMDP permission level if present (certification signatures)
        doc_mdp_perm: int | None = None
        try:
            sig_obj = sig.sig_object
            if "/Reference" in sig_obj:
                refs = sig_obj["/Reference"]
                for ref_item in refs:
                    if "/TransformParams" in ref_item and "/P" in ref_item["/TransformParams"]:
                        doc_mdp_perm = int(ref_item["/TransformParams"]["/P"])
        except Exception:
            pass

        # Cryptographic verification via pyHanko
        crypto_status = "unknown"
        diff_violation_message: str | None = None

        try:
            val_status = validate_pdf_signature(sig)
            if val_status.intact:
                crypto_status = "valid"
            else:
                crypto_status = "invalid"
                has_invalid_sig = True

            diff_res = getattr(val_status, "diff_result", None)
            if diff_res is not None:
                diff_violation_message = str(diff_res)
        except SuspiciousModification as sm:
            crypto_status = "valid"
            diff_violation_message = str(sm)
            has_post_sig_changes = True
        except Exception as val_err:
            logger.warning("Cryptographic validation error for %s: %s", field_name, val_err)
            sig_limits.append(f"Cryptographic validation error: {val_err}")
            crypto_status = "unknown"

        # Detect changes made after signed revision
        post_changes: list[PostSignatureChange] = []
        if later_revision_evidence and signed_end_offset < file_len:
            try:
                signed_slice = pdf_bytes[:signed_end_offset]
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
                logger.debug("Error computing post-signature differences: %s", diff_err)
                sig_limits.append(f"Could not extract signed revision layout: {diff_err}")

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

        # Generate Evidence-Based Findings
        if crypto_status == "invalid":
            findings.append(
                ForensicFinding(
                    code="SIG_CRYPTO_DIGEST_INVALID",
                    category="digital_signatures",
                    severity="high",
                    confidence=0.90,
                    description=f"Digital signature '{field_name}' cryptographic digest failed validation; byte contents within signed range do not match signature hash",
                    evidence={
                        "field_name": field_name,
                        "byte_range": byte_range_list,
                        "crypto_status": crypto_status,
                    },
                    limitations=["Bit-rot or partial transmission corruption can invalidate cryptographic digests."],
                )
            )

        if later_revision_evidence:
            evidence_dict: dict[str, Any] = {
                "field_name": field_name,
                "signed_end_offset": signed_end_offset,
                "file_length": file_len,
                "appended_bytes_count": file_len - signed_end_offset,
                "post_signature_changes_count": len(post_changes),
            }
            if diff_violation_message:
                evidence_dict["diff_violation"] = diff_violation_message
            if doc_mdp_perm is not None:
                evidence_dict["doc_mdp_p"] = doc_mdp_perm

            # If certification signature permitted no changes (P=1) or page text was modified
            is_unauthorized = bool(
                post_changes
                or diff_violation_message
                or (doc_mdp_perm == 1)
            )

            if is_unauthorized:
                findings.append(
                    ForensicFinding(
                        code="SIG_POST_SIGNING_MODIFICATION",
                        category="digital_signatures",
                        severity="high",
                        confidence=0.92,
                        description=f"Document was modified after digital signature '{field_name}' was applied; appended revision exists outside signed byte range",
                        evidence=evidence_dict,
                        limitations=[
                            "Authorized form filling or incremental countersigning can also append bytes; "
                            "check document certification permissions.",
                        ],
                    )
                )
            else:
                findings.append(
                    ForensicFinding(
                        code="SIG_POST_SIGNING_PERMITTED_APPEND",
                        category="digital_signatures",
                        severity="low",
                        confidence=0.30,
                        description=f"Signature '{field_name}' does not cover EOF, but modifications appear confined to permitted incremental changes",
                        evidence=evidence_dict,
                        limitations=["Appended bytes exist after the signed revision."],
                    )
                )
        elif crypto_status == "valid":
            findings.append(
                ForensicFinding(
                    code="SIG_INTACT_CRYPTOGRAPHICALLY_VALID",
                    category="digital_signatures",
                    severity="info",
                    confidence=0.05,
                    description=f"Digital signature '{field_name}' is cryptographically intact and covers the entire document to EOF",
                    evidence={
                        "field_name": field_name,
                        "covers_current_file": True,
                        "byte_range": byte_range_list,
                    },
                    limitations=[
                        "Cryptographic validity proves bytes are unchanged since signing; "
                        "certificate trust was not evaluated against public PKI anchors.",
                    ],
                )
            )

    # Legacy status mapping
    if has_post_sig_changes:
        legacy_status = "post_signature_changes_detected"
    elif has_invalid_sig:
        legacy_status = "signature_invalid"
    else:
        legacy_status = "signed_intact_no_later_changes"

    return SignatureForensicsResult(
        module_status="completed",
        signatures_found=len(sig_results),
        has_signatures=True,
        has_post_signature_changes=has_post_sig_changes,
        has_invalid_signatures=has_invalid_sig,
        signature_results=sig_results,
        findings=findings,
        limitations=limitations,
        legacy_status=legacy_status,
    )
