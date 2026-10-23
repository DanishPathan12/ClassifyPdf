# PDF & Document Forensic Edit Detection Service

A Python-based PDF and Document forensic analysis service with an interactive web dashboard and API that accepts **one PDF file** and determines whether there is reliable evidence of editing.

The system supports 3 specialized edit detection test cases alongside metadata forensics:

1. **Test Case 1 — PDF with Incremental Revisions:** Detects and recovers changes by analyzing previous revisions stored inside the same PDF.
2. **Test Case 2 — Digitally Signed PDF Modified After Signing:** Validates digital signatures with pyHanko, verifies `/ByteRange` coverage, and identifies changes made after the signed revision.
3. **Test Case 3 — Fully Re-saved PDF Without Revision History:** Analyzes PDF content and layout for suspicious changes when the previous version cannot be recovered.

---

## Forensic Philosophy

- **Flags, not verdicts**: Findings record objective inconsistencies and anomalies, never declarative statements of authenticity or forgery.
- **Evidence-Backed Claims**: The system never falsely claims that it can recover exact original content from every PDF. Exact changes are only reported when a trustworthy earlier revision state can be reconstructed or a cryptographic signature provides verifiable signed bytes.
- **Explicit Classifications**:
  - `confirmed_changes`: A reliable historical comparison or signed revision establishes specific changes.
  - `suspicious_indicators`: Anomalies exist (metadata flags, layout overlaps, font anomalies), but the evidence does not prove editing.
  - `no_edit_evidence_found`: No evidence was found by the implemented checks. This does not prove the PDF was never edited.
  - `inconclusive`: Analysis could not reliably determine whether relevant changes occurred (e.g. malformed or unparseable structures).
- **Document Context Awareness**: Evaluates modification timestamps contextually:
  - *Standard working documents* (resumes, drafts, reports): normal expected lifecycle (`severity: info`).
  - *Official records* (bank receipts, invoices, government IDs): flagged as suspicious (`severity: high` / `medium`) if modified after generation.
- **Human-Readable Standardized Timestamps**: Dates are normalized to clean strings (`"Thursday, October 22, 2026 at 02:05:47 PM UTC"`).

---

## Architecture & Project Structure

```text
PDF-analyser/
├── app/
│   ├── main.py                          # FastAPI app entrypoint, UI route, root /analyze
│   ├── api/
│   │   └── routes/
│   │       └── analyze.py               # Modular APIRouter mounted at /api/v1/analyze
│   ├── schemas/
│   │   ├── __init__.py
│   │   └── analysis.py                  # Pydantic v2 schemas for TC1, TC2, TC3 and UnifiedResponse
│   ├── services/
│   │   └── pdf_analysis/
│   │       ├── __init__.py
│   │       ├── pdf_loader.py            # Validates upload, preserves bytes, SHA-256
│   │       ├── shared_utils.py          # Pure-Python & PyMuPDF layout, geometry, text diffing
│   │       ├── test_case_1_incremental_revisions.py  # Revision chain & historical state recovery
│   │       ├── test_case_2_digital_signatures.py     # pyHanko signature validation & post-sig diffs
│   │       ├── test_case_3_resaved_pdf.py            # Text overlaps, font anomalies, image overlays
│   │       ├── orchestrator.py          # Runs all 3 test cases with isolated failure safety
│   │       └── result_builder.py        # Consolidates results into evidence-based unified response
│   ├── validation.py                    # Chunked upload streaming, 20 MB limit, magic bytes
│   ├── metadata.py                      # Info & XMP metadata extraction, 12 forensic checks
│   ├── models.py                        # Backward-compatible schemas for existing consumers
│   └── templates/
│       └── index.html                   # Web dashboard with drag-and-drop & live results
├── tests/
│   ├── fixtures/
│   │   └── pdf_generators.py            # Synthetic generators for signed, incremental, and flat PDFs
│   ├── test_incremental_revisions.py    # Test Case 1 unit tests
│   ├── test_digital_signatures.py       # Test Case 2 unit tests
│   ├── test_resaved_pdf.py              # Test Case 3 unit tests
│   ├── test_analyze_api.py              # API endpoint integration tests
│   ├── test_validation.py               # File validation & rejection tests
│   └── test_metadata.py                 # Metadata forensic checks tests
├── requirements.txt
└── README.md
```

---

## The 3 Edit Detection Test Cases

### Test Case 1: Incremental Revision Analysis
- **Core Mechanism**: Follows ISO 32000-1 §7.5.6 cross-reference and trailer `/Prev` pointer chains. Identifies total revisions and structural `%%EOF` offsets.
- **Historical Reconstruction**: Slices the exact byte sequences corresponding to historical revisions and validates each state with `pikepdf`.
- **Text & Layout Comparison**: Compares consecutive revision states to extract added text, removed text, changed text, and page additions/removals with bounding boxes (`[x0, y0, x1, y1]`).
- **Safety Guarantee**: If revision reconstruction is unreliable, reports `inconclusive` rather than guessing changes.

### Test Case 2: Digital Signatures & Post-Signature Changes
- **Core Mechanism**: Discovers embedded signature dictionaries (`/Type /Sig`) and inspects `/ByteRange [offset1, len1, offset2, len2]`.
- **Cryptographic Validation**: Uses `pyHanko` to verify cryptographic integrity (`valid`, `invalid`, `unknown`).
- **Byte Range Coverage**: Verifies whether `offset2 + len2 == total_file_bytes`. If bytes or revisions exist after the signed range, marks `covers_current_file: false` and `later_revision_evidence: true`.
- **Post-Signature Diffing**: Extracts the signed revision bytes up to the signed end offset and compares layout and text against the latest document to detail exact post-signature changes.
- **Trust Evaluation**: Reports `certificate_trust: not_evaluated` and explicitly records the lack of configured root trust stores or online OCSP/CRL checking as limitations.
- **Neutrality**: Documents without signatures are reported as `no_signatures_found` and never classified as tampered.

### Test Case 3: Fully Re-saved PDF Without Revision History
- **Core Mechanism**: When earlier revisions are unavailable (flattened or newly saved PDF), analyzes typography and geometry:
  1. `unusual_text_overlap`: Detects distinct text lines with significant bounding box overlap (> 35%).
  2. `text_over_image`: Detects sparse digital vector text positioned directly over large raster images (scanned documents or receipts).
  3. `inconsistent_font_anomaly`: Uses baseline clustering to detect isolated words in a uniform line with a differing font family or size (> 2.5pt difference).
- **Legitimate Formatting Protection**: Multi-line headings and body paragraphs are grouped separately to prevent false positives on normal styled documents.
- **Confidence Levels**: Assigned as `low` or `medium` with the disclaimer: *"Potential anomaly; not proof of editing"*.

---

## Why a Single Fully Re-saved PDF Cannot Reveal Its Exact Original Content

In the PDF specification, saving a document with a full rewrite or linearization discards superseded object streams and obsolete cross-reference tables. Once a document is fully re-saved:
1. The previous bytes, fonts, and text strings physically do not exist in the file.
2. Without an independent external baseline or an embedded digital signature, any attempt to state the "original" text would be purely speculative.
3. Therefore, the system responsibly reports layout anomalies and suspicious indicators with confidence ratings, explicitly stating:
   > *"No recoverable earlier revision was available. Exact original content cannot be established from this PDF alone."*

---

## Installation & Setup

1. Clone or navigate to the project directory:
   ```bash
   cd c:\Users\Danish\Desktop\PDF-analyser
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```

3. Install pinned dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Running the Service & Dashboard

Start the server with Uvicorn:

```bash
uvicorn app.main:app --reload
```

- **Interactive Web UI**: `http://127.0.0.1:8000/`
- **Health Check**: `http://127.0.0.1:8000/health`
- **Analysis Endpoint (Root)**: `POST http://127.0.0.1:8000/analyze`
- **Analysis Endpoint (API v1)**: `POST http://127.0.0.1:8000/api/v1/analyze`

---

## API Usage Examples

### 1. Analyze an Incremental PDF

```bash
curl -X POST -F "file=@incremental_contract.pdf" http://localhost:8000/analyze
```

### 2. Analyze an Official Bank Receipt

```bash
curl -X POST -F "file=@receipt.pdf" -F "doc_type=official" http://localhost:8000/analyze
```

### 3. Analyze an Image (JPEG, PNG, WebP)

```bash
curl -X POST -F "file=@scanned_invoice.jpg" http://localhost:8000/analyze
```

---

## Example Unified JSON Response

```json
{
  "file": {
    "name": "contract.pdf",
    "size_bytes": 104520,
    "sha256": "4b9e28f7d9a1023c...",
    "pdf_version": "1.7",
    "page_count": 2
  },
  "metadata": {
    "info": {
      "CreationDate": "D:20261022140547+00'00'",
      "ModDate": "D:20261022143000+00'00'",
      "Producer": "ReportEngine v2.0"
    },
    "xmp": {},
    "dates": {
      "creation_date": "Thursday, October 22, 2026 at 02:05:47 PM UTC",
      "modification_date": "Thursday, October 22, 2026 at 02:30:00 PM UTC"
    }
  },
  "findings": [],
  "test_cases": {
    "incremental_revisions": {
      "test_case": "incremental_revisions",
      "status": "changes_detected",
      "revision_count": 2,
      "previous_revision_recovered": true,
      "changes": [
        {
          "type": "text_changed",
          "page": 1,
          "old_text": "Approved Total: $10,000",
          "new_text": "Modified Total: $99,000",
          "location": {
            "bbox": [50.0, 197.52, 140.24, 209.52]
          },
          "evidence": "Line replaced in corresponding bounding box between revisions"
        }
      ],
      "limitations": []
    },
    "digital_signatures": {
      "test_case": "digital_signatures",
      "status": "post_signature_changes_detected",
      "signatures_found": 1,
      "signature_results": [
        {
          "field_name": "Sig1",
          "cryptographic_integrity": "valid",
          "certificate_trust": "not_evaluated",
          "covers_current_file": false,
          "later_revision_evidence": true,
          "post_signature_changes": [
            {
              "type": "text_added",
              "page": 1,
              "old_text": null,
              "new_text": "Modified Total: $99,000",
              "location": {
                "bbox": [50.0, 197.52, 140.24, 209.52]
              }
            }
          ],
          "limitations": [
            "Certificate trust was not evaluated against a local/OS root certificate store.",
            "Online revocation checking (CRL/OCSP) was not evaluated."
          ]
        }
      ],
      "limitations": []
    },
    "resaved_pdf_analysis": {
      "test_case": "resaved_pdf_analysis",
      "status": "no_anomalies_detected",
      "historical_comparison_available": true,
      "findings": [],
      "limitations": [
        "Historical revision recovered; layout scan provides complementary visual anomaly checks.",
        "Exact original content cannot be established from this PDF alone."
      ]
    }
  },
  "summary": {
    "classification": "confirmed_changes",
    "confirmed_changes": 2,
    "suspicious_indicators": 0,
    "confirmed": 2,
    "suspicious": 0,
    "inconclusive": 0,
    "overall": "2 confirmed modification indicator(s) found; these are not proof of tampering.",
    "limitations": [
      "Certificate trust was not evaluated against a local/OS root certificate store."
    ]
  }
}
```

---

## Known Limitations & False-Positive Considerations

1. **Self-Signed Certificates / Untrusted CA Chains**: Without an enterprise PKI trust store configured, signatures evaluate cryptographic integrity directly; certificate trust is marked `not_evaluated`.
2. **Linearized PDFs**: Fast Web View (linearization) reorganizes streams and does not preserve recoverable incremental revisions.
3. **Intentional Typographical Emphasis**: Legitimate documents may use a different font for brand names or symbols; Test Case 3 assigns `low` confidence to isolated font differences and notes they are potential anomalies rather than proof of tampering.
4. **Scanned Images**: Text detected over a scanned image might be an intentional digital OCR layer added by modern scanning software.

---

## Running the Automated Test Suite

Run all 61 automated unit and integration tests:

```bash
pytest -v
```

Run test suite with statement coverage report:

```bash
pytest --cov=app --cov-report=term-missing
```
