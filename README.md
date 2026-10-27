# PDF Forensic Manipulation Detection System

An evidence-based PDF forensic analysis service with an interactive web dashboard and REST API that analyzes **a single PDF independently** to answer one primary question:

> **“Does this PDF contain credible evidence that it has been edited or manipulated?”**

The system does NOT require an original or reference PDF. It does not attempt to reconstruct hypothetical altered words; instead, it focuses on verifiable forensic signals across:
1. **Document Validation & Integrity** (SHA-256, magic bytes, parsing limits, encryption detection)
2. **Structural Revision History** (XRef tables/streams, `/Prev` pointer chains, linearization, critical structure replacement)
3. **Digital Signature Forensics** (`/ByteRange` coverage, cryptographic digest validity, DocMDP permissions, post-signature modification)
4. **Content-Stream & Object Forensics** (Unreferenced orphan streams, dangling font references, invisible text `3 Tr`, graphics state stacking)
5. **Metadata Forensic Checks** (Chronological inversions, Info vs. XMP synchronization, editing software signatures, future dates)
6. **Layout & Typographic Anomalies** (Supporting signals: overlapping text, text over raster scans, font anomalies)

---

## Forensic Philosophy & Verdict System

Findings represent objective forensic evidence evaluated by an **Evidence-Based Decision Engine**:
- **Independent Evidence Evaluation**: Correlated indicators are not counted redundantly.
- **Strict Anti-False-Positive Rules**:
  - Weak layout anomalies alone NEVER trigger a manipulation verdict.
  - Metadata anomalies alone NEVER trigger a manipulation verdict.
  - Incremental revisions alone NEVER trigger a manipulation verdict (editors frequently save incrementally).
  - Malformed or password-protected documents are classified as `inconclusive`, not manipulated.
  - Unsigned documents are classified as normal, not manipulated.

### Standardized Verdicts

| Verdict | Meaning | `edit_detected` | Confidence Range |
| :--- | :--- | :---: | :---: |
| `likely_edited` | Credible evidence supports subsequent modification or manipulation (e.g. post-signature modifications, cryptographically broken signatures, critical structure replacement, or multi-domain moderate anomalies). | `true` | `0.75` – `0.95` |
| `suspicious_indicators` | Anomalies exist, but the evidence is insufficient on its own to conclude that the PDF was edited (e.g. isolated layout overlap, single metadata date mismatch). | `null` | `0.15` – `0.65` |
| `no_edit_evidence_found` | Analysis completed and found no meaningful evidence of editing. *This does not prove the document is an untouched original.* | `false` | `0.00` |
| `inconclusive` | Analysis could not produce a reliable conclusion (e.g. password-encrypted, corrupted, or unsupported PDF). | `null` | `0.00` |

---

## API Response Schema

The `/analyze` (and `/api/v1/analyze`) endpoint returns:

```json
{
  "file_name": "contract.pdf",
  "file_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "verdict": "likely_edited",
  "edit_detected": true,
  "confidence": 0.90,
  "summary": "Credible forensic evidence indicates subsequent modification: Document was modified after digital signature 'Sig1' was applied; appended revision exists outside signed byte range. These findings are not proof of tampering.",
  "analysis_status": "completed",
  "checks": {
    "metadata": "completed",
    "revision_history": "completed",
    "digital_signatures": "completed",
    "content_streams": "completed",
    "layout_analysis": "completed"
  },
  "findings": [
    {
      "code": "SIG_POST_SIGNING_MODIFICATION",
      "category": "confirmed",
      "domain": "digital_signatures",
      "severity": "high",
      "confidence": 0.92,
      "description": "Document was modified after digital signature 'Sig1' was applied; appended revision exists outside signed byte range",
      "evidence": {
        "field_name": "Sig1",
        "signed_end_offset": 8412,
        "file_length": 9120,
        "appended_bytes_count": 708
      },
      "limitations": [
        "Authorized form filling or incremental countersigning can also append bytes; check document certification permissions."
      ]
    }
  ],
  "limitations": [
    "Analysis evaluates structural, cryptographic, metadata, and content-stream indicators on a single PDF without a reference copy.",
    "Absence of detected anomalies does not certify document authenticity; a clean resave can discard historical revision traces.",
    "Confidence scores reflect heuristic calibration across observed forensic signals, not statistical probability or legal certification."
  ]
}
```

*Note: Legacy response attributes (`file`, `metadata`, `test_cases`, `summary.classification`) are fully preserved for backward compatibility.*

---

## Project Architecture

```text
PDF-analyser/
├── app/
│   ├── main.py                                      # FastAPI app entrypoint, UI route, root /analyze
│   ├── api/
│   │   └── routes/
│   │       └── analyze.py                           # Modular APIRouter mounted at /api/v1/analyze
│   ├── schemas/
│   │   ├── __init__.py
│   │   └── analysis.py                              # ForensicFinding, ForensicVerdict, UnifiedAnalysisResponse
│   ├── services/
│   │   └── pdf_analysis/
│   │       ├── __init__.py
│   │       ├── pdf_loader.py                        # Safe loading, size/page limits, SHA-256, encryption check
│   │       ├── shared_utils.py                      # Geometric helpers, PyMuPDF layout & font span extraction
│   │       ├── revision_forensics.py                # XRef tables/streams, /Prev chains, structure replacements
│   │       ├── signature_forensics.py               # pyHanko signature validation, /ByteRange coverage, DocMDP
│   │       ├── structural_forensics.py              # Orphan streams, dangling fonts, 3 Tr invisible text, q/Q state
│   │       ├── layout_analysis.py                   # Supporting text overlap and font inconsistency signals
│   │       ├── decision_engine.py                   # Evidence synthesis, independence rules, verdict & confidence
│   │       ├── orchestrator.py                      # Multi-module pipeline with isolated failure handling
│   │       ├── result_builder.py                    # Schema consolidation & backward compatibility
│   │       ├── test_case_1_incremental_revisions.py # Legacy adapter for TC1
│   │       ├── test_case_2_digital_signatures.py    # Legacy adapter for TC2
│   │       └── test_case_3_resaved_pdf.py           # Legacy adapter for TC3
│   ├── validation.py                                # Streaming upload validation, magic byte checks
│   ├── metadata.py                                  # Info & XMP extraction, chronological & tool checks
│   ├── models.py                                    # Backward-compatible schemas for existing consumers
│   └── templates/
│       └── index.html                               # Interactive web dashboard with verdict badge & findings
├── scripts/
│   └── evaluate_corpus.py                           # Honest evaluation script reporting precision, recall, F1
├── tests/
│   ├── fixtures/
│   │   └── pdf_generators.py                        # Synthetic generators for legitimate & manipulated PDFs
│   ├── test_analyze_api.py                          # Integration tests for /analyze and /api/v1/analyze
│   ├── test_digital_signatures.py                   # Digital signature unit tests
│   ├── test_forensic_decision_engine.py             # Decision engine & structural forensics test suite
│   ├── test_incremental_revisions.py                # Incremental revision unit tests
│   ├── test_metadata.py                             # Metadata forensics unit tests
│   ├── test_resaved_pdf.py                          # Re-saved layout unit tests
│   └── test_validation.py                           # File loading & rejection tests
├── requirements.txt
└── README.md
```

---

## Evaluation & Measured Accuracy

The system includes an evaluation tool (`scripts/evaluate_corpus.py`) that benchmarks performance on a labeled corpus of untouched and manipulated documents:

```bash
python scripts/evaluate_corpus.py
```

### Measured Performance Summary

- **Precision**: 100.00% (No legitimate documents falsely accused)
- **False Positives (FP)**: 0 (Prioritized 100% specificity on untouched documents)
- **Specificity**: 100.00%
- **Recall (Sensitivity)**: 50.00% under strict binary `likely_edited` (Subtle single-anomaly edits are safely categorized as `suspicious_indicators` rather than false positives)
- **F1 Score**: 66.67%
- **Overall Accuracy**: 73.68% under strict binary evaluation; 100% anomaly detection across manipulated samples.

### Methodological Limitations
1. **Zero False Positives Priority**: The system strictly avoids false accusations on legitimate newsletters, complex multi-column layouts, watermarks, scanned OCR documents, and intact signatures.
2. **Conservative Sensitivity Tradeoff**: Subtle single-signal anomalies (such as an isolated date mismatch) yield `suspicious_indicators` (`edit_detected=null`) rather than forcing a binary `likely_edited`.
3. **99% Reliability Disclaimer**: While high accuracy is achieved on controlled test fixtures, claiming 99% real-world accuracy without a massive (10,000+ files) multi-vendor wild corpus would be scientifically unverified. Real-world PDFs present edge cases from hundreds of legacy print drivers and scanning appliances.

---

## Running the Application

### 1. Run the Test Suite
```bash
python -m pytest
```

### 2. Start the Development Server
```bash
uvicorn app.main:app --reload --port 8000
```
Open `http://localhost:8000` in your browser to access the interactive forensic dashboard.
