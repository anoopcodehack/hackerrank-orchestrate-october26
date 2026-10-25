# HackerRank Orchestrate - October 2026: Ghost Data Still Exists

Automated Deletion Audit Engine that determines whether personal data was completely deleted across distributed microservices, databases, search indexes, backups, and logs, generating deterministic remediation plans and verification suites in compliance with GDPR/CCPA privacy standards.

---

## 1. Executive Summary & Architecture

A deletion workflow may report `Complete` while personal data persists in cold backups, un-anonymized analytics cohorts, un-redacted customer support tickets, active integration data pipelines, or failover database replicas.

The **Deletion Audit Engine** (`code/audit_engine.py` & `code/main.py`) provides an end-to-end audit framework:
1. **Intake Request Classifier**: Distinguishes non-deletion requests (`NOT_APPLICABLE` with `[]` steps) from deletion audits based on NLP semantics and activity logs.
2. **Deterministic Identity Resolution**: Links primary emails, historical aliases, names, phone numbers, and SHA-256 email hashes across `user_identities.csv` and `user_audit_log.csv`.
3. **Temporal Multi-Modal Evidence Ingestion**:
   - **Handover Reports (`.txt`)**: Parses operational handover records for confirmed deletion IDs and missing resource flags.
   - **Service Resource Exports (`.json`)**: Extracts per-service profile dumps, cohorts, message excerpts, and connector states.
   - **Snapshot Bundles (`.json`)**: Audits multi-tenant point-in-time database snapshots across accounts, identity tombstones, and security audit tables.
   - **Database Replicas & Inventory SQL (`.sql`)**: Executes in-memory SQLite instances to verify row presence, deletion flags, and replication drift across primary, read, reporting, and failover replicas.
   - **Distributed Trace Logs (`.log`)**: Evaluates asynchronous lookup events by `trace_id` and filters out intermediate `*_started` events to evaluate definitive `*_completed` states.
   - **Catalog Linkages**: Binds multi-modal attachments (PDFs, images) via `LINK_RESOURCE_IDENTITY` events within relevant evaluation time windows.
4. **Remediation & Verification Planner**:
   - Sequences steps in strict order:
     $$\text{FINDING} \longrightarrow \text{REMEDIATION} \longrightarrow \text{VERIFICATION}$$
   - Orders operations by canonical priority, ascending `system_id`, and ascending `resource_id`.
   - Numbered sequentially (`step_no`: 1, 2, ...).
   - Enforces exact citation rules:
     - `COMPLETE` cases: All verifications cite authoritative evidence files.
     - `INCOMPLETE` cases: Findings cite observed evidence files; remediations and verifications cite `evidence_id = ""`.

---

## 2. Directory Structure

```text
.
├── README.md                           # Solution overview and execution guide
├── output.csv                          # Final 518 evaluation answers (case_33 to case_550)
├── log.txt                             # Turn-by-turn agent development transcript
├── code/
│   ├── audit_engine.py                 # Core DeletionAuditEngine implementation
│   ├── main.py                         # CLI pipeline entrypoint generating output.csv
│   └── evaluation/
│       ├── main.py                     # Evaluation benchmark runner
│       ├── evaluation_report.md        # Detailed accuracy, metrics, and custom test cases
│       └── usage_report.md             # Token usage, latency, and cost analysis
└── dataset/                            # Input requests, evidence files, rules, and identities
```

---

## 3. Quick Start & Execution

### Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Required packages: `pandas`, `pypdf`, `pillow` (all standard or installed via requirements)

```bash
pip install pandas pypdf pillow
```

### Run Full Deletion Audit Pipeline
To evaluate all 518 cases from `dataset/deletion_requests.csv` and write `output.csv` to the repository root:

```bash
python code/main.py
```

### Run Benchmarking & Evaluation Suite
To execute the benchmark against the 32 ground-truth sample cases and regenerate evaluation reports:

```bash
python code/evaluation/main.py
```

---

## 4. Benchmark Performance & Results

- **Sample Status Accuracy**: **32 / 32 (100.0%)**
- **Sample Exact Sequence Accuracy**: **32 / 32 (100.0%)**
- **Step Precision / Recall / F1**: **100.0% / 100.0% / 100.0%**
- **Evaluation Cases Generated**: Exactly **518** rows (`case_33` through `case_550`)
- **Throughput**: **44.8 requests/second** (~22 ms/case)

---

## 5. Submission Deliverables Verification

| Deliverable | Location | Status |
| :--- | :--- | :---: |
| **Output File** | `output.csv` (repo root) | **Verified (518 cases, 519 lines)** |
| **Code Package** | `code.zip` (containing `code/` and `README.md`) | **Ready to package** |
| **Evaluation Report** | `code/evaluation/evaluation_report.md` | **Verified** |
| **Usage Report** | `code/evaluation/usage_report.md` | **Verified** |
| **Agent Transcript** | `log.txt` (repo root) | **Verified (adheres to AGENTS.md)** |
