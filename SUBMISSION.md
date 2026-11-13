# Submission

## Candidate
- **Name:** Not provided in this workspace
- **Assignment chosen:** A (Data)
- **Time spent:** Not independently tracked; implementation and verification were completed in this coding session.

## How to run
See [solution/README.md](solution/README.md) for exact Windows PowerShell setup and run commands. Python 3.11+ is required. The database and generated input/output directories are ignored by git.

## Design
The pipeline uses SQLite for durable lead, event, file-manifest, rejection, and quality-counter state. Leads are uniquely identified by workflow plus HMAC-SHA-256 of the canonical phone. The phone and customer name are encrypted using AES-256-GCM before storage; event files keep a phone digest instead of raw phone data. Event IDs have a database uniqueness constraint. Orphan events remain quarantined and are reconsidered whenever leads or events arrive.

Each source file is handled transactionally and recorded by absolute path and SHA-256 digest. An identical replay is a no-op. Changes to an already ingested file are rejected to avoid silently corrupting incremental state. Lead field merges preserve the original batch and replace only non-null values. Reports derive call facts from linked events and write deterministic, sorted CSVs plus data quality JSON.

```text
leads ──> validate ──> encrypted/merged rows ───┐
                                                ├──> IST call facts ──> contract reports
events ──> deduplicate ──> link or quarantine ──┘
```

## Decisions & assumptions

| Decision | Why | Alternative considered |
|---|---|---|
| SQLite WAL with file-level transactions | Simple deployment with durable incremental state and safe retry after a process interruption | PostgreSQL adds operational overhead for this single-process assignment |
| AES-GCM random nonce per PII value and a separate keyed phone HMAC | Encrypts PII while allowing deterministic identity and event matching | Plain SHA phone hashes are vulnerable to phone-number enumeration |
| Stable per-file absolute path and content digest manifest | Same path and bytes replay safely; modifying an ingested file fails loudly | Content-only dedupe could incorrectly skip distinct batches with identical contents |
| Orphans remain stored and relink on every ingestion | Supports events that precede lead uploads and call-linked overrides | Drop unresolved rows loses valid late-arriving data |
| Unknown dispositions are counted only once the event can link | Follows the specified orphan-before-unknown processing order | Counting every unknown before checking lead linkage |
| Naive timestamps are interpreted as IST; aware timestamps are converted to IST | Matches the explicit reporting timezone rule | Treating naive timestamps as UTC |

## Failure modes considered
Malformed JSON and missing event IDs increment malformed counts and are skipped. Duplicate event IDs are counted and skipped. Invalid rows are rejected with one schema-ordered reason and contain no PII in rejection output. Optional invalid values become null and increment warnings. File transactions roll back on an exception, allowing safe retry. Key loss makes encrypted data unreadable; changing the phone HMAC key prevents identity matching, so both secrets must be backed up and kept stable. Multi-process concurrent ingestion and key rotation are outside this implementation.

## Testing
`pytest -q solution/tests` passes 6 focused tests covering phone, date and decimal normalization, override precedence, bucket precedence, orphan relinking, and PII encryption. The provided seed-42 small dataset was generated, ingested as two drops, and all five reports were produced. Re-running the pipeline on a fresh database completed without errors. A full independent expected-output diff for a fresh evaluator seed has not been performed.

## Results
For seed 42 small: 2,057 lead rows, 108 rejections, 57 merged duplicate rows, 122 field warnings, 8,745 event lines, 8 malformed events, 237 duplicate events dropped, 462 final orphan events, and 18 unknown disposition events. The run produced all report files. No timing claim is made.

## If I had another day
1. Add end-to-end contract fixtures with golden report snapshots and split-drop versus single-shot parity checks.
2. Exercise the large generator scale and profile memory, ingestion, and report runtime.
3. Add explicit key versioning/envelope encryption and concurrent-worker coordination for production deployments.
