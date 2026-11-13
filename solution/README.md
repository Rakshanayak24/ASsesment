# Assignment A: Interaction Ledger & Reporting Pipeline

This implementation uses SQLite for durable state, AES-256-GCM for field-level PII encryption,
and a keyed HMAC-SHA-256 digest for deterministic phone matching. It supports incremental drop
ingestion, idempotent file replay, orphan relinking, and the five contract reports.

## Setup and run

From the repository root (Python 3.11+):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:AU_PII_KEY = (python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())").Trim()
$env:AU_PHONE_HASH_KEY = (python -c "import secrets; print(secrets.token_hex(32))").Trim()
python assignment-a-data/tools/generate_data.py --seed 42 --scale small --out data
python solution/pipeline.py ingest data/drop_1
python solution/pipeline.py ingest data/drop_2
python solution/pipeline.py report --out reports
pytest -q solution/tests
```

The two secrets must remain stable for the lifetime of a database. Keep them outside the
repository; loss or rotation makes existing records unreadable or breaks phone matching. Override
the database location with `--db path/to/file.sqlite` before the subcommand. Each file is tracked
by its absolute path and content digest; an identical re-run is a no-op, while changing an already
ingested file in place is rejected.

## Model

`leads` stores canonical fields as JSON with each schema-marked PII value independently encrypted.
Phone identity is `(workflow_id, HMAC(phone))`, so matching works without storing plaintext phone
in an index. `events` is the durable event ledger and has a unique event ID. It stores payload,
timestamp and call metadata, plus the phone digest; events that cannot yet be linked remain in
`orphan` status and are linked when later drops add the lead. Unknown dispositions are retained as
ignored ledger records for audit and excluded from derived reports. File ingestion, dedupe state,
quality counters and data writes are persisted in SQLite.

```text
CSV batches ──validate/merge──> encrypted leads ───┐
                                                   ├─> IST call facts ──> five reports
JSONL ──dedupe/link/quarantine──> append-only events┘
```

Only `call.initiated` creates a reportable call. Effective disposition uses the latest override if
one exists, otherwise the latest set event. Rates and success-lead counts are calculated at
workflow/day grain, and report rows are sorted per contract.

## Operational notes

Use a unique database and stable secrets for each environment. SQLite WAL and per-file
transactions keep each completed source file durable; interruption partway through a file rolls
back that file so it can be retried. The model is suitable for a single worker. For 100k leads/day,
use PostgreSQL, object-store source manifests, scheduled partitioned ingestion, bounded retries,
dead-letter alerts, and explicit backfill runs; derive aggregates in SQL and rotate encryption keys
with a managed envelope-encryption service.
