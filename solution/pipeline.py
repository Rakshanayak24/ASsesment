"""Assignment A interaction ledger and reporting pipeline."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import secrets
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "assignment-a-data" / "schemas"
IST = timezone(timedelta(hours=5, minutes=30))
UTC = timezone.utc
QUALITY_DEFAULTS = {
    "lead_rows_total": 0, "lead_rows_rejected": 0, "rejections_by_reason": {},
    "duplicate_lead_rows_merged": 0, "field_warnings": 0, "events_total": 0,
    "malformed_events": 0, "duplicate_events_dropped": 0, "orphan_events": 0,
    "unknown_disposition_events": 0,
}


def norm_header(value: str) -> str:
    return re.sub(r"[_\s]+", " ", value.strip().lower())


def normalize_phone(value: str) -> str | None:
    digits = re.sub(r"\D", "", value)
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    if len(digits) != 10 or digits[0] not in "6789":
        return None
    return "+91" + digits


def parse_date(value: str) -> str | None:
    value = value.strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d-%b-%Y"):
        try:
            return datetime.strptime(value, fmt).date().isoformat()
        except ValueError:
            pass
    return None


def parse_decimal(value: str) -> str | None:
    text = re.sub(r"^(?:₹|rs\.?|inr)\s*", "", value.strip(), flags=re.I)
    if not re.fullmatch(r"(?:\d+|\d{1,3}(?:,\d{3})+)(?:\.\d+)?", text):
        return None
    text = text.replace(",", "")
    try:
        number = Decimal(text)
        if not number.is_finite() or number < 0:
            return None
        return format(number.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP), ".2f")
    except InvalidOperation:
        return None


def parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=IST)
    return dt.astimezone(IST)


class Crypto:
    """AES-GCM encryption with a deployment-provided 32-byte key."""
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AU_PII_KEY must decode to exactly 32 bytes")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:
            raise RuntimeError("Install requirements.txt (cryptography is required)") from exc
        self.aes = AESGCM(key)

    @classmethod
    def from_env(cls) -> "Crypto":
        raw = os.environ.get("AU_PII_KEY")
        if not raw:
            raise RuntimeError("Set AU_PII_KEY to a base64-encoded 32-byte key (generate with: python -c \"import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())\")")
        try:
            key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except Exception as exc:
            raise RuntimeError("AU_PII_KEY is not valid base64") from exc
        return cls(key)

    def encrypt(self, plaintext: str) -> str:
        nonce = secrets.token_bytes(12)
        blob = nonce + self.aes.encrypt(nonce, plaintext.encode(), None)
        return base64.urlsafe_b64encode(blob).decode()

    def decrypt(self, token: str) -> str:
        blob = base64.urlsafe_b64decode(token)
        return self.aes.decrypt(blob[:12], blob[12:], None).decode()


def phone_hash(phone: str) -> str:
    key = os.environ.get("AU_PHONE_HASH_KEY")
    if not key:
        raise RuntimeError("Set AU_PHONE_HASH_KEY to a stable random secret for deterministic phone matching")
    return hmac_digest(key.encode(), phone.encode())


def hmac_digest(key: bytes, value: bytes) -> str:
    import hmac
    return hmac.new(key, value, hashlib.sha256).hexdigest()


def load_schemas() -> dict[str, dict[str, Any]]:
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(SCHEMA_DIR.glob("*.json"))}


def load_dispositions() -> dict[tuple[str, str], dict[str, bool]]:
    out = {}
    with (SCHEMA_DIR / "dispositions.csv").open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            out[(row["workflow_id"], row["code"])] = {
                "terminal": row["is_terminal"].lower() == "true",
                "success": row["is_success"].lower() == "true",
            }
    return out


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
      CREATE TABLE IF NOT EXISTS leads(
        id INTEGER PRIMARY KEY, workflow_id TEXT NOT NULL, phone_hash TEXT NOT NULL,
        fields_json TEXT NOT NULL, batch_id TEXT NOT NULL,
        UNIQUE(workflow_id, phone_hash));
      CREATE TABLE IF NOT EXISTS event_ids(event_id TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS events(
        event_id TEXT PRIMARY KEY REFERENCES event_ids(event_id), workflow_id TEXT NOT NULL,
        lead_id INTEGER REFERENCES leads(id), call_id TEXT, event_type TEXT NOT NULL,
        occurred_at TEXT, payload_json TEXT NOT NULL, phone_hash TEXT,
        status TEXT NOT NULL CHECK(status IN ('linked','orphan','ignored')));
      CREATE INDEX IF NOT EXISTS events_call_idx ON events(workflow_id, call_id);
      CREATE INDEX IF NOT EXISTS events_lead_idx ON events(lead_id, event_type);
      CREATE TABLE IF NOT EXISTS ingested_files(
        path_key TEXT PRIMARY KEY, content_hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS rejections(
        workflow_id TEXT NOT NULL, batch_id TEXT NOT NULL, row_number INTEGER NOT NULL,
        reason TEXT NOT NULL, PRIMARY KEY(workflow_id,batch_id,row_number));
      CREATE TABLE IF NOT EXISTS quality(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
    """)
    return db


def qadd(db: sqlite3.Connection, key: str, amount: int = 1) -> None:
    db.execute("INSERT INTO quality(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=value+excluded.value", (key, amount))


def file_key(path: Path) -> str:
    return str(path.resolve()).casefold()


def already_ingested(db: sqlite3.Connection, path: Path, digest: str) -> bool:
    row = db.execute("SELECT content_hash FROM ingested_files WHERE path_key=?", (file_key(path),)).fetchone()
    if row and row[0] == digest:
        return True
    if row:
        raise ValueError(f"Previously ingested file changed in place: {path}")
    return False


def mark_ingested(db: sqlite3.Connection, path: Path, digest: str) -> None:
    db.execute("INSERT INTO ingested_files VALUES(?,?)", (file_key(path), digest))


def validate_row(raw: dict[str, str], schema: dict[str, Any]) -> tuple[dict[str, Any], str | None, int]:
    mapped: dict[str, str] = {}
    names = {}
    for field in schema["fields"]:
        for name in [field["name"], *field.get("aliases", [])]:
            names[norm_header(name)] = field["name"]
    for header, value in raw.items():
        target = names.get(norm_header(header or ""))
        if target and target not in mapped:
            mapped[target] = (value or "").strip()
    values: dict[str, Any] = {}
    warning_count = 0
    for f in schema["fields"]:
        name, typ = f["name"], f["type"]
        raw_value = mapped.get(name, "")
        if not raw_value:
            values[name] = None
            if f.get("required"):
                return values, f"missing_required:{name}", 0
            continue
        parsed: Any = raw_value
        if typ == "phone":
            parsed = normalize_phone(raw_value)
        elif typ == "date":
            parsed = parse_date(raw_value)
        elif typ == "decimal":
            parsed = parse_decimal(raw_value)
        elif typ == "enum":
            parsed = raw_value.lower()
            if parsed not in [v.lower() for v in f.get("values", [])]:
                parsed = None
        if parsed is None:
            if f.get("required"):
                reason = "invalid_phone" if typ == "phone" else f"missing_required:{name}"
                return values, reason, 0
            warning_count += 1
        values[name] = parsed
    return values, None, warning_count


def encrypt_fields(fields: dict[str, Any], schema: dict[str, Any], crypto: Crypto) -> str:
    pii = {f["name"] for f in schema["fields"] if f.get("pii")}
    saved = {k: ("enc:" + crypto.encrypt(str(v)) if k in pii and v is not None else v) for k, v in fields.items()}
    return json.dumps(saved, ensure_ascii=False, separators=(",", ":"))


def decrypt_fields(value: str, crypto: Crypto) -> dict[str, Any]:
    data = json.loads(value)
    return {k: crypto.decrypt(v[4:]) if isinstance(v, str) and v.startswith("enc:") else v for k, v in data.items()}


def ingest_lead_file(db: sqlite3.Connection, path: Path, workflow_id: str, schemas: dict[str, Any], crypto: Crypto) -> None:
    schema = schemas.get(workflow_id)
    if schema is None:
        raise ValueError(f"No lead schema for workflow directory {workflow_id!r}")
    raw_bytes = path.read_bytes()
    digest = hashlib.sha256(raw_bytes).hexdigest()
    if already_ingested(db, path, digest):
        return
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        with db:
            for row_num, row in enumerate((r for r in reader if any((v or "").strip() for v in r.values())), 1):
                qadd(db, "lead_rows_total")
                values, reason, warnings = validate_row(row, schema)
                batch = path.stem
                if reason:
                    qadd(db, "lead_rows_rejected")
                    db.execute("INSERT OR IGNORE INTO rejections VALUES(?,?,?,?)", (workflow_id, batch, row_num, reason))
                    db.execute("INSERT INTO quality(key,value) VALUES(?,1) ON CONFLICT(key) DO UPDATE SET value=value+1", ("reason:" + reason,))
                    continue
                qadd(db, "field_warnings", warnings)
                ph = values["phone"]
                phash = phone_hash(ph)
                old = db.execute("SELECT id,fields_json FROM leads WHERE workflow_id=? AND phone_hash=?", (workflow_id, phash)).fetchone()
                if old:
                    qadd(db, "duplicate_lead_rows_merged")
                    previous = decrypt_fields(old["fields_json"], crypto)
                    for key, val in values.items():
                        if val is not None:
                            previous[key] = val
                    db.execute("UPDATE leads SET fields_json=? WHERE id=?", (encrypt_fields(previous, schema, crypto), old["id"]))
                else:
                    for field in schema["fields"]:
                        if values.get(field["name"]) is None and "default" in field:
                            values[field["name"]] = field["default"]
                    db.execute("INSERT INTO leads(workflow_id,phone_hash,fields_json,batch_id) VALUES(?,?,?,?)", (workflow_id, phash, encrypt_fields(values, schema, crypto), batch))
    mark_ingested(db, path, digest)
    db.commit()
    relink_orphans(db)


def event_phone_hash(event: dict[str, Any]) -> str | None:
    if not event.get("phone"):
        return None
    normalized = normalize_phone(str(event["phone"]))
    return phone_hash(normalized) if normalized else None


def link_call_override(db: sqlite3.Connection, workflow: str, call_id: str) -> int | None:
    row = db.execute("SELECT lead_id FROM events WHERE workflow_id=? AND call_id=? AND lead_id IS NOT NULL ORDER BY rowid LIMIT 1", (workflow, call_id)).fetchone()
    return int(row[0]) if row else None


def relink_orphans(db: sqlite3.Connection) -> None:
    dispositions = load_dispositions()
    while True:
        rows = db.execute("SELECT event_id,workflow_id,call_id,event_type,phone_hash FROM events WHERE status='orphan'").fetchall()
        changed = 0
        with db:
            for row in rows:
                lead_id = None
                if row["event_type"] == "disposition.override" and row["call_id"]:
                    lead_id = link_call_override(db, row["workflow_id"], row["call_id"])
                elif row["phone_hash"]:
                    match = db.execute("SELECT id FROM leads WHERE workflow_id=? AND phone_hash=?", (row["workflow_id"], row["phone_hash"])).fetchone()
                    lead_id = int(match[0]) if match else None
                if lead_id:
                    if row["event_type"].startswith("disposition."):
                        payload_row = db.execute("SELECT payload_json FROM events WHERE event_id=?", (row["event_id"],)).fetchone()
                        code = json.loads(payload_row[0]).get("disposition_code")
                        if (row["workflow_id"], code) not in dispositions:
                            qadd(db, "unknown_disposition_events")
                            db.execute("UPDATE events SET lead_id=?,status='ignored' WHERE event_id=?", (lead_id, row["event_id"]))
                            changed += 1
                            continue
                    db.execute("UPDATE events SET lead_id=?,status='linked' WHERE event_id=?", (lead_id, row["event_id"]))
                    changed += 1
        if not changed:
            break


def ingest_event_file(db: sqlite3.Connection, path: Path, crypto: Crypto, dispositions: dict[tuple[str, str], dict[str, bool]]) -> None:
    raw_bytes = path.read_bytes()
    digest = hashlib.sha256(raw_bytes).hexdigest()
    if already_ingested(db, path, digest):
        return
    with path.open(encoding="utf-8-sig") as f:
        with db:
            for line in f:
                if not line.strip():
                    continue
                qadd(db, "events_total")
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict) or not event.get("event_id"):
                        raise ValueError("missing event_id")
                except (json.JSONDecodeError, ValueError):
                    qadd(db, "malformed_events")
                    continue
                event_id = str(event["event_id"])
                cur = db.execute("INSERT OR IGNORE INTO event_ids VALUES(?)", (event_id,))
                if not cur.rowcount:
                    qadd(db, "duplicate_events_dropped")
                    continue
                workflow = str(event.get("workflow_id", ""))
                etype = str(event.get("event_type", ""))
                payload = event.get("payload") or {}
                if not isinstance(payload, dict):
                    payload = {}
                phone_hash_value = event_phone_hash(event)
                lead_id = None
                if etype == "disposition.override":
                    if event.get("call_id"):
                        lead_id = link_call_override(db, workflow, str(event["call_id"]))
                elif phone_hash_value:
                    found = db.execute("SELECT id FROM leads WHERE workflow_id=? AND phone_hash=?", (workflow, phone_hash_value)).fetchone()
                    lead_id = int(found[0]) if found else None
                if lead_id and etype.startswith("disposition.") and (workflow, payload.get("disposition_code")) not in dispositions:
                    qadd(db, "unknown_disposition_events")
                    db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)", (event_id, workflow, lead_id, event.get("call_id"), etype, event.get("occurred_at"), json.dumps(payload), phone_hash_value, "ignored"))
                    continue
                status = "linked" if lead_id else "orphan"
                # Preserve no raw event phone or other unneeded top-level data.
                db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)", (event_id, workflow, lead_id, event.get("call_id"), etype, event.get("occurred_at"), json.dumps(payload, ensure_ascii=False), phone_hash_value, status))
    mark_ingested(db, path, digest)
    db.commit()
    relink_orphans(db)


def ingest(db: sqlite3.Connection, drop: Path, schemas: dict[str, Any], crypto: Crypto, dispositions: dict[tuple[str, str], dict[str, bool]]) -> None:
    if not (drop / "leads").exists() and not (drop / "events").exists():
        children = sorted((p for p in drop.iterdir() if p.is_dir() and p.name.startswith("drop_")), key=lambda p: p.name) if drop.exists() else []
        if children:
            for child in children:
                ingest(db, child, schemas, crypto, dispositions)
        return
    leads_root = drop / "leads"
    if leads_root.exists():
        for path in sorted(leads_root.glob("*/*.csv"), key=lambda p: (p.parent.name, p.name)):
            ingest_lead_file(db, path, path.parent.name, schemas, crypto)
    events_root = drop / "events"
    if events_root.exists():
        for path in sorted(events_root.glob("*.jsonl"), key=lambda p: p.name):
            ingest_event_file(db, path, crypto, dispositions)


def effective_disposition(events: list[dict[str, Any]]) -> str | None:
    overrides = [e for e in events if e["event_type"] == "disposition.override"]
    candidates = overrides or [e for e in events if e["event_type"] == "disposition.set"]
    if not candidates:
        return None
    return max(candidates, key=lambda e: (parse_timestamp(e["occurred_at"]) if e["occurred_at"] else datetime.min.replace(tzinfo=IST), e["event_id"]))["payload"].get("disposition_code")


def bucket_for(calls: list[dict[str, Any]], call_events: dict[str, list[dict[str, Any]]], dispositions: dict[tuple[str, str], dict[str, bool]]) -> str:
    if not calls:
        return "yet_to_reach_out"
    if any(dispositions.get((c["workflow_id"], c["disposition"]), {}).get("terminal", False) for c in calls):
        return "completed"
    if all(any(e["event_type"] == "call.telephony_failed" for e in call_events[c["call_id"]]) for c in calls):
        return "in_progress_telephony_failed"
    return "in_progress_dialed"


def build_reports(db: sqlite3.Connection, out: Path, crypto: Crypto, schemas: dict[str, Any], dispositions: dict[tuple[str, str], dict[str, bool]]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    leads = db.execute("SELECT * FROM leads ORDER BY workflow_id, id").fetchall()
    events = db.execute("SELECT * FROM events WHERE status='linked' ORDER BY rowid").fetchall()
    by_lead: dict[int, list[dict[str, Any]]] = defaultdict(list)
    call_lead: dict[tuple[str, str], int] = {}
    for row in events:
        event = dict(row)
        event["payload"] = json.loads(event["payload_json"])
        by_lead[event["lead_id"]].append(event)
        if event["call_id"]:
            call_lead[(event["workflow_id"], event["call_id"])] = event["lead_id"]
    report_rows = []
    batch_counts: dict[tuple[str, str], Counter] = defaultdict(Counter)
    daily: dict[tuple[str, str], dict[str, Any]] = {}
    for lead in leads:
        workflow = lead["workflow_id"]
        schema = schemas[workflow]
        fields = decrypt_fields(lead["fields_json"], crypto)
        phone = fields["phone"]
        levents = by_lead.get(lead["id"], [])
        per_call: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for e in levents:
            if e["call_id"]:
                per_call[e["call_id"]].append(e)
        calls = []
        for call_id, cev in per_call.items():
            initiated = [e for e in cev if e["event_type"] == "call.initiated"]
            if not initiated:
                continue
            init = min(initiated, key=lambda e: (parse_timestamp(e["occurred_at"]), e["event_id"]))
            calls.append({"call_id": call_id, "workflow_id": workflow, "at": parse_timestamp(init["occurred_at"]),
                          "connected": any(e["event_type"] == "call.connected" for e in cev),
                          "disposition": effective_disposition(cev), "events": cev})
        calls.sort(key=lambda c: (c["at"], c["call_id"]))
        bucket = bucket_for(calls, {c["call_id"]: c["events"] for c in calls}, dispositions)
        batch_counts[(workflow, lead["batch_id"])][bucket] += 1
        success = any(dispositions.get((workflow, c["disposition"]), {}).get("success", False) for c in calls)
        last = calls[-1] if calls else None
        current = next((c["disposition"] for c in reversed(calls) if c["disposition"]), None)
        phone_digits = re.sub(r"\D", "", phone)
        ref_field = next(f["name"] for f in schema["fields"] if f.get("reference"))
        report_rows.append({"workflow_id": workflow, "external_ref": fields.get(ref_field) or "", "batch_id": lead["batch_id"],
                            "phone_masked": "+91******" + phone_digits[-4:], "bucket": bucket, "total_calls": len(calls),
                            "connected_calls": sum(c["connected"] for c in calls), "last_call_at": last["at"].isoformat() if last else "",
                            "current_disposition": current or "", "ever_success": str(success).lower()})
        for call in calls:
            day = call["at"].date().isoformat()
            key = (workflow, day)
            item = daily.setdefault(key, {"total_calls": 0, "connected_calls": 0, "success_leads": set()})
            item["total_calls"] += 1
            item["connected_calls"] += int(call["connected"])
            if dispositions.get((workflow, call["disposition"]), {}).get("success", False):
                item["success_leads"].add(lead["id"])
    def write_csv(name: str, headers: list[str], rows: list[dict[str, Any]]) -> None:
        with (out / name).open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=headers, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
    batch_rows = []
    bucket_names = ["yet_to_reach_out", "in_progress_telephony_failed", "in_progress_dialed", "completed"]
    for (workflow, batch), counts in sorted(batch_counts.items()):
        batch_rows.append({"workflow_id": workflow, "batch_id": batch, "total_leads": sum(counts.values()), **{b: counts[b] for b in bucket_names}})
    write_csv("batch_summary.csv", ["workflow_id", "batch_id", "total_leads", *bucket_names], batch_rows)
    daily_rows = []
    for (workflow, day), d in sorted(daily.items()):
        daily_rows.append({"workflow_id": workflow, "date": day, "total_calls": d["total_calls"], "connected_calls": d["connected_calls"],
                           "connectivity_rate": f"{d['connected_calls']/d['total_calls']:.4f}", "success_leads": len(d["success_leads"])})
    write_csv("daily_overview.csv", ["workflow_id", "date", "total_calls", "connected_calls", "connectivity_rate", "success_leads"], daily_rows)
    write_csv("lead_report.csv", ["workflow_id", "external_ref", "batch_id", "phone_masked", "bucket", "total_calls", "connected_calls", "last_call_at", "current_disposition", "ever_success"], sorted(report_rows, key=lambda x: (x["workflow_id"], x["external_ref"])))
    rejections = [dict(row) for row in db.execute("SELECT workflow_id,batch_id,row_number,reason FROM rejections ORDER BY workflow_id,batch_id,row_number")]
    write_csv("rejections.csv", ["workflow_id", "batch_id", "row_number", "reason"], rejections)
    quality = dict(QUALITY_DEFAULTS)
    reason_keys = {"invalid_phone"}
    reason_keys.update("missing_required:" + field["name"] for schema in schemas.values() for field in schema["fields"] if field.get("required") and field["type"] != "phone")
    reasons = {k[7:]: int(v) for k, v in db.execute("SELECT key,value FROM quality WHERE key LIKE 'reason:%'")}
    quality["rejections_by_reason"] = {key: reasons.get(key, 0) for key in sorted(reason_keys | reasons.keys())}
    for key in QUALITY_DEFAULTS:
        if key == "rejections_by_reason":
            continue
        row = db.execute("SELECT value FROM quality WHERE key=?", (key,)).fetchone()
        if row:
            quality[key] = int(row[0])
    quality["orphan_events"] = int(db.execute("SELECT COUNT(*) FROM events WHERE status='orphan'").fetchone()[0])
    (out / "data_quality.json").write_text(json.dumps(quality, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PII-safe interaction ledger pipeline")
    parser.add_argument("--db", default="pipeline.sqlite", help="SQLite database path (default: pipeline.sqlite)")
    sub = parser.add_subparsers(dest="command", required=True)
    p_ingest = sub.add_parser("ingest")
    p_ingest.add_argument("drop", type=Path)
    p_report = sub.add_parser("report")
    p_report.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        crypto = Crypto.from_env()
        db = connect(Path(args.db))
        schemas = load_schemas()
        dispositions = load_dispositions()
        if args.command == "ingest":
            ingest(db, args.drop, schemas, crypto, dispositions)
        else:
            relink_orphans(db)
            build_reports(db, args.out, crypto, schemas, dispositions)
        db.close()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
