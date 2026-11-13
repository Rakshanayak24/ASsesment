import json
import sqlite3
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from solution.pipeline import (
    Crypto, bucket_for, connect, effective_disposition, normalize_phone,
    parse_date, parse_decimal, relink_orphans,
)


def test_phone_normalization():
    assert normalize_phone("+91 (98765) 43210") == "+919876543210"
    assert normalize_phone("09876543210") == "+919876543210"
    assert normalize_phone("5876543210") is None
    assert normalize_phone("123") is None


def test_date_and_decimal_parsing():
    assert parse_date("01-Dec-2026") == "2026-12-01"
    assert parse_date("31/02/2026") is None
    assert parse_date("2026-02-03") == "2026-02-03"
    assert parse_decimal("Rs. 1,234.567") == "1234.57"
    assert parse_decimal("1,23") is None
    assert parse_decimal("-1") is None


def test_override_precedence_and_latest_timestamp():
    events = [
        {"event_id": "1", "event_type": "disposition.set", "occurred_at": "2026-01-02T10:00:00+05:30", "payload": {"disposition_code": "old"}},
        {"event_id": "2", "event_type": "disposition.set", "occurred_at": "2026-01-02T11:00:00+05:30", "payload": {"disposition_code": "new"}},
        {"event_id": "3", "event_type": "disposition.override", "occurred_at": "2026-01-02T09:00:00+05:30", "payload": {"disposition_code": "override"}},
    ]
    assert effective_disposition(events) == "override"


def test_bucket_precedence():
    catalogue = {("w", "done"): {"terminal": True, "success": False}}
    assert bucket_for([], {}, catalogue) == "yet_to_reach_out"
    calls = [{"workflow_id": "w", "call_id": "c", "disposition": "done"}]
    assert bucket_for(calls, {"c": [{"event_type": "call.telephony_failed"}]}, catalogue) == "completed"
    assert bucket_for([{"workflow_id": "w", "call_id": "a", "disposition": None}, {"workflow_id": "w", "call_id": "b", "disposition": None}], {"a": [{"event_type": "call.telephony_failed"}], "b": [{"event_type": "call.telephony_failed"}]}, catalogue) == "in_progress_telephony_failed"


def test_orphan_relinks_when_lead_arrives(tmp_path, monkeypatch):
    monkeypatch.setenv("AU_PHONE_HASH_KEY", "test-key")
    db = connect(tmp_path / "x.sqlite")
    from solution.pipeline import phone_hash
    digest = phone_hash("+919876543210")
    db.execute("INSERT INTO event_ids VALUES('e')")
    db.execute("INSERT INTO events VALUES('e','w',NULL,'c','call.initiated','2026-01-01T00:00:00Z','{}',?,'orphan')", (digest,))
    db.execute("INSERT INTO leads(workflow_id,phone_hash,fields_json,batch_id) VALUES('w',?,'{}','b')", (digest,))
    relink_orphans(db)
    assert db.execute("SELECT status,lead_id FROM events WHERE event_id='e'").fetchone()["status"] == "linked"
    db.close()


def test_pii_ciphertext_does_not_include_plaintext():
    crypto = Crypto(bytes(range(32)))
    token = crypto.encrypt("Ravi Sharma")
    assert "Ravi Sharma" not in token
    assert crypto.decrypt(token) == "Ravi Sharma"
