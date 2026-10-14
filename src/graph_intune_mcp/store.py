"""SQLite snapshot store used for encryption trend tracking."""
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

DEFAULT_DB = os.path.expanduser("~/.graph-intune-mcp/history.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT, taken_at TEXT NOT NULL, total INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS device_states (
  snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL, device_name TEXT, os TEXT,
  encryption_state TEXT, readiness TEXT, policy_state TEXT,
  bitlocker_state TEXT, filevault_state TEXT, tpm_version TEXT);
CREATE INDEX IF NOT EXISTS ix_ds_snap ON device_states(snapshot_id);
"""


def now() -> datetime:
    return datetime.now(timezone.utc)


def connect(path: str | None = None) -> sqlite3.Connection:
    path = path or os.environ.get("INTUNE_HISTORY_DB", DEFAULT_DB)
    if path != ":memory:":
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript(SCHEMA)
    return db


def normalize(s: dict[str, Any]) -> dict[str, Any]:
    return {
        "device_id": s.get("id"),
        "device_name": s.get("deviceName"),
        "os": s.get("deviceType") or s.get("osVersion"),
        "encryption_state": s.get("encryptionState"),
        "readiness": s.get("encryptionReadinessState"),
        "policy_state": s.get("encryptionPolicySettingState"),
        "bitlocker_state": s.get("advancedBitLockerStates"),
        "filevault_state": s.get("fileVaultStates"),
        "tpm_version": s.get("tpmSpecificationVersion"),
    }


def save_snapshot(db: sqlite3.Connection, states: list[dict[str, Any]], taken_at: datetime | None = None) -> int:
    ts = (taken_at or now()).isoformat()
    cur = db.execute("INSERT INTO snapshots(taken_at,total) VALUES (?,?)", (ts, len(states)))
    sid = cur.lastrowid
    db.executemany(
        "INSERT INTO device_states VALUES (?,?,?,?,?,?,?,?,?,?)",
        [(sid, *normalize(s).values()) for s in states],
    )
    db.commit()
    return sid


def trend(db: sqlite3.Connection, days: int = 30) -> list[dict[str, Any]]:
    since = (now() - timedelta(days=days)).isoformat()
    out = []
    for snap in db.execute("SELECT id,taken_at,total FROM snapshots WHERE taken_at>=? ORDER BY taken_at", (since,)):
        counts = {r["encryption_state"] or "unknown": r["n"] for r in db.execute(
            "SELECT encryption_state, COUNT(*) n FROM device_states WHERE snapshot_id=? GROUP BY 1", (snap["id"],))}
        enc = counts.get("encrypted", 0)
        out.append({"taken_at": snap["taken_at"], "total": snap["total"], "by_state": counts,
                    "encrypted_pct": round(100 * enc / snap["total"], 1) if snap["total"] else None})
    return out


def changes(db: sqlite3.Connection, days: int = 30) -> list[dict[str, Any]]:
    """Devices whose encryption state differs between the oldest and latest snapshot in the window."""
    since = (now() - timedelta(days=days)).isoformat()
    snaps = db.execute("SELECT id FROM snapshots WHERE taken_at>=? ORDER BY taken_at", (since,)).fetchall()
    if len(snaps) < 2:
        return []
    old, new = snaps[0]["id"], snaps[-1]["id"]
    rows = db.execute(
        """SELECT n.device_id, n.device_name, o.encryption_state AS previous, n.encryption_state AS current
           FROM device_states n JOIN device_states o ON o.device_id=n.device_id AND o.snapshot_id=?
           WHERE n.snapshot_id=? AND COALESCE(o.encryption_state,'')<>COALESCE(n.encryption_state,'')""",
        (old, new))
    return [dict(r) for r in rows]
