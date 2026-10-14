"""MCP server exposing Intune encryption state, trend, and last-sync tools."""
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import store
from .graph import GraphClient

mcp = FastMCP("graph-intune")
_client: GraphClient | None = None


def client() -> GraphClient:
    global _client
    if _client is None:
        _client = GraphClient()
    return _client


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


@mcp.tool()
def get_encryption_status(summary_only: bool = False, state_filter: str | None = None) -> dict[str, Any]:
    """Current detailed encryption state of all Intune devices (BitLocker/FileVault, readiness,
    policy state, TPM). Optionally filter by encryptionState (e.g. 'notEncrypted')."""
    states = [store.normalize(s) for s in client().encryption_states()]
    summary = {
        "total": len(states),
        "by_encryption_state": dict(Counter(s["encryption_state"] or "unknown" for s in states)),
        "by_readiness": dict(Counter(s["readiness"] or "unknown" for s in states)),
        "by_policy_state": dict(Counter(s["policy_state"] or "unknown" for s in states)),
    }
    if summary_only:
        return {"summary": summary}
    if state_filter:
        states = [s for s in states if s["encryption_state"] == state_filter]
    return {"summary": summary, "devices": states}


@mcp.tool()
def record_encryption_snapshot() -> dict[str, Any]:
    """Capture current encryption states into local history for trend tracking.
    Call on a schedule (e.g. daily)."""
    states = client().encryption_states()
    db = store.connect()
    sid = store.save_snapshot(db, states)
    return {"snapshot_id": sid, "devices": len(states)}


@mcp.tool()
def get_encryption_trend(days: int = 30, include_changes: bool = True) -> dict[str, Any]:
    """Encryption compliance over time from recorded snapshots: per-snapshot counts by state and
    % encrypted, plus devices whose state changed across the window."""
    db = store.connect()
    result: dict[str, Any] = {"days": days, "points": store.trend(db, days)}
    if include_changes:
        result["changed_devices"] = store.changes(db, days)
    return result


@mcp.tool()
def get_last_sync_active_devices(active_within_days: int = 30, stale_after_hours: int = 24) -> dict[str, Any]:
    """Last Intune check-in for active devices (synced within active_within_days), newest first.
    Devices not synced for stale_after_hours are flagged stale. Inactive devices are only counted."""
    cutoff_active = store.now() - timedelta(days=active_within_days)
    stale_cutoff = store.now() - timedelta(hours=stale_after_hours)
    active, inactive = [], 0
    for d in client().managed_devices():
        last = _parse(d.get("lastSyncDateTime"))
        if not last or last < cutoff_active:
            inactive += 1
            continue
        active.append({
            "device_name": d.get("deviceName"), "user": d.get("userPrincipalName"),
            "os": d.get("operatingSystem"), "os_version": d.get("osVersion"),
            "compliance": d.get("complianceState"), "is_encrypted": d.get("isEncrypted"),
            "last_sync": last.isoformat(),
            "hours_since_sync": round((store.now() - last).total_seconds() / 3600, 1),
            "stale": last < stale_cutoff,
        })
    active.sort(key=lambda x: x["last_sync"], reverse=True)
    return {"active_count": len(active), "stale_count": sum(a["stale"] for a in active),
            "inactive_count": inactive, "devices": active}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
