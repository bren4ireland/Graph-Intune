"""MCP server exposing Intune encryption state, trend, and last-sync tools."""
import os
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import insights, store
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


def _insight() -> dict[str, Any]:
    c = client()
    states = [store.normalize(s) for s in c.encryption_states()]
    return insights.analyze(insights.enrich(states, c.managed_devices()))


@mcp.tool()
def get_encryption_health_insights() -> dict[str, Any]:
    """Deep encryption health analysis: grade, % by OS, reasons devices are unencrypted
    (readiness/policy), TPM versions, active-but-unencrypted at-risk devices, and policy gaps."""
    return _insight()


def _allowed(recipient: str) -> bool:
    domains = [d.strip().lower() for d in os.environ.get("MAIL_ALLOWED_DOMAINS", "").split(",") if d.strip()]
    return bool(domains) and recipient.rsplit("@", 1)[-1].lower() in domains


@mcp.tool()
def email_encryption_report(recipients: list[str], include_trend: bool = True, preview: bool = True) -> dict[str, Any]:
    """Email the encryption health report (HTML). Defaults to preview=True, which only renders it;
    set preview=False to actually send. Recipients must be in MAIL_ALLOWED_DOMAINS and the
    sending mailbox is MAIL_SENDER."""
    bad = [r for r in recipients if not _allowed(r)]
    if bad:
        return {"sent": False, "error": f"Recipients not in MAIL_ALLOWED_DOMAINS: {bad}"}
    trend = store.trend(store.connect(), 30) if include_trend else None
    html = insights.render_html(_insight(), trend)
    subject = f"Intune encryption health report - {store.now():%Y-%m-%d}"
    if preview:
        return {"sent": False, "preview": True, "subject": subject, "recipients": recipients, "html": html}
    sender = os.environ.get("MAIL_SENDER")
    if not sender:
        return {"sent": False, "error": "MAIL_SENDER is not set"}
    client().send_mail(sender, recipients, subject, html)
    return {"sent": True, "subject": subject, "recipients": recipients}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
