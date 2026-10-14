"""Pure analysis of encryption health (no network), plus HTML report rendering."""
from collections import Counter
from datetime import datetime, timedelta, timezone
from html import escape
from typing import Any


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def enrich(states: list[dict[str, Any]], devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Join normalized encryption states with managed-device info (last sync, user, compliance) by device id."""
    by_id = {d.get("id"): d for d in devices}
    out = []
    for s in states:
        d = by_id.get(s["device_id"], {})
        out.append({**s, "user": d.get("userPrincipalName"), "last_sync": d.get("lastSyncDateTime"),
                    "compliance": d.get("complianceState"), "managed_os": d.get("operatingSystem")})
    return out


def analyze(rows: list[dict[str, Any]], now: datetime | None = None, active_days: int = 30) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    total = len(rows)
    encrypted = [r for r in rows if r["encryption_state"] == "encrypted"]
    unencrypted = [r for r in rows if r["encryption_state"] != "encrypted"]

    def active(r: dict[str, Any]) -> bool:
        ls = _parse(r.get("last_sync"))
        return bool(ls and ls >= now - timedelta(days=active_days))

    at_risk = []
    for r in unencrypted:
        if active(r):
            at_risk.append({k: r.get(k) for k in (
                "device_name", "user", "managed_os", "encryption_state", "readiness",
                "policy_state", "tpm_version", "last_sync")})
    at_risk.sort(key=lambda r: r["last_sync"] or "", reverse=True)

    by_os: dict[str, dict[str, Any]] = {}
    for r in rows:
        os_name = r.get("managed_os") or r.get("os") or "unknown"
        o = by_os.setdefault(os_name, {"total": 0, "encrypted": 0})
        o["total"] += 1
        o["encrypted"] += r["encryption_state"] == "encrypted"
    for o in by_os.values():
        o["encrypted_pct"] = round(100 * o["encrypted"] / o["total"], 1)

    # Encrypted on paper but no policy, or policy not applied: a drift signal
    policy_gaps = [r["device_name"] for r in encrypted
                   if r.get("policy_state") not in (None, "compliant", "notApplicable")]
    stale_unknown = [r["device_name"] for r in rows if not _parse(r.get("last_sync"))]

    pct = round(100 * len(encrypted) / total, 1) if total else None
    return {
        "total_devices": total,
        "encrypted_pct": pct,
        "health_grade": None if pct is None else "A" if pct >= 98 else "B" if pct >= 90 else "C" if pct >= 75 else "D",
        "by_os": by_os,
        "unencrypted_reasons": dict(Counter(
            f"{r['readiness'] or 'unknown'} / {r['policy_state'] or 'unknown'}" for r in unencrypted)),
        "tpm_versions": dict(Counter(r.get("tpm_version") or "unknown" for r in rows)),
        "at_risk_active_unencrypted": at_risk,
        "encrypted_with_policy_gap": policy_gaps,
        "never_synced_count": len(stale_unknown),
    }


def render_html(insight: dict[str, Any], trend: list[dict[str, Any]] | None = None) -> str:
    def table(headers: list[str], rows: list[list[Any]]) -> str:
        th = "".join(f"<th style='text-align:left;padding:4px 10px;border-bottom:1px solid #ccc'>{escape(h)}</th>" for h in headers)
        body = "".join("<tr>" + "".join(f"<td style='padding:4px 10px'>{escape(str(c if c is not None else ''))}</td>" for c in row) + "</tr>" for row in rows)
        return f"<table style='border-collapse:collapse;font-size:13px'><tr>{th}</tr>{body}</table>"

    parts = [
        "<h2>Intune Encryption Health Report</h2>",
        f"<p><b>{insight['encrypted_pct']}%</b> of {insight['total_devices']} devices encrypted "
        f"(grade <b>{insight['health_grade']}</b>). "
        f"{len(insight['at_risk_active_unencrypted'])} active devices are not encrypted.</p>",
        "<h3>By OS</h3>",
        table(["OS", "Total", "Encrypted", "%"], [[k, v["total"], v["encrypted"], v["encrypted_pct"]] for k, v in insight["by_os"].items()]),
        "<h3>Why devices are not encrypted (readiness / policy)</h3>",
        table(["Reason", "Devices"], list(insight["unencrypted_reasons"].items())),
        "<h3>Active, unencrypted devices</h3>",
        table(["Device", "User", "OS", "State", "Last sync"],
              [[r["device_name"], r["user"], r["managed_os"], r["encryption_state"], r["last_sync"]]
               for r in insight["at_risk_active_unencrypted"][:50]]),
    ]
    if trend:
        parts += ["<h3>Trend</h3>", table(["Taken", "Total", "% encrypted"], [[t["taken_at"][:16], t["total"], t["encrypted_pct"]] for t in trend])]
    return "".join(parts)
