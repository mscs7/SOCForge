"""SQLite persistence, incident correlation, audit log, case workflow."""
from __future__ import annotations

import json
from contextlib import contextmanager
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .engine import calculate_risk, family_title, utc_now

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    host TEXT NOT NULL,
    family TEXT NOT NULL,
    score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    analyst TEXT NOT NULL DEFAULT 'Unassigned',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    risk_reasons TEXT NOT NULL DEFAULT '[]',
    containment_requested INTEGER NOT NULL DEFAULT 0,
    containment_simulated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_incident_search ON incidents (fingerprint, last_seen);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key TEXT NOT NULL UNIQUE,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    source TEXT NOT NULL,
    event_time TEXT NOT NULL,
    received_at TEXT NOT NULL,
    host TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    level INTEGER NOT NULL,
    source_ip TEXT NOT NULL,
    username TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    family TEXT NOT NULL,
    technique TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    raw_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_incident ON alerts (incident_id);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id),
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    description TEXT NOT NULL,
    event_time TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit (incident_id);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS automation_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    destination TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    event_time TEXT NOT NULL
);
"""


@contextmanager
def connect(path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=20, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialise(path: str) -> None:
    with connect(path) as conn:
        conn.executescript(SCHEMA)


def asdict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


def record_audit(conn: sqlite3.Connection, incident_id: int, event_type: str, actor: str, description: str) -> None:
    conn.execute("INSERT INTO audit (incident_id,event_type,actor,description,event_time) VALUES (?,?,?,?,?)",
                 (incident_id, event_type, actor, description, utc_now()))


def ingest(path: str, alert: dict[str, Any]) -> dict[str, Any]:
    """Duplicate IDs are idempotent. Correlate same host+family in a 60-minute ingest window."""
    with connect(path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        duplicate = conn.execute("SELECT incident_id,id FROM alerts WHERE event_key=?", (alert["event_key"],)).fetchone()
        if duplicate:
            return {"created": False, "incident_id": duplicate["incident_id"], "alert_id": duplicate["id"]}
        now = utc_now()
        fingerprint = f"{alert['host'].lower()}::{alert['family']}"
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=60)).isoformat(timespec="seconds")
        incident = conn.execute(
            "SELECT * FROM incidents WHERE fingerprint=? AND last_seen>=? AND status NOT IN ('resolved','false_positive') "
            "ORDER BY id DESC LIMIT 1", (fingerprint, cutoff)
        ).fetchone()
        if incident:
            incident_id = incident["id"]
            new_incident = False
        else:
            title = family_title(alert["family"], alert["host"])
            incident_id = conn.execute(
                "INSERT INTO incidents (fingerprint,title,host,family,score,severity,status,first_seen,last_seen,updated_at) "
                "VALUES (?,?,?,?,0,'low','new',?,?,?)",
                (fingerprint, title, alert["host"], alert["family"], now, now, now)
            ).lastrowid
            new_incident = True
            record_audit(conn, incident_id, "incident_created", "SOCForge", "Incident created from incoming alert")
        cur = conn.execute(
            "INSERT INTO alerts (event_key,incident_id,source,event_time,received_at,host,rule_id,level,source_ip,username,title,category,family,technique,technique_name,raw_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (alert["event_key"], incident_id, alert["source"], alert["event_time"], now, alert["host"],
             alert["rule_id"], alert["level"], alert["source_ip"], alert["username"], alert["title"],
             alert["category"], alert["family"], alert["technique"], alert["technique_name"], alert["raw_json"])
        )
        records = [dict(row) for row in conn.execute("SELECT * FROM alerts WHERE incident_id=?", (incident_id,)).fetchall()]
        score, severity, reasons = calculate_risk(records)
        before = incident["severity"] if incident else "low"
        conn.execute("UPDATE incidents SET score=?,severity=?,risk_reasons=?,last_seen=?,updated_at=? WHERE id=?",
                     (score, severity, json.dumps(reasons), now, now, incident_id))
        record_audit(conn, incident_id, "alert_received", "SOCForge", f"Rule {alert['rule_id']} received from {alert['source']}")
        if severity != before:
            record_audit(conn, incident_id, "priority_changed", "SOCForge", f"Risk priority changed from {before} to {severity} ({score}/100)")
        return {"created": True, "new_incident": new_incident, "incident_id": incident_id,
                "alert_id": cur.lastrowid, "severity": severity, "score": score,
                "notify": new_incident or severity != before}


def serialize_incident(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["risk_reasons"] = json.loads(result.pop("risk_reasons"))
    result["containment_requested"] = bool(result["containment_requested"])
    result["containment_simulated"] = bool(result["containment_simulated"])
    return result


def list_incidents(path: str, status: str = "", severity: str = "", search: str = "") -> list[dict[str, Any]]:
    clause = ["1=1"]
    args: list[Any] = []
    if status:
        clause.append("i.status=?")
        args.append(status)
    if severity:
        clause.append("i.severity=?")
        args.append(severity)
    if search:
        clause.append("(i.title LIKE ? OR i.host LIKE ? OR CAST(i.id AS TEXT) LIKE ?)")
        args.extend([f"%{search}%"] * 3)
    sql = ("SELECT i.*, COUNT(a.id) AS alert_count FROM incidents i "
           "LEFT JOIN alerts a ON a.incident_id=i.id WHERE " + " AND ".join(clause) +
           " GROUP BY i.id ORDER BY CASE i.status WHEN 'resolved' THEN 1 WHEN 'false_positive' THEN 1 ELSE 0 END, "
           "i.score DESC, i.last_seen DESC, i.id DESC LIMIT 250")
    with connect(path) as conn:
        return [serialize_incident(row) for row in conn.execute(sql, args)]


def get_incident(path: str, incident_id: int) -> dict[str, Any] | None:
    with connect(path) as conn:
        inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if inc is None:
            return None
        result = serialize_incident(inc)
        rows = conn.execute("SELECT id,event_time,received_at,host,source,rule_id,level,source_ip,username,title,category,technique,technique_name "
                            "FROM alerts WHERE incident_id=? ORDER BY id", (incident_id,)).fetchall()
        result["alerts"] = [dict(a) for a in rows]
        result["notes"] = [dict(n) for n in conn.execute("SELECT id,author,content,created_at FROM notes WHERE incident_id=? ORDER BY id DESC", (incident_id,))]
        result["audit"] = [dict(a) for a in conn.execute("SELECT id,event_type,actor,description,event_time FROM audit WHERE incident_id=? ORDER BY id DESC", (incident_id,))]
        result["techniques"] = sorted({a["technique"] for a in rows if a["technique"]})
        result["indicators"] = sorted({a["source_ip"] for a in rows if a["source_ip"]})
        return result


def metrics(path: str) -> dict[str, Any]:
    with connect(path) as conn:
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        total_incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        open_incidents = conn.execute("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','false_positive')").fetchone()[0]
        urgent = conn.execute("SELECT COUNT(*) FROM incidents WHERE severity IN ('critical','high') AND status NOT IN ('resolved','false_positive')").fetchone()[0]
        unresolved = conn.execute("SELECT COUNT(*) FROM incidents WHERE status='new'").fetchone()[0]
        by_severity = {x: 0 for x in ("critical", "high", "medium", "low")}
        for r in conn.execute("SELECT severity,COUNT(*) AS n FROM incidents GROUP BY severity"):
            by_severity[r["severity"]] = r["n"]
        return {"total_alerts": total_alerts, "total_incidents": total_incidents,
                "open_incidents": open_incidents, "urgent_incidents": urgent,
                "awaiting_triage": unresolved, "by_severity": by_severity}


def activity(path: str, days: int = 7) -> list[dict[str, Any]]:
    today = datetime.now(timezone.utc).date()
    with connect(path) as conn:
        rows = conn.execute("SELECT substr(received_at,1,10) AS day,COUNT(*) AS alerts FROM alerts "
                            "WHERE received_at>=? GROUP BY substr(received_at,1,10)",
                            ((today - timedelta(days=days-1)).isoformat(),)).fetchall()
        counts = {r["day"]: r["alerts"] for r in rows}
    return [{"day": (today-timedelta(days=i)).isoformat(), "alerts": counts.get((today-timedelta(days=i)).isoformat(), 0)}
            for i in range(days-1, -1, -1)]


def change_triage(path: str, incident_id: int, status: str | None, analyst: str | None) -> bool:
    with connect(path) as conn:
        inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not inc:
            return False
        updated = False
        if status is not None and inc["status"] != status:
            conn.execute("UPDATE incidents SET status=?,updated_at=? WHERE id=?", (status, utc_now(), incident_id))
            record_audit(conn, incident_id, "status_updated", "Analyst", f"Status: {inc['status']} -> {status}")
            updated = True
        if analyst is not None and inc["analyst"] != analyst:
            conn.execute("UPDATE incidents SET analyst=?,updated_at=? WHERE id=?", (analyst, utc_now(), incident_id))
            record_audit(conn, incident_id, "ownership_updated", "Analyst", f"Assigned to: {analyst}")
            updated = True
        return True


def add_note(path: str, incident_id: int, author: str, content: str) -> bool:
    with connect(path) as conn:
        if not conn.execute("SELECT 1 FROM incidents WHERE id=?", (incident_id,)).fetchone():
            return False
        conn.execute("INSERT INTO notes (incident_id,author,content,created_at) VALUES (?,?,?,?)", (incident_id, author, content, utc_now()))
        record_audit(conn, incident_id, "note_added", author, "Investigation note recorded")
        return True


def response_action(path: str, incident_id: int, action: str) -> tuple[bool, str]:
    with connect(path) as conn:
        inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not inc:
            return False, "Incident not found"
        if action == "request_containment":
            if inc["containment_requested"]:
                return True, "A containment simulation has already been requested"
            conn.execute("UPDATE incidents SET containment_requested=1,updated_at=? WHERE id=?", (utc_now(), incident_id))
            record_audit(conn, incident_id, "simulation_requested", "Analyst", "Containment simulation requested; no endpoint commands sent")
            return True, "Containment simulation requested"
        if action == "approve_simulation":
            if not inc["containment_requested"]:
                return False, "Request a simulation before approving it"
            if inc["containment_simulated"]:
                return True, "Simulation already approved"
            conn.execute("UPDATE incidents SET containment_simulated=1,status='contained',updated_at=? WHERE id=?",
                         (utc_now(), incident_id))
            record_audit(conn, incident_id, "simulation_approved", "Analyst", "SIMULATED containment approved - NO real blocks, isolation or changes performed")
            return True, "Simulation recorded (no action performed on any host)"
        return False, "Unsupported action"


def record_automation(path: str, incident_id: int, destination: str, status: str, message: str) -> None:
    with connect(path) as conn:
        conn.execute("INSERT INTO automation_logs (incident_id,destination,status,message,event_time) VALUES (?,?,?,?,?)",
                     (incident_id, destination, status, message[:500], utc_now()))


def automation_log(path: str) -> list[dict[str, Any]]:
    with connect(path) as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM automation_logs ORDER BY id DESC LIMIT 40")]


def reset_demo(path: str) -> dict[str, int]:
    """Remove demo source records only, never live ingest records."""
    with connect(path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        demo_incident_ids = [x[0] for x in conn.execute("SELECT DISTINCT incident_id FROM alerts WHERE source='demo'")]
        count = conn.execute("DELETE FROM alerts WHERE source='demo'").rowcount
        removed = 0
        for incident_id in demo_incident_ids:
            remaining = conn.execute("SELECT * FROM alerts WHERE incident_id=?", (incident_id,)).fetchall()
            if not remaining:
                conn.execute("DELETE FROM audit WHERE incident_id=?", (incident_id,))
                conn.execute("DELETE FROM notes WHERE incident_id=?", (incident_id,))
                conn.execute("DELETE FROM automation_logs WHERE incident_id=?", (incident_id,))
                conn.execute("DELETE FROM incidents WHERE id=?", (incident_id,))
                removed += 1
            else:
                score,severity,reasons=calculate_risk([dict(a) for a in remaining])
                conn.execute("UPDATE incidents SET score=?,severity=?,risk_reasons=? WHERE id=?", (score,severity,json.dumps(reasons),incident_id))
        return {"alerts_removed": count, "incidents_removed": removed}
