"""Deterministic, explainable incident triage. No external reputation calls."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any

TECHNIQUES = {
    "authentication_failure": ("T1110", "Brute Force"),
    "account_created": ("T1136", "Create Account"),
    "privilege_change": ("T1098", "Account Manipulation"),
    "suspicious_execution": ("T1059", "Command and Scripting Interpreter"),
    "malware_detection": ("T1204", "User Execution"),
    "web_attack": ("T1190", "Exploit Public-Facing Application"),
    "network_scan": ("T1046", "Network Service Discovery"),
}

CATEGORY_FAMILY = {
    "authentication_failure": "authentication",
    "account_created": "endpoint_account_activity",
    "privilege_change": "endpoint_account_activity",
    "suspicious_execution": "endpoint_account_activity",
    "malware_detection": "endpoint_account_activity",
    "web_attack": "web_application",
    "network_scan": "network_discovery",
    "other": "other",
}

CATEGORY_LABELS = {
    "authentication_failure": "Authentication failures",
    "account_created": "New account created",
    "privilege_change": "Privilege change",
    "suspicious_execution": "Suspicious process execution",
    "malware_detection": "Malware indicator",
    "web_attack": "Web application attack activity",
    "network_scan": "Network reconnaissance activity",
    "other": "Security event",
}

PLAYBOOKS = {
    "authentication": ["Review failed sign-in volume and source addresses", "Verify affected accounts and successful sign-ins", "Escalate if brute-force attempts succeed; consider approved access controls"],
    "endpoint_account_activity": ["Review the process tree and executable provenance", "Verify account creation and privileged group changes with the endpoint owner", "If authorised, isolate the test host in a controlled lab", "Preserve relevant logs and notify the incident owner"],
    "web_application": ["Inspect affected endpoints, request patterns and response codes", "Check related authentication and web-server events", "Validate access-control findings within an approved test scope"],
    "network_discovery": ["Review source IP and affected ports", "Confirm whether scanning was approved", "Investigate related authentication or service exploitation events"],
    "other": ["Validate the alert against raw telemetry", "Identify the affected asset and business context", "Document triage outcome and escalation decision"],
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ip_context(ip: str | None) -> str:
    if not ip:
        return "Not supplied"
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "Unrecognised IP format"
    if address.is_global:
        return "Publicly routable (reputation not checked)"
    if address.is_private:
        return "Private/non-public address (reputation not checked)"
    return "Reserved/non-routable (reputation not checked)"


def classify(description: str, rule_id: str, event_id: str, groups: list[str]) -> str:
    text = f"{description} {' '.join(groups)}".lower()
    if event_id in ("4728", "4732", "4756", "4672") or any(t in text for t in ["added to administrators", "privileged group", "privilege escalat", "admin group", "group membership"]):
        return "privilege_change"
    if event_id in ("4720",) or any(t in text for t in ["account created", "new local user", "user account was created"]):
        return "account_created"
    if any(t in text for t in ["malware", "trojan", "virus detected", "ransomware detected"]):
        return "malware_detection"
    if any(t in text for t in ["powershell encoded", "suspicious process", "suspicious script", "encoded command"]):
        return "suspicious_execution"
    if "authentication" in text or "login failed" in text or "failed password" in text or "sshd" in text or "brute force" in text:
        return "authentication_failure"
    if any(t in text for t in ["sql injection", "path traversal", "idor", "unauthorized object", "web attack", "waf"]):
        return "web_attack"
    if "scan" in text or "port sweep" in text:
        return "network_scan"
    return "other"


def normalize(payload: dict[str, Any], source_override: str | None = None) -> dict[str, Any]:
    """Accept standard Wazuh alerts or a minimal generic event schema."""
    if not isinstance(payload, dict):
        raise ValueError("Each alert must be a JSON object")
    wazuh = isinstance(payload.get("rule"), dict) and isinstance(payload.get("agent"), dict)
    source = source_override or ("wazuh" if wazuh else str(payload.get("source") or "generic"))
    if wazuh:
        rule = payload["rule"]
        agent = payload["agent"]
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        win = data.get("win") if isinstance(data.get("win"), dict) else {}
        system = win.get("system") if isinstance(win.get("system"), dict) else {}
        eventdata = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
        event_id = str(system.get("eventID") or system.get("eventId") or "")
        groups = rule.get("groups") or []
        groups = groups if isinstance(groups, list) else []
        desc = str(rule.get("description") or "Wazuh alert")
        rule_id = str(rule.get("id") or "unknown")
        host = str(agent.get("name") or agent.get("id") or "unknown")
        level = int(rule.get("level", 5))
        source_ip = str(payload.get("srcip") or data.get("srcip") or eventdata.get("ipAddress") or "").strip()
        user = str(data.get("dstuser") or eventdata.get("targetUserName") or eventdata.get("subjectUserName") or "").strip()
        category = classify(desc, rule_id, event_id, groups)
        event_time = str(payload.get("timestamp") or utc_now())
    else:
        desc = str(payload.get("title") or payload.get("description") or "Security event")
        rule_id = str(payload.get("rule_id") or "custom")
        host = str(payload.get("host") or "unknown")
        level = int(payload.get("level", 5))
        source_ip = str(payload.get("source_ip") or "").strip()
        user = str(payload.get("user") or "").strip()
        category = str(payload.get("category") or "").strip()
        if category not in CATEGORY_FAMILY:
            category = classify(desc, rule_id, "", [])
        event_time = str(payload.get("timestamp") or utc_now())
    level = max(0, min(16, level))
    if len(desc) > 400 or len(host) > 120 or len(user) > 120 or len(source_ip) > 60:
        raise ValueError("Alert field exceeds maximum length")
    raw = json.dumps(payload, sort_keys=True, default=str)
    if len(raw.encode()) > 120_000:
        raise ValueError("Alert exceeds the per-event size limit")
    external_id = str(payload.get("id") or "")
    event_key = f"{source}:{external_id}" if external_id else f"{source}:sha256:{hashlib.sha256(raw.encode()).hexdigest()}"
    technique, technique_name = TECHNIQUES.get(category, ("", ""))
    return {
        "event_key": event_key, "source": source[:40], "event_time": event_time[:50],
        "host": host, "rule_id": rule_id[:40], "level": level, "source_ip": source_ip,
        "username": user, "title": desc, "category": category,
        "family": CATEGORY_FAMILY[category], "technique": technique,
        "technique_name": technique_name, "raw_json": raw,
    }


def calculate_risk(alerts: list[dict[str, Any]]) -> tuple[int, str, list[str]]:
    if not alerts:
        return 0, "low", []
    peak = max(int(a["level"]) for a in alerts)
    score = 10 + peak * 5
    reasons = [f"Highest source rule level: {peak}/16"]
    categories = {a["category"] for a in alerts}
    if "privilege_change" in categories:
        score += 17
        reasons.append("Privileged account or group change observed")
    if "suspicious_execution" in categories:
        score += 8
        reasons.append("Suspicious execution event observed")
    if "malware_detection" in categories:
        score += 12
        reasons.append("Malware-related alert observed (not independently verified)")
    if len(alerts) > 1:
        score += min(12, (len(alerts) - 1) * 3)
        reasons.append(f"{len(alerts)} related alerts correlated on one host")
    if len(alerts) >= 3 and categories == {"authentication_failure"}:
        score += 10
        reasons.append("Repeated authentication failures on one host warrant triage")
    if {"suspicious_execution", "account_created", "privilege_change"}.issubset(categories):
        score += 9
        reasons.append("Execution, account creation and privilege change occur together")
    if any(a.get("source_ip") and ip_context(a["source_ip"]).startswith("Publicly") for a in alerts):
        score += 4
        reasons.append("An alert contains a publicly routable source IP; reputation unverified")
    score = min(100, score)
    severity = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low"
    return score, severity, reasons


def family_title(family: str, host: str) -> str:
    return {
        "authentication": f"Authentication activity on {host}",
        "endpoint_account_activity": f"Suspicious endpoint / account activity on {host}",
        "web_application": f"Web application security events on {host}",
        "network_discovery": f"Network discovery activity on {host}",
    }.get(family, f"Security events on {host}")
