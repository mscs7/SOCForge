"""Opt-in, minimal outbound POST to n8n. No real containment or auto-blocking."""
import json
import urllib.error
import urllib.parse
import urllib.request

from .db import record_automation


def deliver(path: str, webhook_url: str, incident_id: int, severity: str, title: str, score: int) -> None:
    parsed = urllib.parse.urlparse(webhook_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        record_automation(path, incident_id, "n8n", "error", "Invalid configured webhook URL")
        return
    payload = json.dumps({"event": "socforge.incident", "incident_id": incident_id,
                          "title": title, "severity": severity, "risk_score": score,
                          "mode": "lab", "action": "triage_required"}).encode("utf-8")
    try:
        req = urllib.request.Request(webhook_url, payload,
              headers={"Content-Type": "application/json", "User-Agent": "SOCForge/1.0"}, method="POST")
        with urllib.request.urlopen(req, timeout=3) as response:
            status = getattr(response, "status", 200)
            if 200 <= status < 300:
                record_automation(path, incident_id, "n8n", "sent", f"HTTP {status}; incident notification delivered")
            else:
                record_automation(path, incident_id, "n8n", "error", f"n8n returned HTTP {status}")
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        record_automation(path, incident_id, "n8n", "error", f"Notification failed: {type(exc).__name__}")
