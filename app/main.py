"""SOCForge v1: local, explicitly non-production SOC automation lab."""
from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from . import db
from .engine import normalize, ip_context, PLAYBOOKS
from .notifications import deliver

BASE = Path(__file__).resolve().parent.parent
STATIC = BASE / "app" / "static"


class TriageUpdate(BaseModel):
    status: Literal["new", "investigating", "contained", "resolved", "false_positive"] | None = None
    analyst: str | None = Field(default=None, min_length=1, max_length=80)


class NoteCreate(BaseModel):
    author: str = Field(default="Analyst", min_length=1, max_length=60)
    content: str = Field(min_length=3, max_length=4000)


class ActionRequest(BaseModel):
    action: Literal["request_containment", "approve_simulation"]


class ResetRequest(BaseModel):
    confirm: Literal["RESET_DEMO"]


def create_app(db_path: str | None = None, api_key: str | None = None, n8n_url: str | None = None) -> FastAPI:
    database = db_path if db_path is not None else os.environ.get("SOCFORGE_DB", str(BASE / "data" / "socforge.db"))
    secret = api_key if api_key is not None else os.environ.get("SOCFORGE_API_KEY", "")
    webhook = n8n_url if n8n_url is not None else os.environ.get("SOCFORGE_N8N_WEBHOOK_URL", "")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db.initialise(database)
        yield

    app = FastAPI(title="SOCForge Lab API", version="1.0.0", description="Local SOC triage prototype; NOT a production SOAR", lifespan=lifespan)
    app.state.database = database

    def ingest_one(payload: dict[str, Any], source_override: str | None = None) -> dict[str, Any]:
        try:
            alert = normalize(payload, source_override=source_override)
            return db.ingest(database, alert)
        except (ValueError, TypeError, OverflowError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/assets/{name}", include_in_schema=False)
    def asset(name: str):
        if name not in {"app.js", "app.css"}:
            raise HTTPException(404)
        media = "text/javascript" if name.endswith("js") else "text/css"
        return FileResponse(STATIC / name, media_type=media)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "1.0.0", "mode": "local_lab",
                "wazuh_adapter": "available", "n8n_configured": bool(webhook),
                "ingestion_api_key_enabled": bool(secret), "real_containment_enabled": False}

    @app.post("/api/alerts")
    async def post_alerts(request: Request, background_tasks: BackgroundTasks, x_api_key: str | None = Header(default=None)):
        # A configured key protects Wazuh/third-party alert ingestion. UI is local-only by design.
        import hmac
        if secret and not hmac.compare_digest(x_api_key or "", secret):
            raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")
        body = await request.body()
        if len(body) > 1_048_576:
            raise HTTPException(413, detail="Request must be 1 MiB or less")
        try:
            items = json.loads(body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise HTTPException(400, detail="Expected valid JSON") from exc
        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, list) or len(items) > 50 or not items:
            raise HTTPException(422, detail="Provide 1-50 JSON alert objects")
        if any(not isinstance(item, dict) for item in items):
            raise HTTPException(422, detail="Every alert must be an object")
        results = []
        for item in items:
            result = ingest_one(item)
            results.append(result)
            if webhook and result.get("notify"):
                incident = db.get_incident(database, result["incident_id"])
                background_tasks.add_task(deliver, database, webhook, incident["id"], incident["severity"], incident["title"], incident["score"])
        return {"accepted": sum(1 for r in results if r["created"]), "duplicates": sum(1 for r in results if not r["created"]), "results": results}

    @app.get("/api/metrics")
    def metrics():
        return db.metrics(database)

    @app.get("/api/activity")
    def activity(days: int = Query(default=7, ge=1, le=30)):
        return db.activity(database, days)

    @app.get("/api/incidents")
    def incidents(status: str = "", severity: str = "", search: str = ""):
        if status not in ("", "new", "investigating", "contained", "resolved", "false_positive"):
            raise HTTPException(422, detail="Invalid status")
        if severity not in ("", "critical", "high", "medium", "low"):
            raise HTTPException(422, detail="Invalid severity")
        return db.list_incidents(database, status, severity, search[:120])

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: int):
        result = db.get_incident(database, incident_id)
        if not result:
            raise HTTPException(404, detail="Incident not found")
        result["playbook"] = PLAYBOOKS.get(result["family"], PLAYBOOKS["other"])
        result["indicator_context"] = [{"value": value, "context": ip_context(value)} for value in result["indicators"]]
        return result

    @app.patch("/api/incidents/{incident_id}")
    def triage(incident_id: int, body: TriageUpdate):
        if body.status is None and body.analyst is None:
            raise HTTPException(422, detail="Provide status or analyst")
        if not db.change_triage(database, incident_id, body.status, body.analyst):
            raise HTTPException(404, detail="Incident not found")
        return {"ok": True, "incident": db.get_incident(database, incident_id)}

    @app.post("/api/incidents/{incident_id}/notes")
    def add_note(incident_id: int, body: NoteCreate):
        if not db.add_note(database, incident_id, body.author.strip(), body.content.strip()):
            raise HTTPException(404, detail="Incident not found")
        return {"ok": True}

    @app.post("/api/incidents/{incident_id}/actions")
    def action(incident_id: int, body: ActionRequest):
        ok, message = db.response_action(database, incident_id, body.action)
        if not ok:
            raise HTTPException(409 if message.startswith("Request") else 404, detail=message)
        return {"ok": True, "message": message}

    @app.get("/api/incidents/{incident_id}/report")
    def report(incident_id: int):
        inc = db.get_incident(database, incident_id)
        if not inc:
            raise HTTPException(404, detail="Incident not found")
        lines = [f"# SOCForge Case Report — INC-{inc['id']:04d}", "", "> Lab-generated report. Incident data may be synthetic. Not a forensic finding.", "",
                 f"**Title:** {inc['title']}", f"**Host:** {inc['host']}", f"**Priority:** {inc['severity'].upper()} ({inc['score']}/100)",
                 f"**Status:** {inc['status']}", f"**Analyst:** {inc['analyst']}", f"**First seen:** {inc['first_seen']}",
                 "", "## Risk rationale"]
        lines.extend(f"- {r}" for r in inc["risk_reasons"])
        lines += ["", "## Evidence timeline"]
        lines.extend(f"- {a['event_time']} | {a['source']} | rule {a['rule_id']} | {a['title']}" for a in inc["alerts"])
        lines += ["", "## ATT&CK references (hypotheses, not confirmed attribution)"]
        lines.extend(f"- {tech}" for tech in inc["techniques"])
        lines += ["", "## Investigation notes"]
        lines.extend(f"- {note['created_at']} / {note['author']}: {note['content']}" for note in inc["notes"])
        lines += ["", "## Response and caveats", "- This tool never executes real network blocks, endpoint isolation, account removal or other containment commands.",
                  f"- Simulated response approved: {'yes' if inc['containment_simulated'] else 'no'}. "]
        return PlainTextResponse("\n".join(lines) + "\n", media_type="text/markdown",
                                 headers={"Content-Disposition": f'attachment; filename="SOCForge_INC-{incident_id:04d}.md"'})

    @app.get("/api/automation")
    def automation():
        return db.automation_log(database)

    @app.post("/api/demo/load")
    def demo_load():
        items = json.loads((BASE / "examples" / "demo_alerts.json").read_text(encoding="utf-8"))
        results = [ingest_one(payload, source_override="demo") for payload in items]
        return {"accepted": sum(r["created"] for r in results), "duplicates": sum(not r["created"] for r in results),
                "incidents": db.metrics(database)["total_incidents"]}

    @app.post("/api/demo/reset")
    def demo_reset(body: ResetRequest):
        return db.reset_demo(database)

    return app


app = create_app()
