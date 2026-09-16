"""
HawkEye AI - AI SOC Analyst Copilot
Main FastAPI application.

Run with:
    uvicorn main:app --reload --port 8000

Endpoints:
    POST /api/logs/generate     -> generate fresh synthetic logs (for demo/dev)
    POST /api/logs/ingest       -> ingest your own logs (matches LogEvent schema)
    GET  /api/logs              -> raw logs currently stored
    GET  /api/alerts            -> correlated + MITRE-tagged incidents
    GET  /api/alerts/{id}       -> single incident detail
    GET  /api/alerts/{id}/report-> AI-generated incident report
    POST /api/chat              -> ask the copilot a question
    DELETE /api/logs             -> clear all stored logs (reset demo)
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from models import LogIngestRequest, ChatRequest, ChatResponse
import db
from services.log_generator import generate_logs, generate_all_scenarios
from services.correlation import correlate_logs
from services.mitre_mapper import map_incident_events
from services.report_generator import generate_report
from services.chat_service import answer_question
from services.llm_client import llm_enabled
from services.analytics import build_stats

app = FastAPI(title="HawkEye AI - SOC Analyst Copilot")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

db.init_db()


def _get_correlated_incidents():
    """Fetch all logs and run them through correlation + MITRE mapping."""
    logs = db.fetch_all_logs()
    incidents = correlate_logs(logs)
    for inc in incidents:
        inc["mitre_tags"] = map_incident_events(inc["events"])
    return incidents


@app.get("/api/status")
def status():
    return {
        "status": "ok",
        "llm_enabled": llm_enabled(),
        "log_count": db.count_logs(),
    }


@app.post("/api/logs/generate")
def generate_demo_logs(full: bool = False):
    """
    Generate synthetic demo logs and store them.
    full=true generates every attack scenario at once (good for a demo).
    """
    events = generate_all_scenarios() if full else generate_logs()
    db.insert_logs(events)
    return {"inserted": len(events)}


@app.post("/api/logs/ingest")
def ingest_logs(payload: LogIngestRequest):
    """Ingest external logs matching the LogEvent schema."""
    events = [
        {
            "timestamp": log.timestamp.isoformat(),
            "src_ip": log.src_ip,
            "user": log.user,
            "asset": log.asset,
            "event_type": log.event_type,
            "raw_message": log.raw_message,
            "geo_country": log.geo_country,
        }
        for log in payload.logs
    ]
    db.insert_logs(events)
    return {"inserted": len(events)}


@app.get("/api/stats")
def get_stats():
    """
    Aggregated dashboard analytics: severity breakdown, MITRE ATT&CK
    coverage, top targeted assets, noisiest source IPs, and an hourly
    activity timeline.
    """
    return build_stats(_get_correlated_incidents())


@app.get("/api/logs")
def get_logs(limit: int = 200):
    return db.fetch_all_logs(limit=limit)


@app.delete("/api/logs")
def reset_logs():
    db.clear_logs()
    return {"status": "cleared"}


@app.get("/api/alerts")
def get_alerts():
    return _get_correlated_incidents()


@app.get("/api/alerts/{incident_id}")
def get_alert(incident_id: int):
    incidents = _get_correlated_incidents()
    for inc in incidents:
        if inc["id"] == incident_id:
            return inc
    raise HTTPException(status_code=404, detail="Incident not found")


@app.get("/api/alerts/{incident_id}/report")
def get_alert_report(incident_id: int):
    incidents = _get_correlated_incidents()
    for inc in incidents:
        if inc["id"] == incident_id:
            return generate_report(inc, inc["mitre_tags"])
    raise HTTPException(status_code=404, detail="Incident not found")


@app.post("/api/chat", response_model=ChatResponse)
def chat(payload: ChatRequest):
    incidents = _get_correlated_incidents()
    reply = answer_question(payload.message, incidents, payload.incident_id)
    return ChatResponse(reply=reply)


# --- Serve the frontend dashboard as static files ---
# Mounted at root ("/") with html=True so that:
#   - "/" automatically serves frontend/index.html
#   - relative paths inside index.html (css/style.css, js/app.js, assets/logo.png)
#     resolve correctly, since everything shares the same origin/path base.
# NOTE: this mount is registered LAST, after all /api/... routes above, so those
# routes are matched first and this mount only catches everything else.
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="static")
