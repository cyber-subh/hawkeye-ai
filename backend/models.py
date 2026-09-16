"""
Pydantic models used across HawkEye AI.
These define the shape of data flowing between ingestion, correlation,
MITRE mapping, report generation, and the API layer.
"""

from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


class LogEvent(BaseModel):
    """A single raw security log/event coming from any source
    (firewall, endpoint, auth system, IDS, etc.)"""
    timestamp: datetime
    src_ip: str
    user: Optional[str] = None
    asset: str
    event_type: str  # e.g. failed_login, port_scan, privilege_escalation
    raw_message: Optional[str] = None
    geo_country: Optional[str] = None


class LogIngestRequest(BaseModel):
    logs: List[LogEvent]


class MitreTag(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str


class Incident(BaseModel):
    id: int
    src_ip: str
    user: Optional[str]
    assets_involved: List[str]
    event_count: int
    first_seen: datetime
    last_seen: datetime
    severity: str  # low / medium / high / critical
    severity_score: int  # 0-100
    mitre_tags: List[MitreTag]
    reason: str  # human-readable "why flagged" explanation
    events: List[LogEvent]


class IncidentReport(BaseModel):
    incident_id: int
    summary: str
    affected_assets: List[str]
    severity: str
    recommended_actions: List[str]
    generated_by: str  # "llm" or "template"


class ChatRequest(BaseModel):
    message: str
    incident_id: Optional[int] = None  # optional context to scope the question


class ChatResponse(BaseModel):
    reply: str
