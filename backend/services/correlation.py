"""
Correlation engine.

Groups raw log events into "incidents" - i.e. related events that likely
represent a single attack chain. Uses rule-based clustering (grouped by
src_ip + user, within a time window) rather than heavy ML, which keeps it
fast, transparent, and easy to explain (important for SOC tooling - a
black-box correlation decision is not trustworthy to an analyst).

Each incident also gets:
- a severity score (0-100) based on event types and volume
- a human-readable "reason" explaining why it was flagged (explainability)
"""

from datetime import datetime
from collections import defaultdict

# Weight given to each event type when computing severity.
# Higher = more dangerous behavior.
EVENT_SEVERITY_WEIGHTS = {
    "failed_login": 8,
    "successful_login_unusual": 25,
    "port_scan": 10,
    "lateral_movement": 20,
    "privilege_escalation": 30,
    "file_encryption": 40,
    "suspicious_outbound": 22,
    "successful_login": 1,
    "file_access": 1,
    "app_usage": 0,
    "logout": 0,
}

SEVERITY_THRESHOLDS = [
    (75, "critical"),
    (45, "high"),
    (20, "medium"),
    (0, "low"),
]


def _severity_label(score: int) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "low"


def _build_reason(events: list) -> str:
    """Build a plain-English explanation of why this group was flagged."""
    event_types = [e["event_type"] for e in events]
    reasons = []

    failed_logins = event_types.count("failed_login")
    if failed_logins >= 3:
        reasons.append(f"{failed_logins} failed login attempts in a short window")

    if "successful_login_unusual" in event_types:
        reasons.append("a successful login from an unusual location immediately after failed attempts")

    if "lateral_movement" in event_types:
        assets = set(e["asset"] for e in events if e["event_type"] == "lateral_movement")
        if len(assets) > 1:
            reasons.append(f"the same account accessed {len(assets)} different assets in quick succession")

    if event_types.count("port_scan") >= 3:
        reasons.append("repeated port/service scanning behavior")

    if "file_encryption" in event_types:
        reasons.append("mass file modification consistent with ransomware activity")

    if "suspicious_outbound" in event_types and event_types.count("suspicious_outbound") >= 3:
        reasons.append("regular-interval outbound connections consistent with C2 beaconing")

    if not reasons:
        reasons.append("multiple related events grouped by source and time proximity")

    return "Flagged because: " + "; ".join(reasons) + "."


def correlate_logs(logs: list, time_window_minutes: int = 15) -> list:
    """
    Group logs by (src_ip, user) key, then split into time-windowed
    sub-groups. Groups with meaningful signal (severity > 0 and more than
    one interesting event, OR a single high-severity event) become incidents.
    """
    grouped = defaultdict(list)
    for log in logs:
        key = f"{log['src_ip']}|{log.get('user') or 'unknown'}"
        grouped[key].append(log)

    incidents = []
    incident_id = 1

    for key, events in grouped.items():
        # sort by time
        events_sorted = sorted(events, key=lambda e: e["timestamp"])

        # only consider events that carry some signal (skip pure noise groups)
        signal_events = [e for e in events_sorted if EVENT_SEVERITY_WEIGHTS.get(e["event_type"], 0) > 0]
        if not signal_events:
            continue

        # require either multiple signal events, or one very severe event
        max_weight = max(EVENT_SEVERITY_WEIGHTS.get(e["event_type"], 0) for e in signal_events)
        if len(signal_events) < 2 and max_weight < 25:
            continue

        score = min(100, sum(EVENT_SEVERITY_WEIGHTS.get(e["event_type"], 0) for e in signal_events))
        severity = _severity_label(score)

        src_ip, user = key.split("|")
        assets_involved = sorted(set(e["asset"] for e in signal_events))

        incidents.append({
            "id": incident_id,
            "src_ip": src_ip,
            "user": None if user == "unknown" else user,
            "assets_involved": assets_involved,
            "event_count": len(signal_events),
            "first_seen": signal_events[0]["timestamp"],
            "last_seen": signal_events[-1]["timestamp"],
            "severity": severity,
            "severity_score": score,
            "reason": _build_reason(signal_events),
            "events": signal_events,
        })
        incident_id += 1

    # sort incidents by severity score, most severe first
    incidents.sort(key=lambda i: i["severity_score"], reverse=True)
    # re-assign display IDs after sorting so #1 is always the most severe
    for idx, inc in enumerate(incidents, start=1):
        inc["id"] = idx

    return incidents
