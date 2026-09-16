"""
Analytics service.

Aggregates the correlated incident list into the summary numbers the
dashboard visualises: severity breakdown, MITRE ATT&CK coverage, the
most-targeted assets, the noisiest source IPs, and an hourly activity
timeline.

All of this could technically be computed in the browser, but doing it
here keeps the frontend simple, keeps the aggregation logic testable in
Python, and means any future client (a CLI, a report exporter, another
dashboard) gets the same numbers for free.
"""

from collections import Counter, defaultdict
from datetime import datetime

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _parse_ts(value: str) -> datetime:
    """Parse an ISO timestamp string, tolerating trailing 'Z' or missing microseconds."""
    try:
        return datetime.fromisoformat(value.replace("Z", ""))
    except (ValueError, AttributeError):
        return datetime.utcnow()


def build_stats(incidents: list) -> dict:
    """
    Turn the correlated incident list into everything the dashboard's
    overview panels need, in one pass.
    """
    severity_counts = Counter()
    technique_counts = Counter()
    technique_names = {}
    asset_counts = Counter()
    ip_counts = Counter()
    event_type_counts = Counter()
    hourly = defaultdict(int)

    total_events = 0
    highest = None

    for inc in incidents:
        severity_counts[inc["severity"]] += 1
        total_events += inc["event_count"]

        for tag in inc.get("mitre_tags", []):
            technique_counts[tag["technique_id"]] += 1
            technique_names[tag["technique_id"]] = tag["technique_name"]

        for asset in inc["assets_involved"]:
            asset_counts[asset] += 1

        ip_counts[inc["src_ip"]] += inc["event_count"]

        for event in inc["events"]:
            event_type_counts[event["event_type"]] += 1
            hour_key = _parse_ts(event["timestamp"]).strftime("%H:00")
            hourly[hour_key] += 1

        if highest is None or inc["severity_score"] > highest["severity_score"]:
            highest = inc

    return {
        "total_incidents": len(incidents),
        "total_events": total_events,
        "unique_ips": len(ip_counts),
        "unique_assets": len(asset_counts),
        "severity_breakdown": [
            {"severity": sev, "count": severity_counts.get(sev, 0)} for sev in SEVERITY_ORDER
        ],
        "mitre_coverage": [
            {"technique_id": tid, "technique_name": technique_names[tid], "count": count}
            for tid, count in technique_counts.most_common()
        ],
        "top_assets": [
            {"asset": asset, "count": count} for asset, count in asset_counts.most_common(5)
        ],
        "top_ips": [
            {"src_ip": ip, "count": count} for ip, count in ip_counts.most_common(5)
        ],
        "event_type_breakdown": [
            {"event_type": et, "count": count} for et, count in event_type_counts.most_common()
        ],
        "hourly_activity": [
            {"hour": hour, "count": hourly[hour]} for hour in sorted(hourly.keys())
        ],
        "highest_severity_incident": (
            {
                "id": highest["id"],
                "src_ip": highest["src_ip"],
                "severity": highest["severity"],
                "severity_score": highest["severity_score"],
            }
            if highest
            else None
        ),
    }
