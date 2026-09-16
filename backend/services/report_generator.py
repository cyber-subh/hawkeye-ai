"""
Incident report generator.

Turns a correlated incident (+ its MITRE tags) into a human-readable
report an analyst can act on immediately. Uses the LLM when available
for a natural-language summary; otherwise falls back to a deterministic
template so the feature always works.
"""

from .llm_client import ask_llm, llm_enabled


def _fmt_ts(value: str) -> str:
    """Trim an ISO timestamp to 'YYYY-MM-DD HH:MM:SS' for human-readable reports."""
    return str(value).replace("T", " ").split(".")[0]


def _template_report(incident: dict, mitre_tags: list) -> dict:
    """Deterministic fallback report - no LLM required."""
    technique_names = ", ".join(f"{t['technique_id']} ({t['technique_name']})" for t in mitre_tags) or "None identified"

    summary = (
        f"Incident #{incident['id']}: {incident['event_count']} related events observed from "
        f"source IP {incident['src_ip']}"
        + (f" (user: {incident['user']})" if incident.get('user') else "")
        + f" between {_fmt_ts(incident['first_seen'])} and {_fmt_ts(incident['last_seen'])}. "
        f"Assets involved: {', '.join(incident['assets_involved'])}. "
        f"Matched MITRE ATT&CK techniques: {technique_names}. "
        f"{incident['reason']}"
    )

    actions = _default_actions(incident, mitre_tags)

    return {
        "incident_id": incident["id"],
        "summary": summary,
        "affected_assets": incident["assets_involved"],
        "severity": incident["severity"],
        "recommended_actions": actions,
        "generated_by": "template",
    }


def _default_actions(incident: dict, mitre_tags: list) -> list:
    technique_ids = {t["technique_id"] for t in mitre_tags}
    actions = []

    if "T1110" in technique_ids:
        actions.append(f"Block or rate-limit source IP {incident['src_ip']} at the firewall/WAF.")
        actions.append("Force a password reset for the targeted account and review MFA enforcement.")
    if "T1078" in technique_ids:
        actions.append("Verify the login location/device with the account owner; consider session revocation.")
    if "T1021" in technique_ids:
        actions.append("Isolate affected hosts and audit the account's access scope for unnecessary privileges.")
    if "T1046" in technique_ids:
        actions.append(f"Add {incident['src_ip']} to the watchlist and review exposed ports on {', '.join(incident['assets_involved'])}.")
    if "T1486" in technique_ids:
        actions.append("Immediately isolate the affected file server from the network to contain potential ransomware.")
        actions.append("Restore affected files from the latest clean backup after containment.")
    if "T1071" in technique_ids:
        actions.append("Block outbound traffic to the flagged IP and inspect the host for malware/implants.")

    if not actions:
        actions.append("Review the raw events manually; no automated playbook matched this pattern.")

    actions.append("Document findings and escalate to Tier 2 if severity is high or critical.")
    return actions


def generate_report(incident: dict, mitre_tags: list) -> dict:
    """
    Generate an incident report. Tries the LLM first (for a richer,
    natural-language write-up); falls back to the template if the LLM
    isn't configured or the call fails for any reason.
    """
    if not llm_enabled():
        return _template_report(incident, mitre_tags)

    technique_lines = "\n".join(
        f"- {t['technique_id']} ({t['technique_name']}) - Tactic: {t['tactic']}" for t in mitre_tags
    ) or "None identified"

    event_lines = "\n".join(
        f"- [{e['timestamp']}] {e['event_type']} on {e['asset']}"
        + (f" (user: {e['user']})" if e.get('user') else "")
        + (f": {e['raw_message']}" if e.get('raw_message') else "")
        for e in incident["events"]
    )

    prompt = f"""You are a SOC (Security Operations Center) analyst assistant. Write a concise, professional
incident report based on the correlated alert data below. The audience is a security analyst who needs
to quickly understand what happened and what to do next.

Incident metadata:
- Source IP: {incident['src_ip']}
- User: {incident.get('user') or 'N/A'}
- Assets involved: {', '.join(incident['assets_involved'])}
- Severity: {incident['severity']} (score: {incident['severity_score']}/100)
- Time range: {_fmt_ts(incident['first_seen'])} to {_fmt_ts(incident['last_seen'])}
- Automated flagging reason: {incident['reason']}

Matched MITRE ATT&CK techniques:
{technique_lines}

Raw correlated events:
{event_lines}

Write the report with these exact sections:
1. Summary (2-3 sentences, plain English, no jargon overload)
2. Affected Assets (bullet list)
3. Severity Justification (1-2 sentences on why this severity level)
4. Recommended Actions (3-5 concrete, prioritized bullet points)

Keep the whole report under 250 words. Do not use markdown headers with #, just bold labels."""

    try:
        llm_text = ask_llm(prompt)
        return {
            "incident_id": incident["id"],
            "summary": llm_text,
            "affected_assets": incident["assets_involved"],
            "severity": incident["severity"],
            "recommended_actions": _default_actions(incident, mitre_tags),  # keep structured actions too
            "generated_by": "llm",
        }
    except Exception:
        # Any LLM failure (network, rate limit, etc.) - degrade gracefully
        return _template_report(incident, mitre_tags)
