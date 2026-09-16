"""
Analyst chat service.

Lets an analyst ask natural-language questions about the current logs/
incidents (e.g. "what happened with john.doe in the last hour?").
Passes relevant context (either one incident, or a summary of all
incidents) to the LLM. Falls back to a rule-based responder if the LLM
isn't configured - this handles a handful of common query patterns
(severity filters, summary/overview requests, MITRE technique lookups,
and IP/user/asset keyword search) so the dashboard stays useful even
without an API key.
"""

from .llm_client import ask_llm, llm_enabled

SEVERITY_WORDS = ["critical", "high", "medium", "low"]
SUMMARY_WORDS = ["summary", "overview", "how many", "total", "all incidents", "what's happening", "whats happening", "status"]


def _format_incident_line(inc: dict) -> str:
    return (
        f"Incident #{inc['id']} ({inc['severity']}): {inc['event_count']} events from "
        f"{inc['src_ip']}, involving {', '.join(inc['assets_involved'])}. {inc['reason']}"
    )


def _fallback_reply(message: str, incidents: list) -> str:
    """
    Rule-based fallback used when no LLM is configured. Handles:
    1. Summary/overview questions ("how many incidents", "give me a summary")
    2. Severity-filtered questions ("show me critical incidents")
    3. MITRE technique questions ("which incidents involve T1486" / "ransomware")
    4. Keyword search against IP / user / asset (original behavior)
    """
    message_lower = message.lower()

    if not incidents:
        return "There are no incidents right now. Generate some logs first, then ask me again."

    # 1. Summary / overview style questions
    if any(w in message_lower for w in SUMMARY_WORDS):
        counts = {}
        for inc in incidents:
            counts[inc["severity"]] = counts.get(inc["severity"], 0) + 1
        breakdown = ", ".join(f"{v} {k}" for k, v in counts.items())
        top = sorted(incidents, key=lambda i: i["severity_score"], reverse=True)[:3]
        top_lines = "\n".join(_format_incident_line(i) for i in top)
        return (
            f"{len(incidents)} incident(s) currently correlated: {breakdown}.\n\n"
            f"Top {len(top)} by severity:\n{top_lines}"
        )

    # 2. Severity-filtered questions
    for sev in SEVERITY_WORDS:
        if sev in message_lower:
            matches = [i for i in incidents if i["severity"] == sev]
            if not matches:
                return f"No {sev}-severity incidents right now."
            lines = "\n".join(_format_incident_line(i) for i in matches[:5])
            return f"{len(matches)} {sev}-severity incident(s):\n{lines}"

    # 3. MITRE technique / attack-type questions
    mitre_keyword_map = {
        "brute force": "T1110", "t1110": "T1110",
        "ransomware": "T1486", "encrypt": "T1486", "t1486": "T1486",
        "lateral movement": "T1021", "t1021": "T1021",
        "port scan": "T1046", "scanning": "T1046", "t1046": "T1046",
        "phishing": "T1566", "t1566": "T1566",
        "beacon": "T1071", "c2": "T1071", "t1071": "T1071",
        "privilege escalation": "T1068", "t1068": "T1068",
        "valid account": "T1078", "t1078": "T1078",
    }
    for keyword, technique_id in mitre_keyword_map.items():
        if keyword in message_lower:
            matches = [i for i in incidents if any(t["technique_id"] == technique_id for t in i.get("mitre_tags", []))]
            if not matches:
                return f"No incidents currently match {technique_id}."
            lines = "\n".join(_format_incident_line(i) for i in matches[:5])
            return f"{len(matches)} incident(s) matching {technique_id}:\n{lines}"

    # 4. Original keyword search against IP / user / asset
    matches = []
    for inc in incidents:
        haystack = f"{inc['src_ip']} {inc.get('user','')} {' '.join(inc['assets_involved'])}".lower()
        if any(word in haystack for word in message_lower.split() if len(word) > 2):
            matches.append(inc)

    if not matches:
        return (
            "I couldn't find a match for that (LLM is not configured, so this is a rule-based "
            "responder - set ANTHROPIC_API_KEY for full natural-language answers). Try asking "
            "about a specific IP, username, asset name, severity level (critical/high/medium/low), "
            "an attack type (ransomware/brute force/phishing/etc.), or ask for a \"summary\"."
        )

    lines = "\n".join(_format_incident_line(i) for i in matches[:3])
    return lines


def answer_question(message: str, incidents: list, incident_id: int = None) -> str:
    scoped_incidents = incidents
    if incident_id is not None:
        scoped_incidents = [i for i in incidents if i["id"] == incident_id]

    if not llm_enabled():
        return _fallback_reply(message, scoped_incidents or incidents)

    context_lines = []
    for inc in scoped_incidents[:10]:  # cap context size
        context_lines.append(
            f"Incident #{inc['id']} | severity={inc['severity']} | src_ip={inc['src_ip']} | "
            f"user={inc.get('user')} | assets={inc['assets_involved']} | "
            f"time={inc['first_seen']} to {inc['last_seen']} | reason={inc['reason']}"
        )
    context_block = "\n".join(context_lines) if context_lines else "No incidents currently correlated."

    prompt = f"""You are a SOC analyst copilot embedded in a security dashboard. An analyst is asking you
a question. Answer using ONLY the incident context provided below - if the answer isn't in the context,
say so honestly rather than guessing. Be concise and direct, like a colleague, not a formal report.

Incident context:
{context_block}

Analyst question: {message}
"""

    try:
        return ask_llm(prompt, max_tokens=400)
    except Exception:
        return _fallback_reply(message, scoped_incidents or incidents)
