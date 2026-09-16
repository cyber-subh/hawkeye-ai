"""
MITRE ATT&CK mapping service.

Maps event_type strings to MITRE ATT&CK techniques using the local
mitre_lite.json reference data. Uses simple keyword matching, which is
fast, deterministic, and fully explainable - good enough for a portfolio
project. If you want to make this "smarter" later, swap the matching
logic for embedding-based semantic similarity (e.g. sentence-transformers)
against the `description` field of each technique, without changing the
public function signature below.
"""

import json
import os

_MITRE_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "mitre_lite.json")

with open(_MITRE_PATH, "r") as f:
    MITRE_DB = json.load(f)

# Build a flat lookup: event_type keyword -> technique_id
_KEYWORD_TO_TECHNIQUE = {}
for technique_id, info in MITRE_DB.items():
    for kw in info["keywords"]:
        _KEYWORD_TO_TECHNIQUE[kw] = technique_id


def map_event_type(event_type: str):
    """Return a MITRE tag dict for a single event_type, or None if no match."""
    technique_id = _KEYWORD_TO_TECHNIQUE.get(event_type)
    if not technique_id:
        return None
    info = MITRE_DB[technique_id]
    return {
        "technique_id": technique_id,
        "technique_name": info["name"],
        "tactic": info["tactic"],
    }


def map_incident_events(events: list):
    """
    Given a list of events belonging to one incident, return a de-duplicated
    list of MITRE tags covering all techniques observed.
    """
    tags = {}
    for event in events:
        tag = map_event_type(event["event_type"])
        if tag:
            tags[tag["technique_id"]] = tag
    return list(tags.values())
