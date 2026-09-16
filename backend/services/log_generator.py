"""
Synthetic log generator.

Generates realistic-looking SOC log data:
- Background "noise" (normal everyday events)
- Embedded attack scenarios (brute force, lateral movement, ransomware-like
  file encryption, port scans, C2 beaconing) so the correlation engine has
  something meaningful to detect.

This lets you develop and demo HawkEye without needing a real log source.
Swap this out later for a real ingestion pipeline (Syslog, Windows Event
Forwarding, EDR export, etc.) - the rest of the system doesn't care where
logs come from as long as they match the LogEvent schema.
"""

import random
from datetime import datetime, timedelta

USERS = ["john.doe", "priya.sharma", "admin", "svc_backup", "amit.verma", "guest"]
ASSETS = ["web-server-01", "db-server-02", "workstation-15", "workstation-22",
          "file-server-01", "vpn-gateway", "domain-controller-01"]
COUNTRIES = ["IN", "US", "RU", "CN", "NL", "BR"]

NORMAL_EVENT_TYPES = ["successful_login", "file_access", "app_usage", "logout"]


def _random_ip(suspicious=False):
    if suspicious:
        # Simulate external/unusual IP ranges
        return f"{random.choice([45, 91, 103, 185])}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    return f"192.168.1.{random.randint(2, 254)}"


def _ts(minutes_ago):
    return (datetime.utcnow() - timedelta(minutes=minutes_ago)).isoformat()


def _normal_noise(count=40):
    """Generate benign background events."""
    events = []
    for _ in range(count):
        events.append({
            "timestamp": _ts(random.randint(0, 500)),
            "src_ip": _random_ip(),
            "user": random.choice(USERS),
            "asset": random.choice(ASSETS),
            "event_type": random.choice(NORMAL_EVENT_TYPES),
            "raw_message": "Routine activity",
            "geo_country": "IN",
        })
    return events


def _scenario_brute_force():
    """A single external IP hammering login on one asset."""
    ip = _random_ip(suspicious=True)
    asset = random.choice(ASSETS)
    events = []
    base_minute = random.randint(20, 300)
    for i in range(6):
        events.append({
            "timestamp": _ts(base_minute - i),
            "src_ip": ip,
            "user": "admin",
            "asset": asset,
            "event_type": "failed_login",
            "raw_message": f"Failed login attempt for admin from {ip}",
            "geo_country": random.choice(["RU", "CN"]),
        })
    # followed by a successful login (breach!)
    events.append({
        "timestamp": _ts(base_minute - 6),
        "src_ip": ip,
        "user": "admin",
        "asset": asset,
        "event_type": "successful_login_unusual",
        "raw_message": f"Successful login for admin from unusual location {ip}",
        "geo_country": random.choice(["RU", "CN"]),
    })
    return events


def _scenario_lateral_movement():
    """One compromised user account touching multiple assets rapidly."""
    ip = _random_ip(suspicious=True)
    user = "svc_backup"
    events = []
    base_minute = random.randint(20, 250)
    for i, asset in enumerate(random.sample(ASSETS, 4)):
        events.append({
            "timestamp": _ts(base_minute - i * 2),
            "src_ip": ip,
            "user": user,
            "asset": asset,
            "event_type": "lateral_movement",
            "raw_message": f"Remote session established on {asset} using {user}",
            "geo_country": "IN",
        })
    return events


def _scenario_port_scan():
    """External IP scanning many ports/services on one asset."""
    ip = _random_ip(suspicious=True)
    asset = "vpn-gateway"
    events = []
    base_minute = random.randint(15, 200)
    for i in range(8):
        events.append({
            "timestamp": _ts(base_minute - i),
            "src_ip": ip,
            "user": None,
            "asset": asset,
            "event_type": "port_scan",
            "raw_message": f"Port scan detected from {ip} targeting {asset}",
            "geo_country": random.choice(["CN", "NL"]),
        })
    return events


def _scenario_ransomware():
    """Mass file encryption events on a file server - classic ransomware signature."""
    ip = _random_ip()
    asset = "file-server-01"
    user = "priya.sharma"
    events = []
    base_minute = random.randint(10, 120)
    for i in range(10):
        events.append({
            "timestamp": _ts(base_minute - i * 0.5),
            "src_ip": ip,
            "user": user,
            "asset": asset,
            "event_type": "file_encryption",
            "raw_message": f"Bulk file modification detected: {random.randint(50,300)} files renamed with .locked extension",
            "geo_country": "IN",
        })
    return events


def _scenario_c2_beaconing():
    """Regular-interval outbound connections to an external IP - beaconing pattern."""
    ip = _random_ip(suspicious=True)
    asset = "workstation-22"
    user = "amit.verma"
    events = []
    base_minute = random.randint(30, 340)
    for i in range(5):
        events.append({
            "timestamp": _ts(base_minute - i * 10),
            "src_ip": ip,
            "user": user,
            "asset": asset,
            "event_type": "suspicious_outbound",
            "raw_message": f"Outbound beacon-like connection to {ip} every ~10 minutes",
            "geo_country": random.choice(["RU", "BR"]),
        })
    return events


SCENARIOS = [
    _scenario_brute_force,
    _scenario_lateral_movement,
    _scenario_port_scan,
    _scenario_ransomware,
    _scenario_c2_beaconing,
]


def generate_logs(noise_count=40, num_scenarios=3):
    """
    Generate a batch of synthetic logs: background noise + a random
    selection of attack scenarios embedded in it.
    """
    events = _normal_noise(noise_count)
    chosen = random.sample(SCENARIOS, k=min(num_scenarios, len(SCENARIOS)))
    for scenario_fn in chosen:
        events.extend(scenario_fn())

    random.shuffle(events)
    return events


def generate_all_scenarios():
    """Generate noise + ALL attack scenarios at once (good for demo)."""
    events = _normal_noise(50)
    for scenario_fn in SCENARIOS:
        events.extend(scenario_fn())
    random.shuffle(events)
    return events
