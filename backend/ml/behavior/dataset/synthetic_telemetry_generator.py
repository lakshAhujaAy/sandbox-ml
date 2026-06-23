"""
ml/behavior/dataset/synthetic_telemetry_generator.py
========================================================
Generates synthetic sandbox telemetry (network requests, process events,
file operations, logs) for bootstrapping the Behavior classifier's training
pipeline — same honest bootstrap pattern as the Vision model's synthetic
screenshot generator (see ml/vision/dataset/synthetic_generator.py and its
TRAINING_NOTES.md for the full rationale).

WHY SYNTHETIC: there is no public dataset of raw sandbox telemetry logs
(network requests + process events + file operations) paired with
malicious/benign labels. Real datasets in this space (e.g. EMBER, SOREL-20M)
provide static PE file features, not dynamic sandbox execution traces in
this schema, and accessing live malware samples to generate real traces
requires infrastructure (an actual malware sandbox, isolated network,
samples from VirusTotal/MalwareBazaar) well beyond this project's scope.

WHAT'S REAL ABOUT THIS DATA: the behavioral ARCHETYPES below are not
invented arbitrarily — each one encodes a well-documented, named malware
technique (cited inline), the same techniques BehaviorAnalyzer's rule-based
fallback already checks for. This generator produces RAW telemetry (request
lists, process spawn events) that EXERCISES those techniques realistically,
rather than directly writing the already-aggregated feature counts — so the
trained model has to learn the same pattern-recognition task a real
classifier would, not just memorize summary statistics.

WHAT'S NOT REAL: actual malware never ran. No real network traffic, no real
process trees. This is a structured simulation for pipeline-validation,
exactly like the Vision model's synthetic screenshots.
"""
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List


# ── Benign archetypes ──────────────────────────────────────────────────────────
# Realistic legitimate browsing/application sessions — no malicious indicators.

BENIGN_DOMAINS = [
    "cdn.jsdelivr.net", "fonts.googleapis.com", "ajax.googleapis.com",
    "cdnjs.cloudflare.com", "www.google-analytics.com", "static.cloudflareinsights.com",
    "github.com", "api.github.com", "raw.githubusercontent.com",
    "stackoverflow.com", "cdn.segment.com", "fonts.gstatic.com",
]

BENIGN_CONTENT_TYPES = [
    "text/html", "text/css", "application/javascript", "image/png",
    "image/jpeg", "image/svg+xml", "application/json", "font/woff2",
]


def generate_benign_session() -> Dict[str, Any]:
    """A normal page load: a handful of requests to CDNs/analytics, one
    browser process, no file writes, no suspicious processes."""
    now = datetime.now(timezone.utc)
    # Wide range, including sparse single-page sites — a legitimate site
    # can load from just 1-2 hosts (e.g. a static page with no CDN deps),
    # so host count alone must NOT be a reliable malicious/benign signal.
    num_requests = random.randint(1, 15)
    hosts = random.choices(BENIGN_DOMAINS, k=num_requests)  # with replacement — allows repeats/low unique counts

    network_requests = []
    for i, host in enumerate(hosts):
        network_requests.append({
            "url": f"https://{host}/{'assets/' if random.random() > 0.5 else ''}resource_{i}.{'js' if random.random() > 0.5 else 'css'}",
            "method": "GET",
            "status": 200,
            "content_type": random.choice(BENIGN_CONTENT_TYPES),
        })

    process_events = [
        {"pid": 1000, "name": "chromium", "event": "spawn", "args": ["--headless"]},
    ]
    # Browsers do spawn a small number of renderer/GPU child processes legitimately
    if random.random() < 0.4:
        process_events.append({
            "pid": 1001, "name": "chromium", "event": "spawn",
            "args": ["--type=renderer"],
        })

    logs = [{
        "timestamp": (now + timedelta(milliseconds=i * 50)).isoformat(),
        "level": "info", "category": "network",
        "message": f"GET {r['url']} -> {r['status']} OK",
    } for i, r in enumerate(network_requests[:5])]

    return {
        "network_requests": network_requests,
        "process_events": process_events,
        "file_operations": [],
        "logs": logs,
        "label": "benign",
        "archetype": "normal_page_load",
    }


def generate_benign_login_form() -> Dict[str, Any]:
    """A LEGITIMATE login page (e.g. a real bank or email provider) — has a
    password field (which the rule-based fallback flags as a mild signal)
    but nothing else malicious. Tests that the model learns password forms
    alone aren't sufficient for a malicious verdict — context matters."""
    base = generate_benign_session()
    base["logs"].append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": "info", "category": "visual",
        "message": "Password input field detected on page (forms=1, pwd_inputs=1)",
    })
    base["archetype"] = "legitimate_login_page"
    return base


# ── Malicious archetypes ───────────────────────────────────────────────────────
# Each grounded in a real, named, documented technique.

def generate_drive_by_download() -> Dict[str, Any]:
    """
    Drive-by download: page silently fetches and would execute a binary
    payload without user interaction. Classic technique documented across
    MITRE ATT&CK T1189 (Drive-by Compromise).
    """
    now = datetime.now(timezone.utc)
    evil_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    payload_name = random.choice(["update.exe", "invoice.exe", "document.scr", "setup.msi"])

    network_requests = [
        {"url": "https://legit-looking-cdn.com/loader.js", "method": "GET", "status": 200, "content_type": "application/javascript"},
        {"url": f"http://{evil_ip}/{payload_name}", "method": "GET", "status": 200, "content_type": "application/octet-stream"},
    ]
    process_events = [
        {"pid": 2000, "name": "chromium", "event": "spawn", "args": ["--headless"]},
    ]
    logs = [
        {"timestamp": now.isoformat(), "level": "info", "category": "network", "message": "GET https://legit-looking-cdn.com/loader.js -> 200 OK"},
        {"timestamp": (now + timedelta(milliseconds=300)).isoformat(), "level": "alert", "category": "network",
         "message": f"Binary download detected: http://{evil_ip}/{payload_name} [application/octet-stream]"},
    ]

    return {
        "network_requests": network_requests,
        "process_events": process_events,
        "file_operations": [],
        "logs": logs,
        "label": "malicious",
        "archetype": "drive_by_download",
    }


def generate_powershell_dropper() -> Dict[str, Any]:
    """
    Obfuscated PowerShell dropper: page triggers a process that spawns
    powershell.exe with a base64-encoded -EncodedCommand argument — a
    well-documented technique (MITRE ATT&CK T1059.001 PowerShell,
    T1027 Obfuscated Files or Information) used to evade static signature
    detection.
    """
    now = datetime.now(timezone.utc)
    fake_b64 = "".join(random.choices(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", k=random.randint(40, 200)
    ))

    network_requests = [
        {"url": "https://compromised-site.net/index.html", "method": "GET", "status": 200, "content_type": "text/html"},
    ]
    process_events = [
        {"pid": 3000, "name": "chromium", "event": "spawn", "args": ["--headless"]},
        {"pid": 3001, "name": "powershell.exe", "event": "spawn",
         "args": ["-WindowStyle", "Hidden", "-EncodedCommand", fake_b64]},
    ]
    logs = [
        {"timestamp": now.isoformat(), "level": "info", "category": "network", "message": "GET https://compromised-site.net/index.html -> 200 OK"},
        {"timestamp": (now + timedelta(milliseconds=500)).isoformat(), "level": "alert", "category": "process",
         "message": "Suspicious process: encoded PowerShell spawned"},
    ]

    return {
        "network_requests": network_requests,
        "process_events": process_events,
        "file_operations": [],
        "logs": logs,
        "label": "malicious",
        "archetype": "powershell_dropper",
    }


def generate_c2_beacon() -> Dict[str, Any]:
    """
    Command-and-control beaconing: repeated outbound connections to a
    handful of IPs on non-standard ports commonly associated with C2
    frameworks (Metasploit's default 4444, Cobalt Strike's common 8080/443
    variants, etc.) — MITRE ATT&CK T1071 (Application Layer Protocol),
    T1571 (Non-Standard Port).

    Realistically also includes 0-3 legitimate-looking CDN requests first —
    real C2 frameworks (esp. Cobalt Strike) often "domain front" through
    legitimate CDN infrastructure to blend in before the actual beacon
    callback, so host count alone should not distinguish this from benign
    traffic; the malicious signal is the C2 port + IP-literal connection,
    not how many hosts were contacted.
    """
    now = datetime.now(timezone.utc)
    c2_ports = [4444, 8080, 1337, 9001]
    evil_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    port = random.choice(c2_ports)

    # Optional CDN-fronting noise (legitimate-looking requests before the beacon)
    network_requests = []
    if random.random() < 0.5:
        for host in random.sample(BENIGN_DOMAINS, k=random.randint(1, 4)):
            network_requests.append({
                "url": f"https://{host}/resource.js", "method": "GET", "status": 200,
                "content_type": "application/javascript",
            })

    network_requests += [
        {"url": f"http://{evil_ip}:{port}/beacon", "method": "POST", "status": 200, "content_type": "application/octet-stream"}
        for _ in range(random.randint(2, 5))
    ]
    process_events = [
        {"pid": 4000, "name": "chromium", "event": "spawn", "args": ["--headless"]},
    ]
    logs = [{
        "timestamp": (now + timedelta(seconds=i)).isoformat(), "level": "alert", "category": "network",
        "message": f"Connection to known C2 port: {evil_ip}:{port}",
    } for i in range(sum(1 for r in network_requests if str(port) in r["url"]))]

    return {
        "network_requests": network_requests,
        "process_events": process_events,
        "file_operations": [],
        "logs": logs,
        "label": "malicious",
        "archetype": "c2_beaconing",
    }


def generate_persistence_mechanism() -> Dict[str, Any]:
    """
    Filesystem persistence: writes to Windows Startup folder, System32, or
    a Linux crontab — MITRE ATT&CK T1547 (Boot or Logon Autostart
    Execution), T1053 (Scheduled Task/Job).
    """
    now = datetime.now(timezone.utc)
    sensitive_paths = [
        r"C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.exe",
        r"C:\Windows\System32\drivers\svchost_helper.dll",
        "/etc/crontab",
        "/etc/cron.d/system-update",
    ]
    path = random.choice(sensitive_paths)

    network_requests = [
        {"url": "http://malicious-payload-host.com/dropper.exe", "method": "GET", "status": 200, "content_type": "application/octet-stream"},
    ]
    process_events = [
        {"pid": 5000, "name": "chromium", "event": "spawn", "args": ["--headless"]},
        {"pid": 5001, "name": "cmd.exe", "event": "spawn", "args": ["/c", "copy", "payload.exe", path]},
    ]
    file_operations = [
        {"operation": "write", "path": path},
    ]
    logs = [
        {"timestamp": now.isoformat(), "level": "alert", "category": "network", "message": "Binary download detected: http://malicious-payload-host.com/dropper.exe"},
        {"timestamp": (now + timedelta(milliseconds=400)).isoformat(), "level": "alert", "category": "filesystem", "message": f"Write to sensitive path: {path}"},
    ]

    return {
        "network_requests": network_requests,
        "process_events": process_events,
        "file_operations": file_operations,
        "logs": logs,
        "label": "malicious",
        "archetype": "persistence_mechanism",
    }


def generate_credential_harvester() -> Dict[str, Any]:
    """
    Credential phishing page combined with a covert exfiltration beacon —
    the password form ALONE isn't enough signal (legitimate sites have
    those too), but combined with suspicious outbound IP connections it's
    a strong malicious indicator. MITRE ATT&CK T1056.003 (Web Portal
    Capture), T1071.
    """
    now = datetime.now(timezone.utc)
    evil_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

    network_requests = [
        {"url": "https://account-verify-secure.com/login.html", "method": "GET", "status": 200, "content_type": "text/html"},
        {"url": f"http://{evil_ip}/collect.php", "method": "POST", "status": 200, "content_type": "text/plain"},
    ]
    process_events = [
        {"pid": 6000, "name": "chromium", "event": "spawn", "args": ["--headless"]},
    ]
    logs = [
        {"timestamp": now.isoformat(), "level": "info", "category": "visual", "message": "Password input field detected on page (forms=1, pwd_inputs=1)"},
        {"timestamp": (now + timedelta(milliseconds=600)).isoformat(), "level": "alert", "category": "network", "message": f"Direct IP connection bypassing DNS: {evil_ip}"},
    ]

    return {
        "network_requests": network_requests,
        "process_events": process_events,
        "file_operations": [],
        "logs": logs,
        "label": "malicious",
        "archetype": "credential_harvester",
    }


GENERATORS = {
    "benign": [generate_benign_session, generate_benign_login_form],
    "malicious": [
        generate_drive_by_download, generate_powershell_dropper,
        generate_c2_beacon, generate_persistence_mechanism,
        generate_credential_harvester,
    ],
}


def build_dataset(n_benign: int = 400, n_malicious: int = 400, seed: int = 42) -> List[Dict[str, Any]]:
    """Builds a balanced synthetic telemetry dataset across all archetypes."""
    random.seed(seed)
    samples = []

    for _ in range(n_benign):
        gen = random.choice(GENERATORS["benign"])
        samples.append(gen())

    for _ in range(n_malicious):
        gen = random.choice(GENERATORS["malicious"])
        samples.append(gen())

    random.shuffle(samples)
    return samples


if __name__ == "__main__":
    import json
    from pathlib import Path

    out_path = Path(__file__).parent / "synthetic_telemetry.json"
    samples = build_dataset(n_benign=400, n_malicious=400)

    with open(out_path, "w") as f:
        json.dump(samples, f, indent=2)

    from collections import Counter
    print(f"Generated {len(samples)} samples -> {out_path}")
    print("Label distribution:", Counter(s["label"] for s in samples))
    print("Archetype distribution:", Counter(s["archetype"] for s in samples))
