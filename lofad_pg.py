#!/usr/bin/env python3
"""
LoFAD - Log File Anomaly Detector
Enhanced version with auth failure and suspicious command detection using user-defined regex patterns.
"""

import os
import re
import time
import json
import requests
from collections import deque
from datetime import datetime, timezone

# ===================== CONFIGURATION =====================
CONFIG_JSON = r"""
{
  "log_file": "/var/log/auth.log",
  "failed_login_threshold": 5,
  "time_window_sec": 60,
  "alert_mode": "both",
  "slack_webhook": "",
  "abuseipdb_api_key": "",
  "filesystem_watch_paths": ["/home"],
  "filesystem_poll_interval": 5,
  "encryption_extensions": [".enc", ".lock", ".crypt", ".crypted"],
  "encryption_burst_threshold": 10
}
"""
CONFIG = json.loads(CONFIG_JSON)

# ===================== PATTERNS =====================
AUTH_PATTERNS = [
    re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[0-9.]+)"),
    re.compile(r"authentication failure;.*rhost=(?P<ip>[0-9.]+)"),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9.]+)"),
    re.compile(r"sudo: .*authentication failure;.*rhost=(?P<ip>[0-9.]+)"),
]

CMD_PATTERNS = [
    re.compile(r"\b(nc|netcat)\b"),
    re.compile(r"\b(wget|curl)\b.*http"),
    re.compile(r"\bpython -c\b"),
    re.compile(r"\b/bin/bash -i\b"),
]

# ===================== ALERTING =====================

def send_slack(message: str):
    webhook = CONFIG.get("slack_webhook")
    if not webhook:
        return
    try:
        requests.post(webhook, json={"text": message}, timeout=5)
    except Exception as e:
        print(f"[WARN] Slack send failed: {e}")

def alert(message: str):
    mode = CONFIG.get("alert_mode", "console")
    print(f"[ALERT] {message}")
    if mode in ("both", "slack"):
        send_slack(message)

def abuseipdb_lookup(ip: str):
    api_key = CONFIG.get("abuseipdb_api_key")
    if not api_key or not ip:
        return
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": api_key}
        r = requests.get(url, params={"ipAddress": ip}, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json().get("data", {})
            score = data.get("abuseConfidenceScore")
            if score and score > 50:
                alert(f"IP {ip} has bad reputation (AbuseIPDB score {score})")
    except Exception as e:
        print(f"[WARN] AbuseIPDB check failed: {e}")

# ===================== LOG MONITORING =====================

def follow_log(path):
    print(f"[INFO] Following log: {path}")
    with open(path, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()

def monitor_log():
    log_path = CONFIG["log_file"]
    window = deque()
    time_window = CONFIG["time_window_sec"]
    fail_threshold = CONFIG["failed_login_threshold"]

    for line in follow_log(log_path):
        now = time.time()

        # Failed login detection
        for pattern in AUTH_PATTERNS:
            m = pattern.search(line)
            if m:
                ip = m.groupdict().get("ip", "unknown")
                window.append((ip, now))
                while window and now - window[0][1] > time_window:
                    window.popleft()
                count = sum(1 for i, t in window if i == ip)
                if count >= fail_threshold:
                    alert(f"Repeated failed logins from {ip} (count={count})")
                    abuseipdb_lookup(ip)
                break

        # Suspicious command detection
        for pattern in CMD_PATTERNS:
            if pattern.search(line):
                alert(f"Suspicious command detected: '{pattern.pattern}' in line: {line}")
                break

# ===================== FILESYSTEM WATCH =====================

def monitor_filesystem():
    watch_paths = CONFIG["filesystem_watch_paths"]
    poll_interval = CONFIG["filesystem_poll_interval"]
    enc_exts = CONFIG["encryption_extensions"]
    threshold = CONFIG["encryption_burst_threshold"]

    known_files = set()
    for path in watch_paths:
        for root, _, files in os.walk(path):
            for f in files:
                known_files.add(os.path.join(root, f))

    while True:
        time.sleep(poll_interval)
        new_enc = []
        for path in watch_paths:
            for root, _, files in os.walk(path):
                for f in files:
                    full_path = os.path.join(root, f)
                    if full_path not in known_files:
                        known_files.add(full_path)
                        if any(f.endswith(ext) for ext in enc_exts):
                            new_enc.append(full_path)
        if len(new_enc) >= threshold:
            alert(f"Possible ransomware activity: {len(new_enc)} encrypted files detected")
            for f in new_enc[:5]:
                print(f" - {f}")

# ===================== MAIN =====================

def main():
    import threading
    log_thread = threading.Thread(target=monitor_log, daemon=True)
    fs_thread = threading.Thread(target=monitor_filesystem, daemon=True)
    log_thread.start()
    fs_thread.start()
    print("[INFO] LoFAD running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[INFO] Exiting LoFAD...")

if __name__ == "__main__":
    main()