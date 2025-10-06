"""
detector.py

Core detection logic for LoFAD - Log File Anomaly Detector.

This module defines the LoFAD class, which monitors a log file for
authentication failures, suspicious command usage, and ransomware-like
file activity. It sends alerts through Slack or Email when anomalies
are detected.
"""

import re
import time
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta

from .alerts import send_email, send_slack, abuseipdb_check
from .patterns import AUTH_PATTERNS, CMD_PATTERNS
from .utils import RotatingTail


class LoFAD:
    """
    Main LoFAD class that handles log monitoring and anomaly detection.
    """

    def __init__(self, config_path: str = "config.json"):
        """
        Initialize LoFAD with configuration file path.
        """
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = json.load(f)

        self.failed_logins = defaultdict(deque)
        self.last_alert_time = defaultdict(float)
        self.last_cmd_alert = 0
        self.alert_cooldown = 30  # seconds

        print(f"[LoFAD] Initialized with log file: {self.config['log_file']}")

    # ---------------------------------------------------------------------
    # AUTHENTICATION FAILURE DETECTION
    # ---------------------------------------------------------------------
    def _detect_auth_failure(self, line: str):
        """
        Detect failed authentication attempts from log line.
        """
        for pattern in AUTH_PATTERNS:
            m = pattern.search(line)
            if m:
                ip = m.group("ip")
                user = m.groupdict().get("user", "?")
                now = time.time()
                dq = self.failed_logins[ip]
                dq.append(now)

                # Remove entries older than time_window_sec
                window = self.config["time_window_sec"]
                while dq and now - dq[0] > window:
                    dq.popleft()

                if len(dq) >= self.config["failed_login_threshold"]:
                    if now - self.last_alert_time[ip] > self.alert_cooldown:
                        msg = f"[LoFAD] 🚨 Multiple failed logins from {ip} (user: {user})"
                        print(msg)
                        self._send_alert(msg)
                        self.last_alert_time[ip] = now
                        self._abuse_lookup(ip)
                return True
        return False

    # ---------------------------------------------------------------------
    # SUSPICIOUS COMMAND DETECTION
    # ---------------------------------------------------------------------
    def _detect_suspicious_command(self, line: str):
        """
        Detect suspicious command usage in log line.
        """
        now = time.time()
        if now - self.last_cmd_alert < self.alert_cooldown:
            return False

        for pattern in CMD_PATTERNS:
            if pattern.search(line):
                msg = f"[LoFAD] ⚠️ Suspicious command detected: {line.strip()}"
                print(msg)
                self._send_alert(msg)
                self.last_cmd_alert = now
                return True
        return False

    # ---------------------------------------------------------------------
    # ALERT HANDLERS
    # ---------------------------------------------------------------------
    def _send_alert(self, message: str):
        """
        Send alert through configured methods.
        """
        mode = self.config.get("alert_mode", "console")
        if mode in ("both", "slack") and self.config.get("slack_webhook"):
            send_slack(self.config["slack_webhook"], message)

        if mode in ("both", "email") and self.config.get("smtp_server"):
            send_email(
                smtp_server=self.config["smtp_server"],
                smtp_port=self.config.get("smtp_port", 587),
                username=self.config["smtp_username"],
                password=self.config["smtp_password"],
                to_list=self.config.get("alert_recipients", []),
                subject="LoFAD Alert",
                body=message,
            )

    def _abuse_lookup(self, ip: str):
        """
        Perform IP reputation lookup using AbuseIPDB.
        """
        api_key = self.config.get("abuseipdb_api_key")
        if not api_key:
            return
        result = abuseipdb_check(api_key, ip)
        if result:
            data = result.get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            if score > 50:
                msg = f"[LoFAD] 🚫 IP {ip} has bad reputation (Abuse Score: {score})"
                print(msg)
                self._send_alert(msg)

    # ---------------------------------------------------------------------
    # MONITORING LOOP
    # ---------------------------------------------------------------------
    def run(self):
        """
        Start monitoring the configured log file for anomalies.
        """
        log_file = self.config["log_file"]
        tail = RotatingTail(log_file)

        print(f"[LoFAD] Monitoring started on {log_file}...")
        for line in tail.follow():
            line = line.strip()
            if not line:
                continue
            if self._detect_auth_failure(line):
                continue
            self._detect_suspicious_command(line)
