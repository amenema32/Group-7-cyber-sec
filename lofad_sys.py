

import argparse
import re
import time
import os
import sys
import json
import smtplib
from email.message import EmailMessage
from collections import deque, defaultdict
from datetime import datetime, timedelta

try:
    import requests
except Exception:
    requests = None

try:
    import yaml
except Exception:
    yaml = None

# -------------------- Default Config --------------------
DEFAULT_CONFIG = {
    "thresholds": {
        "failed_login_count": 5,
        "failed_login_window_seconds": 300,
        "suspicious_cmd_count": 3,
        "suspicious_cmd_window_seconds": 300,
    },
    "alerts": {
        "console": True,
        "slack_webhook": None,
        "smtp": {
            "enabled": False,
            "server": "localhost",
            "port": 25,
            "from": "lofad@example.com",
            "to": ["admin@example.com"],
        },
        "abuseipdb_api_key": None,
    },
    "patterns": {
        "failed_login": [
            "Failed password for",
            "authentication failure",
            "Failed publickey for",
        ],
        "suspicious_cmd": [
            "\\bnc\\b",
            "\\bwget\\b",
            "\\bcurl\\b",
            "python -c",
            "bash -i",
            "perl -e",
            "ruby -e",
        ],
        "ip_regex": "(\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b)",
    },
}

# -------------------- Utilities --------------------
def load_config(path=None):
    config = DEFAULT_CONFIG.copy()
    if path and os.path.exists(path):
        if yaml and path.lower().endswith(('.yml', '.yaml')):
            with open(path, 'r') as f:
                user = yaml.safe_load(f) or {}
        else:
            with open(path, 'r') as f:
                user = json.load(f)
        for k, v in user.items():
            if k in config and isinstance(config[k], dict):
                config[k].update(v)
            else:
                config[k] = v
    return config

# tail -F style file follower
class FileFollower:
    def __init__(self, path, poll_interval=1.0):
        self.path = path
        self.poll_interval = poll_interval
        self._ino = None
        self._fp = None

    def _open(self):
        if self._fp:
            try:
                stat = os.fstat(self._fp.fileno())
                if stat.st_ino == self._ino:
                    return
            except Exception:
                pass
        if self._fp:
            try:
                self._fp.close()
            except Exception:
                pass
        while True:
            try:
                self._fp = open(self.path, 'r', errors='ignore')
                stat = os.fstat(self._fp.fileno())
                self._ino = stat.st_ino
                self._fp.seek(0, os.SEEK_END)
                break
            except FileNotFoundError:
                time.sleep(self.poll_interval)

    def follow(self):
        self._open()
        while True:
            line = self._fp.readline()
            if not line:
                try:
                    cur_ino = os.stat(self.path).st_ino
                except Exception:
                    cur_ino = None
                if cur_ino and cur_ino != self._ino:
                    self._open()
                time.sleep(self.poll_interval)
                continue
            yield line

# -------------------- Detection Engine --------------------
class SlidingCounter:
    def __init__(self, window_seconds):
        self.window = timedelta(seconds=window_seconds)
        self.events = defaultdict(deque)

    def add(self, key, t=None):
        t = t or datetime.utcnow()
        dq = self.events[key]
        dq.append(t)
        self._prune(dq, t)

    def count(self, key, t=None):
        t = t or datetime.utcnow()
        dq = self.events.get(key, deque())
        self._prune(dq, t)
        return len(dq)

    def _prune(self, dq, now):
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

# -------------------- Alerts --------------------
class AlertManager:
    def __init__(self, config):
        self.config = config

    def alert_console(self, title, body):
        print(f"[LoFAD] {title}: {body}")

    def alert_slack(self, title, body):
        webhook = self.config['alerts'].get('slack_webhook')
        if not webhook or not requests:
            return
        payload = {"text": f"*{title}*\n{body}"}
        try:
            requests.post(webhook, json=payload, timeout=5)
        except Exception as e:
            self.alert_console('Slack error', str(e))

    def alert_smtp(self, title, body):
        sconf = self.config['alerts'].get('smtp', {})
        if not sconf.get('enabled'):
            return
        msg = EmailMessage()
        msg['Subject'] = f"LoFAD Alert: {title}"
        msg['From'] = sconf.get('from')
        to = sconf.get('to') or []
        if isinstance(to, str):
            to = [to]
        msg['To'] = ','.join(to)
        msg.set_content(body)
        try:
            with smtplib.SMTP(sconf.get('server', 'localhost'),
                              sconf.get('port', 25),
                              timeout=10) as s:
                s.send_message(msg)
        except Exception as e:
            self.alert_console('SMTP error', str(e))

    def alert_all(self, title, body):
        if self.config['alerts'].get('console'):
            self.alert_console(title, body)
        if self.config['alerts'].get('slack_webhook'):
            self.alert_slack(title, body)
        if self.config['alerts'].get('smtp', {}).get('enabled'):
            self.alert_smtp(title, body)

# Optional AbuseIPDB check
def abuseipdb_check(ip, api_key):
    if not api_key or not requests:
        return None
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Key': api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip}
        r = requests.get(url, headers=headers, params=params, timeout=5)
        if r.status_code == 200:
            return r.json().get('data')
    except Exception:
        return None
    return None

# -------------------- Pattern Handling --------------------
def compile_patterns(cfg):
    p = cfg['patterns']
    ip_re = re.compile(p.get('ip_regex'))
    failed_list = [re.compile(s, re.IGNORECASE) for s in p.get('failed_login', [])]
    suspicious_list = [re.compile(s, re.IGNORECASE) for s in p.get('suspicious_cmd', [])]
    return ip_re, failed_list, suspicious_list

def extract_ips(line, ip_re):
    return ip_re.findall(line)

# -------------------- Main Monitor --------------------
def monitor_file(path, config):
    ip_re, failed_list, suspicious_list = compile_patterns(config)
    failed_window = config['thresholds']['failed_login_window_seconds']
    failed_threshold = config['thresholds']['failed_login_count']
    suspicious_window = config['thresholds']['suspicious_cmd_window_seconds']
    suspicious_threshold = config['thresholds']['suspicious_cmd_count']

    failed_counter = SlidingCounter(failed_window)
    suspicious_counter = SlidingCounter(suspicious_window)
    alerts = AlertManager(config)
    follower = FileFollower(path)

    for line in follower.follow():
        now = datetime.utcnow()
        ln = line.strip()

        for rx in failed_list:
            if rx.search(ln):
                ips = extract_ips(ln, ip_re)
                key = ips[0] if ips else 'unknown'
                failed_counter.add(key, now)
                c = failed_counter.count(key, now)
                if c >= failed_threshold:
                    body = f"Failed login from {key} ({c}/{failed_threshold})\n{ln}"
                    aip = config['alerts'].get('abuseipdb_api_key')
                    if aip and ips:
                        data = abuseipdb_check(key, aip)
                        if data:
                            body += f"\nAbuseIPDB Score: {data.get('abuseConfidenceScore')}"
                    alerts.alert_all(f"Failed Login ({key})", body)

        for rx in suspicious_list:
            if rx.search(ln):
                ips = extract_ips(ln, ip_re)
                key = ips[0] if ips else 'host'
                suspicious_counter.add(key, now)
                c = suspicious_counter.count(key, now)
                if c >= suspicious_threshold:
                    body = f"Suspicious command from {key} ({c}/{suspicious_threshold})\n{ln}"
                    alerts.alert_all(f"Suspicious Command ({key})", body)

# -------------------- CLI --------------------
def parse_args():
    ap = argparse.ArgumentParser(description='LoFAD - Log File Anomaly Detector')
    ap.add_argument('--file', '-f', required=True, help='Log file to monitor')
    ap.add_argument('--config', '-c', help='Path to JSON/YAML config')
    ap.add_argument('--once', action='store_true', help='Process current content then exit')
    return ap.parse_args()

def process_once(path, config):
    ip_re, failed_list, suspicious_list = compile_patterns(config)
    alerts = AlertManager(config)
    with open(path, 'r', errors='ignore') as fp:
        for line in fp:
            ln = line.strip()
            for rx in failed_list:
                if rx.search(ln):
                    alerts.alert_all('Failed login (once)', ln)
            for rx in suspicious_list:
                if rx.search(ln):
                    alerts.alert_all('Suspicious (once)', ln)

if __name__ == '__main__':
    args = parse_args()
    cfg = load_config(args.config)
    if args.once:
        process_once(args.file, cfg)
        sys.exit(0)
    try:
        monitor_file(args.file, cfg)
    except KeyboardInterrupt:
        print("\nLoFAD stopped by user")