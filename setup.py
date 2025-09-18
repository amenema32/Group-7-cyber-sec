from setuptools import setup
import time
import re
from collections import defaultdict

# ---------------- LoFAD Core Code ---------------- #
SUSPICIOUS_COMMANDS = [
    r"wget\s+",
    r"curl\s+",
    r"nc\s+",
    r"python\s+-c",
]

FAILED_LOGIN_PATTERN = re.compile(r"Failed password for.*from (\d+\.\d+\.\d+\.\d+)")
SUSPICIOUS_CMD_PATTERN = re.compile("|".join(SUSPICIOUS_COMMANDS))

FAILED_LOGIN_THRESHOLD = 5   # Number of failed logins
TIME_WINDOW = 300            # In seconds (5 minutes)

failed_logins = defaultdict(list)


def monitor_log(filepath):
    """Monitor the log file in real time."""
    with open(filepath, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            check_failed_login(line)
            check_suspicious_command(line)


def check_failed_login(line):
    """Detect repeated failed SSH logins."""
    match = FAILED_LOGIN_PATTERN.search(line)
    if match:
        ip = match.group(1)
        now = time.time()
        failed_logins[ip].append(now)

        # Remove old entries
        failed_logins[ip] = [t for t in failed_logins[ip] if now - t <= TIME_WINDOW]

        if len(failed_logins[ip]) >= FAILED_LOGIN_THRESHOLD:
            print(f"[ALERT] {len(failed_logins[ip])} failed logins from {ip} within {TIME_WINDOW//60} minutes!")


def check_suspicious_command(line):
    """Detect dangerous commands in logs."""
    if SUSPICIOUS_CMD_PATTERN.search(line):
        print(f"[ALERT] Suspicious command detected: {line.strip()}")


def main():
    log_file = "/var/log/auth.log"
    print(f"LoFAD started. Monitoring: {log_file}")
    monitor_log(log_file)


# ---------------- Setup Config ---------------- #
setup(
    name="LoFAD",
    version="0.1.0",
    author="Group-7 Cyber",
    author_email="your_email@example.com",
    description="LoFAD - Log File Anomaly Detector (lightweight log monitoring for suspicious activity)",
    long_description="LoFAD monitors log files and detects suspicious activities like failed logins and dangerous commands.",
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "lofad=__main__:main",
        ],
    },
)