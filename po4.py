
import time
import re

# ======= CONFIGURATION =======
LOG_FILE = "/var/log/auth.log"  # Change this to the log file you want to monitor
SUSPICIOUS_PATTERNS = {
    "Failed login attempt": re.compile(r"Failed password"),
    "Root login": re.compile(r"root"),
    "Invalid user access": re.compile(r"Invalid user"),
    "Possible brute force": re.compile(r"authentication failure|failed login"),
}

ALERT_PREFIX = "[!] ALERT:"
# ==============================

def follow(file):
    """Generator that yields new lines as they are added to a log file."""
    file.seek(0, 2)  # Move to the end of the file
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line

def check_for_anomalies(line):
    """Check each line for suspicious patterns."""
    for description, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(line):
            print(f"{ALERT_PREFIX} {description} detected → {line.strip()}")

def main():
    print("🔍 LoFAD started. Monitoring:", LOG_FILE)
    print("Press Ctrl+C to stop.\n")

    try:
        with open(LOG_FILE, "r") as logfile:
            loglines = follow(logfile)
            for line in loglines:
                check_for_anomalies(line)
    except FileNotFoundError:
        print(f"Error: Log file '{LOG_FILE}' not found.")
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()