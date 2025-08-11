Log File Anomaly Detector
is a lightweight real-time log anomaly detector written in Python.  
It’s designed to help security ops teams and system administrators detect suspicious activity early — such as repeated failed login attempts, suspicious commands, or potential brute-force attacks — without requiring a full SIEM stack.
but also  helps security analysts, incident responders, and IT admins detect malicious activities such as ransomware encryption, unauthorized data exfiltration

our project is simple enough for small-scale deployment but robust enough to be extended for enterprise environments.

## Objective%%%%

-  real-time log monitoring** with pure-Python tailing (handles log rotation).
-  Threshold-based detection** of excessive auth failures (configurable per IP).
-  Suspicious command detection*
-  Sliding time-window** logic 
-  Polymorphic alerting
-  Optional integration** with AbuseIPDB for threat intelligence enrichment.
-  JSON config support ann flexible deployment.



Features

Monitors file creation, deletion, and modification in real-time
logs all events with timestamps and details
Customizable monitoring paths via config
Works on Linux, Windows, and macOS
No heavy dependencies — simple and portable



future Enhancements or adjusment
GUI interface (may be)
ADVANCED FEATURE - POSSILBLE
CLOUD INTEGRATION FOR ALERTING

### Prerequisites

Python 3.8+
(`requests` library for Slack / AbuseIPDB integration)

Install dependencies:

```bash
pip install requests
