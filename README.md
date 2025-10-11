# LoFAD - Log File Anomaly Detector

**LoFAD** is a lightweight Python tool for monitoring log files and detecting suspicious activities such as repeated failed logins, unusual admin access, and suspicious command executions.

---

## Features

- Monitors logs in real-time (`tail -F` style)
- Detects repeated failed login attempts (SSH, sudo, PAM)
- Detects suspicious commands (`nc`, `wget`, `curl`, `python -c`)
- Alerts via:
Console output
- Slack webhook
  - Email (SMTP)
- Optional AbuseIPDB IP reputation lookup
- Configurable thresholds and sliding time window

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/amenema32/Group-7-cyber-sec.git
cd Group-7-cyber-sec

