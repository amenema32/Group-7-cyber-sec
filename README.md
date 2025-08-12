# Log File Anomaly Detector

**Log File Anomaly Detector** is a lightweight, real-time log anomaly detection tool written in Python.  

It’s designed to help **security operations teams** and **system administrators** detect suspicious activity early — such as repeated failed login attempts, suspicious commands, or potential brute-force attacks — without requiring a full SIEM stack.

It also helps **security analysts, incident responders, and IT admins** detect malicious activities such as:
- Ransomware encryption
- Unauthorized data exfiltration

Our project is **simple enough for small-scale deployment**, but **robust enough to be extended** for enterprise environments.

---

## 🎯 Objectives

- **Real-time log monitoring** with pure-Python tailing (handles log rotation)
- **Threshold-based detection** of excessive authentication failures (configurable per IP)
- **Suspicious command detection**
- **Sliding time-window** logic
- **Polymorphic alerting**
- **Optional integration** with AbuseIPDB for threat intelligence enrichment
- **JSON config support** and flexible deployment

---

## ✨ Features

- Monitors file creation, deletion, and modification in real-time  
- Logs all events with timestamps and details  
- Customizable monitoring paths via configuration  
- Works on **Linux**, **Windows**, and **macOS**  
- No heavy dependencies — simple and portable  

---

## 🔮 Future Enhancements / Adjustments

- GUI interface (possible)  
- Advanced detection features (possible)  
- Cloud integration for alerting  

---

## 🛠 Prerequisites

- **Python 3.8+**  
- [`requests`](https://pypi.org/project/requests/) library (for Slack / AbuseIPDB integration)  

**Install dependencies:**
```bash
pip
pip install requests
