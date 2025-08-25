import smtplib
import requests
import json
from email.message import EmailMessage

USER_AGENT = "LoFAD/1.0"

def send_slack(webhook: str, text: str) -> bool:
    if not webhook:
        return False
    payload = {"text": text}
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.post(webhook, json=payload, headers=headers, timeout=10)
        return r.status_code in (200, 201, 202)
    except Exception as e:
        print(f"[LoFAD] Slack send failed: {e}")
        return False

def send_email(smtp_server: str, smtp_port: int, username: str, password: str,
               to_list: list, subject: str, body: str) -> bool:
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = username
    msg['To'] = ','.join(to_list)
    msg.set_content(body)
    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=20) as s:
            s.ehlo()
            s.starttls()
            s.login(username, password)
            s.send_message(msg)
        return True
    except Exception as e:
        print(f"[LoFAD] Email send failed: {e}")
        return False

def abuseipdb_check(api_key: str, ip: str):
    if not api_key:
        return None
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': api_key,
        'User-Agent': USER_AGENT,
    }
    params = {"ipAddress": ip}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"[LoFAD] AbuseIPDB lookup failed: {e}")
    return None
