import json
from .alerts import send_email, send_slack

def load_config(path: str) -> dict:
    """Load JSON config file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def send_alerts(config: dict, subject: str, body: str):
    """Send Slack and/or Email alerts using config."""
    if config.get("slack_webhook"):
        send_slack(config["slack_webhook"], body)
    if config.get("smtp_server"):
        send_email(
            smtp_server=config["smtp_server"],
            smtp_port=config.get("smtp_port", 587),
            username=config["smtp_username"],
            password=config["smtp_password"],
            to_list=config.get("alert_recipients", []),
            subject=subject,
            body=body,
        )
