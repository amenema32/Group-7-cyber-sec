import argparse

import sys

from pathlib import Path



# Import from package

try:

    from lofad import LoFAD, load_config, send_alerts

except ImportError as e:

    print(f"[❌] Could not load LoFAD modules: {e}", file=sys.stderr)

    sys.exit(1)





def parse_args() -> argparse.Namespace:

    parser = argparse.ArgumentParser(

        prog="lofad",

        description="LoFAD - Lightweight Log File Anomaly Detector"

    )

    parser.add_argument(

        "--config",

        required=True,

        help="Path to your configuration JSON file"

    )

    parser.add_argument(

        "--test-alert",

        action="store_true",

        help="Send a test alert (Slack/Email) to confirm your setup"

    )

    return parser.parse_args()





def run_test_alert(config: dict) -> None:

    print("[ℹ️] Sending test alert...")

    subject = "[LoFAD] Test Alert"

    body = "✅ This is a test alert to confirm that your alert settings work."

    send_alerts(config, subject, body)

    print("[✔️] Test alert sent. Check your Slack/email inbox.")





def run_lofad(config: dict) -> None:

    print("[🚀] LoFAD is now watching your logs. Press Ctrl+C to stop.")

    detector = LoFAD(config)

    detector.run()





def main() -> None:

    args = parse_args()



    # Load config

    config_path = Path(args.config)

    if not config_path.exists():

        print(f"[❌] Config file not found: {config_path}", file=sys.stderr)

        sys.exit(1)



    try:

        config = load_config(str(config_path))

    except Exception as e:

        print(f"[❌] Failed to load config: {e}", file=sys.stderr)

        sys.exit(1)



    # Run test alert if requested

    if args.test_alert:

        run_test_alert(config)

        sys.exit(0)



    # Otherwise start monitoring

    try:

        run_lofad(config)

    except KeyboardInterrupt:

        print("\n[🛑] Stopped by user. Goodbye!")

        sys.exit(0)





if __name__ == "__main__":

    main()
