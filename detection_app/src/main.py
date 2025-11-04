import argparse
import logging
from datetime import datetime, timezone
from src.consent_collector import ConsentCollector

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect external consented apps and sign-ins."
    )
    parser.add_argument("--start", help="Start date (YYYY-MM-DD)", required=False)
    parser.add_argument("--end", help="End date (YYYY-MM-DD)", required=False)
    parser.add_argument(
        "--output",
        help="Base name for output files (no extension)",
        default="external_consents",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    collector = ConsentCollector()

    start = (
        datetime.fromisoformat(args.start).replace(tzinfo=timezone.utc)
        if args.start
        else None
    )
    end = (
        datetime.fromisoformat(args.end).replace(tzinfo=timezone.utc)
        if args.end
        else None
    )

    if start and end:
        collector.collect_signins(start, end)

    consents = collector.collect_external_consents(start, end)
    collector._write_outputs(consents, args.output)


if __name__ == "__main__":
    main()
