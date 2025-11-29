import argparse
import logging
import os
from pathlib import Path
from src.consent_collector import ConsentCollector
from src.detection_pipeline import DetectionPipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect external consented apps and sign-ins."
    )
    parser.add_argument(
        "--permission-db",
        dest="permission_db_path",
        type=Path,
        default=Path(os.getenv("PERMISSION_DB", "permission_analysis.db")),
        help="Path to permission_analysis.db (env: PERMISSION_DB).",
    )
    parser.add_argument(
        "--state-db",
        dest="state_db_path",
        type=Path,
        default=Path(os.getenv("DETECTION_STATE_DB", "detection_state.db")),
        help="Path to detection_state.db (env: DETECTION_STATE_DB).",
    )
    parser.add_argument(
        "--output",
        help="Base name for output files (no extension)",
        default="consents",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    collector = ConsentCollector()

    collector = ConsentCollector()
    pipeline = DetectionPipeline(
        collector,
        permission_db_path=args.permission_db_path,
        state_db_path=args.state_db_path,
    )
    pipeline.run_detection()


if __name__ == "__main__":
    main()
