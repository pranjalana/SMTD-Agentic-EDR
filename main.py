
"""SMTD Module 2: collect, parse, normalize and store Windows events."""

import json
from datetime import datetime
from pathlib import Path

from collector import collect_events
from normalizer import normalize_event
from storage import read_jsonl, write_jsonl

ROOT = Path(__file__).resolve().parent
NORMALIZED_DIR = ROOT / "data" / "normalized"
REPORT_DIR = ROOT / "reports"


def main():
    NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Collect a fresh batch. Existing raw files remain untouched.
    raw_path, collected = collect_events(limit=100)

    normalized = []
    failures = []

    # 2. Read raw JSONL, parse its XML and normalize each record.
    for line_number, record in enumerate(read_jsonl(raw_path), start=1):
        try:
            item = normalize_event(record)

            if item.get("event_id") is None:
                raise ValueError("Missing event ID")
            if not item.get("timestamp"):
                raise ValueError("Missing event timestamp")
            if not item.get("raw_xml"):
                raise ValueError("Missing original XML evidence")

            normalized.append(item)

        except Exception as exc:
            failures.append({
                "line": line_number,
                "error": str(exc),
            })

    # 3. Save to a new timestamped output file.
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = NORMALIZED_DIR / f"pipeline_{stamp}.jsonl"
    written = write_jsonl(output_path, normalized)

    # 4. Read the saved output back and compare records.
    reloaded = list(read_jsonl(output_path))
    storage_match = reloaded == normalized

    report = {
        "raw_file": str(raw_path),
        "normalized_file": str(output_path),
        "events_collected": collected,
        "events_normalized": len(normalized),
        "failures": failures,
        "records_written": written,
        "records_reloaded": len(reloaded),
        "storage_roundtrip_match": storage_match,
    }

    report_path = REPORT_DIR / f"pipeline_{stamp}.json"
    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))

    if failures or written != len(normalized) or not storage_match:
        raise SystemExit("Pipeline validation failed; inspect the report.")

    print("\nPASS: Module 2 pipeline completed successfully.")


if __name__ == "__main__":
    main()
