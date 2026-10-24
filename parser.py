
import json
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent
RAW_DIR = BASE_DIR / "data" / "raw"
NORMALIZED_DIR = BASE_DIR / "data" / "normalized"


def parse_timestamp(value):
    """Parse a timestamp and convert it to UTC ISO 8601."""
    if not value:
        return None

    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if timestamp.tzinfo is None:
            return None

        return timestamp.astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

    except (ValueError, TypeError):
        return None


def normalize_event(event):
    """Preserve original event data and expose standard fields."""
    return {
        "timestamp": parse_timestamp(event.get("time_created")),
        "collected_at": event.get("collected_at"),
        "source_log": event.get("source_log"),
        "event_id": event.get("event_id"),
        "record_id": event.get("record_id"),
        "provider": event.get("provider"),
        "computer": event.get("computer"),
        "message": event.get("message"),
        "raw_xml": event.get("raw_xml"),
        "normalization_status": (
            "ok" if parse_timestamp(event.get("time_created"))
            else "invalid_timestamp"
        ),
    }


def main():
    if not RAW_DIR.exists():
        raise FileNotFoundError(f"Raw directory not found: {RAW_DIR}")

    raw_files = sorted(
        RAW_DIR.glob("raw_events_*.jsonl"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    if not raw_files:
        raise FileNotFoundError(
            f"No raw_events_*.jsonl files found in {RAW_DIR}"
        )

    input_file = raw_files[0]
    NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)

    output_file = NORMALIZED_DIR / (
        f"normalized_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.jsonl"
    )

    total = 0
    valid = 0
    invalid_json = 0
    invalid_timestamp = 0

    with input_file.open("r", encoding="utf-8") as source, \
            output_file.open("w", encoding="utf-8") as destination:

        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)

                if not isinstance(event, dict):
                    invalid_json += 1
                    print(f"Line {line_number}: expected a JSON object")
                    continue

                normalized = normalize_event(event)
                destination.write(
                    json.dumps(normalized, ensure_ascii=False) + "\n"
                )

                total += 1

                if normalized["normalization_status"] == "ok":
                    valid += 1
                else:
                    invalid_timestamp += 1

            except json.JSONDecodeError as error:
                invalid_json += 1
                print(f"Line {line_number}: invalid JSON: {error}")

    print("\nNormalization complete")
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    print(f"Records processed: {total}")
    print(f"Valid timestamps: {valid}")
    print(f"Invalid timestamps: {invalid_timestamp}")
    print(f"Invalid JSON records: {invalid_json}")


if __name__ == "__main__":
    main()
