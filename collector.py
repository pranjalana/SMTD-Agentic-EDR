
import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path

# ===== CONFIGURATION =====

# ORIGINAL: Keep the repository-relative storage path.
ROOT = Path(__file__).resolve().parent
RAW_DIR = ROOT / "data" / "raw"

# ADDED: Persistent bookmark storage.
# This is separate from the raw JSONL files.
STATE_FILE = ROOT / "data" / "bookmarks.json"

# ORIGINAL: All five Windows Event Log channels are unchanged.
CHANNELS = [
    "Microsoft-Windows-Sysmon/Operational",
    "Security",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Application",
]

# ADDED: Continuous collection every 5 seconds
POLL_SECONDS = 5
# batch size 500
BATCH_SIZE = 500


# ===== PERSISTENT BOOKMARKS =====

# ADDED: Load previously saved EventRecordIDs.
def load_bookmarks():
    if STATE_FILE.exists():
        with STATE_FILE.open("r", encoding="utf-8") as file:
            return json.load(file)

    return {}


# ADDED: Save bookmarks safely using a temporary file.
def save_bookmarks(bookmarks):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    temp_file = STATE_FILE.with_suffix(".tmp")

    with temp_file.open("w", encoding="utf-8") as file:
        json.dump(bookmarks, file, indent=2)
        file.flush()
        os.fsync(file.fileno())

    os.replace(temp_file, STATE_FILE)


# ===== WINDOWS EVENT COLLECTION =====

# CHANGED: Accept a bookmark so only newer records are queried.
# ORIGINAL: Still uses PowerShell Get-WinEvent.
def query_events(channel, after_id=0, limit=BATCH_SIZE):

    # ADDED: EventRecordID filtering.
    # Ascending order ensures that the oldest uncollected events are processed first.
    script = f"""
    $ErrorActionPreference = 'Stop'

    $xpath = '*[System[EventRecordID > {int(after_id)}]]'

    $events = @(
        Get-WinEvent -LogName '{channel}' `
            -FilterXPath $xpath `
            -Oldest `
            -MaxEvents {int(limit)} `
            -ErrorAction Stop
    )

    # ORIGINAL: Preserve all detailed metadata.
    $output = @(
        foreach ($e in $events) {{
            [PSCustomObject]@{{
                source_log = $e.LogName
                event_id = $e.Id
                record_id = $e.RecordId
                time_created = $e.TimeCreated.ToUniversalTime().ToString('o')
                provider = $e.ProviderName
                computer = $e.MachineName
                message = $e.Message
                raw_xml = $e.ToXml()
            }}
        }}
    )

    ConvertTo-Json -InputObject @($output) -Compress -Depth 4
    """

    # ORIGINAL: Preserve PowerShell subprocess configuration.
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )

    if result.returncode != 0:
        error = result.stderr.strip()

        # FIXED: No matching events should not stop collection.
        # Get-WinEvent may report this as a nonzero return code.
        if (
            "No events were found" in error
            or "No events found" in error
        ):
            return []

        raise RuntimeError(error[-500:] or "PowerShell query failed")

    output = result.stdout.lstrip("\ufeff").strip()

    if not output:
        return []

    # ORIGINAL: Decode PowerShell JSON output.
    events = json.loads(output)

    if isinstance(events, dict):
        events = [events]

    if not isinstance(events, list):
        raise ValueError("Expected a JSON array of events")

    # ADDED: Filter and sort records defensively.
    parsed = []

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Invalid event record")

        record_id = int(event["record_id"])

        if record_id <= after_id:
            continue

        # ORIGINAL: Preserve collected_at metadata.
        event["collected_at"] = (
            datetime.now().astimezone().isoformat()
        )

        parsed.append(event)

    parsed.sort(key=lambda event: int(event["record_id"]))

    return parsed


# ===== RAW JSONL STORAGE =====

# CHANGED: Save each collected batch in the same raw directory.
# ORIGINAL: Preserve the timestamped JSONL file format.
def save_events(events):
    if not events:
        return None

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    # FIXED: Include microseconds to avoid filename collisions.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    output_file = RAW_DIR / f"raw_events_{timestamp}.jsonl"

    # FIXED: Write to a temporary file first.
    temp_file = output_file.with_suffix(".tmp")

    with temp_file.open("w", encoding="utf-8") as file:
        for event in events:
            file.write(
                json.dumps(event, ensure_ascii=False) + "\n"
            )

        file.flush()
        os.fsync(file.fileno())

    # FIXED: Publish only a completely written batch.
    os.replace(temp_file, output_file)

    return output_file


# ===== COLLECT ONE CYCLE =====

# CHANGED: Keep the original collect_events function name.
# ADDED: Read bookmarks and collect incrementally.
def collect_events(limit=BATCH_SIZE):

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    bookmarks = load_bookmarks()
    total = 0
    warnings = []
    last_output_file = None

    for channel in CHANNELS:
        print(f"Reading: {channel}")

        try:
            last_id = int(bookmarks.get(channel, 0))
            channel_total = 0

            # ADDED: Drain multiple batches if more than
            # the configured limit of events are pending.
            while True:
                events = query_events(
                    channel,
                    after_id=last_id,
                    limit=limit,
                )

                if not events:
                    break

                # ORIGINAL: Save the same JSON metadata.
                output_file = save_events(events)

                # ADDED: Update bookmark only after events
                # have been successfully written to disk.
                last_id = int(events[-1]["record_id"])
                bookmarks[channel] = last_id
                save_bookmarks(bookmarks)

                last_output_file = output_file
                channel_total += len(events)
                total += len(events)

                # ADDED: Continue when a full batch is returned.
                if len(events) < limit:
                    break

            print(f"  Collected {channel_total} new events")

        except Exception as error:
            warnings.append({
                "channel": channel,
                "error": str(error)[-500:],
            })

            # ORIGINAL: One failed channel does not stop others.
            print(f"Skipped: {error}")

    print(f"\nTotal new events collected: {total}")

    if last_output_file:
        print(f"Latest raw file: {last_output_file}")

    if warnings:
        print(f"Channel warnings: {len(warnings)}")

        for warning in warnings:
            print(
                f"  {warning['channel']}: "
                f"{warning['error']}"
            )

    # CHANGED: Return total events for this polling cycle.
    # The output file is None if no new events were collected.
    return last_output_file, total


# ===== CONTINUOUS COLLECTION =====

# ADDED: Continuous polling from your previous collector.
def main():

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    print("================================")
    print(" AGENTIC ENDPOINT DEFENSE")
    print(" Windows Log Collector")
    print("================================")
    print(f"Raw directory: {RAW_DIR}")
    print(f"Bookmarks: {STATE_FILE}")
    print(f"Polling interval: {POLL_SECONDS} seconds")
    print(f"Batch size: {BATCH_SIZE}")
    print("Press Ctrl+C to stop.\n")

    while True:
        try:
            collect_events(limit=BATCH_SIZE)

        except Exception as error:
            print(f"[ERROR] Collection cycle: {error}")

        print(
            f"[{time.strftime('%H:%M:%S')}] "
            f"Collection cycle completed\n"
        )

        time.sleep(POLL_SECONDS)


# ===== PROGRAM ENTRY POINT =====

# CHANGED: Start continuous collection instead of running one batch and exiting
if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print("\nCollector stopped.")
