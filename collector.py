
import json
import subprocess
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW_DIR = ROOT / "data" / "raw"

CHANNELS = [
    "Microsoft-Windows-Sysmon/Operational",
    "Security",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Application",
]


def collect_events(limit=100):
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    all_events = []
    warnings = []

    for channel in CHANNELS:
        print(f"Reading: {channel}")

        script = f"""
        $ErrorActionPreference = 'Stop'
        $events = @(Get-WinEvent -LogName '{channel}' `
            -MaxEvents {limit} -ErrorAction Stop)

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
            warnings.append({
                "channel": channel,
                "error": result.stderr.strip()[-500:],
            })
            print("Skipped: unavailable or inaccessible")
            continue

        try:
            events = json.loads(result.stdout.lstrip("\ufeff").strip())
            if isinstance(events, dict):
                events = [events]

            for event in events or []:
                event["collected_at"] = datetime.now().astimezone().isoformat()
                all_events.append(event)

            print(f"  Collected {len(events or [])} events")

        except json.JSONDecodeError as exc:
            warnings.append({
                "channel": channel,
                "error": f"JSON decoding failed: {exc}",
            })
            print("Warning: could not parse PowerShell output")

    if not all_events:
        raise RuntimeError(
            "No events collected. Check log permissions and channel names."
        )

    output_file = RAW_DIR / (
        "raw_events_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".jsonl"
    )

    with output_file.open("w", encoding="utf-8") as file:
        for event in all_events:
            file.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(f"\nTotal events collected: {len(all_events)}")
    print(f"Raw events saved to: {output_file}")

    if warnings:
        print(f"Channel warnings: {len(warnings)}")
        for warning in warnings:
            print(f"  {warning['channel']}: {warning['error']}")

    return output_file, len(all_events)


if __name__ == "__main__":
    collect_events(limit=100)
