
"""Reusable JSONL storage helpers for the SMTD project."""

import json
from pathlib import Path
from typing import Iterable, Iterator


def write_jsonl(path: str | Path, records: Iterable[dict]) -> int:
    """Write records to a JSONL file and return the record count."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    count = 0

    with output.open("w", encoding="utf-8", newline="\n") as file:
        for record in records:
            file.write(
                json.dumps(record, ensure_ascii=False) + "\n"
            )
            count += 1

    return count


def read_jsonl(path: str | Path) -> Iterator[dict]:
    """Read JSON objects from JSONL, reporting the faulty line if needed."""
    source = Path(path)

    with source.open("r", encoding="utf-8-sig") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in {source}, line {line_number}: {exc}"
                ) from exc

            if not isinstance(record, dict):
                raise ValueError(
                    f"Expected a JSON object in {source}, "
                    f"line {line_number}"
                )

            yield record
