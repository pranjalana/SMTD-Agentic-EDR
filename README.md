# SMTD — Agentic Endpoint Defense

## 1. Project Overview

This project is part of the Security Monitoring & Threat Detection (SMTD) project. It aims to build an endpoint-defense pipeline that collects Windows event logs, normalizes events into a common format, and supports security detection and analysis.

**Current status:** Initial Module 2 pipeline implemented and tested. Module 3 detection and analysis is still in progress.

## 2. Current Pipeline

Windows Event Logs → Collection → XML Parsing and Normalization → JSONL Storage → Validation

The current pipeline collected 500 events in a test run, normalized all 500 without processing failures, and passed the storage read-back comparison.

## 3. Requirements

- Windows 10 or Windows 11
- Python 3 installed and available in PowerShell
- Git installed
- Permission to read the required Windows event channels
- VS Code (recommended)

## 4. Setup on Your Own Windows Machine

### Step 1: Clone the repository

Open PowerShell and run:

```powershell
git clone https://github.com/pranjalana/SMTD-Agentic-EDR.git
cd SMTD-Agentic-EDR
```

### Step 2: Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If activation is blocked, run Python directly using:

```powershell
.\.venv\Scripts\python.exe --version
```

### Step 3: Run the pipeline

```powershell
python main.py
```

The collector reads events from configured Windows channels. Some channels may require PowerShell to be run as Administrator.

## 5. Main Files

- `collector.py` — collects Windows event records from configured event channels.
- `normalizer.py` — extracts event XML fields and converts records into a normalized structure.
- `storage.py` — reads and writes JSONL records.
- `main.py` — runs the collection, normalization, storage, and validation pipeline.
- `parser.py` — earlier parser implementation; currently not called directly by `main.py`.
- `.gitignore` — excludes local data, virtual environments, and other files from Git tracking.

## 6. Local Output

The pipeline writes data locally:

- `data/raw/` — collected original event records.
- `data/normalized/` — normalized JSONL records.
- `reports/` — pipeline validation reports.

Each team member should generate their own data on their own Windows machine. Do not upload raw logs, normalized logs, or reports containing sensitive event information to GitHub.

## 7. Development Workflow

Before starting work, get the latest shared code:

```powershell
git pull
```

After editing and testing code:

```powershell
git add <changed-file>
git commit -m "Describe your change"
git push
```

Replace `<changed-file>` with the file you actually changed.

Coordinate changes to shared files with the team to avoid merge conflicts. Team members need repository write access to push changes.

## 8. Current Limitations and Next Steps

- Confirm the normalized schema with the team.
- Validate important event types and extracted fields.
- Clarify the division of responsibility between `parser.py` and `normalizer.py`.
- Implement and test Module 3 detection and analysis logic.

## 9. Security Notes

- Never commit passwords, access tokens, private keys, or sensitive logs.
- This repository is public, so anyone can view its contents.
- Keep virtual machine images and local event data outside the repository.
