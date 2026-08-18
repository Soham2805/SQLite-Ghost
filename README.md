# SQLite-Ghost 👻

A schema-agnostic Python framework designed to carve deleted records, reconstruct unallocated page space, and perform differential Write-Ahead Log (WAL) analysis on SQLite databases without relying on the `sqlite_master` schema table.

*Initially developed as a proof-of-concept for mobile database forensics.*

## Features
- **Schema-Agnostic Carving:** Extracts data from slack space and unallocated freelists purely through heuristic pattern matching of SQLite Serial Types. No table schemas needed!
- **Differential WAL Analysis:** Cross-references Write-Ahead Logs against the main database to identify uncommitted or "Phantom" transactions.
- **Forensic Threat Level Scoring:** Actively scans raw B-Tree structures for malicious tampering. Detects structural overlaps, out-of-order RowIDs, and Timestamp contradictions.
- **Pure Python:** Built entirely using raw binary `struct` parsing. Zero reliance on OS SQLite drivers (the `sqlite3` module is strictly banned from the core engine), making it immune to intentional database corruption intended to crash standard tools.
- **HTML Reporting:** Generates interactive, single-page forensics reports.

## Installation

### Option 1: Standalone Windows Executable (Recommended)
You do not need Python installed to run SQLite-Ghost! 
Simply download `sqlite-ghost.exe` from the GitHub Releases page and run it directly from your command line.

### Option 2: Build from Source
If you want to modify the code or build the executable yourself:

```bash
git clone <your-repo-url>
cd SqliteGhost

# Install dependencies
python -m pip install -e .

# (Optional) Build standalone executable
python -m pip install pyinstaller
pyinstaller --onefile --name sqlite-ghost cli_entry.py
```

## Usage

SQLite-Ghost exposes a simple command-line interface. If you downloaded the executable, use `sqlite-ghost.exe` instead of `sqlite-ghost` in the commands below:

**1. Parse a Database**
```bash
sqlite-ghost parse sample.db
```

**2. Differential WAL Analysis**
```bash
sqlite-ghost parse sample.db --wal sample.db-wal
```

**3. Carve Unallocated Data**
```bash
sqlite-ghost carve sample.db
```

**4. Generate Forensics HTML Report**
```bash
sqlite-ghost report sample.db --html report.html
```

## Running Tests
This project uses `pytest` to validate the low-level byte parsers.
```bash
pytest
```
