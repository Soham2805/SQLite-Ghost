# Mission Brief & Technical Specification: SQLite-Ghost

## 1. Executive Summary & Architecture Overview
**Project Name:** `SQLite-Ghost`  
**Objective:** Build an open-source, schema-agnostic Python framework designed to carve deleted records, reconstruct unallocated page space, and perform differential Write-Ahead Log (WAL) analysis on SQLite databases without relying on the `sqlite_master` schema table.

**Academic Context:** Proof-of-concept tool for a research paper on mobile database forensics (*Case Study: Deflategate / iOS `sms.db`*).

```text
sqlite-ghost/
├── sqlite_ghost/
│   ├── __init__.py
│   ├── cli.py                   # Click CLI entrypoint
│   ├── core/
│   │   ├── btree_parser.py      # Low-level B-Tree page reader & Cell extractor
│   │   ├── varint.py            # SQLite Varint decoder
│   │   ├── serial_types.py      # Serial Type payload dynamic parser
│   │   ├── wal_engine.py        # WAL header/frame differential analyzer
│   │   └── carver.py            # Slack space & Freelist unallocated carver
│   ├── analyzers/
│   │   └── anomaly.py           # Anomaly scoring & Timestamp validator
│   └── reporters/
│       ├── json_reporter.py     # Machine-readable output
│       └── html_reporter.py     # Interactive single-page HTML report
├── tests/                       # Automated Pytest suite
│   ├── test_varint.py
│   ├── test_btree.py
│   ├── test_wal.py
│   └── samples/                 # Test database files
├── requirements.txt
├── setup.py
└── README.md
```

---

## 2. Low-Level Technical Requirements & Byte Specs

> **STRICT SYSTEM CONSTRAINT:** The core parsing engine MUST NOT import `sqlite3` or execute SQL queries. It must parse the raw binary byte stream using Python's `struct` module.

### A. SQLite File Header Specs (Database Page 1, Bytes 0–99)
* **Magic Header:** Must match `b"SQLite format 3\x00"` (16 bytes).
* **Page Size:** 2-byte big-endian integer at offset `16..18`. (Note: If value is `1`, actual page size is `65536`).
* **Reserved Bytes per Page:** 1-byte integer at offset `20`.
* **Freelist Trunk Page Count:** 4-byte big-endian integer at offset `32..36`.
* **Total Freelist Pages:** 4-byte big-endian integer at offset `36..40`.

### B. B-Tree Page Header Specs
Every page starts with a B-Tree page header (offset `100` on Page 1; offset `0` on all other pages).
* **Page Type Flag (1 byte at offset 0):**
  * `0x0D` (13): **Table Leaf Page** (*Primary Target for Data Carving*)
  * `0x05` (5): Table Interior Page
  * `0x0A` (10): Index Leaf Page
  * `0x02` (2): Index Interior Page
* **Cell Count:** 2-byte big-endian integer at offset `3..5`.
* **Start of Cell Content Area:** 2-byte big-endian integer at offset `5..7`. (If `0`, value is `65536`).
* **Fragmented Free Bytes:** 1-byte integer at offset `7`.
* **Cell Pointer Array:** Starts immediately after the page header (offset `8` for Leaf pages, offset `12` for Interior pages). Contains `Cell Count` number of 2-byte big-endian relative offsets pointing to individual cell bodies.

### C. Varint Decoding Rules (`core/varint.py`)
SQLite variable-length integers (Varints) are 1 to 9 bytes long:
* For bytes 1 through 8: The Most Significant Bit (MSB `0x80`) indicates if another byte follows. The lower 7 bits (`0x7F`) contain payload data.
* Byte 9 (if reached): All 8 bits are used as payload data.
* **Function Signature:** `decode_varint(buffer: bytes, offset: int = 0) -> tuple[int, int]` (returns `(decoded_value, bytes_read)`).

### D. Payload Header & Serial Type Encoding (`core/serial_types.py`)
Each B-Tree Cell on a Table Leaf Page (`0x0D`) consists of:
1. `payload_size` (Varint)
2. `row_id` (Varint)
3. `payload` (bytes) -> Contains `header_size` (Varint) followed by a series of `Serial Type` Varints.

**Serial Type Lookup Table:**
* `0`: NULL
* `1`: 8-bit Signed Integer (int8)
* `2`: 16-bit Big-Endian Integer (int16)
* `3`: 24-bit Big-Endian Integer (int24)
* `4`: 32-bit Big-Endian Integer (int32)
* `5`: 48-bit Big-Endian Integer (int48)
* `6`: 64-bit Big-Endian Integer (int64)
* `7`: 64-bit IEEE 754 Floating Point (float64)
* `8`: Constant 0
* `9`: Constant 1
* `10, 11`: Reserved for internal SQLite extensions.
* `N >= 12` and **EVEN**: BLOB of length `(N - 12) / 2`
* `N >= 13` and **ODD**: String (UTF-8 / ASCII) of length `(N - 13) / 2`

### E. Write-Ahead Log (WAL) Specifications (`core/wal_engine.py`)
* **WAL Header Size:** 32 bytes at offset `0`.
* **Magic Number (Bytes 0..4):** `0x377f0682` or `0x377f0683`.
* **Page Size (Bytes 8..12):** 4-byte big-endian integer.
* **WAL Frame Header:** Each 24-byte frame header precedes its corresponding page data payload:
  * `Bytes 0..4`: Page Number in main database file.
  * `Bytes 4..8`: Commit size (non-zero indicates a commit frame).
  * `Bytes 16..24`: Frame Checksums.
* **Differential Logic:** Parse WAL frames in sequence. If a frame modifies a page present in the main `.db` file, compare payload cells to flag "Phantom Records" (data deleted in the main DB but active in WAL frames).

---

## 3. Detailed Component Requirements

### 1. `carver.py` (Unallocated & Slack Space Carver)
* Must scan page regions between the end of the Cell Pointer Array and `Start of Cell Content Area` (slack space).
* Must walk the Freelist page chains (pointers from database header bytes `32..36`).
* Must use pattern matching to identify valid `Serial Type` header clusters without needing table schema definitions.

### 2. `anomaly.py` (Forensic Anomaly Engine)
Calculate an **Anomaly Score (0.0 to 1.0)** based on:
* **Timestamp Contradictions:** Compare embedded Unix/Mac Epoch dates against OS file metadata (`ctime`/`mtime`).
* **Orphaned Payload Cells:** Detect valid Serial Type payloads in slack space that have no corresponding pointer in the Cell Pointer Array.
* **Corrupted Pointer Offsets:** Pointers pointing beyond page boundaries or into header space.

### 3. `cli.py` (CLI Interface using `click`)
Expose the following commands:
* `sqlite-ghost parse <db_path>`: Standard extraction output to terminal.
* `sqlite-ghost parse <db_path> --wal <wal_path>`: Runs differential analysis against WAL.
* `sqlite-ghost carve <db_path>`: Deep scan of unallocated slack space.
* `sqlite-ghost report <db_path> --html <output_path>`: Generates interactive single-page HTML report.

---

## 4. Execution Plan for Google Antigravity

Please execute this project in four distinct phases, delivering code and test artifacts for each step:

1. **Phase 1: Foundation & Low-Level Engines**
   * Scaffold project structure, `requirements.txt` (`click`, `pytest`, `jinja2`), and `setup.py`.
   * Implement `varint.py` and `serial_types.py`.
   * Write unit tests in `test_varint.py` covering 1-byte, multi-byte, and 9-byte varints.

2. **Phase 2: B-Tree & WAL Parsing Engines**
   * Implement `btree_parser.py` (Page header, cell pointer array, payload extraction).
   * Implement `wal_engine.py` (WAL header verification, frame extraction, DB differential mapping).

3. **Phase 3: Carving & Anomaly Detection**
   * Implement `carver.py` (Slack space scanner, freelist parser).
   * Implement `anomaly.py` (Timestamp validation, anomaly scoring).

4. **Phase 4: CLI & Reporting**
   * Implement `cli.py` with `click`.
   * Implement `html_reporter.py` generating a clean, interactive single-page dashboard.
   * Run full test suite using `pytest`.