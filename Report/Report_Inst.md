# Mission Brief: Generate CIAP Forensic Project Report & Presentation Content

**Objective:** Create a comprehensive, professionally formatted CIAP Digital Forensics Project Report for `SQLite-Ghost`, matching the structure, depth, visual slide breakdowns, and technical formatting of the provided reference report ("Browser History Analysis: A Forensic Approach").

---

## 1. Project Metadata
* **Project Title:** Mobile Forensics & SQLite Data Recovery: The `SQLite-Ghost` Framework
* **Sub-title:** Schema-Agnostic B-Tree Cell Parsing & WAL Anomaly Detection (NFL Deflategate Investigation)
* **Course:** Digital Forensics / Cybercrime Investigation
* **Team Members:**
  1. Soham Alpesh Phulare (23UF17971CM107)
  2. Sumeet Devrukhkar (23UF17758CM073)

---

## 2. Document Structure Requirements
Please generate the complete report formatted in Markdown, incorporating all of the following explicit steps and presentation chapter breakdowns:

### Chapter 1: Foundational Concepts & Presentation Slides
* **Slide 1: Title & Authors** (Project metadata, course details, clean layout description).
* **Slide 2: The Role of Mobile Forensics** (Establishing timelines, determining intent, tracing exfiltration in messaging apps).
* **Slide 3: Project Objective & Target** (iOS `sms.db`, B-Tree Leaf Page `0x0D`, `.db-wal` Write-Ahead Logs).
* **Slide 4: Defining Suspicious Markers for Triage** (Deflategate keywords: "deflator", "balloon", "espn", "shoes", "psi").
* **Slide 5: Locating and Securing Evidence** (Copying DB/WAL to temp path, establishing SHA-256 hashes, avoiding database locks).
* **Slide 6: Database Handling & Varint Conversion** (Raw byte reading using `struct`, Varint payload decoding, Apple Mac Absolute Time to UTC conversion).
* **Slide 7: Detection & Carving Logic** (Diagrammatic workflow: Read raw bytes -> Identify `0x0D` Leaf Pages -> Extract Varint Serial Types -> Recover Slack Space -> Output Report).
* **Slide 8: Output Report Overview** (Section 1: Carved Deleted Messages; Section 2: Anomaly Confidence Scores).
* **Slide 9: Summary & Future Work** (Functionality recap, zero-dependency engine, future GUI & SQLCipher support).

---

### Step 2: Identify Digital Evidence Sources
Provide a formatted table with two columns (**Evidence Source** | **Description**):
1. **Primary SQLite Database (`sms.db`):** Stores active chat threads (`message` and `handle` tables).
2. **Write-Ahead Log (`sms.db-wal`):** Stores uncommitted or recently deleted B-Tree frames.
3. **Unallocated Freelist & Slack Space:** Regions between cell pointers where erased text fragments remain.
4. **Cryptographic Hashes (SHA-256):** Preserved baseline hashes for chain-of-custody verification.
5. **Carved Forensic Text Output (`ghost_report.txt`):** Automated report detailing recovered messages, hex offsets, and timestamps.

---

### Step 3: Conceptual Exploration & Forensic Principles Applied
* **Forensic Principles Applied:**
  * *Integrity & Preservation:* Working on temporary binary copies with SHA-256 hash validation.
  * *Auditability & Transparency:* Documented binary parsing logic without black-box SQL queries.
  * *Reproducibility:* Scriptable, deterministic byte-level parsing on any standard SQLite file.
  * *Schema-Agnostic Autonomy:* Bypasses `sqlite_master` dependency to carve deleted records.
* **Tools & Techniques:** Python 3 (`struct`, `os`, `sys`, `shutil`, `tempfile`), HxD, DB Browser for SQLite.
* **Core Binary Offsets & Parsing Formulas:**
  * B-Tree Leaf Page Flag: `0x0D` (Byte offset 0).
  * Varint Decoding Math: Read bits 0..6 as payload; bit 7 as continuation flag.
  * iOS Timestamp Formula: `UTC_Datetime = datetime(2001, 1, 1) + timedelta(seconds=Mac_Absolute_Timestamp)`.

---

### Step 4: Hypothesis & Investigation Plan
* **Hypothesis:** Deleted mobile communications and uncommitted transaction artifacts can be reliably carved and reconstructed from iOS `sms.db` unallocated space and `.db-wal` files using low-level Varint payload decoding without relying on an intact database schema.
* **7-Step Investigation Plan:**
  1. Locate and duplicate `sms.db` and `sms.db-wal` to a isolated temporary path.
  2. Generate SHA-256 hashes for baseline chain of custody.
  3. Scan database pages for `0x0D` Leaf B-Tree page headers.
  4. Parse cell pointer arrays and traverse unallocated slack space between cell contents.
  5. Decode Varint Serial Types to reconstruct string text payloads and integer contact handles.
  6. Perform differential analysis between `.db-wal` frame headers and main database pages.
  7. Generate structured forensic output with anomaly confidence scores.

---

### Step 5: Sample Forensic Output
Provide a realistic terminal execution transcript and output tables mirroring the style of the sample PDF:
* **Section 1: Carved / Recovered Deleted Communications** (Columns: *Timestamp (UTC) | Sender / Contact | Carved Payload Text | Recovery Origin*). Include the Deflategate messages (e.g., "im going make that next ball a f***ing balloon", "I am not going to espn........yet.").
* **Section 2: Anomaly & Tampering Log** (Columns: *Flag Triggered | Offset / Page | Confidence Score | Detail*).
* **Execution Log Simulation:** Terminal output showing step-by-step progress (`[+] STEP 1: Copying sms.db...`, `[+] STEP 2: Parsing B-Tree Leaf Pages...`, `[!] Carved Deleted Record at Offset 0x0E80`).

---

### Step 6: Recommendations & Next Steps
* Extend parsing engine to support encrypted SQLite databases (SQLCipher).
* Develop a real-time daemon for live WAL monitoring during active incidents.
* Integrate an automated GUI dashboard (e.g., PyQt / Electron) for non-technical analysts.
* Benchmark against NIST CFReDS datasets for formal tool validation.

---

### Step 7: Code & Output (Standalone Demonstration Script)
Provide a complete, fully functional, standalone Python script named `sqlite_ghost_demo.py` that implements:
1. Copying DB to temp directory.
2. Low-level Varint decoding (`decode_varint`).
3. Binary page header inspection for `0x0D` leaf pages.
4. Basic string carving from unallocated slack space.
5. Formatting and printing the forensic report to terminal and file.

---

**Execution Instructions:** Please output the entire document cleanly in Markdown so it can be compiled directly into a PDF or presentation slide deck.