# ANVESH
## AI Malware Detector
> *"Uncover what your files hide."*

**ANVESH** is a web-based static malicious-file analysis and threat-risk assessment system. It allows users and security analysts to upload untrusted files and receive an in-depth, evidence-based security report without ever executing the uploaded binary or document.

Positioned strictly as a **static file analysis and threat-risk assessment tool** (not a commercial endpoint antivirus), ANVESH adheres to the principle of **Real Functionality > Fake AI**: every displayed metric, hash, entropy value, section table, and risk finding is computed through actual server-side binary inspection and genuine antivirus engine queries.

---

## 1. Problem Statement

Modern malware attacks often employ deception techniques to evade end-user suspicion and basic email filters:
- Disguising Windows executables as innocent documents (e.g., `invoice.pdf` having an internal Windows PE `MZ` header).
- Embedding malicious auto-executing macros in Microsoft Office files (`vbaProject.bin`, `AutoOpen`).
- Embedding `/Launch` and `/JavaScript` action triggers within PDF document object hierarchies.
- Bundling payloads inside archives with path traversal exploits (`../` Zip Slip) or deceptive double extensions (`report.pdf.exe`).
- Obfuscating or packing malicious binaries with runtime crypters (e.g., UPX, Themida), causing abnormally high Shannon byte entropy.

Most non-technical users and analysts lack safe, non-destructive tools to inspect suspicious files before double-clicking them.

---

## 2. Solution: ANVESH

ANVESH provides a secure, web-accessible inspection platform:
1. **Isolated Buffer Handling:** Untrusted uploads are stored in an isolated temporary location with randomized UUID names and are never executed.
2. **Deep Static Analysis:** Evaluates file magic bytes, PE headers, COFF tables, section entropy, import directories, suspicious APIs, PDF tags, Office relations, and archive entries.
3. **Cryptographic Fingerprinting:** Computes SHA-256, SHA-1, and MD5 hashes for reproducible tracking.
4. **Antivirus Integration (ClamAV):** Connects to a live ClamAV daemon (`clamd`) via TCP or local `clamscan` binary. When unavailable, it honestly marks ClamAV as unavailable instead of fabricating results.
5. **Explainable Risk Engine:** Aggregates findings into structured signals (`signal_id`, `category`, `severity`, `technical_evidence`, `plain_language`) and provides clear user recommendations.
6. **Bilingual UX (Technical + Plain English):** Every technical finding features an immediate *"In simple words"* translation so non-technical users understand the risk.

---

## 3. Architecture & Data Flow

```text
User / Web Browser (React + Vite + TailwindCSS)
         │
         ▼  (Multipart File Upload over HTTP)
Express.js Backend (Helmet + Rate Limiting + Multer Sandbox)
         │
         ├──► 1. File Identifier (Magic Bytes Inspection at Offset 0x00)
         ├──► 2. Hash Engine (SHA-256, SHA-1, MD5 via native node:crypto)
         ├──► 3. Shannon Entropy Calculator (Overall & 32-Chunk Distribution)
         ├──► 4. Format-Specific Analyzers:
         │         ├─ Windows PE Parser (Headers, Sections, Imports, Digital Sig, Overlay)
         │         ├─ PDF Structure Inspector (/Launch, /JS, /OpenAction, Streams)
         │         ├─ Office OpenXML & OLE Analyzer (VBA Macros, Remote Templates)
         │         ├─ Archive Inspector (Zip Slip, Bomb Ratios, Double Exts)
         │         └─ Script Heuristic Engine (LOLBins, Base64 Obfuscation, IEX)
         ├──► 5. ClamAV Engine (INSTREAM TCP protocol to clamd:3310 / CLI fallback)
         ├──► 6. External Threat Intelligence (Optional VirusTotal v3 Hash Lookup)
         │
         ▼
Explainable Risk Engine (Evidence Aggregation -> Risk Level & Confidence Calculation)
         │
         ▼  (Immediate Server Cleanup: File Unlinked & Zeroed)
Security Report Delivery (Structured JSON + Plain-English Guidance)
```

---

## 4. Key Features

- **Genuine File Type Identification:** Reads real magic bytes (e.g., `4D 5A` for PE, `%PDF-` for PDF, `50 4B 03 04` for ZIP/Office) rather than trusting untrusted extensions.
- **Extension Spoofing Detection:** Instantly flags high-severity mismatches when an executable masquerades as a PDF, JPEG, or DOCX document.
- **Shannon Byte Entropy:** Measures randomness on a scale from 0.0 to 8.0, identifying packed code, runtime crypters, and encrypted payloads.
- **Windows PE Executable Parsing:**
  - Architecture (x86, x64, ARM) and Subsystem (GUI vs CUI).
  - COFF Compile Timestamp analysis (detects future or ancient zeroed timestamps).
  - Section Table with virtual vs raw sizes, section entropy, and writable+executable (`W+X`) memory flags.
  - Suspicious API Import categorization (Process Injection, Memory Manipulation, Keylogging, Network C2, Anti-Debug).
  - Digital Signature presence check via the PE Security Data Directory.
  - Overlay data detection (data appended past the end of the last PE section).
- **Document & Archive Inspection:**
  - PDF `/JavaScript`, `/Launch`, `/OpenAction`, and `/EmbeddedFiles` detection.
  - Microsoft Office VBA macro detection (`vbaProject.bin`, `AutoOpen`) and external template injection (`_rels`).
  - ZIP archive inspection with decompression ratio safeguards (Zip Bomb protection) and directory traversal (`../` Zip Slip) detection.
- **URL & Network Extraction:** Safely extracts embedded URLs and IPv4 addresses without resolving them (SSRF-safe).
- **ClamAV Integration:** Streams files to `clamd` on port 3310 or calls local `clamscan`. If offline, honestly reports `ClamAV: Unavailable`.
- **Confidence vs. Risk:** Explicitly separates threat severity (Risk Level) from diagnostic completeness (Confidence Level).
- **Interactive Test Samples:** Built-in 1-click test samples (Clean PDF, Extension Spoof, EICAR Standard Antivirus Test, Suspicious Script) for immediate evaluation and viva demonstrations.
- **Scan History:** Client-side persistent history stored in browser `localStorage` (safe metadata only, no file storage).

---

## 5. Technology Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 18, Vite 6, TailwindCSS 3, Lucide Icons, JetBrains Mono & Inter typography |
| **Backend** | Node.js v24, Express.js 4, Multer, Helmet, CORS, Express-Rate-Limit |
| **Analysis Parsers** | Pure binary PE parser, PDF stream scanner, Yauzl streaming ZIP inspector, native `node:crypto` |
| **Antivirus Engine** | ClamAV (`clamd` TCP socket client via `INSTREAM` protocol / `clamscan` CLI fallback) |
| **External Intel** | Optional VirusTotal v3 REST API integration |
| **Testing** | Node.js native test runner (`node --test`), 23 automated unit and integration tests |

---

## 6. Installation & Setup

### Prerequisites
- **Node.js:** v18.0.0 or later (Node.js v24 recommended)
- **npm:** v9.0.0 or later
- **ClamAV (Optional for Antivirus Signatures):**
  - **Linux (Ubuntu/Debian):** `sudo apt install clamav clamav-daemon && sudo freshclam && sudo systemctl start clamav-daemon`
  - **macOS:** `brew install clamav && freshclam && clamd`
  - **Windows:** Download ClamAV for Windows from [ClamAV.net](https://www.clamav.net/downloads), run `freshclam.exe`, and start `clamd.exe` on port 3310.

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/mayanksupadhye-source/Anvesh-.git
cd Anvesh-
npm install
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Default configuration:
```env
PORT=5000
NODE_ENV=development
MAX_FILE_SIZE_MB=30
CLAMAV_HOST=127.0.0.1
CLAMAV_PORT=3310
CLAMSCAN_PATH=clamscan
VIRUSTOTAL_API_KEY=
```

### 3. Run Automated Tests
```bash
npm test
```
All 23 unit and integration tests will execute and verify binary parsers, entropy calculations, extension spoofing, risk engine scoring, and API routes.

### 4. Build the Production Bundle
```bash
npm run build
```

### 5. Start the Application
To run in production mode (Express serves both API and React frontend on port 5000):
```bash
npm start
```
Or for concurrent development with live hot-reloading:
```bash
npm run dev
```

Open your browser at:
```text
http://localhost:5000  (Production)
http://localhost:3000  (Vite Dev Server)
```

---

## 7. Safe Demonstration & Testing Guide

ANVESH does **NOT** require downloading or handling destructive malware. It includes built-in benign demonstration files accessible directly from the UI or via API:

1. **Clean Document Test (`sample_clean_document.pdf`):**
   - Click "Clean Document" under Interactive Test Samples.
   - Result: `LOW RISK`, zero suspicious signals, standard caution recommendation.
2. **Extension Spoofing Test (`urgent_invoice_october.pdf`):**
   - Click "Extension Spoof".
   - Demonstrates: File has `.pdf` extension, but binary header inspection reveals Windows PE `MZ` signature.
   - Result: `HIGH RISK`, flagged as `FILE_EXTENSION_SPOOFING`.
3. **EICAR Antivirus Test (`eicar_antivirus_test.com`):**
   - Click "EICAR Antivirus".
   - Demonstrates: Industry-standard benign 68-byte test string recognized worldwide by antivirus engines.
   - Result: If ClamAV is running, triggers `CRITICAL RISK` with `Win.Test.EICAR_HDB-1 FOUND`. If ClamAV is offline, accurately reports `ClamAV: Offline`.
4. **Suspicious Script Test (`suspicious_downloader.ps1`):**
   - Click "Suspicious Script".
   - Demonstrates: Harmless PowerShell script containing LOLBin commands (`certutil -urlcache`), base64 chunks, and `Invoke-Expression` patterns.
   - Result: `MEDIUM / HIGH RISK`, flagged by static heuristic rules.

---

## 8. Viva & Technical Presentation Preparation Guide

When explaining ANVESH to examiners or technical reviewers, use these verified technical answers:

### Q1: Why do we use cryptographic hashing (SHA-256) in malware analysis?
> **Answer:** Cryptographic hashing produces a deterministic, collision-resistant 256-bit unique digital fingerprint of the file contents. In cybersecurity, SHA-256 allows analysts to query global threat databases (e.g., VirusTotal, MalwareBazaar) and establish positive identification without transferring the file itself. Changing even 1 single bit in the file completely changes the hash (the avalanche effect).

### Q2: What is a magic byte / file signature, and why can file extensions not be trusted?
> **Answer:** A file extension is simply a string in the filename (e.g., `.pdf`) that an operating system uses as a hint for which default app to open. An attacker can easily rename `malware.exe` to `receipt.pdf`. Magic bytes are immutable byte sequences placed at offset `0x00` of a file by its format specification (e.g., `4D 5A` for PE binaries, `%PDF-` for PDFs, `50 4B 03 04` for ZIP/Office). ANVESH inspects the true binary header to detect extension spoofing immediately.

### Q3: What is Shannon Entropy, and how does it indicate packing or encryption?
> **Answer:** Shannon Entropy ($H = -\sum p_i \log_2 p_i$) measures the information density and randomness of byte values (0 to 255) on a scale from 0.0 to 8.0. Normal compiled program code typically has an entropy between 4.5 and 6.5. When entropy exceeds 7.2 in an executable section, it indicates that the bytes are uniformly randomized—a hallmark of encryption, compression, or runtime crypters (e.g., UPX, Themida) designed to evade static antivirus signatures.

### Q4: Why must uploaded files NEVER be executed on the analysis server?
> **Answer:** Executing untrusted files (dynamic execution) on a web server creates extreme risk: arbitrary code execution, ransomware encrypting the host, lateral network movement, or reverse shells. ANVESH operates strictly as a static analysis engine. Files are ingested into memory/isolated storage purely as read-only binary buffers (`Buffer`), parsed mathematically, and unlinked immediately.

### Q5: What is the difference between Risk Level and Confidence Level?
> **Answer:** Risk and Confidence are fundamentally separate dimensions.
> - **Risk Level** measures *how dangerous* the observed evidence is (LOW, MEDIUM, HIGH, CRITICAL).
> - **Confidence Level** measures *how complete and thorough* the analysis was (LOW, MEDIUM, HIGH).
> For example: A file with extension mismatch has `HIGH RISK`, but if ClamAV was offline, the analysis has `MEDIUM CONFIDENCE` because signature verification was unavailable. Similarly, a clean file where all parsers and ClamAV ran has `LOW RISK` with `HIGH CONFIDENCE`.

### Q6: What does the digital signature directory in a PE file indicate?
> **Answer:** A digital signature (Authenticode) uses public-key cryptography to prove that an executable was signed by a verified publisher and has not been altered since signing. In PE files, this is tracked in Data Directory index 4. Being unsigned does *not* prove maliciousness (many open-source or internal tools are unsigned), but having a valid signature removes a suspicion indicator.

### Q7: Why can no malware detector guarantee 100% detection?
> **Answer:** Malware authors continuously use polymorphic code, zero-day vulnerabilities, bespoke obfuscation, and living-off-the-land binaries (LOLBins) that carry no prior signature. Therefore, ANVESH does not claim to replace enterprise EDR or catch all threats; it positions itself honestly as an evidence-based static malicious-file analyzer and threat assessment platform.

---

## 9. Security & Hardening Controls

ANVESH incorporates defensive engineering principles for its own operation:
- **Zero Execution Guarantee:** Files are parsed as data streams; no child processes execute user uploads.
- **Path Traversal Protection:** User filenames are stripped via `path.basename()`. Internal storage utilizes randomized cryptographically secure UUID filenames (`crypto.randomBytes(16)`).
- **Automated Immediate Cleanup:** Uploaded temporary files are deleted in `finally` blocks upon completion of static analysis.
- **Resource & Upload Limits:** Default 30 MB upload cap; archive decompression safeguards prevent zip bomb memory/disk exhaustion.
- **SSRF Prevention:** Extracted URLs and IPs are parsed and categorized via regex; the server **never** makes outbound network requests to extracted links.
- **Security Headers & Rate Limiting:** Protected by `helmet` and `express-rate-limit` (100 requests per 15-minute window).
- **Leak Prevention:** Production error responses omit internal stack traces and server file paths.

---

## 10. Limitations & Future Scope

### Limitations
- **No Dynamic Sandbox Execution:** ANVESH does not execute files in a virtual machine (e.g., Cuckoo Sandbox); behaviors that only unpack at runtime cannot be captured dynamically.
- **Password-Protected Archives:** Encrypted zip files cannot have their internal file contents inspected without the key.
- **ClamAV Dependency for Signatures:** Antivirus signature detection requires a reachable ClamAV instance; otherwise, ANVESH relies purely on static structural heuristics.

### Future Scope
- Implementation of YARA rule compilation and custom rule loading.
- Machine Learning classification models trained on static PE section features (EMBER dataset).
- Automated disassembly / control-flow graph visualization using Capstone/Ghidra headless.
- Automated PDF JavaScript sandbox emulation using isolated V8 contexts.

---

## 11. Project Identity & Team

- **Product Name:** ANVESH (AI Malware Detector)
- **Tagline:** *Uncover what your files hide.*
- **Repository:** [https://github.com/mayanksupadhye-source/Anvesh-](https://github.com/mayanksupadhye-source/Anvesh-)
- **Developer:** Mayank Upadhye ([@mayanksupadhye-source](https://github.com/mayanksupadhye-source))
