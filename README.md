# 🔍 mime-scanner

> Production-grade MIME type identification for files and directories — powered by [Google Magika](https://github.com/google/magika).

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Powered by Magika](https://img.shields.io/badge/powered%20by-Magika-orange)](https://github.com/google/magika)

---

## Overview

`mime-scanner` wraps Google's deep-learning-based Magika library into a clean, importable Python module and a ready-to-use CLI tool. It was designed to work
equally well embedded in application code or invoked from a shell script, CI pipeline, or orchestration layer.

**Key features:**

- Dual-mode — import as a library **or** run as a CLI script with no code changes
- Structured `FileScanResult` dataclass with `mime_type`, `label`, `status`, and `error` fields
- Multiple output formats: JSON, table, CSV
- Recursive directory scanning via `--recursive`
- Per-file error isolation — one bad file never crashes the whole scan
- CI-friendly exit codes with `--fail-on-error`
- Fully typed with `from __future__ import annotations` + standard `typing`
- Standard `logging` integration (no rogue `print()` calls in library mode)

---

## Requirements

- Python 3.9+
- [Magika](https://github.com/google/magika) (`pip install magika`)

---

## Installation

```bash
# Clone the repo
git clone https://github.com/your-org/mime-scanner.git
cd mime-scanner

# Install dependencies
pip install -r requirements.txt
```

`requirements.txt`:

```
magika>=0.5.0
```

---

## Usage

### As a CLI tool

```bash
# Scan a single file
python mime_scanner.py -filepath /path/to/file.bin

# Scan a directory (top-level only), output as JSON
python mime_scanner.py -filepath /path/to/folder --output json

# Recursive scan, table output, verbose logging
python mime_scanner.py -filepath /data --recursive --output table --log-level DEBUG

# Use in a shell pipeline — exit code 2 on any scan error
python mime_scanner.py -filepath /uploads --fail-on-error && echo "All clean"
```

**Output formats:**

| Flag             | Description                            |
| ---------------- | -------------------------------------- |
| `--output table` | Human-readable aligned table (default) |
| `--output json`  | Machine-readable JSON array            |
| `--output csv`   | CSV with header row, pipe-friendly     |

**All CLI flags:**

```
-filepath PATH        File or directory to scan (default: .)
-r, --recursive       Recurse into sub-directories
--output FORMAT       Output format: json, table, csv (default: table)
--log-level LEVEL     DEBUG / INFO / WARNING / ERROR / CRITICAL (default: WARNING)
--fail-on-error       Exit with code 2 if any file failed to scan
```

---

### As a Python module

The public API surface is intentionally minimal — two functions cover every use case:

#### `scan_path(path, *, recursive=False, magika_instance=None)`

Scan a file or an entire directory tree.

```python
from mime_scanner import scan_path, ScanStatus

results = scan_path("/data/uploads", recursive=True)

for r in results:
    if r.status == ScanStatus.OK:
        print(f"{r.path} → {r.label} ({r.mime_type})")
    elif r.status == ScanStatus.ERROR:
        print(f"Failed: {r.path} — {r.error}")
```

#### `scan_files(file_paths, *, magika_instance=None)`

Scan an explicit list of file paths (useful when you already have a list from another source).

```python
from mime_scanner import scan_files

paths = ["/tmp/upload_a.bin", "/tmp/upload_b.docx"]
results = scan_files(paths)
```

#### `format_results(results, fmt)`

Render results into any supported output format programmatically.

```python
from mime_scanner import scan_path, format_results, OutputFormat

results = scan_path("/data")
csv_output = format_results(results, OutputFormat.CSV)

with open("report.csv", "w") as f:
    f.write(csv_output)
```

---

### The `FileScanResult` dataclass

Every function returns a `list[FileScanResult]`. Fields:

| Field       | Type          | Description                                  |
| ----------- | ------------- | -------------------------------------------- |
| `path`      | `str`         | Absolute or relative path scanned            |
| `mime_type` | `str \| None` | Full MIME type string e.g. `application/pdf` |
| `label`     | `str \| None` | Magika short label e.g. `pdf`, `elf`, `zip`  |
| `status`    | `ScanStatus`  | `ok`, `error`, or `skipped`                  |
| `error`     | `str \| None` | Error message if `status != ok`              |

Call `.to_dict()` on any result for a plain `dict` (JSON-serializable).

---

## Integration Examples

### FastAPI endpoint — validate uploaded files

```python
from fastapi import UploadFile, HTTPException
from mime_scanner import scan_files, ScanStatus

ALLOWED_MIME = {"application/pdf", "image/jpeg", "image/png"}

async def upload(file: UploadFile):
    tmp = f"/tmp/{file.filename}"
    with open(tmp, "wb") as f:
        f.write(await file.read())

    results = scan_files([tmp])
    r = results[0]

    if r.status != ScanStatus.OK or r.mime_type not in ALLOWED_MIME:
        raise HTTPException(status_code=415, detail=f"Unsupported file type: {r.mime_type}")

    return {"mime_type": r.mime_type, "label": r.label}
```

### Batch processing with a shared Magika instance

```python
from magika import Magika
from mime_scanner import scan_files

# Reuse one instance across thousands of files — much faster
mg = Magika()

for batch in chunks(all_files, size=500):
    results = scan_files(batch, magika_instance=mg)
    process(results)
```

### Shell pipeline — output JSON, filter with jq

```bash
python mime_scanner.py -filepath /uploads --output json \
  | jq '[.[] | select(.status == "ok" and .label == "elf")]'
```

---

## Project Structure

```
mime-scanner/
├── mime_scanner.py      # Main module — CLI + importable API
├── requirements.txt
├── tests/
│   ├── test_scan.py
│   └── fixtures/        # Sample files for unit tests
└── README.md
```

---

## Testing

```bash
pip install pytest
pytest tests/ -v
```

---

## Exit Codes

| Code | Meaning                                                |
| ---- | ------------------------------------------------------ |
| `0`  | Success                                                |
| `1`  | Invalid path / usage error                             |
| `2`  | One or more files failed (only with `--fail-on-error`) |

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgements

Built on top of [Google Magika](https://github.com/google/magika) — a content-type detection tool that uses deep learning to identify file types accurately,
even when extensions are missing or spoofed.
