#!/usr/bin/env python3
"""Verify the received package against its delivery manifest; no network needed."""
from pathlib import Path
import hashlib
import sys
root = Path(__file__).resolve().parent
bad = []
count = 0
for line in (root / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
    expected, relative = line.split("  ", 1)
    path = root / relative
    if not path.resolve().is_relative_to(root) or not path.is_file():
        bad.append(relative + ": missing or invalid path")
    elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        bad.append(relative + ": checksum mismatch")
    count += 1
print(f"Checked {count} files; mismatches: {len(bad)}")
for problem in bad:
    print(problem)
sys.exit(1 if bad else 0)
