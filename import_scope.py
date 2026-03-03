#!/usr/bin/env python3
"""Import plain asset lines into scope.txt as allow rules.
Usage: python3 import_scope.py assets.txt scope.txt
"""
from pathlib import Path
import sys


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 import_scope.py <assets.txt> <scope.txt>")
        return 2
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    if not src.exists():
        print(f"Source not found: {src}")
        return 2

    rules = []
    for line in src.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("allow:", "deny:")):
            rules.append(line)
        else:
            rules.append(f"allow:{line}")

    existing = dst.read_text(encoding="utf-8") if dst.exists() else ""
    with dst.open("a", encoding="utf-8") as f:
        if existing and not existing.endswith("\n"):
            f.write("\n")
        f.write("\n# Imported rules\n")
        for r in rules:
            f.write(r + "\n")

    print(f"Imported {len(rules)} rules into {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
