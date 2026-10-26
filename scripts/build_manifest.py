#!/usr/bin/env python3
"""Build a deterministic SHA-256 manifest for the public artifact tree."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", default="MANIFEST.sha256")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    output = root / args.output
    paths = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and ".git" not in path.relative_to(root).parts
        and "__pycache__" not in path.relative_to(root).parts
        and path.suffix not in {".pyc", ".pyo"}
        and path.resolve() != output.resolve()
    )
    lines = [f"{sha256(path)}  {path.relative_to(root).as_posix()}" for path in paths]
    output.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {output} with {len(lines)} entries")


if __name__ == "__main__":
    main()
