#!/usr/bin/env python3
"""
ClamAV signature importer for akavdb-tool.

Parses ClamAV .hdb (MD5 hash) and .ndb (byte-pattern) signature files
and converts them to the JSON format accepted by akavdb_tool.py compile.

ClamAV formats:
    .hdb  —  MD5_hash:file_size:malware_name
    .ndb  —  malware_name:target_type:offset:hex_signature

Usage:
    python -m importers.clamav --hdb sigs.hdb --ndb sigs.ndb -o output.json [--limit 100]
    python -m importers.clamav --hdb sigs.hdb -o output.json
"""

import argparse
import json
import re
import sys


def parse_hdb(path: str, limit: int = 0) -> list:
    """Parse a ClamAV .hdb file (MD5 hash signatures).

    Format: MD5_hash:file_size:malware_name
    Returns list of {"name": str, "hash": str} dicts for the md5 section.
    """
    entries = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) < 3:
                print(f"WARNING: {path}:{lineno}: malformed line (expected 3+ fields), skipping",
                      file=sys.stderr)
                continue

            md5_hash = parts[0].lower()
            # file_size = parts[1]  # not used in our format
            name = parts[2]

            # Validate MD5 hex
            if not re.fullmatch(r"[0-9a-f]{32}", md5_hash):
                print(f"WARNING: {path}:{lineno}: invalid MD5 '{md5_hash}', skipping",
                      file=sys.stderr)
                continue

            entries.append({"name": name, "hash": md5_hash})

            if 0 < limit <= len(entries):
                break

    return entries


def parse_ndb(path: str, limit: int = 0) -> list:
    """Parse a ClamAV .ndb file (byte-pattern signatures).

    Format: malware_name:target_type:offset:hex_signature
    Target types: 0=any, 1=PE, 2=OLE2, etc.
    Offset: *, N, or EP+N/EP-N (we only support * and literal offsets).

    Returns list of {"name": str, "pattern": str} dicts for the bytestream section.
    Only imports signatures with clean hex patterns (no wildcards like {n},
    (aa|bb), or ??).
    """
    entries = []
    skipped_wildcard = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) < 4:
                print(f"WARNING: {path}:{lineno}: malformed line (expected 4+ fields), skipping",
                      file=sys.stderr)
                continue

            name = parts[0]
            # target_type = parts[1]  # informational only
            # offset = parts[2]       # not used for Aho-Corasick (full-buffer scan)
            hex_sig = parts[3]

            # Strip trailing whitespace/newlines from hex sig
            hex_sig = hex_sig.strip().lower()

            # Skip signatures with ClamAV-specific wildcards we can't represent:
            #   ?? (any byte), {n} or {n-m} (byte ranges), (aa|bb) (alternation),
            #   * (any number of bytes), ! (negation)
            if re.search(r"[?*!{}()|]", hex_sig):
                skipped_wildcard += 1
                continue

            # Validate remaining hex
            if not re.fullmatch(r"[0-9a-f]+", hex_sig):
                print(f"WARNING: {path}:{lineno}: non-hex chars in sig, skipping",
                      file=sys.stderr)
                continue

            # Must be even length (complete bytes)
            if len(hex_sig) % 2 != 0:
                print(f"WARNING: {path}:{lineno}: odd-length hex sig, skipping",
                      file=sys.stderr)
                continue

            # Skip very short patterns (< 4 bytes) — too many false positives
            if len(hex_sig) < 8:
                continue

            entries.append({"name": name, "pattern": hex_sig})

            if 0 < limit <= len(entries):
                break

    if skipped_wildcard > 0:
        print(f"INFO: Skipped {skipped_wildcard} .ndb sigs with wildcards "
              f"(not supported by Aho-Corasick literal matching)",
              file=sys.stderr)

    return entries


def import_clamav(hdb_path: str = None, ndb_path: str = None,
                  limit: int = 0) -> dict:
    """Import ClamAV signatures and return akavdb-tool JSON structure."""
    result = {}

    if hdb_path:
        md5_sigs = parse_hdb(hdb_path, limit)
        if md5_sigs:
            result["md5"] = md5_sigs
            print(f"Imported {len(md5_sigs)} MD5 signatures from {hdb_path}",
                  file=sys.stderr)

    if ndb_path:
        ndb_limit = max(0, limit - len(result.get("md5", []))) if limit > 0 else 0
        byte_sigs = parse_ndb(ndb_path, ndb_limit)
        if byte_sigs:
            result["bytestream"] = byte_sigs
            print(f"Imported {len(byte_sigs)} byte-pattern signatures from {ndb_path}",
                  file=sys.stderr)

    total = sum(len(v) for v in result.values())
    print(f"Total: {total} signatures", file=sys.stderr)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Import ClamAV .hdb/.ndb signatures to akavdb-tool JSON format"
    )
    parser.add_argument("--hdb", help="ClamAV .hdb file (MD5 hash signatures)")
    parser.add_argument("--ndb", help="ClamAV .ndb file (byte-pattern signatures)")
    parser.add_argument("-o", "--output", required=True,
                        help="Output JSON file for akavdb_tool.py compile")
    parser.add_argument("--limit", type=int, default=0,
                        help="Max total signatures to import (0=unlimited)")

    args = parser.parse_args()

    if not args.hdb and not args.ndb:
        print("ERROR: specify at least one of --hdb or --ndb", file=sys.stderr)
        sys.exit(1)

    sig_defs = import_clamav(args.hdb, args.ndb, args.limit)

    with open(args.output, "w") as f:
        json.dump(sig_defs, f, indent=2)

    print(f"Wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
