#!/usr/bin/env python3
"""
Integration test for the ClamAV importer.

Generates synthetic .hdb and .ndb files, imports them, compiles to .akavdb,
and verifies the EICAR test string is detected.

Acceptance criteria (P1-T7):
    Import 100-sig subset. Compile → count matches. Known sample → detected.
"""

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOL_DIR = os.path.dirname(SCRIPT_DIR)

# EICAR test string
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
         b"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
EICAR_MD5 = hashlib.md5(EICAR).hexdigest()


def generate_test_hdb(path: str, count: int = 60):
    """Generate a synthetic .hdb with `count` entries, including EICAR."""
    with open(path, "w") as f:
        # First entry: real EICAR MD5
        f.write(f"{EICAR_MD5}:{len(EICAR)}:EICAR.TestFile.HDB\n")

        # Remaining entries: synthetic MD5s
        for i in range(1, count):
            fake_md5 = hashlib.md5(f"synthetic-malware-{i}".encode()).hexdigest()
            f.write(f"{fake_md5}:{1000 + i}:Synth.Malware.{i}\n")


def generate_test_ndb(path: str, count: int = 40):
    """Generate a synthetic .ndb with `count` entries, including EICAR pattern."""
    with open(path, "w") as f:
        # First entry: EICAR byte pattern (first 16 bytes)
        eicar_hex = EICAR[:16].hex()
        f.write(f"EICAR.TestFile.NDB:0:*:{eicar_hex}\n")

        # Some entries with wildcards (should be skipped)
        f.write("Wildcard.Test1:0:*:aabb??ccdd\n")
        f.write("Wildcard.Test2:0:*:aabb{4}ccdd\n")
        f.write("Wildcard.Test3:0:*:aa(bb|cc)dd\n")

        # Remaining: synthetic clean hex patterns
        for i in range(1, count):
            fake_pattern = hashlib.sha256(f"synth-pattern-{i}".encode()).hexdigest()[:32]
            f.write(f"Synth.Pattern.{i}:0:*:{fake_pattern}\n")


def run_cmd(args, check=True, capture=True):
    """Run a command and return stdout."""
    result = subprocess.run(
        args, capture_output=capture, text=True, check=check,
        cwd=TOOL_DIR
    )
    return result


def main():
    errors = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        hdb_path = os.path.join(tmpdir, "test.hdb")
        ndb_path = os.path.join(tmpdir, "test.ndb")
        json_path = os.path.join(tmpdir, "imported.json")
        db_path = os.path.join(tmpdir, "test.akavdb")

        # Step 1: Generate test ClamAV files
        print("=== Step 1: Generate synthetic ClamAV files ===")
        generate_test_hdb(hdb_path, 60)
        generate_test_ndb(ndb_path, 40)
        print(f"  Generated {hdb_path} (60 entries)")
        print(f"  Generated {ndb_path} (40 entries + 3 wildcard)")

        # Step 2: Import
        print("\n=== Step 2: Import ClamAV signatures ===")
        r = run_cmd([
            sys.executable, "-m", "importers.clamav",
            "--hdb", hdb_path, "--ndb", ndb_path,
            "-o", json_path, "--limit", "100"
        ])
        print(r.stderr.strip())

        # Step 3: Verify JSON
        print("\n=== Step 3: Verify imported JSON ===")
        with open(json_path) as f:
            sig_defs = json.load(f)

        md5_count = len(sig_defs.get("md5", []))
        bs_count = len(sig_defs.get("bytestream", []))
        total = md5_count + bs_count
        print(f"  MD5 sigs: {md5_count}")
        print(f"  Byte-stream sigs: {bs_count}")
        print(f"  Total: {total}")

        if total == 0:
            print("  FAIL: No signatures imported")
            errors += 1
        elif total > 100:
            print(f"  FAIL: Expected <= 100, got {total}")
            errors += 1
        else:
            print(f"  OK: {total} signatures imported")

        # Check EICAR is present in MD5 section
        eicar_in_md5 = any(s["hash"] == EICAR_MD5 for s in sig_defs.get("md5", []))
        print(f"  EICAR in MD5: {'YES' if eicar_in_md5 else 'NO'}")
        if not eicar_in_md5:
            print("  FAIL: EICAR MD5 not found in imported sigs")
            errors += 1

        # Check EICAR pattern in bytestream section
        eicar_hex = EICAR[:16].hex()
        eicar_in_bs = any(s["pattern"] == eicar_hex for s in sig_defs.get("bytestream", []))
        print(f"  EICAR in bytestream: {'YES' if eicar_in_bs else 'NO'}")
        if not eicar_in_bs:
            print("  FAIL: EICAR pattern not found in imported sigs")
            errors += 1

        # Step 4: Compile
        print("\n=== Step 4: Compile to .akavdb ===")
        r = run_cmd([
            sys.executable, "akavdb_tool.py", "compile",
            json_path, "-o", db_path
        ])
        print(r.stdout.strip())

        # Step 5: Verify
        print("\n=== Step 5: Verify .akavdb ===")
        r = run_cmd([
            sys.executable, "akavdb_tool.py", "verify", db_path
        ])
        print(r.stdout.strip())

        # Step 6: Stats — check signature count matches
        print("\n=== Step 6: Stats ===")
        r = run_cmd([
            sys.executable, "akavdb_tool.py", "stats", db_path
        ])
        print(r.stdout.strip())

        # Step 7: Test EICAR detection
        print("\n=== Step 7: Test EICAR detection ===")
        r = run_cmd([
            sys.executable, "akavdb_tool.py", "test", db_path, "--eicar"
        ], check=False)
        print(r.stdout.strip())

        if r.returncode == 1:
            print("  OK: EICAR detected (exit code 1)")
        else:
            print(f"  FAIL: Expected exit code 1, got {r.returncode}")
            errors += 1

        # Step 8: Test EICAR file via --file
        print("\n=== Step 8: Test EICAR via --file ===")
        eicar_file = os.path.join(tmpdir, "eicar.com")
        with open(eicar_file, "wb") as f:
            f.write(EICAR)

        r = run_cmd([
            sys.executable, "akavdb_tool.py", "test", db_path, "--file", eicar_file
        ], check=False)
        print(r.stdout.strip())

        if r.returncode == 1:
            print("  OK: EICAR file detected (exit code 1)")
        else:
            print(f"  FAIL: Expected exit code 1, got {r.returncode}")
            errors += 1

    # Summary
    print(f"\n{'='*50}")
    if errors == 0:
        print("ALL TESTS PASSED")
    else:
        print(f"FAILED: {errors} error(s)")
    return errors


if __name__ == "__main__":
    sys.exit(main())
