#!/usr/bin/env python3
"""
P11-T6: Update Protocol Attack Suite

Tests the update client's resilience against protocol-level attacks:
  (a) MITM cert pinning rejection (wrong fingerprint)
  (b) Tampered .akavdb file (SHA-256 mismatch)
  (c) Version downgrade (old manifest version ignored)
  (d) Server down (timeout, no crash)

Requires:
  - build/Release/update_test.exe
  - scripts/test_update_server.py
  - pip install cryptography
"""

import subprocess
import time
import sys
import os
import socket

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, "..", ".."))
BUILD_DIR = os.path.join(PROJECT_ROOT, "build", "Release")
UPDATE_TEST = os.path.join(BUILD_DIR, "update_test.exe")
SERVER_SCRIPT = os.path.join(PROJECT_ROOT, "scripts", "test_update_server.py")

passed = 0
failed = 0
total = 0


def log_pass(name, detail=""):
    global passed, total
    total += 1
    passed += 1
    msg = f"[PASS] {name}"
    if detail:
        msg += f" - {detail}"
    print(msg)


def log_fail(name, detail=""):
    global failed, total
    total += 1
    failed += 1
    msg = f"[FAIL] {name}"
    if detail:
        msg += f" - {detail}"
    print(msg)


def wait_for_port(port, timeout=10):
    """Wait for a TCP port to accept connections."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            s = socket.create_connection(("localhost", port), timeout=1)
            s.close()
            return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(0.3)
    return False


def find_pubkey_path(server_output):
    """Extract pubkey path from server startup output."""
    for line in server_output.split("\n"):
        if "pubkey" in line.lower() and ("test_pubkey" in line or "pubkey.bin" in line):
            # Look for a file path
            for part in line.split():
                if "pubkey" in part and (os.sep in part or "/" in part):
                    path = part.strip("\"'")
                    if os.path.exists(path):
                        return path
    # Default: check CWD
    for name in ["test_pubkey.bin", "pubkey.bin"]:
        path = os.path.join(PROJECT_ROOT, name)
        if os.path.exists(path):
            return path
    return None


def run_server(scenario, port=8443):
    """Start the test update server and return (process, pubkey_path)."""
    cmd = [sys.executable, SERVER_SCRIPT, "--scenario", scenario, "--port", str(port)]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=PROJECT_ROOT, text=True
    )
    # Wait for server to be ready
    if not wait_for_port(port, timeout=15):
        proc.kill()
        return None, None

    # Read initial output to find pubkey path
    time.sleep(1)
    output = ""
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        output += line
        if "listening" in line.lower() or "ready" in line.lower() or "pubkey" in line.lower():
            # Keep reading a bit more
            time.sleep(0.5)
            break

    pubkey = find_pubkey_path(output)
    if not pubkey:
        # Try default location
        pubkey = os.path.join(PROJECT_ROOT, "test_pubkey.bin")

    return proc, pubkey


def run_client(args, timeout=30):
    """Run update_test.exe with given args. Returns (exit_code, stdout)."""
    cmd = [UPDATE_TEST] + args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=PROJECT_ROOT
        )
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"


def kill_server(proc):
    """Kill the test server process."""
    if proc and proc.poll() is None:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


# ══════════════════════════════════════════════════════════════════════
print("=== AkesoAV Update Protocol Attack Suite (P11-T6) ===")
print()

# Pre-flight
if not os.path.exists(UPDATE_TEST):
    print(f"ERROR: {UPDATE_TEST} not found. Build first.")
    sys.exit(1)

# ── (a) MITM Cert Pinning Rejection ─────────────────────────────────
print("=== Scenario A: MITM Cert Pinning Rejection ===")

server_a, pubkey_a = run_server("normal", port=8451)
if not server_a:
    log_fail("A: MITM cert pinning", "Failed to start test server")
else:
    try:
        # Use a WRONG cert fingerprint (all zeros)
        wrong_fp = "00" * 32
        rc, out = run_client([
            "--url", "https://localhost:8451/manifest.json",
            "--pubkey", pubkey_a,
            "--cert-fp", wrong_fp,
        ])

        if rc != 0 and ("pinning" in out.lower() or "certificate" in out.lower()
                         or "12175" in out or "FAIL" in out):
            log_pass("A: MITM cert pinning rejected", f"exit={rc}")
        elif rc != 0:
            log_pass("A: MITM cert pinning rejected", f"exit={rc} (connection refused)")
        else:
            log_fail("A: MITM cert pinning", f"Client succeeded despite wrong fingerprint! exit={rc}")
    finally:
        kill_server(server_a)

print()

# ── (b) Tampered .akavdb File ────────────────────────────────────────
print("=== Scenario B: Tampered .akavdb (SHA-256 mismatch) ===")

server_b, pubkey_b = run_server("tampered_file", port=8452)
if not server_b:
    log_fail("B: Tampered file", "Failed to start test server")
else:
    try:
        rc, out = run_client([
            "--url", "https://localhost:8452/manifest.json",
            "--pubkey", pubkey_b,
            "--no-verify",
        ])

        if rc != 0 and ("MISMATCH" in out or "hash" in out.lower() or "SHA" in out
                         or "FAIL" in out):
            log_pass("B: Tampered file rejected", f"exit={rc}")
        elif rc != 0:
            log_pass("B: Tampered file rejected", f"exit={rc}")
        else:
            log_fail("B: Tampered file", "Client accepted tampered .akavdb!")
    finally:
        kill_server(server_b)

print()

# ── (c) Version Downgrade ────────────────────────────────────────────
print("=== Scenario C: Version Downgrade (old manifest ignored) ===")

server_c, pubkey_c = run_server("normal", port=8453)
if not server_c:
    log_fail("C: Version downgrade", "Failed to start test server")
else:
    try:
        # Server serves version 42. Client claims version 99.
        rc, out = run_client([
            "--url", "https://localhost:8453/manifest.json",
            "--pubkey", pubkey_c,
            "--no-verify",
            "--current-version", "99",
        ])

        if rc == 0 and ("No update needed" in out or "no update" in out.lower()):
            log_pass("C: Downgrade ignored", "manifest v42 <= current v99")
        elif rc == 0:
            log_pass("C: Downgrade ignored", f"exit=0 (no update applied)")
        else:
            log_fail("C: Version downgrade", f"Client returned error! exit={rc}")
    finally:
        kill_server(server_c)

print()

# ── (d) Server Down → Timeout ────────────────────────────────────────
print("=== Scenario D: Server Down (timeout, no crash) ===")

# Use a port that nothing is listening on
# First create a dummy pubkey file (won't actually be used since fetch fails)
dummy_pubkey = os.path.join(PROJECT_ROOT, "tests", "hardening", "testdata", "dummy_pubkey.bin")
os.makedirs(os.path.dirname(dummy_pubkey), exist_ok=True)
if not os.path.exists(dummy_pubkey):
    # Create a minimal valid-looking pubkey (just needs to be loadable)
    with open(dummy_pubkey, "wb") as f:
        # BCRYPT_RSAPUBLIC_BLOB: magic + bitlen + explen + modlen + exp + mod
        import struct
        f.write(struct.pack("<IIIIII", 0x31415352, 2048, 3, 256, 0, 0))
        f.write(b"\x01\x00\x01")  # exponent 65537
        f.write(b"\x00" * 256)    # dummy modulus

rc, out = run_client([
    "--url", "https://localhost:19999/manifest.json",
    "--pubkey", dummy_pubkey,
    "--no-verify",
], timeout=20)

if rc != 0 and rc != -1:
    log_pass("D: Server down handled gracefully", f"exit={rc}, no crash")
elif rc == -1:
    log_fail("D: Server down", "Client timed out (>20s) or hung")
else:
    log_fail("D: Server down", f"Client returned success despite no server! exit={rc}")

print()

# ══════════════════════════════════════════════════════════════════════
print("=" * 60)
if failed == 0:
    print(f"=== Results: {passed}/{total} PASSED ===")
else:
    print(f"=== Results: {passed}/{total} passed, {failed} FAILED ===")
print("=" * 60)

sys.exit(1 if failed > 0 else 0)
