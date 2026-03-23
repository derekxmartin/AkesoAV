#!/usr/bin/env python3
"""test_update_server.py -- Local HTTPS test server for update client integration testing.

Generates a self-signed cert + RSA key pair, serves a manifest and .akavdb file,
and supports tampered/expired cert scenarios.

Usage:
    python scripts/test_update_server.py [--port 8443] [--scenario normal|tampered_manifest|tampered_file|expired_cert]

Scenarios:
    normal            - Serve valid manifest + valid .akavdb (default)
    tampered_manifest - Serve manifest with wrong RSA signature
    tampered_file     - Serve .akavdb with wrong SHA-256
    expired_cert      - Serve with an expired TLS certificate

The script prints:
    - Server cert SHA-256 fingerprint (for cert pinning)
    - RSA public key blob (hex, for signature verification)
    - Manifest URL
"""

import argparse
import hashlib
import http.server
import json
import os
import ssl
import struct
import sys
import tempfile
from datetime import datetime, timedelta, timezone

# Try to import cryptography; fall back to subprocess openssl if unavailable
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.x509.oid import NameOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    print("WARNING: 'cryptography' package not installed. Install with:")
    print("  pip install cryptography")
    sys.exit(1)


def generate_rsa_keypair():
    """Generate RSA-2048 key pair, return (private_key, public_key_bcrypt_blob)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = private_key.public_key()
    pub_numbers = pub.public_numbers()

    # Build BCRYPT_RSAPUBLIC_BLOB
    # struct { ULONG Magic, BitLength, cbPublicExp, cbModulus; }
    # followed by exponent bytes (big-endian) and modulus bytes (big-endian)
    e_bytes = pub_numbers.e.to_bytes(3, 'big')  # 65537 = 3 bytes
    n_bytes = pub_numbers.n.to_bytes(256, 'big')

    blob = struct.pack('<IIII', 0x31415352, 2048, len(e_bytes), len(n_bytes))
    blob += e_bytes + n_bytes

    return private_key, blob


def rsa_sign(private_key, data: bytes) -> bytes:
    """Sign data with RSA PKCS1v15 + SHA256."""
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def generate_self_signed_cert(private_key, expired=False):
    """Generate a self-signed TLS certificate. If expired=True, cert is already expired."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AkesoAV Test"),
    ])

    now = datetime.now(timezone.utc)
    if expired:
        not_before = now - timedelta(days=365)
        not_after = now - timedelta(days=1)
    else:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=365)

    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False)
            .sign(private_key, hashes.SHA256()))

    return cert


def cert_sha256_fingerprint(cert) -> bytes:
    """Get SHA-256 fingerprint of certificate DER encoding."""
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).digest()


def create_test_akavdb(version=42):
    """Create a minimal test .akavdb file."""
    # Simplified: just a version marker + some data
    data = b"AKAVDB_TEST_V" + str(version).encode() + b"\x00" * 1000
    return data


def build_manifest(private_key, signing_key_blob, akavdb_data, port,
                   tamper_manifest=False, tamper_file=False):
    """Build the update manifest JSON."""
    sha256_hex = hashlib.sha256(akavdb_data).hexdigest()
    if tamper_file:
        # Flip a character in the hash so verification fails
        sha256_hex = "0000" + sha256_hex[4:]

    file_sig = rsa_sign(private_key, akavdb_data)

    import base64
    manifest_body = {
        "version": 42,
        "published_at": datetime.now(timezone.utc).isoformat(),
        "minimum_engine_version": 1,
        "files": [
            {
                "name": "signatures.akavdb",
                "url": f"https://localhost:{port}/signatures.akavdb",
                "sha256": sha256_hex,
                "rsa_signature": base64.b64encode(file_sig).decode(),
                "size": len(akavdb_data),
                "type": "full"
            }
        ],
        "manifest_signature": ""  # placeholder, filled below
    }

    # Sign the manifest (with empty manifest_signature field)
    body_json = json.dumps(manifest_body, indent=2)
    if tamper_manifest:
        # Sign, then modify the manifest so signature is invalid
        manifest_sig = rsa_sign(private_key, body_json.encode())
        manifest_body["manifest_signature"] = base64.b64encode(manifest_sig).decode()
        manifest_body["version"] = 99  # tamper after signing
    else:
        manifest_sig = rsa_sign(private_key, body_json.encode())
        manifest_body["manifest_signature"] = base64.b64encode(manifest_sig).decode()

    return json.dumps(manifest_body, indent=2)


class UpdateHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler serving manifest and .akavdb files."""

    manifest_json = b""
    akavdb_data = b""

    def do_GET(self):
        if self.path == "/manifest.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(UpdateHandler.manifest_json)
        elif self.path == "/signatures.akavdb":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(UpdateHandler.akavdb_data)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        print(f"  [{self.client_address[0]}] {format % args}")


def main():
    parser = argparse.ArgumentParser(description="AkesoAV Update Test Server")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--scenario", choices=["normal", "tampered_manifest",
                                                "tampered_file", "expired_cert"],
                        default="normal")
    args = parser.parse_args()

    print(f"=== AkesoAV Update Test Server ===")
    print(f"Scenario: {args.scenario}")
    print()

    # Generate RSA signing key pair
    signing_key, pub_blob = generate_rsa_keypair()
    print(f"RSA public key blob ({len(pub_blob)} bytes, hex):")
    print(f"  {pub_blob.hex()}")
    print()

    # Generate TLS certificate
    tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired = (args.scenario == "expired_cert")
    tls_cert = generate_self_signed_cert(tls_key, expired=expired)

    cert_fp = cert_sha256_fingerprint(tls_cert)
    print(f"Server cert SHA-256 fingerprint:")
    print(f"  {cert_fp.hex()}")
    print()

    # Create test .akavdb
    akavdb = create_test_akavdb()

    # Build manifest
    manifest = build_manifest(
        signing_key, pub_blob, akavdb, args.port,
        tamper_manifest=(args.scenario == "tampered_manifest"),
        tamper_file=(args.scenario == "tampered_file"))

    UpdateHandler.manifest_json = manifest.encode()
    UpdateHandler.akavdb_data = akavdb

    # Write cert + key to temp files
    tmpdir = tempfile.mkdtemp(prefix="akav_update_test_")
    cert_path = os.path.join(tmpdir, "server.crt")
    key_path = os.path.join(tmpdir, "server.key")

    with open(cert_path, "wb") as f:
        f.write(tls_cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(tls_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))

    # Start HTTPS server
    server = http.server.HTTPServer(("localhost", args.port), UpdateHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"Manifest URL: https://localhost:{args.port}/manifest.json")
    print(f"DB URL:       https://localhost:{args.port}/signatures.akavdb")
    print()
    print(f"To test with akavscan or unit tests, use:")
    print(f"  Cert fingerprint: {cert_fp.hex()}")
    print(f"  Public key blob:  (saved to {tmpdir}\\pubkey.bin)")
    print()

    # Save public key blob for test consumption
    with open(os.path.join(tmpdir, "pubkey.bin"), "wb") as f:
        f.write(pub_blob)

    print(f"Serving on https://localhost:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()
        # Clean up temp files
        os.unlink(cert_path)
        os.unlink(key_path)
        os.unlink(os.path.join(tmpdir, "pubkey.bin"))
        os.rmdir(tmpdir)


if __name__ == "__main__":
    main()
