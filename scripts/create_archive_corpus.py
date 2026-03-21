#!/usr/bin/env python3
"""create_archive_corpus.py — Generate seed corpus files for fuzz_zip and fuzz_gzip.

Usage:
    python scripts/create_archive_corpus.py

Creates:
    tests/fuzz/corpus_zip/   — seed ZIP files
    tests/fuzz/corpus_gzip/  — seed GZIP and TAR files
"""

import gzip
import io
import os
import struct
import tarfile
import zipfile
import zlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

CORPUS_ZIP = os.path.join(PROJECT_ROOT, "tests", "fuzz", "corpus_zip")
CORPUS_GZIP = os.path.join(PROJECT_ROOT, "tests", "fuzz", "corpus_gzip")


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


# ── ZIP corpus ─────────────────────────────────────────────────────

def make_zip_stored(name, payload):
    """Create a ZIP with a single stored (uncompressed) entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr(name, payload)
    return buf.getvalue()


def make_zip_deflated(name, payload):
    """Create a ZIP with a single deflated entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, payload)
    return buf.getvalue()


def make_zip_multi(entries):
    """Create a ZIP with multiple entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries:
            zf.writestr(name, payload)
    return buf.getvalue()


def make_zip_nested():
    """Create a ZIP containing another ZIP."""
    inner = make_zip_stored("inner.txt", "hello from inner")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("inner.zip", inner)
    return buf.getvalue()


def create_zip_corpus():
    ensure_dir(CORPUS_ZIP)

    seeds = {
        "empty.zip": make_zip_stored("empty.txt", ""),
        "small_stored.zip": make_zip_stored("hello.txt", "Hello, world!"),
        "small_deflated.zip": make_zip_deflated("hello.txt", "Hello, world!" * 100),
        "multi.zip": make_zip_multi([
            ("a.txt", "aaa"),
            ("b.txt", "bbb" * 50),
            ("subdir/c.txt", "ccc" * 200),
        ]),
        "nested.zip": make_zip_nested(),
        "binary.zip": make_zip_stored("data.bin", bytes(range(256))),
        "large_name.zip": make_zip_stored("a" * 200 + ".txt", "long name test"),
        # Minimal valid ZIP (just end-of-central-directory)
        "minimal.zip": b"PK\x05\x06" + b"\x00" * 18,
    }

    for name, data in seeds.items():
        path = os.path.join(CORPUS_ZIP, name)
        with open(path, "wb") as f:
            f.write(data)

    print(f"Created {len(seeds)} ZIP seed files in {CORPUS_ZIP}")


# ── GZIP / TAR corpus ─────────────────────────────────────────────

def make_gzip(payload):
    """Create a gzip-compressed blob."""
    return gzip.compress(payload)


def make_tar(entries):
    """Create a TAR archive from (name, data) pairs."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_tar_gz(entries):
    """Create a .tar.gz from (name, data) pairs."""
    tar_data = make_tar(entries)
    return gzip.compress(tar_data)


def create_gzip_corpus():
    ensure_dir(CORPUS_GZIP)

    small_text = b"Hello, world!"
    medium_text = b"A" * 4096
    binary_data = bytes(range(256)) * 4

    tar_single = make_tar([("hello.txt", b"Hello from TAR")])
    tar_multi = make_tar([
        ("a.txt", b"aaa"),
        ("b.txt", b"bbb" * 50),
        ("subdir/c.txt", b"ccc" * 200),
    ])

    seeds = {
        # Pure GZIP
        "small.gz": make_gzip(small_text),
        "medium.gz": make_gzip(medium_text),
        "binary.gz": make_gzip(binary_data),
        "empty_payload.gz": make_gzip(b""),
        # Pure TAR (no compression)
        "single.tar": tar_single,
        "multi.tar": tar_multi,
        "empty.tar": make_tar([]),
        # TAR.GZ
        "single.tar.gz": make_tar_gz([("hello.txt", b"Hello from TAR.GZ")]),
        "multi.tar.gz": make_tar_gz([
            ("a.txt", b"aaa"),
            ("b.txt", b"bbb" * 50),
            ("dir/c.txt", b"ccc" * 200),
        ]),
        # Minimal gzip header (10 bytes header + empty deflate + crc + size)
        "minimal.gz": bytes([
            0x1f, 0x8b, 0x08, 0x00,  # magic, method, flags
            0x00, 0x00, 0x00, 0x00,  # mtime
            0x00, 0x03,              # xfl, os
            0x03, 0x00,              # empty deflate stream
            0x00, 0x00, 0x00, 0x00,  # crc32
            0x00, 0x00, 0x00, 0x00,  # isize
        ]),
    }

    for name, data in seeds.items():
        path = os.path.join(CORPUS_GZIP, name)
        with open(path, "wb") as f:
            f.write(data)

    print(f"Created {len(seeds)} GZIP/TAR seed files in {CORPUS_GZIP}")


if __name__ == "__main__":
    create_zip_corpus()
    create_gzip_corpus()
    print("Done.")
