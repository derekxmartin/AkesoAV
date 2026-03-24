#!/usr/bin/env python3
"""
akavdb-tool — Compiler, verifier, and tester for .akavdb signature databases.

Subcommands:
    compile   Build a .akavdb from a YAML signature definition file
    verify    Validate magic, version, sections, and RSA signature
    stats     Print database statistics
    test      Scan a file or the built-in EICAR test string

Usage:
    python akavdb_tool.py compile sigs.yaml -o output.akavdb [--key private.pem]
    python akavdb_tool.py verify output.akavdb [--pubkey public.pem]
    python akavdb_tool.py stats output.akavdb
    python akavdb_tool.py test output.akavdb [--eicar] [--file path]
"""

import argparse
import hashlib
import struct
import sys
import os
import time
import json

# ── Constants matching §3.4 and sigdb.h ───────────────────────────────

AKAV_DB_MAGIC = 0x56414B41  # "AKAV" little-endian
AKAV_DB_VERSION = 1
AKAV_DB_HEADER_SIZE = 0x0118  # 280 bytes
AKAV_DB_RSA_SIG_SIZE = 256

# Section types
SECTION_BLOOM = 0
SECTION_MD5 = 1
SECTION_SHA256 = 2
SECTION_CRC32 = 3
SECTION_AHO_CORASICK = 4
SECTION_FUZZY_HASH = 5
SECTION_GRAPH_SIG = 6
SECTION_YARA = 7
SECTION_WHITELIST = 8
SECTION_STRING_TABLE = 0xFF

SECTION_NAMES = {
    SECTION_BLOOM: "Bloom",
    SECTION_MD5: "MD5",
    SECTION_SHA256: "SHA256",
    SECTION_CRC32: "CRC32",
    SECTION_AHO_CORASICK: "AhoCorasick",
    SECTION_FUZZY_HASH: "FuzzyHash",
    SECTION_GRAPH_SIG: "GraphSig",
    SECTION_YARA: "YARA",
    SECTION_WHITELIST: "Whitelist",
    SECTION_STRING_TABLE: "StringTable",
}

# EICAR test string
EICAR_STRING = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
    b"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


# ── String Table Builder ──────────────────────────────────────────────

class StringTable:
    def __init__(self):
        self._data = bytearray()
        self._index = {}  # name -> offset

    def add(self, name: str) -> int:
        """Add a string, return its byte offset (name_index)."""
        if name in self._index:
            return self._index[name]
        offset = len(self._data)
        self._index[name] = offset
        self._data.extend(name.encode("utf-8"))
        self._data.append(0)  # null terminator
        return offset

    def data(self) -> bytes:
        return bytes(self._data)

    def size(self) -> int:
        return len(self._data)


# ── Signature Definitions ─────────────────────────────────────────────

def parse_sig_file(path: str) -> dict:
    """Parse a YAML or JSON signature definition file."""
    with open(path, "r") as f:
        content = f.read()

    # Try JSON first, then YAML
    try:
        return json.loads(content)
    except (json.JSONDecodeError, ValueError):
        pass

    try:
        import yaml
        return yaml.safe_load(content)
    except ImportError:
        print("ERROR: PyYAML not installed. Use JSON format or: pip install pyyaml",
              file=sys.stderr)
        sys.exit(1)


# ── Section Builders ──────────────────────────────────────────────────

def build_md5_section(sigs: list, strtab: StringTable) -> tuple:
    """Build sorted MD5 section. Returns (data_bytes, entry_count)."""
    entries = []
    for sig in sigs:
        md5_hex = sig["hash"]
        md5_bytes = bytes.fromhex(md5_hex)
        assert len(md5_bytes) == 16, f"MD5 must be 16 bytes, got {len(md5_bytes)}"
        name_idx = strtab.add(sig["name"])
        entries.append((md5_bytes, name_idx))

    # Sort by hash bytes
    entries.sort(key=lambda e: e[0])

    data = bytearray()
    for md5_bytes, name_idx in entries:
        data.extend(md5_bytes)              # 16 bytes
        data.extend(struct.pack("<I", name_idx))  # 4 bytes
    return bytes(data), len(entries)


def build_sha256_section(sigs: list, strtab: StringTable) -> tuple:
    """Build sorted SHA256 section."""
    entries = []
    for sig in sigs:
        sha_hex = sig["hash"]
        sha_bytes = bytes.fromhex(sha_hex)
        assert len(sha_bytes) == 32, f"SHA256 must be 32 bytes, got {len(sha_bytes)}"
        name_idx = strtab.add(sig["name"])
        entries.append((sha_bytes, name_idx))

    entries.sort(key=lambda e: e[0])

    data = bytearray()
    for sha_bytes, name_idx in entries:
        data.extend(sha_bytes)
        data.extend(struct.pack("<I", name_idx))
    return bytes(data), len(entries)


def build_crc32_section(sigs: list, strtab: StringTable) -> tuple:
    """Build CRC32 section."""
    data = bytearray()
    for sig in sigs:
        region_type = sig.get("region_type", 0)
        offset = sig.get("offset", 0)
        length = sig.get("length", 0)
        expected_crc = sig["crc32"]
        if isinstance(expected_crc, str):
            expected_crc = int(expected_crc, 16)
        name_idx = strtab.add(sig["name"])

        data.append(region_type & 0xFF)
        data.extend(struct.pack("<I", offset))
        data.extend(struct.pack("<I", length))
        data.extend(struct.pack("<I", expected_crc))
        data.extend(struct.pack("<I", name_idx))
    return bytes(data), len(sigs)


def build_aho_corasick_section(sigs: list, strtab: StringTable) -> tuple:
    """Build Aho-Corasick section with a simple serialized automaton.

    Uses our own serialization format matching akav_ac_serialize:
      [4] magic "AKAC"
      [4] version 1
      [4] node_count
      [4] pattern_count
      [1] finalized
      [node_count * 1040] nodes
      [pattern_count * 8] pattern_info
    """
    AKAC_MAGIC = 0x43414B41
    AKAC_VERSION = 1

    # Build trie
    # Node: children[256] (int32), failure (int32), output_link (int32),
    #        pattern_index (int32), depth (uint32)
    nodes = []  # list of dicts

    def new_node(depth=0):
        node = {
            "children": [-1] * 256,
            "failure": 0,
            "output_link": -1,
            "pattern_index": -1,
            "depth": depth,
        }
        nodes.append(node)
        return len(nodes) - 1

    # Root
    new_node(0)

    patterns = []  # list of (pattern_id, pattern_len)

    for i, sig in enumerate(sigs):
        pattern_hex = sig["pattern"]
        pattern_bytes = bytes.fromhex(pattern_hex)
        name_idx = strtab.add(sig["name"])

        # Walk/build trie
        current = 0
        for j, byte in enumerate(pattern_bytes):
            if nodes[current]["children"][byte] < 0:
                child = new_node(j + 1)
                nodes[current]["children"][byte] = child
            current = nodes[current]["children"][byte]

        nodes[current]["pattern_index"] = len(patterns)
        patterns.append((name_idx, len(pattern_bytes)))

    # Build failure links via BFS
    from collections import deque
    queue = deque()

    for c in range(256):
        child = nodes[0]["children"][c]
        if child > 0:
            nodes[child]["failure"] = 0
            queue.append(child)
        else:
            nodes[0]["children"][c] = 0

    while queue:
        u = queue.popleft()
        for c in range(256):
            v = nodes[u]["children"][c]
            if v > 0:
                f = nodes[u]["failure"]
                while f > 0 and nodes[f]["children"][c] <= 0:
                    f = nodes[f]["failure"]
                fc = nodes[f]["children"][c]
                nodes[v]["failure"] = fc if (fc > 0 and fc != v) else 0

                fail = nodes[v]["failure"]
                if nodes[fail]["pattern_index"] >= 0:
                    nodes[v]["output_link"] = fail
                else:
                    nodes[v]["output_link"] = nodes[fail]["output_link"]

                queue.append(v)
            else:
                f = nodes[u]["failure"]
                nodes[u]["children"][c] = nodes[f]["children"][c]

    # Serialize
    data = bytearray()
    data.extend(struct.pack("<I", AKAC_MAGIC))
    data.extend(struct.pack("<I", AKAC_VERSION))
    data.extend(struct.pack("<I", len(nodes)))
    data.extend(struct.pack("<I", len(patterns)))
    data.append(1)  # finalized

    for node in nodes:
        for c in range(256):
            data.extend(struct.pack("<i", node["children"][c]))
        data.extend(struct.pack("<i", node["failure"]))
        data.extend(struct.pack("<i", node["output_link"]))
        data.extend(struct.pack("<i", node["pattern_index"]))
        data.extend(struct.pack("<I", node["depth"]))

    for pattern_id, pattern_len in patterns:
        data.extend(struct.pack("<I", pattern_id))
        data.extend(struct.pack("<I", pattern_len))

    return bytes(data), len(sigs)


def build_fuzzy_section(sigs: list, strtab) -> tuple:
    """Build fuzzy hash section. Each entry = 128-byte hash (null-padded) + 4-byte name_index."""
    FUZZY_HASH_MAX = 128
    data = bytearray()
    for sig in sigs:
        hash_str = sig["hash"].encode("utf-8")
        padded = hash_str[:FUZZY_HASH_MAX - 1].ljust(FUZZY_HASH_MAX, b'\x00')
        name_idx = strtab.add(sig["name"])
        data.extend(padded)
        data.extend(struct.pack("<I", name_idx))
    return bytes(data), len(sigs)


def build_yara_section(yara_defs: list) -> tuple:
    """Build YARA section from a list of rule definitions.

    Each entry is either:
      - {"file": "path/to/rules.yar"} — include file contents
      - {"source": "rule foo { ... }"} — inline source

    The section data is all rule source concatenated as a single UTF-8 blob.
    entry_count = number of individual rules (approximate, based on 'rule' keyword count).
    """
    combined_source = []
    for entry in yara_defs:
        if "file" in entry:
            with open(entry["file"], "r", encoding="utf-8") as f:
                combined_source.append(f.read())
        elif "source" in entry:
            combined_source.append(entry["source"])
        else:
            raise ValueError(f"YARA entry must have 'file' or 'source' key: {entry}")

    full_source = "\n".join(combined_source)
    data = full_source.encode("utf-8")

    # Approximate rule count
    rule_count = full_source.count("\nrule ") + (1 if full_source.startswith("rule ") else 0)
    return data, max(rule_count, len(yara_defs))


# ── Database Compiler ─────────────────────────────────────────────────

def compile_db(sig_defs: dict, private_key_path: str = None) -> bytes:
    """Compile signature definitions into a .akavdb binary."""
    strtab = StringTable()
    sections = []  # list of (type, data_bytes, entry_count)
    total_sigs = 0

    # Process each signature type
    if "md5" in sig_defs and sig_defs["md5"]:
        data, count = build_md5_section(sig_defs["md5"], strtab)
        sections.append((SECTION_MD5, data, count))
        total_sigs += count

    if "sha256" in sig_defs and sig_defs["sha256"]:
        data, count = build_sha256_section(sig_defs["sha256"], strtab)
        sections.append((SECTION_SHA256, data, count))
        total_sigs += count

    if "crc32" in sig_defs and sig_defs["crc32"]:
        data, count = build_crc32_section(sig_defs["crc32"], strtab)
        sections.append((SECTION_CRC32, data, count))
        total_sigs += count

    if "fuzzy" in sig_defs and sig_defs["fuzzy"]:
        data, count = build_fuzzy_section(sig_defs["fuzzy"], strtab)
        sections.append((SECTION_FUZZY_HASH, data, count))
        total_sigs += count

    if "bytestream" in sig_defs and sig_defs["bytestream"]:
        data, count = build_aho_corasick_section(sig_defs["bytestream"], strtab)
        sections.append((SECTION_AHO_CORASICK, data, count))
        total_sigs += count

    if "yara" in sig_defs and sig_defs["yara"]:
        data, count = build_yara_section(sig_defs["yara"])
        sections.append((SECTION_YARA, data, count))
        total_sigs += count

    # Add string table as last section
    strtab_data = strtab.data()
    if strtab_data:
        sections.append((SECTION_STRING_TABLE, strtab_data, 0))

    # Calculate layout
    section_count = len(sections)
    offset_table_size = section_count * 16
    data_start = AKAV_DB_HEADER_SIZE + offset_table_size

    # Build section offset table and collect data
    offset_table = bytearray()
    section_data = bytearray()
    current_offset = data_start

    for sec_type, sec_data, entry_count in sections:
        offset_table.extend(struct.pack("<I", sec_type))
        offset_table.extend(struct.pack("<I", current_offset))
        offset_table.extend(struct.pack("<I", len(sec_data)))
        offset_table.extend(struct.pack("<I", entry_count))
        section_data.extend(sec_data)
        current_offset += len(sec_data)

    # Build header (280 bytes)
    created_at = int(time.time())
    header = bytearray(AKAV_DB_HEADER_SIZE)
    struct.pack_into("<I", header, 0, AKAV_DB_MAGIC)
    struct.pack_into("<I", header, 4, AKAV_DB_VERSION)
    struct.pack_into("<I", header, 8, total_sigs)
    struct.pack_into("<q", header, 12, created_at)
    struct.pack_into("<I", header, 20, section_count)
    # RSA signature at offset 0x18 (256 bytes) — filled below or left zero

    # RSA sign if key provided
    if private_key_path:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            # Signed payload: header bytes 0x00-0x17 (24 bytes) + all section data
            signed_payload = bytes(header[:0x18]) + bytes(section_data)
            signature = private_key.sign(
                signed_payload,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            header[0x18:0x18 + AKAV_DB_RSA_SIG_SIZE] = signature[:AKAV_DB_RSA_SIG_SIZE]
        except ImportError:
            print("WARNING: cryptography library not installed. "
                  "Skipping RSA signing.", file=sys.stderr)
        except Exception as e:
            print(f"WARNING: RSA signing failed: {e}", file=sys.stderr)

    # Assemble final binary
    return bytes(header) + bytes(offset_table) + bytes(section_data)


# ── Database Reader (for verify/stats/test) ───────────────────────────

class AkavDb:
    def __init__(self, data: bytes):
        self.data = data
        self.size = len(data)

        if self.size < AKAV_DB_HEADER_SIZE:
            raise ValueError("File too small for header")

        self.magic = struct.unpack_from("<I", data, 0)[0]
        self.version = struct.unpack_from("<I", data, 4)[0]
        self.signature_count = struct.unpack_from("<I", data, 8)[0]
        self.created_at = struct.unpack_from("<q", data, 12)[0]
        self.section_count = struct.unpack_from("<I", data, 20)[0]
        self.rsa_signature = data[0x18:0x18 + AKAV_DB_RSA_SIG_SIZE]

        # Parse section offset table
        self.sections = []
        offset = AKAV_DB_HEADER_SIZE
        for i in range(self.section_count):
            if offset + 16 > self.size:
                raise ValueError(f"Section table entry {i} extends past file")
            sec_type = struct.unpack_from("<I", data, offset)[0]
            sec_offset = struct.unpack_from("<I", data, offset + 4)[0]
            sec_size = struct.unpack_from("<I", data, offset + 8)[0]
            entry_count = struct.unpack_from("<I", data, offset + 12)[0]
            self.sections.append({
                "type": sec_type,
                "offset": sec_offset,
                "size": sec_size,
                "entry_count": entry_count,
            })
            offset += 16

        # Find string table
        self.string_table_offset = None
        self.string_table_size = 0
        for sec in self.sections:
            if sec["type"] == SECTION_STRING_TABLE:
                self.string_table_offset = sec["offset"]
                self.string_table_size = sec["size"]
                break

    def validate(self, pubkey_path: str = None) -> list:
        """Return list of validation errors (empty = valid)."""
        errors = []

        if self.magic != AKAV_DB_MAGIC:
            errors.append(f"Bad magic: 0x{self.magic:08X} (expected 0x{AKAV_DB_MAGIC:08X})")

        if self.version != AKAV_DB_VERSION:
            errors.append(f"Bad version: {self.version} (expected {AKAV_DB_VERSION})")

        for i, sec in enumerate(self.sections):
            end = sec["offset"] + sec["size"]
            if end > self.size:
                errors.append(f"Section {i} (type={sec['type']}) extends past file: "
                              f"offset={sec['offset']} size={sec['size']} file_size={self.size}")

        if pubkey_path:
            try:
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import padding

                with open(pubkey_path, "rb") as f:
                    public_key = serialization.load_pem_public_key(f.read())

                # Reconstruct signed payload
                section_data_start = AKAV_DB_HEADER_SIZE + self.section_count * 16
                signed_payload = self.data[:0x18] + self.data[section_data_start:]

                public_key.verify(
                    self.rsa_signature,
                    signed_payload,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            except ImportError:
                errors.append("cryptography library not installed — cannot verify RSA")
            except Exception as e:
                errors.append(f"RSA signature verification failed: {e}")

        return errors

    def lookup_string(self, name_index: int) -> str:
        if self.string_table_offset is None:
            return "<no string table>"
        start = self.string_table_offset + name_index
        if start >= self.string_table_offset + self.string_table_size:
            return "<out of bounds>"
        end = self.data.index(0, start)
        return self.data[start:end].decode("utf-8", errors="replace")

    def find_section(self, sec_type: int) -> dict:
        for sec in self.sections:
            if sec["type"] == sec_type:
                return sec
        return None

    def section_data(self, sec: dict) -> bytes:
        return self.data[sec["offset"]:sec["offset"] + sec["size"]]

    def search_aho_corasick(self, input_data: bytes) -> list:
        """Search input against the Aho-Corasick automaton. Returns matches."""
        sec = self.find_section(SECTION_AHO_CORASICK)
        if not sec:
            return []

        blob = self.section_data(sec)
        if len(blob) < 17:
            return []

        magic = struct.unpack_from("<I", blob, 0)[0]
        version = struct.unpack_from("<I", blob, 4)[0]
        node_count = struct.unpack_from("<I", blob, 8)[0]
        pattern_count = struct.unpack_from("<I", blob, 12)[0]
        finalized = blob[16]

        if magic != 0x43414B41 or version != 1 or not finalized:
            return []

        # Parse nodes
        NODE_SIZE = 1040
        nodes_offset = 17
        if len(blob) < nodes_offset + node_count * NODE_SIZE:
            return []

        # Parse patterns
        pat_offset = nodes_offset + node_count * NODE_SIZE
        patterns = []
        for i in range(pattern_count):
            off = pat_offset + i * 8
            if off + 8 > len(blob):
                break
            pid = struct.unpack_from("<I", blob, off)[0]
            plen = struct.unpack_from("<I", blob, off + 4)[0]
            patterns.append((pid, plen))

        # Search
        matches = []
        state = 0
        for i, byte in enumerate(input_data):
            # Follow transition
            child_offset = nodes_offset + state * NODE_SIZE + byte * 4
            state = struct.unpack_from("<i", blob, child_offset)[0]
            if state < 0 or state >= node_count:
                state = 0

            # Check matches
            temp = state
            while temp > 0:
                pidx_offset = nodes_offset + temp * NODE_SIZE + 1032
                pidx = struct.unpack_from("<i", blob, pidx_offset)[0]
                if 0 <= pidx < len(patterns):
                    pid, plen = patterns[pidx]
                    name = self.lookup_string(pid)
                    matches.append({
                        "name": name,
                        "name_index": pid,
                        "offset": i,
                        "pattern_len": plen,
                    })
                # Follow output link
                olink_offset = nodes_offset + temp * NODE_SIZE + 1028
                temp = struct.unpack_from("<i", blob, olink_offset)[0]

        return matches


# ── Subcommands ───────────────────────────────────────────────────────

def cmd_compile(args):
    sig_defs = parse_sig_file(args.input)
    db_bytes = compile_db(sig_defs, args.key)

    with open(args.output, "wb") as f:
        f.write(db_bytes)

    print(f"Compiled {args.output}: {len(db_bytes)} bytes")

    # Quick stats
    db = AkavDb(db_bytes)
    print(f"  Signatures: {db.signature_count}")
    print(f"  Sections:   {db.section_count}")
    for sec in db.sections:
        name = SECTION_NAMES.get(sec["type"], f"Unknown({sec['type']})")
        print(f"    [{name}] offset=0x{sec['offset']:X} "
              f"size={sec['size']} entries={sec['entry_count']}")


def cmd_verify(args):
    with open(args.input, "rb") as f:
        data = f.read()

    try:
        db = AkavDb(data)
    except ValueError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        sys.exit(2)

    errors = db.validate(args.pubkey)
    if errors:
        print("INVALID:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(2)
    else:
        print(f"VALID: {args.input}")
        print(f"  Magic:      0x{db.magic:08X}")
        print(f"  Version:    {db.version}")
        print(f"  Signatures: {db.signature_count}")
        print(f"  Sections:   {db.section_count}")
        print(f"  Created:    {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(db.created_at))}")


def cmd_stats(args):
    with open(args.input, "rb") as f:
        data = f.read()

    db = AkavDb(data)
    print(f"Database: {args.input}")
    print(f"  File size:    {db.size} bytes")
    print(f"  Magic:        0x{db.magic:08X} ({'AKAV' if db.magic == AKAV_DB_MAGIC else 'UNKNOWN'})")
    print(f"  Version:      {db.version}")
    print(f"  Signatures:   {db.signature_count}")
    print(f"  Sections:     {db.section_count}")
    print(f"  Created:      {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(db.created_at))}")
    print()

    for i, sec in enumerate(db.sections):
        name = SECTION_NAMES.get(sec["type"], f"Unknown({sec['type']})")
        print(f"  Section {i}: {name}")
        print(f"    Type:       {sec['type']}")
        print(f"    Offset:     0x{sec['offset']:X}")
        print(f"    Size:       {sec['size']} bytes")
        print(f"    Entries:    {sec['entry_count']}")

    # String table dump
    if db.string_table_offset is not None:
        print(f"\n  String Table ({db.string_table_size} bytes):")
        offset = 0
        while offset < db.string_table_size:
            s = db.lookup_string(offset)
            print(f"    [{offset:4d}] {s}")
            offset += len(s) + 1


def cmd_test(args):
    with open(args.input, "rb") as f:
        data = f.read()

    db = AkavDb(data)

    if args.eicar:
        print("Testing EICAR standard test string...")
        matches = db.search_aho_corasick(EICAR_STRING)
        if matches:
            for m in matches:
                print(f"  DETECTED: {m['name']} at offset {m['offset']} "
                      f"(pattern_len={m['pattern_len']})")
            sys.exit(1)  # infected
        else:
            print("  No detection (EICAR not in byte-stream signatures)")
            sys.exit(0)

    elif args.file:
        print(f"Testing file: {args.file}")
        with open(args.file, "rb") as f:
            file_data = f.read()

        detected = False

        # Check MD5
        md5_sec = db.find_section(SECTION_MD5)
        if md5_sec:
            file_md5 = hashlib.md5(file_data).digest()
            sec_data = db.section_data(md5_sec)
            entry_size = 20  # 16 + 4
            for i in range(md5_sec["entry_count"]):
                off = i * entry_size
                sig_md5 = sec_data[off:off + 16]
                if sig_md5 == file_md5:
                    name_idx = struct.unpack_from("<I", sec_data, off + 16)[0]
                    name = db.lookup_string(name_idx)
                    print(f"  MD5 MATCH: {name} ({file_md5.hex()})")
                    detected = True

        # Check SHA256
        sha_sec = db.find_section(SECTION_SHA256)
        if sha_sec:
            file_sha = hashlib.sha256(file_data).digest()
            sec_data = db.section_data(sha_sec)
            entry_size = 36  # 32 + 4
            for i in range(sha_sec["entry_count"]):
                off = i * entry_size
                sig_sha = sec_data[off:off + 32]
                if sig_sha == file_sha:
                    name_idx = struct.unpack_from("<I", sec_data, off + 32)[0]
                    name = db.lookup_string(name_idx)
                    print(f"  SHA256 MATCH: {name} ({file_sha.hex()})")
                    detected = True

        # Check Aho-Corasick byte patterns
        matches = db.search_aho_corasick(file_data)
        for m in matches:
            print(f"  BYTESTREAM MATCH: {m['name']} at offset {m['offset']}")
            detected = True

        if detected:
            print("  Result: INFECTED")
            sys.exit(1)
        else:
            print("  Result: CLEAN")
            sys.exit(0)
    else:
        print("ERROR: specify --eicar or --file <path>", file=sys.stderr)
        sys.exit(2)


def cmd_import(args):
    """Import signatures from external formats into .akavdb."""
    if args.format == "yara":
        # Collect all .yar/.yara files from the input paths
        yara_files = []
        for path in args.input:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for f in sorted(files):
                        if f.endswith((".yar", ".yara")):
                            yara_files.append(os.path.join(root, f))
            elif os.path.isfile(path):
                yara_files.append(path)
            else:
                print(f"WARNING: skipping {path} (not found)", file=sys.stderr)

        if not yara_files:
            print("ERROR: no YARA files found", file=sys.stderr)
            sys.exit(1)

        print(f"Importing {len(yara_files)} YARA file(s)...")

        # Build sig_defs with yara entries
        sig_defs = {
            "yara": [{"file": f} for f in yara_files]
        }

        # If appending to an existing db, load it first
        # (For v1, we just create a new db with only YARA rules)

        db_bytes = compile_db(sig_defs, args.key)

        with open(args.output, "wb") as f:
            f.write(db_bytes)

        print(f"Wrote {args.output}: {len(db_bytes)} bytes")
        for yf in yara_files:
            print(f"  + {yf}")
    else:
        print(f"ERROR: unsupported format '{args.format}'", file=sys.stderr)
        sys.exit(1)


# ── Main ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="akavdb-tool: compile, verify, and test .akavdb signature databases"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # compile
    p_compile = subparsers.add_parser("compile", help="Compile signatures into .akavdb")
    p_compile.add_argument("input", help="Signature definition file (JSON or YAML)")
    p_compile.add_argument("-o", "--output", required=True, help="Output .akavdb path")
    p_compile.add_argument("--key", help="RSA private key PEM file for signing")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify a .akavdb file")
    p_verify.add_argument("input", help=".akavdb file to verify")
    p_verify.add_argument("--pubkey", help="RSA public key PEM file")

    # stats
    p_stats = subparsers.add_parser("stats", help="Print database statistics")
    p_stats.add_argument("input", help=".akavdb file")

    # test
    p_test = subparsers.add_parser("test", help="Test scanning with the database")
    p_test.add_argument("input", help=".akavdb file")
    p_test.add_argument("--eicar", action="store_true", help="Test EICAR detection")
    p_test.add_argument("--file", help="File to scan")

    # import
    p_import = subparsers.add_parser("import", help="Import signatures from external formats")
    p_import.add_argument("input", nargs="+", help="Input files or directories")
    p_import.add_argument("-o", "--output", required=True, help="Output .akavdb path")
    p_import.add_argument("--format", required=True, choices=["yara"],
                          help="Import format (yara)")
    p_import.add_argument("--key", help="RSA private key PEM file for signing")

    args = parser.parse_args()

    if args.command == "compile":
        cmd_compile(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "stats":
        cmd_stats(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "import":
        cmd_import(args)


if __name__ == "__main__":
    main()
