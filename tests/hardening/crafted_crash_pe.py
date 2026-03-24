#!/usr/bin/env python3
"""
P11-T2: Generate crafted samples for parser crash resilience testing.

Creates:
  1. malformed_pe.exe   — PE with SizeOfHeaders=0xFFFFFFFF + AC marker pattern
  2. bomb_eicar.zip     — ZIP with bomb entry + EICAR in entry 2
  3. malformed_pdf.pdf  — PDF with corrupted xref + AC marker in stream
"""

import struct
import os
import zlib
import sys

# Distinctive byte pattern for Aho-Corasick matching (not a real signature)
AC_MARKER = b"\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22\x33\x44\x55\x66\x77\x88\x99\x00" \
            b"AKAV_CRASH_RESILIENCE_TEST_MARKER"

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def create_malformed_pe(output_path):
    """Create a PE with SizeOfHeaders=0xFFFFFFFF (integer overflow).

    The PE parser should fail on this, but the Aho-Corasick scanner
    should still find AC_MARKER in the raw bytes.
    """
    pe = bytearray()

    # DOS Header
    pe += b"MZ"                    # e_magic
    pe += b"\x00" * 58             # padding
    pe += struct.pack("<I", 0x80)  # e_lfanew

    # Pad to 0x80
    pe += b"\x00" * (0x80 - len(pe))

    # PE Signature
    pe += b"PE\x00\x00"

    # COFF Header (20 bytes)
    pe += struct.pack("<H", 0x8664)   # Machine = AMD64
    pe += struct.pack("<H", 1)        # NumberOfSections
    pe += struct.pack("<I", 0)        # TimeDateStamp
    pe += struct.pack("<I", 0)        # PointerToSymbolTable
    pe += struct.pack("<I", 0)        # NumberOfSymbols
    pe += struct.pack("<H", 0xF0)     # SizeOfOptionalHeader (240 for PE32+)
    pe += struct.pack("<H", 0x0022)   # Characteristics

    # Optional Header PE32+ (240 bytes)
    pe += struct.pack("<H", 0x020B)   # Magic = PE32+
    pe += struct.pack("<B", 14)       # MajorLinkerVersion
    pe += struct.pack("<B", 0)        # MinorLinkerVersion
    pe += struct.pack("<I", 0x200)    # SizeOfCode
    pe += struct.pack("<I", 0)        # SizeOfInitializedData
    pe += struct.pack("<I", 0)        # SizeOfUninitializedData
    pe += struct.pack("<I", 0x1000)   # AddressOfEntryPoint
    pe += struct.pack("<I", 0x1000)   # BaseOfCode
    pe += struct.pack("<Q", 0x140000000)  # ImageBase
    pe += struct.pack("<I", 0x1000)   # SectionAlignment
    pe += struct.pack("<I", 0x200)    # FileAlignment

    # HERE IS THE BUG: SizeOfHeaders = 0xFFFFFFFF (integer overflow)
    pe += struct.pack("<H", 6)        # MajorOSVersion
    pe += struct.pack("<H", 0)        # MinorOSVersion
    pe += struct.pack("<H", 0)        # MajorImageVersion
    pe += struct.pack("<H", 0)        # MinorImageVersion
    pe += struct.pack("<H", 6)        # MajorSubsystemVersion
    pe += struct.pack("<H", 0)        # MinorSubsystemVersion
    pe += struct.pack("<I", 0)        # Win32VersionValue
    pe += struct.pack("<I", 0x3000)   # SizeOfImage
    pe += struct.pack("<I", 0xFFFFFFFF)  # SizeOfHeaders *** MALFORMED ***
    pe += struct.pack("<I", 0)        # CheckSum
    pe += struct.pack("<H", 3)        # Subsystem = CONSOLE
    pe += struct.pack("<H", 0x8160)   # DllCharacteristics
    pe += struct.pack("<Q", 0x100000) # SizeOfStackReserve
    pe += struct.pack("<Q", 0x1000)   # SizeOfStackCommit
    pe += struct.pack("<Q", 0x100000) # SizeOfHeapReserve
    pe += struct.pack("<Q", 0x1000)   # SizeOfHeapCommit
    pe += struct.pack("<I", 0)        # LoaderFlags
    pe += struct.pack("<I", 16)       # NumberOfRvaAndSizes

    # Data directories (16 entries, all zero)
    pe += b"\x00" * (16 * 8)

    # Section header: .text
    pe += b".text\x00\x00\x00"       # Name
    pe += struct.pack("<I", 0x200)    # VirtualSize
    pe += struct.pack("<I", 0x1000)   # VirtualAddress
    pe += struct.pack("<I", 0x200)    # SizeOfRawData
    pe += struct.pack("<I", 0x200)    # PointerToRawData
    pe += b"\x00" * 12               # Relocations, Linenumbers
    pe += struct.pack("<I", 0x60000020)  # Characteristics

    # Pad to 0x200
    pe += b"\x00" * (0x200 - len(pe))

    # .text section with AC_MARKER embedded
    pe += b"\xCC" * 64   # INT3 padding
    pe += AC_MARKER       # The byte pattern AC will find
    pe += b"\x90" * (0x200 - 64 - len(AC_MARKER))  # NOP padding

    with open(output_path, "wb") as f:
        f.write(pe)
    print(f"  Created: {output_path} ({len(pe)} bytes)")


def create_bomb_zip(output_path):
    """Create a ZIP where entry 1 is a zip bomb and entry 2 contains EICAR.

    Entry 1: tiny compressed data claiming 1GB uncompressed (ratio > 100:1).
    Entry 2: EICAR test string (stored, no compression).
    """

    def make_local_file_header(filename, comp_data, uncomp_size, method=8, crc=0):
        """Build a local file header + data."""
        fname = filename.encode("utf-8")
        crc32_val = zlib.crc32(comp_data) & 0xFFFFFFFF if method == 0 else crc
        comp_size = len(comp_data)
        hdr = struct.pack("<I", 0x04034B50)       # Local file header signature
        hdr += struct.pack("<H", 20)               # Version needed
        hdr += struct.pack("<H", 0)                # Flags
        hdr += struct.pack("<H", method)           # Compression method (0=stored, 8=deflate)
        hdr += struct.pack("<H", 0)                # Mod time
        hdr += struct.pack("<H", 0)                # Mod date
        hdr += struct.pack("<I", crc32_val)        # CRC-32
        hdr += struct.pack("<I", comp_size)        # Compressed size
        hdr += struct.pack("<I", uncomp_size)      # Uncompressed size
        hdr += struct.pack("<H", len(fname))       # Filename length
        hdr += struct.pack("<H", 0)                # Extra field length
        hdr += fname
        hdr += comp_data
        return hdr, comp_size, crc32_val

    def make_central_dir_entry(filename, comp_size, uncomp_size, method, crc, offset):
        """Build a central directory entry."""
        fname = filename.encode("utf-8")
        entry = struct.pack("<I", 0x02014B50)      # Central dir signature
        entry += struct.pack("<H", 20)              # Version made by
        entry += struct.pack("<H", 20)              # Version needed
        entry += struct.pack("<H", 0)               # Flags
        entry += struct.pack("<H", method)          # Compression method
        entry += struct.pack("<H", 0)               # Mod time
        entry += struct.pack("<H", 0)               # Mod date
        entry += struct.pack("<I", crc)             # CRC-32
        entry += struct.pack("<I", comp_size)       # Compressed size
        entry += struct.pack("<I", uncomp_size)     # Uncompressed size
        entry += struct.pack("<H", len(fname))      # Filename length
        entry += struct.pack("<H", 0)               # Extra field length
        entry += struct.pack("<H", 0)               # File comment length
        entry += struct.pack("<H", 0)               # Disk number start
        entry += struct.pack("<H", 0)               # Internal file attributes
        entry += struct.pack("<I", 0)               # External file attributes
        entry += struct.pack("<I", offset)          # Relative offset of local header
        entry += fname
        return entry

    zipdata = bytearray()

    # Entry 1: Bomb — tiny deflated data claiming 1GB uncompressed
    bomb_data = zlib.compress(b"\x00" * 1024, 9)   # Compress 1KB of zeros
    bomb_data = bomb_data[2:-4]  # Strip zlib header/trailer for raw deflate
    bomb_uncomp = 0x40000000     # Claim 1GB uncompressed (triggers ratio check)
    bomb_crc = zlib.crc32(b"\x00" * 1024) & 0xFFFFFFFF
    offset1 = len(zipdata)
    hdr1, comp1, crc1 = make_local_file_header("bomb.bin", bomb_data, bomb_uncomp,
                                                 method=8, crc=bomb_crc)
    zipdata += hdr1

    # Entry 2: EICAR (deflate compressed so pattern not visible in raw ZIP bytes)
    eicar_crc = zlib.crc32(EICAR) & 0xFFFFFFFF
    eicar_deflated = zlib.compress(EICAR, 6)
    eicar_deflated = eicar_deflated[2:-4]  # Strip zlib header/trailer for raw deflate
    offset2 = len(zipdata)
    hdr2, comp2, crc2 = make_local_file_header("eicar.com", eicar_deflated, len(EICAR),
                                                 method=8, crc=eicar_crc)
    zipdata += hdr2

    # Central directory
    cd_offset = len(zipdata)
    cd = bytearray()
    cd += make_central_dir_entry("bomb.bin", comp1, bomb_uncomp, 8, crc1, offset1)
    cd += make_central_dir_entry("eicar.com", comp2, len(EICAR), 8, crc2, offset2)
    cd_size = len(cd)
    zipdata += cd

    # End of central directory
    zipdata += struct.pack("<I", 0x06054B50)   # EOCD signature
    zipdata += struct.pack("<H", 0)            # Disk number
    zipdata += struct.pack("<H", 0)            # Disk with central dir
    zipdata += struct.pack("<H", 2)            # Entries on this disk
    zipdata += struct.pack("<H", 2)            # Total entries
    zipdata += struct.pack("<I", cd_size)      # Size of central directory
    zipdata += struct.pack("<I", cd_offset)    # Offset of central directory
    zipdata += struct.pack("<H", 0)            # Comment length

    with open(output_path, "wb") as f:
        f.write(zipdata)
    print(f"  Created: {output_path} ({len(zipdata)} bytes)")


def create_malformed_pdf(output_path):
    """Create a PDF with corrupted xref table + AC_MARKER in raw bytes.

    The xref table has invalid offsets, which will cause the PDF parser to
    error. But AC_MARKER is embedded in the file so byte-stream scanning
    still detects it.
    """
    marker_hex = AC_MARKER.hex()

    pdf = b"%PDF-1.4\n"
    pdf += b"% Malformed PDF for parser resilience testing\n"

    # Object 1: Catalog
    obj1_offset = len(pdf)
    pdf += b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"

    # Object 2: Pages
    obj2_offset = len(pdf)
    pdf += b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"

    # Object 3: Stream with AC_MARKER embedded
    stream_data = b"BT /F1 12 Tf (Test) Tj ET\n" + AC_MARKER + b"\n"
    obj3_offset = len(pdf)
    pdf += b"3 0 obj\n"
    pdf += b"<< /Length " + str(len(stream_data)).encode() + b" >>\n"
    pdf += b"stream\n"
    pdf += stream_data
    pdf += b"\nendstream\nendobj\n"

    # Corrupted xref table (intentionally wrong offsets)
    xref_offset = len(pdf)
    pdf += b"xref\n"
    pdf += b"0 4\n"
    pdf += b"0000000000 65535 f \n"
    pdf += b"9999999999 00000 n \n"   # INVALID offset for obj 1
    pdf += b"8888888888 00000 n \n"   # INVALID offset for obj 2
    pdf += b"7777777777 00000 n \n"   # INVALID offset for obj 3

    # Trailer
    pdf += b"trailer\n"
    pdf += b"<< /Size 4 /Root 1 0 R >>\n"
    pdf += b"startxref\n"
    pdf += str(xref_offset).encode() + b"\n"
    pdf += b"%%EOF\n"

    with open(output_path, "wb") as f:
        f.write(pdf)
    print(f"  Created: {output_path} ({len(pdf)} bytes)")


def main():
    if len(sys.argv) > 1:
        outdir = sys.argv[1]
    else:
        outdir = os.path.join(os.path.dirname(__file__), "testdata")

    os.makedirs(outdir, exist_ok=True)

    print("Generating parser resilience test samples:")
    create_malformed_pe(os.path.join(outdir, "malformed_pe.exe"))
    create_bomb_zip(os.path.join(outdir, "bomb_eicar.zip"))
    create_malformed_pdf(os.path.join(outdir, "malformed_pdf.pdf"))
    print("Done.")

    # Print the AC marker hex for use in signature definitions
    print(f"\nAC_MARKER hex (for bytestream signature):")
    print(AC_MARKER[:16].hex())


if __name__ == "__main__":
    main()
