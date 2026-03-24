#!/usr/bin/env python3
"""
P11-T4: Generate crafted PEs for heuristic evasion boundary testing.

Creates PEs with specific heuristic scores by combining:
  - Import table entries (injection combo = +35)
  - W+X section characteristics (+20)
  - High entropy .text section (+20)
  - Entry point outside .text (+15)
"""

import struct
import os
import sys
import random

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000


def align(val, alignment):
    return ((val + alignment - 1) // alignment) * alignment


def build_pe(*, imports=None, wx_text=False, high_entropy=False,
             ep_outside_text=False, text_size=0x400):
    """Build a PE64 with specific heuristic-triggering features.

    Args:
        imports: list of (dll_name, [func_names]) tuples for import table
        wx_text: if True, .text is writable+executable
        high_entropy: if True, fill .text with random bytes (entropy >7.0)
        ep_outside_text: if True, set entry point outside .text section
        text_size: size of .text section content
    """
    pe = bytearray()

    # We'll build: headers | .text | .rdata (imports) | .data (optional)
    # Layout:
    #   0x000: DOS header
    #   0x080: PE signature + COFF + Optional Header + Section table
    #   0x200: .text section (code)
    #   0x200+text_aligned: .rdata section (imports)

    text_raw_size = align(text_size, FILE_ALIGN)
    text_file_offset = FILE_ALIGN  # 0x200

    # Build import data first to know .rdata size
    rdata_content = bytearray()
    rdata_rva = SECT_ALIGN + align(text_size, SECT_ALIGN)  # after .text virtual

    import_dir_rva = 0
    import_dir_size = 0
    num_data_dirs = 16

    if imports:
        # Build import structures at known RVA offsets within .rdata
        # Layout within .rdata:
        #   import descriptors (20 bytes each + null terminator)
        #   ILT entries (8 bytes each per DLL + null terminator)
        #   Hint/Name entries
        #   DLL name strings

        num_dlls = len(imports)
        desc_size = (num_dlls + 1) * 20  # +1 for null terminator

        # Calculate offsets for each component
        ilt_offset = desc_size  # ILT starts after descriptors
        total_ilt_size = 0
        for dll_name, funcs in imports:
            total_ilt_size += (len(funcs) + 1) * 8  # +1 for null terminator

        hint_name_offset = ilt_offset + total_ilt_size
        # Build hint/name entries and dll name strings
        hint_names = bytearray()
        dll_names = bytearray()
        func_offsets = {}  # (dll_idx, func_idx) -> offset in rdata

        for di, (dll_name, funcs) in enumerate(imports):
            for fi, func_name in enumerate(funcs):
                func_offsets[(di, fi)] = hint_name_offset + len(hint_names)
                hint_names += struct.pack("<H", 0)  # Hint (ordinal hint)
                hint_names += func_name.encode("ascii") + b"\x00"
                if len(hint_names) % 2:
                    hint_names += b"\x00"  # Align to 2 bytes

        dll_name_offset = hint_name_offset + len(hint_names)
        dll_name_offsets = {}
        for di, (dll_name, funcs) in enumerate(imports):
            dll_name_offsets[di] = dll_name_offset + len(dll_names)
            dll_names += dll_name.encode("ascii") + b"\x00"

        # IAT is same layout as ILT (we duplicate)
        iat_offset = dll_name_offset + len(dll_names)
        iat_offset = align(iat_offset, 8)  # Align IAT to 8 bytes

        total_rdata_size = iat_offset + total_ilt_size

        # Now build the actual bytes
        # Import descriptors
        ilt_running = ilt_offset
        iat_running = iat_offset
        for di, (dll_name, funcs) in enumerate(imports):
            ilt_rva = rdata_rva + ilt_running
            name_rva = rdata_rva + dll_name_offsets[di]
            iat_rva = rdata_rva + iat_running
            rdata_content += struct.pack("<IIIII",
                                         ilt_rva,   # OriginalFirstThunk (ILT)
                                         0,          # TimeDateStamp
                                         0,          # ForwarderChain
                                         name_rva,   # Name
                                         iat_rva)    # FirstThunk (IAT)
            entry_size = (len(funcs) + 1) * 8
            ilt_running += entry_size
            iat_running += entry_size

        # Null descriptor
        rdata_content += b"\x00" * 20

        # ILT entries
        for di, (dll_name, funcs) in enumerate(imports):
            for fi, func_name in enumerate(funcs):
                hint_rva = rdata_rva + func_offsets[(di, fi)]
                rdata_content += struct.pack("<Q", hint_rva)  # PE64: 8-byte entry
            rdata_content += struct.pack("<Q", 0)  # Null terminator

        # Hint/Name entries
        rdata_content += hint_names

        # DLL name strings
        rdata_content += dll_names

        # Pad to IAT alignment
        while len(rdata_content) < iat_offset:
            rdata_content += b"\x00"

        # IAT entries (same as ILT)
        for di, (dll_name, funcs) in enumerate(imports):
            for fi, func_name in enumerate(funcs):
                hint_rva = rdata_rva + func_offsets[(di, fi)]
                rdata_content += struct.pack("<Q", hint_rva)
            rdata_content += struct.pack("<Q", 0)

        import_dir_rva = rdata_rva
        import_dir_size = desc_size

    rdata_raw_size = align(len(rdata_content), FILE_ALIGN) if rdata_content else 0
    rdata_file_offset = text_file_offset + text_raw_size

    num_sections = 1 + (1 if rdata_content else 0)
    image_size = SECT_ALIGN + align(text_size, SECT_ALIGN)
    if rdata_content:
        image_size += align(len(rdata_content), SECT_ALIGN)

    # Entry point
    if ep_outside_text:
        ep_rva = rdata_rva if rdata_content else 0x2000  # Outside .text
    else:
        ep_rva = SECT_ALIGN  # Start of .text

    # ── DOS Header ──
    pe += b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    pe += b"\x00" * (0x80 - len(pe))

    # ── PE Signature ──
    pe += b"PE\x00\x00"

    # ── COFF Header ──
    pe += struct.pack("<H", 0x8664)        # Machine = AMD64
    pe += struct.pack("<H", num_sections)
    pe += struct.pack("<I", 0x65000000)    # TimeDateStamp (2023, valid range)
    pe += struct.pack("<I", 0)             # PointerToSymbolTable
    pe += struct.pack("<I", 0)             # NumberOfSymbols
    pe += struct.pack("<H", 0xF0)          # SizeOfOptionalHeader
    pe += struct.pack("<H", 0x0022)        # Characteristics

    # ── Optional Header PE32+ ──
    pe += struct.pack("<H", 0x020B)        # Magic = PE32+
    pe += struct.pack("<BB", 14, 0)        # Linker version
    pe += struct.pack("<I", text_raw_size) # SizeOfCode
    pe += struct.pack("<I", rdata_raw_size)# SizeOfInitializedData
    pe += struct.pack("<I", 0)             # SizeOfUninitializedData
    pe += struct.pack("<I", ep_rva)        # AddressOfEntryPoint
    pe += struct.pack("<I", SECT_ALIGN)    # BaseOfCode
    pe += struct.pack("<Q", 0x140000000)   # ImageBase
    pe += struct.pack("<II", SECT_ALIGN, FILE_ALIGN)
    pe += struct.pack("<HHHH", 6, 0, 0, 0)  # OS/Image versions
    pe += struct.pack("<HH", 6, 0)         # Subsystem version
    pe += struct.pack("<I", 0)             # Win32VersionValue
    pe += struct.pack("<I", image_size)    # SizeOfImage
    pe += struct.pack("<I", FILE_ALIGN)    # SizeOfHeaders
    pe += struct.pack("<I", 0)             # CheckSum
    pe += struct.pack("<H", 3)             # Subsystem = CONSOLE
    pe += struct.pack("<H", 0x8160)        # DllCharacteristics
    pe += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)  # Stack/Heap
    pe += struct.pack("<I", 0)             # LoaderFlags
    pe += struct.pack("<I", num_data_dirs) # NumberOfRvaAndSizes

    # Data directories (16 entries)
    for i in range(num_data_dirs):
        if i == 1 and import_dir_rva:  # Import directory = index 1
            pe += struct.pack("<II", import_dir_rva, import_dir_size)
        else:
            pe += struct.pack("<II", 0, 0)

    # ── Section Headers ──
    # .text
    text_chars = 0x60000020  # CODE | EXECUTE | READ
    if wx_text:
        text_chars |= 0x80000000  # WRITE
    pe += b".text\x00\x00\x00"
    pe += struct.pack("<I", text_size)         # VirtualSize
    pe += struct.pack("<I", SECT_ALIGN)        # VirtualAddress
    pe += struct.pack("<I", text_raw_size)     # SizeOfRawData
    pe += struct.pack("<I", text_file_offset)  # PointerToRawData
    pe += struct.pack("<III", 0, 0, 0)         # Relocations, Linenumbers (12 bytes)
    pe += struct.pack("<I", text_chars)

    # .rdata (if imports)
    if rdata_content:
        pe += b".rdata\x00\x00"
        pe += struct.pack("<I", len(rdata_content))
        pe += struct.pack("<I", rdata_rva)
        pe += struct.pack("<I", rdata_raw_size)
        pe += struct.pack("<I", rdata_file_offset)
        pe += struct.pack("<III", 0, 0, 0)
        pe += struct.pack("<I", 0x40000040)  # INITIALIZED_DATA | READ

    # ── Pad headers to file alignment ──
    pe += b"\x00" * (text_file_offset - len(pe))

    # ── .text section ──
    if high_entropy:
        rng = random.Random(42)  # Deterministic
        text_data = bytes(rng.getrandbits(8) for _ in range(text_size))
    else:
        text_data = b"\xCC" * text_size  # INT3 fill (low entropy)
    pe += text_data
    pe += b"\x00" * (text_raw_size - len(text_data))

    # ── .rdata section ──
    if rdata_content:
        pe += rdata_content
        pe += b"\x00" * (rdata_raw_size - len(rdata_content))

    return bytes(pe)


def create_pe_score_75(output_path):
    """PE scoring 75: injection imports(+35) + W+X(+20) + high entropy(+20)

    Must avoid triggering:
      - few_import_dlls (+10): need >=3 DLLs
      - suspicious_timestamp (+10): use valid timestamp
      - checksum_mismatch (+5): leave checksum as 0
    """
    pe = build_pe(
        imports=[
            ("kernel32.dll", [
                "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
                "GetModuleHandleA", "GetProcAddress", "CloseHandle",
            ]),
            ("user32.dll", ["MessageBoxA", "GetForegroundWindow"]),
            ("gdi32.dll", ["GetStockObject"]),
        ],
        wx_text=True,
        high_entropy=True,
        text_size=0x400,
    )
    with open(output_path, "wb") as f:
        f.write(pe)
    print(f"  Created: {output_path} ({len(pe)} bytes) [target score=75]")


def create_pe_score_70(output_path):
    """PE scoring 70: injection(+35) + W+X(+20) + low_entropy_text(+15) = 70

    .text filled with INT3 (0xCC) = entropy ~0 -> triggers text_low_entropy(+15).
    No high_entropy, no ep_outside_text. 3 DLLs to avoid few_import_dlls.
    """
    pe = build_pe(
        imports=[
            ("kernel32.dll", [
                "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
                "GetModuleHandleA", "GetProcAddress", "CloseHandle",
            ]),
            ("user32.dll", ["MessageBoxA", "GetForegroundWindow"]),
            ("gdi32.dll", ["GetStockObject"]),
        ],
        wx_text=True,
        high_entropy=False,
        ep_outside_text=False,
        text_size=0x400,
    )
    with open(output_path, "wb") as f:
        f.write(pe)
    print(f"  Created: {output_path} ({len(pe)} bytes) [target score=70]")


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "testdata")
    os.makedirs(outdir, exist_ok=True)

    print("Generating heuristic boundary test PEs:")
    create_pe_score_75(os.path.join(outdir, "heur_score_75.exe"))
    create_pe_score_70(os.path.join(outdir, "heur_score_70.exe"))
    print("Done.")


if __name__ == "__main__":
    main()
