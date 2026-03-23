#!/usr/bin/env python3
"""train_classifier.py -- Train a Random Forest PE malware classifier (P9-T3).

Extracts feature vectors from PE files, trains a Random Forest classifier
using scikit-learn, validates with 5-fold CV and held-out test set, and
exports the model as a JSON decision tree array for C++ inference.

Usage:
    # Train on labeled directories:
    python train_classifier.py train --clean DIR_CLEAN --malware DIR_MALWARE -o model.json

    # Train with synthetic data (for testing/bootstrapping):
    python train_classifier.py synthetic -o model.json

    # Extract features from a single PE:
    python train_classifier.py features FILE.exe

    # Validate model on a directory of clean PEs:
    python train_classifier.py validate --model model.json --clean DIR_CLEAN

Feature vector (14 features):
    0  file_size           - File size in bytes (log2-scaled)
    1  num_sections        - Number of PE sections
    2  text_entropy        - .text section entropy (0-8)
    3  max_entropy         - Max section entropy across all sections
    4  mean_entropy        - Mean section entropy
    5  import_dll_count    - Number of imported DLLs
    6  import_func_count   - Number of imported functions
    7  has_overlay         - 1 if overlay data present, 0 otherwise
    8  overlay_ratio       - Overlay size / file size (0 if no overlay)
    9  has_rich_header     - 1 if rich header present, 0 otherwise
    10 timestamp_suspicious - 1 if timestamp is 0, <1990, or >2035
    11 entry_outside_text  - 1 if entry point is outside .text section
    12 has_authenticode    - 1 if Authenticode signature present
    13 suspicious_api_bits - Bitmask of suspicious import patterns
         bit 0: VirtualAlloc+WriteProcessMemory+CreateRemoteThread
         bit 1: VirtualAlloc+VirtualProtect+CreateThread
         bit 2: CreateService+StartService
         bit 3: RegSetValueEx (Run key)
         bit 4: ordinal-only imports
         bit 5: only GetProcAddress+LoadLibrary
"""

import argparse
import json
import math
import os
import struct
import sys
from pathlib import Path

# ── Feature names (must match C++ inference) ──────────────────────────────

FEATURE_NAMES = [
    "file_size_log2",
    "num_sections",
    "text_entropy",
    "max_entropy",
    "mean_entropy",
    "import_dll_count",
    "import_func_count",
    "has_overlay",
    "overlay_ratio",
    "has_rich_header",
    "timestamp_suspicious",
    "entry_outside_text",
    "has_authenticode",
    "suspicious_api_bits",
]

NUM_FEATURES = len(FEATURE_NAMES)

# ── Suspicious API sets ───────────────────────────────────────────────────

INJECTION_APIS = {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"}
SHELLCODE_APIS = {"VirtualAlloc", "VirtualProtect", "CreateThread"}
SERVICE_APIS = {"CreateService", "StartService", "CreateServiceA", "CreateServiceW",
                "StartServiceA", "StartServiceW"}
PERSIST_APIS = {"RegSetValueEx", "RegSetValueExA", "RegSetValueExW"}
APIHASH_APIS = {"GetProcAddress", "LoadLibrary", "LoadLibraryA", "LoadLibraryW"}

# Packer section name indicators
PACKER_SECTIONS = {".upx0", ".upx1", ".aspack", ".themida", ".vmp0", ".nsp0",
                   ".packed", ".petite", ".pec1", ".spack", ".perplex", ".yp",
                   ".maskpe"}

# ── PE feature extraction (pure Python, no pefile dependency) ─────────────

def _read_u16(data, off):
    if off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]

def _read_u32(data, off):
    if off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]

def _read_u64(data, off):
    if off + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, off)[0]

def _shannon_entropy(data):
    """Compute Shannon entropy in bits (0.0-8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for f in freq:
        if f > 0:
            p = f / n
            ent -= p * math.log2(p)
    return ent

def _parse_imports(data, pe_off, num_data_dirs, is_pe32plus):
    """Parse import directory to get DLL names and function names."""
    dlls = []
    funcs = set()

    # Optional header size varies
    opt_off = pe_off + 24
    # Data directories start at offset 96 (PE32) or 112 (PE32+) into optional header
    dd_off = opt_off + (112 if is_pe32plus else 96)

    if num_data_dirs < 2:
        return dlls, funcs

    import_rva = _read_u32(data, dd_off + 8)  # Import dir is data_dir[1]
    import_size = _read_u32(data, dd_off + 12)
    if import_rva is None or import_size is None or import_rva == 0:
        return dlls, funcs

    # Read section table to resolve RVAs
    coff_off = pe_off + 4
    num_sections = _read_u16(data, coff_off + 2)
    opt_hdr_size = _read_u16(data, coff_off + 16)
    if num_sections is None or opt_hdr_size is None:
        return dlls, funcs

    sections_off = pe_off + 24 + opt_hdr_size

    def rva_to_offset(rva):
        for i in range(min(num_sections, 96)):
            s_off = sections_off + i * 40
            va = _read_u32(data, s_off + 12)
            vs = _read_u32(data, s_off + 8)
            rd_off = _read_u32(data, s_off + 20)
            rd_sz = _read_u32(data, s_off + 16)
            if va is None or vs is None or rd_off is None or rd_sz is None:
                continue
            if va <= rva < va + max(vs, rd_sz):
                return rd_off + (rva - va)
        return None

    import_off = rva_to_offset(import_rva)
    if import_off is None:
        return dlls, funcs

    # Walk IMAGE_IMPORT_DESCRIPTORs (20 bytes each)
    idx = 0
    while idx < 256:
        desc_off = import_off + idx * 20
        if desc_off + 20 > len(data):
            break
        ilt_rva = _read_u32(data, desc_off)
        name_rva = _read_u32(data, desc_off + 12)
        if ilt_rva is None or name_rva is None:
            break
        if ilt_rva == 0 and name_rva == 0:
            break

        # Read DLL name
        name_off = rva_to_offset(name_rva)
        if name_off is not None and name_off < len(data):
            end = data.find(b'\x00', name_off, min(name_off + 256, len(data)))
            if end > name_off:
                dll_name = data[name_off:end].decode('ascii', errors='replace')
                dlls.append(dll_name)

        # Walk ILT/IAT for function names
        ilt_off = rva_to_offset(ilt_rva)
        if ilt_off is not None:
            entry_size = 8 if is_pe32plus else 4
            ordinal_flag = (1 << 63) if is_pe32plus else (1 << 31)
            fi = 0
            while fi < 4096:
                e_off = ilt_off + fi * entry_size
                if e_off + entry_size > len(data):
                    break
                if is_pe32plus:
                    entry = _read_u64(data, e_off)
                else:
                    entry = _read_u32(data, e_off)
                if entry is None or entry == 0:
                    break
                if entry & ordinal_flag:
                    funcs.add(f"__ordinal_{entry & 0xFFFF}")
                else:
                    hint_off = rva_to_offset(entry & 0x7FFFFFFF)
                    if hint_off is not None and hint_off + 2 < len(data):
                        end = data.find(b'\x00', hint_off + 2,
                                        min(hint_off + 258, len(data)))
                        if end > hint_off + 2:
                            fname = data[hint_off+2:end].decode('ascii',
                                                                errors='replace')
                            funcs.add(fname)
                fi += 1
        idx += 1

    return dlls, funcs


def extract_features(filepath):
    """Extract a feature vector from a PE file. Returns list of floats or None."""
    try:
        data = Path(filepath).read_bytes()
    except (OSError, IOError):
        return None

    if len(data) < 64:
        return None

    # DOS header
    dos_magic = _read_u16(data, 0)
    if dos_magic != 0x5A4D:
        return None

    e_lfanew = _read_u32(data, 60)
    if e_lfanew is None or e_lfanew + 24 > len(data):
        return None

    # PE signature
    pe_sig = _read_u32(data, e_lfanew)
    if pe_sig != 0x00004550:
        return None

    coff_off = e_lfanew + 4
    num_sections = _read_u16(data, coff_off + 2)
    timestamp = _read_u32(data, coff_off + 4)
    opt_hdr_size = _read_u16(data, coff_off + 16)
    characteristics = _read_u16(data, coff_off + 18)

    if num_sections is None or timestamp is None or opt_hdr_size is None:
        return None

    # Optional header
    opt_off = e_lfanew + 24
    opt_magic = _read_u16(data, opt_off)
    if opt_magic is None:
        return None
    is_pe32plus = (opt_magic == 0x20B)

    entry_point = _read_u32(data, opt_off + 16)
    if is_pe32plus:
        num_data_dirs = _read_u32(data, opt_off + 108)
    else:
        num_data_dirs = _read_u32(data, opt_off + 92)

    if num_data_dirs is None:
        num_data_dirs = 0
    num_data_dirs = min(num_data_dirs, 16)

    # Sections
    sections_off = e_lfanew + 24 + opt_hdr_size
    entropies = []
    text_entropy = 0.0
    text_va = None
    text_vs = None
    max_raw_end = 0

    for i in range(min(num_sections, 96)):
        s_off = sections_off + i * 40
        if s_off + 40 > len(data):
            break
        name_bytes = data[s_off:s_off+8].rstrip(b'\x00').lower()
        va = _read_u32(data, s_off + 12)
        vs = _read_u32(data, s_off + 8)
        rd_size = _read_u32(data, s_off + 16)
        rd_off = _read_u32(data, s_off + 20)
        chars = _read_u32(data, s_off + 36)

        if rd_off is None or rd_size is None or va is None or vs is None:
            continue

        raw_end = rd_off + rd_size
        if raw_end > max_raw_end:
            max_raw_end = raw_end

        # Compute entropy for this section
        sec_data = data[rd_off:min(rd_off + rd_size, len(data))]
        ent = _shannon_entropy(sec_data) if len(sec_data) > 0 else 0.0
        entropies.append(ent)

        if name_bytes == b'.text' or (text_va is None and chars is not None
                                       and chars & 0x20000000):
            text_entropy = ent
            text_va = va
            text_vs = vs

    # Overlay detection
    has_overlay = 1.0 if max_raw_end < len(data) and max_raw_end > 0 else 0.0
    overlay_size = max(0, len(data) - max_raw_end) if has_overlay else 0
    overlay_ratio = overlay_size / len(data) if len(data) > 0 else 0.0

    # Rich header detection (search for "Rich" marker between DOS stub and PE header)
    has_rich = 0.0
    if e_lfanew > 128:
        rich_region = data[64:e_lfanew]
        if b'Rich' in rich_region:
            has_rich = 1.0

    # Authenticode (data dir index 4 = security)
    has_auth = 0.0
    if num_data_dirs >= 5:
        dd_off = opt_off + (112 if is_pe32plus else 96)
        sec_rva = _read_u32(data, dd_off + 4 * 8)  # dir[4].va
        sec_size = _read_u32(data, dd_off + 4 * 8 + 4)
        if sec_rva and sec_size and sec_rva > 0 and sec_size > 0:
            has_auth = 1.0

    # Timestamp suspicious check
    ts_suspicious = 0.0
    if timestamp == 0 or timestamp < 631152000 or timestamp > 2051222400:
        # < 1990-01-01 or > 2035-01-01
        ts_suspicious = 1.0

    # Entry point outside .text
    entry_outside = 0.0
    if text_va is not None and text_vs is not None and entry_point is not None:
        if entry_point < text_va or entry_point >= text_va + text_vs:
            entry_outside = 1.0

    # Imports
    import_dlls, import_funcs = _parse_imports(data, e_lfanew, num_data_dirs,
                                                is_pe32plus)
    func_names = {f.rstrip("AW") if not f.startswith("__ordinal") else f
                  for f in import_funcs}
    func_names_raw = import_funcs

    # Suspicious API bits
    api_bits = 0
    if INJECTION_APIS.issubset(func_names | {f.rstrip("AW") for f in func_names_raw}):
        api_bits |= 1
    # Check with suffix variants
    all_funcs_normalized = set()
    for f in import_funcs:
        all_funcs_normalized.add(f)
        if f.endswith("A") or f.endswith("W"):
            all_funcs_normalized.add(f[:-1])

    if {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"} <= all_funcs_normalized:
        api_bits |= 1
    if {"VirtualAlloc", "VirtualProtect", "CreateThread"} <= all_funcs_normalized:
        api_bits |= 2
    if ({"CreateService", "StartService"} <= all_funcs_normalized or
        {"CreateServiceA", "StartServiceA"} <= all_funcs_normalized or
        {"CreateServiceW", "StartServiceW"} <= all_funcs_normalized):
        api_bits |= 4
    if {"RegSetValueEx"} <= all_funcs_normalized or \
       {"RegSetValueExA"} <= all_funcs_normalized or \
       {"RegSetValueExW"} <= all_funcs_normalized:
        api_bits |= 8
    # Ordinal-only
    ordinal_count = sum(1 for f in import_funcs if f.startswith("__ordinal"))
    if len(import_funcs) > 0 and ordinal_count == len(import_funcs):
        api_bits |= 16
    # API hashing (only GetProcAddress + LoadLibrary, nothing else meaningful)
    non_ordinal = {f for f in import_funcs if not f.startswith("__ordinal")}
    if non_ordinal and non_ordinal <= {"GetProcAddress", "LoadLibraryA",
                                        "LoadLibraryW", "LoadLibrary"}:
        api_bits |= 32

    # Build feature vector
    features = [
        math.log2(max(len(data), 1)),           # 0: file_size_log2
        float(num_sections),                     # 1: num_sections
        text_entropy,                            # 2: text_entropy
        max(entropies) if entropies else 0.0,    # 3: max_entropy
        (sum(entropies) / len(entropies))
            if entropies else 0.0,               # 4: mean_entropy
        float(len(import_dlls)),                 # 5: import_dll_count
        float(len(import_funcs)),                # 6: import_func_count
        has_overlay,                             # 7: has_overlay
        overlay_ratio,                           # 8: overlay_ratio
        has_rich,                                # 9: has_rich_header
        ts_suspicious,                           # 10: timestamp_suspicious
        entry_outside,                           # 11: entry_outside_text
        has_auth,                                # 12: has_authenticode
        float(api_bits),                         # 13: suspicious_api_bits
    ]

    return features


# ── Synthetic training data generation ────────────────────────────────────

def _generate_synthetic_data(n_clean=500, n_malware=500, seed=42):
    """Generate synthetic PE feature vectors for training/testing.

    Clean profiles: based on typical system32 DLLs and EXEs.
    Malware profiles: based on common malware characteristics.
    """
    import numpy as np
    rng = np.random.RandomState(seed)

    X = []
    y = []

    # Clean PE profiles — calibrated against real system32 PEs:
    #   system DLLs: 35-104 DLLs, 300-1300 funcs, 6-15 sections, api_bits 8-12
    #   system EXEs: 40-50 DLLs, 200-400 funcs, 6-8 sections, api_bits ~8
    #   resource DLLs: 0 imports, 2 sections, low entropy
    #   .NET assemblies: 0-1 DLLs, 2 sections, overlay common
    for _ in range(n_clean):
        profile = rng.choice(["system_dll", "system_exe", "app_exe",
                               "dotnet", "resource_dll"])

        if profile == "system_dll":
            feat = [
                rng.uniform(18, 23),      # file_size_log2 (256KB-8MB)
                rng.choice([6, 7, 8, 10, 15]),  # sections
                rng.uniform(5.8, 6.9),    # text_entropy
                rng.uniform(6.0, 7.1),    # max_entropy
                rng.uniform(4.0, 6.5),    # mean_entropy
                rng.uniform(20, 110),     # import_dlls (real: 35-104)
                rng.uniform(200, 1300),   # import_funcs (real: 300-1273)
                rng.choice([0, 1, 1]),    # overlay (common in system DLLs)
                rng.uniform(0, 0.08),     # overlay_ratio
                1.0,                      # rich_header
                0.0,                      # timestamp_suspicious
                0.0,                      # entry_outside_text
                rng.choice([0, 1, 1, 1]), # authenticode (common)
                rng.choice([8, 8, 8, 9, 10, 12]),  # api_bits (RegSetValueEx common)
            ]
        elif profile == "system_exe":
            feat = [
                rng.uniform(17, 21),
                rng.choice([5, 6, 7, 8]),
                rng.uniform(5.5, 6.8),
                rng.uniform(6.0, 7.1),
                rng.uniform(4.0, 6.0),
                rng.uniform(15, 55),      # import_dlls (real: 40-50)
                rng.uniform(100, 500),    # import_funcs (real: 200-400)
                rng.choice([0, 0, 1]),
                rng.uniform(0, 0.04),
                1.0,
                0.0,
                0.0,
                rng.choice([0, 0, 1]),
                rng.choice([0, 8, 8]),    # api_bits (RegSetValueEx common)
            ]
        elif profile == "app_exe":
            feat = [
                rng.uniform(17, 25),
                rng.choice([4, 5, 6, 7, 8]),
                rng.uniform(5.5, 6.8),
                rng.uniform(6.0, 7.2),
                rng.uniform(4.5, 6.2),
                rng.uniform(5, 40),
                rng.uniform(50, 800),
                rng.choice([0, 1]),
                rng.uniform(0, 0.1),
                rng.choice([0, 1]),
                0.0,
                rng.choice([0, 0, 0, 1]),
                rng.choice([0, 1]),
                rng.choice([0, 0, 8]),    # api_bits (some use registry)
            ]
        elif profile == "resource_dll":
            # Resource-only DLLs (like imageres.dll): no code, low entropy
            feat = [
                rng.uniform(12, 20),
                rng.choice([2, 3]),
                0.0,                      # no .text entropy
                rng.uniform(0.5, 4.0),    # low max entropy
                rng.uniform(0.3, 2.5),    # low mean
                0.0,                      # no imports
                0.0,
                0.0,
                0.0,
                1.0,                      # rich_header
                0.0,
                0.0,
                rng.choice([0, 1]),
                0.0,
            ]
        else:  # dotnet
            feat = [
                rng.uniform(13, 23),      # .NET can be very large
                rng.choice([2, 3]),
                rng.uniform(4.5, 6.5),
                rng.uniform(5.0, 7.0),
                rng.uniform(3.5, 6.0),
                rng.uniform(0, 2),        # mscoree.dll only or none
                rng.uniform(0, 5),
                rng.choice([0, 1, 1]),    # overlay common
                rng.uniform(0, 0.05),
                rng.choice([0, 1]),
                0.0,
                0.0,
                rng.choice([0, 1, 1]),    # authenticode common
                0.0,
            ]
        X.append(feat)
        y.append(0)

    # Malware profiles
    for _ in range(n_malware):
        profile = rng.choice(["packed", "dropper", "injector", "crypter",
                               "shellcode_loader", "minimal"])

        if profile == "packed":
            feat = [
                rng.uniform(14, 20),
                rng.choice([2, 3, 4]),
                rng.uniform(7.0, 7.95),    # high entropy .text
                rng.uniform(7.2, 7.99),    # high max entropy
                rng.uniform(6.0, 7.5),
                rng.uniform(0, 3),         # few imports
                rng.uniform(0, 10),
                rng.choice([0, 1]),
                rng.uniform(0, 0.3),
                rng.choice([0, 0, 1]),
                rng.choice([0, 1]),        # often suspicious timestamp
                rng.choice([0, 1, 1]),     # entry outside .text
                0.0,                       # no authenticode
                rng.choice([0, 16, 32]),   # ordinal-only or API hashing
            ]
        elif profile == "dropper":
            feat = [
                rng.uniform(16, 23),
                rng.choice([3, 4, 5, 6]),
                rng.uniform(5.5, 7.5),
                rng.uniform(6.5, 7.8),
                rng.uniform(5.5, 7.0),
                rng.uniform(3, 10),
                rng.uniform(20, 100),
                1.0,                       # overlay (dropped payload)
                rng.uniform(0.1, 0.6),     # significant overlay
                0.0,
                rng.choice([0, 1]),
                rng.choice([0, 1]),
                0.0,
                rng.choice([0, 4, 8]),     # service install or registry persist
            ]
        elif profile == "injector":
            feat = [
                rng.uniform(13, 18),
                rng.choice([3, 4, 5]),
                rng.uniform(5.5, 7.0),
                rng.uniform(6.0, 7.5),
                rng.uniform(5.0, 6.5),
                rng.uniform(3, 8),
                rng.uniform(15, 80),
                rng.choice([0, 1]),
                rng.uniform(0, 0.1),
                rng.choice([0, 1]),
                rng.choice([0, 1]),
                0.0,
                0.0,
                rng.choice([1, 3]),        # injection + shellcode APIs
            ]
        elif profile == "crypter":
            feat = [
                rng.uniform(14, 19),
                rng.choice([2, 3]),
                rng.uniform(7.2, 7.98),
                rng.uniform(7.5, 7.99),
                rng.uniform(6.5, 7.8),
                rng.uniform(1, 4),
                rng.uniform(2, 15),
                rng.choice([0, 1]),
                rng.uniform(0, 0.2),
                0.0,
                1.0,                       # suspicious timestamp
                1.0,                       # entry outside .text
                0.0,
                rng.choice([0, 16, 32]),
            ]
        elif profile == "shellcode_loader":
            feat = [
                rng.uniform(12, 16),
                rng.choice([2, 3]),
                rng.uniform(5.0, 7.0),
                rng.uniform(6.0, 7.5),
                rng.uniform(4.5, 6.5),
                rng.uniform(1, 4),
                rng.uniform(3, 20),
                rng.choice([0, 1]),
                rng.uniform(0, 0.15),
                0.0,
                rng.choice([0, 1]),
                rng.choice([0, 1]),
                0.0,
                rng.choice([2, 3, 34]),    # shellcode or API hash
            ]
        else:  # minimal
            feat = [
                rng.uniform(10, 14),       # tiny
                rng.choice([1, 2]),
                rng.uniform(4.0, 7.5),
                rng.uniform(5.0, 7.8),
                rng.uniform(4.0, 7.0),
                rng.uniform(0, 2),
                rng.uniform(0, 5),
                0.0,
                0.0,
                0.0,
                1.0,                       # suspicious timestamp
                rng.choice([0, 1]),
                0.0,
                rng.choice([0, 16, 32]),
            ]
        X.append(feat)
        y.append(1)

    return np.array(X), np.array(y)


# ── Model training ────────────────────────────────────────────────────────

def train_model(X, y, n_estimators=100, max_depth=10, random_state=42):
    """Train a Random Forest and return model + metrics."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score, train_test_split
    from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                                 f1_score, confusion_matrix)

    # Split: 80% train, 20% held-out test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=random_state, stratify=y
    )

    # Train
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_leaf=5,
        random_state=random_state,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # 5-fold CV on training set
    cv_scores = cross_val_score(clf, X_train, y_train, cv=5, scoring="accuracy")

    # Held-out evaluation
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    # FP rate on clean samples only
    clean_mask = y_test == 0
    if clean_mask.sum() > 0:
        fp_rate = (y_pred[clean_mask] == 1).sum() / clean_mask.sum()
    else:
        fp_rate = 0.0

    metrics = {
        "cv_accuracy_mean": float(cv_scores.mean()),
        "cv_accuracy_std": float(cv_scores.std()),
        "cv_scores": [float(s) for s in cv_scores],
        "holdout_accuracy": float(accuracy_score(y_test, y_pred)),
        "holdout_precision": float(precision_score(y_test, y_pred,
                                                    zero_division=0)),
        "holdout_recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "holdout_f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "holdout_fp_rate": float(fp_rate),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "n_train": len(X_train),
        "n_test": len(X_test),
        "n_estimators": n_estimators,
        "max_depth": max_depth,
    }

    return clf, metrics


# ── Export model to JSON decision tree array ──────────────────────────────

def _export_tree(tree, feature_names):
    """Convert a single sklearn DecisionTreeClassifier to a JSON-serializable
    structure. Each node is:
        {"feature": idx, "threshold": val, "left": node, "right": node}
    or for a leaf:
        {"value": probability}
    """
    tree_ = tree.tree_

    def recurse(node_id):
        if tree_.children_left[node_id] == tree_.children_right[node_id]:
            # Leaf node
            values = tree_.value[node_id][0]
            total = values.sum()
            prob = float(values[1] / total) if total > 0 else 0.0
            return {"value": round(prob, 6)}
        else:
            feature_idx = int(tree_.feature[node_id])
            threshold = float(tree_.threshold[node_id])
            return {
                "feature": feature_idx,
                "threshold": round(threshold, 6),
                "left": recurse(int(tree_.children_left[node_id])),
                "right": recurse(int(tree_.children_right[node_id])),
            }

    return recurse(0)


def export_model_json(clf, metrics, output_path):
    """Export the Random Forest as a JSON file with decision tree array."""
    trees = []
    for estimator in clf.estimators_:
        trees.append(_export_tree(estimator, FEATURE_NAMES))

    model = {
        "model_type": "random_forest",
        "version": 1,
        "num_trees": len(trees),
        "num_features": NUM_FEATURES,
        "feature_names": FEATURE_NAMES,
        "threshold": 0.5,
        "trees": trees,
        "training_metrics": metrics,
    }

    with open(output_path, "w") as f:
        json.dump(model, f, indent=2)

    return model


# ── Validation on directory of clean PEs ──────────────────────────────────

def validate_clean_dir(model_path, clean_dir):
    """Load exported JSON model and validate FP rate on clean PEs."""
    with open(model_path) as f:
        model = json.load(f)

    trees = model["trees"]
    threshold = model.get("threshold", 0.5)

    def predict_one(features):
        """Walk all trees and average probabilities."""
        probs = []
        for tree in trees:
            node = tree
            while "value" not in node:
                if features[node["feature"]] <= node["threshold"]:
                    node = node["left"]
                else:
                    node = node["right"]
            probs.append(node["value"])
        return sum(probs) / len(probs)

    clean_dir = Path(clean_dir)
    total = 0
    fp = 0
    errors = 0

    for pe_path in sorted(clean_dir.rglob("*")):
        if not pe_path.is_file():
            continue
        if pe_path.suffix.lower() not in (".exe", ".dll", ".sys", ".ocx"):
            continue

        features = extract_features(str(pe_path))
        if features is None:
            errors += 1
            continue

        prob = predict_one(features)
        total += 1
        if prob >= threshold:
            fp += 1
            print(f"  FP: {pe_path.name} (prob={prob:.3f})")

    fp_rate = fp / total if total > 0 else 0.0
    print(f"\nValidation: {total} clean PEs, {fp} false positives "
          f"({fp_rate*100:.1f}%), {errors} parse errors")
    return fp_rate


# ── CLI ───────────────────────────────────────────────────────────────────

def cmd_train(args):
    """Train on labeled PE directories."""
    import numpy as np

    clean_dir = Path(args.clean)
    malware_dir = Path(args.malware)

    print(f"Extracting features from clean PEs: {clean_dir}")
    X_clean = []
    for p in sorted(clean_dir.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in (".exe", ".dll", ".sys", ".ocx"):
            continue
        feat = extract_features(str(p))
        if feat is not None:
            X_clean.append(feat)
    print(f"  {len(X_clean)} clean samples extracted")

    print(f"Extracting features from malware PEs: {malware_dir}")
    X_mal = []
    for p in sorted(malware_dir.rglob("*")):
        if not p.is_file():
            continue
        feat = extract_features(str(p))
        if feat is not None:
            X_mal.append(feat)
    print(f"  {len(X_mal)} malware samples extracted")

    if len(X_clean) < 10 or len(X_mal) < 10:
        print("ERROR: Need at least 10 samples per class.")
        sys.exit(1)

    X = np.array(X_clean + X_mal)
    y = np.array([0] * len(X_clean) + [1] * len(X_mal))

    print(f"\nTraining Random Forest on {len(X)} samples...")
    clf, metrics = train_model(X, y,
                                n_estimators=args.n_estimators,
                                max_depth=args.max_depth)
    _print_metrics(metrics)

    print(f"\nExporting model to {args.output}")
    export_model_json(clf, metrics, args.output)
    print("Done.")


def cmd_synthetic(args):
    """Train on synthetic data."""
    import numpy as np

    print("Generating synthetic training data...")
    X, y = _generate_synthetic_data(
        n_clean=args.n_clean,
        n_malware=args.n_malware,
        seed=args.seed,
    )
    print(f"  {(y==0).sum()} clean, {(y==1).sum()} malware samples")

    print(f"\nTraining Random Forest ({args.n_estimators} trees, "
          f"max_depth={args.max_depth})...")
    clf, metrics = train_model(X, y,
                                n_estimators=args.n_estimators,
                                max_depth=args.max_depth,
                                random_state=args.seed)
    _print_metrics(metrics)

    print(f"\nExporting model to {args.output}")
    export_model_json(clf, metrics, args.output)
    print("Done.")


def cmd_features(args):
    """Extract and print features from a PE file."""
    feat = extract_features(args.file)
    if feat is None:
        print(f"ERROR: Could not extract features from {args.file}")
        sys.exit(1)

    print(f"Features for: {args.file}")
    for i, (name, val) in enumerate(zip(FEATURE_NAMES, feat)):
        print(f"  [{i:2d}] {name:24s} = {val:.4f}")

    if args.json:
        print(json.dumps(dict(zip(FEATURE_NAMES, feat)), indent=2))


def cmd_validate(args):
    """Validate model FP rate on clean PE directory."""
    print(f"Validating model: {args.model}")
    print(f"Clean PE directory: {args.clean}")
    fp_rate = validate_clean_dir(args.model, args.clean)
    if fp_rate > 0.05:
        print(f"WARNING: FP rate {fp_rate*100:.1f}% exceeds 5% threshold!")
        sys.exit(1)
    else:
        print(f"PASS: FP rate {fp_rate*100:.1f}% is within 5% threshold.")


def _print_metrics(metrics):
    """Print training metrics."""
    print(f"\n{'='*50}")
    print(f"5-fold CV accuracy: {metrics['cv_accuracy_mean']:.4f} "
          f"(+/- {metrics['cv_accuracy_std']:.4f})")
    print(f"  Per-fold: {', '.join(f'{s:.3f}' for s in metrics['cv_scores'])}")
    print(f"Held-out accuracy:  {metrics['holdout_accuracy']:.4f}")
    print(f"Held-out precision: {metrics['holdout_precision']:.4f}")
    print(f"Held-out recall:    {metrics['holdout_recall']:.4f}")
    print(f"Held-out F1:        {metrics['holdout_f1']:.4f}")
    print(f"Held-out FP rate:   {metrics['holdout_fp_rate']*100:.1f}%")
    cm = metrics['confusion_matrix']
    print(f"Confusion matrix:")
    print(f"  TN={cm[0][0]:4d}  FP={cm[0][1]:4d}")
    print(f"  FN={cm[1][0]:4d}  TP={cm[1][1]:4d}")
    print(f"{'='*50}")

    # Check acceptance criteria
    ok = True
    if metrics['cv_accuracy_mean'] < 0.85:
        print("FAIL: 5-fold CV accuracy < 85%")
        ok = False
    if metrics['holdout_accuracy'] < 0.80:
        print("FAIL: Held-out accuracy < 80%")
        ok = False
    if metrics['holdout_fp_rate'] > 0.05:
        print("FAIL: FP rate > 5%")
        ok = False
    if ok:
        print("All acceptance criteria PASSED.")


def main():
    parser = argparse.ArgumentParser(
        description="AkesoAV ML classifier training tool (P9-T3)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # train
    p_train = subparsers.add_parser("train",
        help="Train on labeled PE directories")
    p_train.add_argument("--clean", required=True,
        help="Directory of clean PE files")
    p_train.add_argument("--malware", required=True,
        help="Directory of malware PE files")
    p_train.add_argument("-o", "--output", default="model.json",
        help="Output JSON model path (default: model.json)")
    p_train.add_argument("--n-estimators", type=int, default=100,
        help="Number of trees (default: 100)")
    p_train.add_argument("--max-depth", type=int, default=10,
        help="Max tree depth (default: 10)")

    # synthetic
    p_syn = subparsers.add_parser("synthetic",
        help="Train on synthetic data (for bootstrapping)")
    p_syn.add_argument("-o", "--output", default="model.json",
        help="Output JSON model path (default: model.json)")
    p_syn.add_argument("--n-clean", type=int, default=500,
        help="Number of synthetic clean samples (default: 500)")
    p_syn.add_argument("--n-malware", type=int, default=500,
        help="Number of synthetic malware samples (default: 500)")
    p_syn.add_argument("--n-estimators", type=int, default=100,
        help="Number of trees (default: 100)")
    p_syn.add_argument("--max-depth", type=int, default=10,
        help="Max tree depth (default: 10)")
    p_syn.add_argument("--seed", type=int, default=42,
        help="Random seed (default: 42)")

    # features
    p_feat = subparsers.add_parser("features",
        help="Extract features from a PE file")
    p_feat.add_argument("file", help="PE file to analyze")
    p_feat.add_argument("--json", action="store_true",
        help="Also print JSON output")

    # validate
    p_val = subparsers.add_parser("validate",
        help="Validate FP rate on clean PE directory")
    p_val.add_argument("--model", required=True,
        help="Path to exported JSON model")
    p_val.add_argument("--clean", required=True,
        help="Directory of clean PE files")

    args = parser.parse_args()

    if args.command == "train":
        cmd_train(args)
    elif args.command == "synthetic":
        cmd_synthetic(args)
    elif args.command == "features":
        cmd_features(args)
    elif args.command == "validate":
        cmd_validate(args)


if __name__ == "__main__":
    main()
