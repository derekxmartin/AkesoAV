"""pyakav — Python ctypes wrapper for akesoav.dll.

Usage:
    from pyakav import AkesoAV, ScanOptions

    with AkesoAV(dll_path="akesoav.dll", db_path="sigs.akavdb") as av:
        result = av.scan_file("suspect.exe")
        if result.found:
            print(f"Malware: {result.malware_name}")

        result = av.scan_buffer(data, name="inmemory.bin")
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import os
import sys
from ctypes import (
    POINTER,
    Structure,
    byref,
    c_char,
    c_char_p,
    c_double,
    c_int,
    c_int32,
    c_int64,
    c_size_t,
    c_uint8,
    c_uint32,
    c_uint64,
    c_void_p,
)
from dataclasses import dataclass
from typing import Optional

# ── Error codes (mirror akesoav.h) ──────────────────────────────────

AKAV_OK = 0
AKAV_ERROR = -1
AKAV_ERROR_INVALID = -2
AKAV_ERROR_NOMEM = -3
AKAV_ERROR_IO = -4
AKAV_ERROR_DB = -5
AKAV_ERROR_TIMEOUT = -6
AKAV_ERROR_SIGNATURE = -7
AKAV_ERROR_NOT_INIT = -8
AKAV_ERROR_BOMB = -9
AKAV_ERROR_SCAN = -10

_ERROR_NAMES = {
    AKAV_OK: "OK",
    AKAV_ERROR: "Generic error",
    AKAV_ERROR_INVALID: "Invalid parameter",
    AKAV_ERROR_NOMEM: "Memory allocation failed",
    AKAV_ERROR_IO: "I/O error",
    AKAV_ERROR_DB: "Signature database error",
    AKAV_ERROR_TIMEOUT: "Scan timeout exceeded",
    AKAV_ERROR_SIGNATURE: "RSA signature verification failed",
    AKAV_ERROR_NOT_INIT: "Engine not initialized",
    AKAV_ERROR_BOMB: "Decompression bomb detected",
    AKAV_ERROR_SCAN: "Scan stage error",
}

# ── Constants (mirror akesoav.h) ────────────────────────────────────

AKAV_MAX_MALWARE_NAME = 256
AKAV_MAX_SIG_ID = 64
AKAV_MAX_SCANNER_ID = 64
AKAV_MAX_FILE_TYPE = 32
AKAV_MAX_WARNINGS = 8
AKAV_MAX_WARNING_LEN = 128

AKAV_HEUR_OFF = 0
AKAV_HEUR_LOW = 1
AKAV_HEUR_MEDIUM = 2
AKAV_HEUR_HIGH = 3


# ── ctypes structures ───────────────────────────────────────────────

class _ScanOptions(Structure):
    _fields_ = [
        ("scan_archives", c_int),
        ("scan_packed", c_int),
        ("use_heuristics", c_int),
        ("heuristic_level", c_int),
        ("max_filesize", c_int64),
        ("max_scan_depth", c_int),
        ("timeout_ms", c_int),
        ("scan_memory", c_int),
        ("use_cache", c_int),
        ("use_whitelist", c_int),
    ]


class _ScanResult(Structure):
    _fields_ = [
        ("found", c_int),
        ("malware_name", c_char * AKAV_MAX_MALWARE_NAME),
        ("signature_id", c_char * AKAV_MAX_SIG_ID),
        ("scanner_id", c_char * AKAV_MAX_SCANNER_ID),
        ("file_type", c_char * AKAV_MAX_FILE_TYPE),
        ("heuristic_score", c_double),
        ("crc1", c_uint32),
        ("crc2", c_uint32),
        ("in_whitelist", c_int),
        ("total_size", c_int64),
        ("scanned_size", c_int64),
        ("cached", c_int),
        ("scan_time_ms", c_int),
        ("warning_count", c_int),
        ("warnings", (c_char * AKAV_MAX_WARNING_LEN) * AKAV_MAX_WARNINGS),
    ]


# ── Python-friendly result / options ────────────────────────────────

@dataclass
class ScanResult:
    """Result of an AkesoAV scan."""
    found: bool
    malware_name: str
    signature_id: str
    scanner_id: str
    file_type: str
    heuristic_score: float
    crc1: int
    crc2: int
    in_whitelist: bool
    total_size: int
    scanned_size: int
    cached: bool
    scan_time_ms: int
    warnings: list[str]

    @staticmethod
    def _from_c(raw: _ScanResult) -> ScanResult:
        warnings = []
        for i in range(raw.warning_count):
            w = raw.warnings[i].value
            if isinstance(w, bytes):
                w = w.decode("utf-8", errors="replace")
            if w:
                warnings.append(w)
        return ScanResult(
            found=bool(raw.found),
            malware_name=raw.malware_name.decode("utf-8", errors="replace").rstrip("\x00"),
            signature_id=raw.signature_id.decode("utf-8", errors="replace").rstrip("\x00"),
            scanner_id=raw.scanner_id.decode("utf-8", errors="replace").rstrip("\x00"),
            file_type=raw.file_type.decode("utf-8", errors="replace").rstrip("\x00"),
            heuristic_score=raw.heuristic_score,
            crc1=raw.crc1,
            crc2=raw.crc2,
            in_whitelist=bool(raw.in_whitelist),
            total_size=raw.total_size,
            scanned_size=raw.scanned_size,
            cached=bool(raw.cached),
            scan_time_ms=raw.scan_time_ms,
            warnings=warnings,
        )


@dataclass
class ScanOptions:
    """Scan options for AkesoAV engine.

    Defaults match akav_scan_options_default().
    """
    scan_archives: bool = True
    scan_packed: bool = True
    use_heuristics: bool = True
    heuristic_level: int = AKAV_HEUR_MEDIUM
    max_filesize: int = 0
    max_scan_depth: int = 10
    timeout_ms: int = 30000
    scan_memory: bool = False
    use_cache: bool = True
    use_whitelist: bool = True

    def _to_c(self) -> _ScanOptions:
        opts = _ScanOptions()
        opts.scan_archives = int(self.scan_archives)
        opts.scan_packed = int(self.scan_packed)
        opts.use_heuristics = int(self.use_heuristics)
        opts.heuristic_level = self.heuristic_level
        opts.max_filesize = self.max_filesize
        opts.max_scan_depth = self.max_scan_depth
        opts.timeout_ms = self.timeout_ms
        opts.scan_memory = int(self.scan_memory)
        opts.use_cache = int(self.use_cache)
        opts.use_whitelist = int(self.use_whitelist)
        return opts


# ── Exceptions ──────────────────────────────────────────────────────

class AkesoError(Exception):
    """Base exception for AkesoAV errors."""
    def __init__(self, code: int, message: str = ""):
        self.code = code
        self.message = message or _ERROR_NAMES.get(code, f"Unknown error ({code})")
        super().__init__(self.message)


class BombDetectedError(AkesoError):
    """Raised when a decompression bomb is detected."""
    pass


# ── Engine wrapper ──────────────────────────────────────────────────

def _check(code: int) -> None:
    """Raise AkesoError if code != AKAV_OK."""
    if code == AKAV_OK:
        return
    if code == AKAV_ERROR_BOMB:
        raise BombDetectedError(code)
    raise AkesoError(code)


class AkesoAV:
    """Python wrapper around akesoav.dll.

    Args:
        dll_path: Path to akesoav.dll. If relative, searches DLL search order.
        db_path:  Optional path to .akavdb signature database to load on init.
        config_path: Optional config file path passed to akav_engine_init.
    """

    def __init__(
        self,
        dll_path: str = "akesoav.dll",
        db_path: Optional[str] = None,
        config_path: Optional[str] = None,
    ):
        self._handle: c_void_p | None = None
        self._dll = self._load_dll(dll_path)
        self._setup_prototypes()
        self._create_engine()
        self._init_engine(config_path)
        if db_path:
            self.load_signatures(db_path)

    @staticmethod
    def _load_dll(dll_path: str) -> ctypes.CDLL:
        # Add directory containing DLL to search path
        dll_dir = os.path.dirname(os.path.abspath(dll_path))
        if dll_dir and os.path.isdir(dll_dir):
            os.add_dll_directory(dll_dir)
        return ctypes.CDLL(dll_path)

    def _setup_prototypes(self) -> None:
        dll = self._dll

        # Engine lifecycle
        dll.akav_engine_create.argtypes = [POINTER(c_void_p)]
        dll.akav_engine_create.restype = c_int32
        dll.akav_engine_init.argtypes = [c_void_p, c_char_p]
        dll.akav_engine_init.restype = c_int32
        dll.akav_engine_load_signatures.argtypes = [c_void_p, c_char_p]
        dll.akav_engine_load_signatures.restype = c_int32
        dll.akav_engine_destroy.argtypes = [c_void_p]
        dll.akav_engine_destroy.restype = c_int32

        # Scanning
        dll.akav_scan_file.argtypes = [c_void_p, c_char_p, POINTER(_ScanOptions), POINTER(_ScanResult)]
        dll.akav_scan_file.restype = c_int32
        dll.akav_scan_buffer.argtypes = [c_void_p, POINTER(c_uint8), c_size_t, c_char_p,
                                         POINTER(_ScanOptions), POINTER(_ScanResult)]
        dll.akav_scan_buffer.restype = c_int32

        # Info
        dll.akav_engine_version.argtypes = []
        dll.akav_engine_version.restype = c_char_p
        dll.akav_db_version.argtypes = [c_void_p]
        dll.akav_db_version.restype = c_char_p
        dll.akav_strerror.argtypes = [c_int32]
        dll.akav_strerror.restype = c_char_p

        # Defaults
        dll.akav_scan_options_default.argtypes = [POINTER(_ScanOptions)]
        dll.akav_scan_options_default.restype = None

    def _create_engine(self) -> None:
        handle = c_void_p()
        _check(self._dll.akav_engine_create(byref(handle)))
        self._handle = handle

    def _init_engine(self, config_path: Optional[str]) -> None:
        cfg = config_path.encode("utf-8") if config_path else None
        _check(self._dll.akav_engine_init(self._handle, cfg))

    # ── Public API ──────────────────────────────────────────────────

    def load_signatures(self, db_path: str) -> None:
        """Load a .akavdb signature database."""
        _check(self._dll.akav_engine_load_signatures(
            self._handle, db_path.encode("utf-8")))

    def scan_file(self, path: str, options: Optional[ScanOptions] = None) -> ScanResult:
        """Scan a file on disk."""
        opts_c = options._to_c() if options else self._default_options()
        result = _ScanResult()
        _check(self._dll.akav_scan_file(
            self._handle, path.encode("utf-8"), byref(opts_c), byref(result)))
        return ScanResult._from_c(result)

    def scan_buffer(
        self,
        data: bytes,
        name: Optional[str] = None,
        options: Optional[ScanOptions] = None,
    ) -> ScanResult:
        """Scan an in-memory buffer."""
        opts_c = options._to_c() if options else self._default_options()
        result = _ScanResult()
        buf = (c_uint8 * len(data)).from_buffer_copy(data)
        name_c = name.encode("utf-8") if name else None
        _check(self._dll.akav_scan_buffer(
            self._handle, buf, len(data), name_c, byref(opts_c), byref(result)))
        return ScanResult._from_c(result)

    @property
    def engine_version(self) -> str:
        """Return the engine version string."""
        return self._dll.akav_engine_version().decode("utf-8")

    @property
    def db_version(self) -> str:
        """Return the loaded database version string."""
        return self._dll.akav_db_version(self._handle).decode("utf-8")

    def strerror(self, code: int) -> str:
        """Return a human-readable error description."""
        return self._dll.akav_strerror(code).decode("utf-8")

    def close(self) -> None:
        """Destroy the engine and release resources."""
        if self._handle is not None:
            self._dll.akav_engine_destroy(self._handle)
            self._handle = None

    # ── Helpers ─────────────────────────────────────────────────────

    def _default_options(self) -> _ScanOptions:
        opts = _ScanOptions()
        self._dll.akav_scan_options_default(byref(opts))
        return opts

    # ── Context manager ─────────────────────────────────────────────

    def __enter__(self) -> AkesoAV:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()
