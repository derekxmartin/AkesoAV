"""test_pyakav.py — pytest tests for pyakav ctypes wrapper.

Run from project root:
    python -m pytest bindings/python/test_pyakav.py -v

Requires:
    - akesoav.dll built in build/Release/
    - Python 3.10+
"""

from __future__ import annotations

import os
import sys

import pytest

# Add bindings directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from pyakav import (
    AKAV_ERROR_BOMB,
    AKAV_ERROR_INVALID,
    AKAV_HEUR_MEDIUM,
    AKAV_HEUR_OFF,
    AkesoAV,
    AkesoError,
    BombDetectedError,
    ScanOptions,
    ScanResult,
)

# ── Helpers ──────────────────────────────────────────────────────────

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DLL_PATH = os.path.join(PROJECT_ROOT, "build", "Release", "akesoav.dll")
DB_PATH = os.path.join(PROJECT_ROOT, "testdata", "test.akavdb")

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture(scope="session")
def db_path() -> str:
    """Return path to the pre-compiled test.akavdb."""
    if not os.path.isfile(DB_PATH):
        pytest.skip(f"test.akavdb not found at {DB_PATH}")
    return DB_PATH


@pytest.fixture(scope="session")
def eicar_file(tmp_path_factory) -> str:
    """Create a temporary EICAR test file."""
    d = tmp_path_factory.mktemp("eicar")
    path = d / "eicar.com"
    path.write_bytes(EICAR)
    return str(path)


@pytest.fixture(scope="session")
def clean_file(tmp_path_factory) -> str:
    """Create a temporary clean file."""
    d = tmp_path_factory.mktemp("clean")
    path = d / "clean.txt"
    path.write_bytes(b"This is a perfectly clean file with no malware.")
    return str(path)


def skip_if_no_dll():
    if not os.path.isfile(DLL_PATH):
        pytest.skip(f"akesoav.dll not found at {DLL_PATH}")


# ── Tests ────────────────────────────────────────────────────────────

class TestEngineLifecycle:
    """Test engine creation, init, and cleanup."""

    def test_create_and_close(self):
        skip_if_no_dll()
        av = AkesoAV(dll_path=DLL_PATH)
        assert av._handle is not None
        av.close()
        assert av._handle is None

    def test_context_manager(self):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH) as av:
            assert av._handle is not None
        assert av._handle is None

    def test_double_close_is_safe(self):
        skip_if_no_dll()
        av = AkesoAV(dll_path=DLL_PATH)
        av.close()
        av.close()  # Should not raise

    def test_engine_version(self):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH) as av:
            ver = av.engine_version
            assert isinstance(ver, str)
            assert len(ver) > 0

    def test_load_signatures(self, db_path):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH, db_path=db_path) as av:
            db_ver = av.db_version
            assert isinstance(db_ver, str)


class TestScanFile:
    """Test file scanning."""

    def test_eicar_detected(self, db_path, eicar_file):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH, db_path=db_path) as av:
            result = av.scan_file(eicar_file)
            assert result.found is True
            assert result.malware_name != ""

    def test_clean_file(self, db_path, clean_file):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH, db_path=db_path) as av:
            result = av.scan_file(clean_file)
            assert result.found is False
            assert result.malware_name == ""

    def test_result_fields(self, db_path, eicar_file):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH, db_path=db_path) as av:
            result = av.scan_file(eicar_file)
            assert isinstance(result.found, bool)
            assert isinstance(result.malware_name, str)
            assert isinstance(result.signature_id, str)
            assert isinstance(result.file_type, str)
            assert isinstance(result.heuristic_score, float)
            assert isinstance(result.total_size, int)
            assert isinstance(result.scanned_size, int)
            assert isinstance(result.scan_time_ms, int)
            assert isinstance(result.warnings, list)


class TestScanBuffer:
    """Test in-memory buffer scanning."""

    def test_eicar_buffer_detected(self, db_path):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH, db_path=db_path) as av:
            result = av.scan_buffer(EICAR, name="eicar.com")
            assert result.found is True
            assert result.malware_name != ""

    def test_clean_buffer(self, db_path):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH, db_path=db_path) as av:
            result = av.scan_buffer(b"Hello, world!", name="clean.txt")
            assert result.found is False

    def test_empty_buffer(self, db_path):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH, db_path=db_path) as av:
            result = av.scan_buffer(b"", name="empty.bin")
            assert result.found is False

    def test_buffer_no_name(self, db_path):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH, db_path=db_path) as av:
            result = av.scan_buffer(EICAR)
            assert result.found is True


class TestScanOptions:
    """Test scan options."""

    def test_default_options(self):
        opts = ScanOptions()
        assert opts.scan_archives is True
        assert opts.max_scan_depth == 10
        assert opts.timeout_ms == 30000
        assert opts.heuristic_level == AKAV_HEUR_MEDIUM

    def test_custom_options(self, db_path):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH, db_path=db_path) as av:
            opts = ScanOptions(scan_archives=False, timeout_ms=5000)
            result = av.scan_buffer(EICAR, options=opts)
            assert result.found is True  # EICAR detected even without archive scan

    def test_options_roundtrip(self):
        opts = ScanOptions(
            scan_archives=False,
            scan_packed=False,
            use_heuristics=False,
            heuristic_level=AKAV_HEUR_OFF,
            max_filesize=1024 * 1024,
            max_scan_depth=5,
            timeout_ms=10000,
        )
        c_opts = opts._to_c()
        assert c_opts.scan_archives == 0
        assert c_opts.scan_packed == 0
        assert c_opts.use_heuristics == 0
        assert c_opts.heuristic_level == 0
        assert c_opts.max_filesize == 1024 * 1024
        assert c_opts.max_scan_depth == 5
        assert c_opts.timeout_ms == 10000


class TestErrorHandling:
    """Test error propagation."""

    def test_strerror(self):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH) as av:
            msg = av.strerror(AKAV_ERROR_INVALID)
            assert "Invalid" in msg

    def test_bad_db_path_raises(self):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH) as av:
            with pytest.raises(AkesoError):
                av.load_signatures("nonexistent.akavdb")

    def test_bad_file_path_raises(self, db_path):
        skip_if_no_dll()
        with AkesoAV(dll_path=DLL_PATH, db_path=db_path) as av:
            with pytest.raises(AkesoError):
                av.scan_file("totally_nonexistent_file.exe")
