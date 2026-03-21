"""test_end_to_end.py — End-to-end integration tests for AkesoAV.

Pipeline: akavdb-tool compile → engine load → scan mixed test corpus.

Tests:
    - Compile .akavdb from test_sigs.json
    - Load engine with compiled database
    - Scan known-malicious files → all detected
    - Scan known-clean files → zero false positives
    - Scan archives → malware inside detected
    - Scan buffers → EICAR detected in memory
    - Scan truncated/empty files → no crash, clean result

Run from project root:
    python -m pytest tests/integration/test_end_to_end.py -v
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

# Add bindings to path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "bindings", "python"))

from pyakav import AkesoAV, AkesoError, ScanOptions, ScanResult

# ── Paths ────────────────────────────────────────────────────────────

DLL_PATH = os.path.join(PROJECT_ROOT, "build", "Release", "akesoav.dll")
TESTDATA = os.path.join(PROJECT_ROOT, "testdata")
AKAVDB_TOOL = os.path.join(PROJECT_ROOT, "tools", "akavdb-tool", "akavdb_tool.py")
# Use integration-specific sigs (no MZ bytestream pattern that FPs on all PEs)
SIGS_JSON = os.path.join(os.path.dirname(__file__), "integration_sigs.json")

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def skip_if_missing(path: str, label: str):
    if not os.path.isfile(path):
        pytest.skip(f"{label} not found at {path}")


# ── Fixtures ─────────────────────────────────────────────────────────

def _run_cli(args: list[str]) -> tuple[int, str]:
    """Run a CLI command and return (exit_code, output).

    Runs via os.system with a temp output file in the project root
    to work around subprocess handle inheritance issues in Python 3.14.
    """
    fd, outfile = tempfile.mkstemp(suffix=".txt", dir=PROJECT_ROOT)
    os.close(fd)
    try:
        # Build command with proper quoting
        parts = []
        for a in args:
            if " " in a or "(" in a:
                parts.append(f'"{a}"')
            else:
                parts.append(a)
        cmd = " ".join(parts) + f' > "{outfile}" 2>&1'
        exit_code = os.system(cmd)
        with open(outfile, "r", errors="replace") as f:
            output = f.read()
        return exit_code, output
    finally:
        try:
            os.unlink(outfile)
        except OSError:
            pass


# Compiled DB path (in project dir to avoid temp path issues)
_COMPILED_DB_PATH = os.path.join(PROJECT_ROOT, "testdata", "integration_test.akavdb")


@pytest.fixture(scope="session")
def compiled_db() -> str:
    """Compile a fresh .akavdb from integration_sigs.json using akavdb_tool."""
    skip_if_missing(AKAVDB_TOOL, "akavdb_tool.py")
    skip_if_missing(SIGS_JSON, "integration_sigs.json")

    db_path = _COMPILED_DB_PATH

    # Import and run akavdb_tool directly to avoid subprocess issues
    tool_dir = os.path.dirname(AKAVDB_TOOL)
    sys.path.insert(0, tool_dir)
    try:
        import importlib
        import akavdb_tool
        importlib.reload(akavdb_tool)  # Ensure fresh import

        old_argv = sys.argv
        sys.argv = ["akavdb_tool", "compile", SIGS_JSON, "-o", db_path]
        try:
            akavdb_tool.main()
        finally:
            sys.argv = old_argv
    finally:
        sys.path.remove(tool_dir)

    assert os.path.isfile(db_path), "Compiled .akavdb not created"
    yield db_path
    # Cleanup
    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture(scope="session")
def engine(compiled_db) -> AkesoAV:
    """Create an AkesoAV engine loaded with the freshly compiled database."""
    skip_if_missing(DLL_PATH, "akesoav.dll")
    av = AkesoAV(dll_path=DLL_PATH, db_path=compiled_db)
    yield av
    av.close()


# ── Database compilation tests ───────────────────────────────────────

class TestDatabaseCompilation:
    """Verify akavdb-tool can compile and the engine can load the result."""

    def test_compile_produces_valid_db(self, compiled_db):
        """Compiled .akavdb is non-empty and loadable."""
        assert os.path.getsize(compiled_db) > 280  # At least header size

    def test_engine_loads_compiled_db(self, engine):
        """Engine initializes and loads the compiled database."""
        assert engine._handle is not None
        ver = engine.db_version
        assert isinstance(ver, str)

    def test_engine_version_string(self, engine):
        """Engine reports a valid version string."""
        ver = engine.engine_version
        assert ver and len(ver) > 0


# ── Malware detection tests (true positives) ─────────────────────────

class TestMalwareDetection:
    """All known-malicious files should be detected."""

    def test_eicar_plaintext(self, engine):
        """EICAR in plaintext is detected."""
        path = os.path.join(TESTDATA, "eicar.com.txt")
        skip_if_missing(path, "eicar.com.txt")
        result = engine.scan_file(path)
        assert result.found is True, "EICAR plaintext not detected"

    def test_eicar_in_zip(self, engine):
        """EICAR inside a ZIP archive is detected."""
        path = os.path.join(TESTDATA, "eicar.zip")
        skip_if_missing(path, "eicar.zip")
        result = engine.scan_file(path)
        assert result.found is True, "EICAR in ZIP not detected"

    def test_eicar_in_nested_zip(self, engine):
        """EICAR inside a nested ZIP (zip-in-zip) is detected."""
        path = os.path.join(TESTDATA, "eicar_nested.zip")
        skip_if_missing(path, "eicar_nested.zip")
        result = engine.scan_file(path)
        assert result.found is True, "EICAR in nested ZIP not detected"

    def test_eicar_in_gzip(self, engine):
        """EICAR inside a GZIP archive is detected."""
        path = os.path.join(TESTDATA, "eicar.gz")
        skip_if_missing(path, "eicar.gz")
        result = engine.scan_file(path)
        assert result.found is True, "EICAR in GZIP not detected"

    def test_eicar_in_tar_gz(self, engine):
        """EICAR inside a .tar.gz is detected."""
        path = os.path.join(TESTDATA, "eicar.tar.gz")
        skip_if_missing(path, "eicar.tar.gz")
        result = engine.scan_file(path)
        assert result.found is True, "EICAR in tar.gz not detected"

    def test_eicar_buffer(self, engine):
        """EICAR detected when scanned as a raw buffer."""
        result = engine.scan_buffer(EICAR, name="eicar.com")
        assert result.found is True, "EICAR buffer not detected"

    def test_detection_has_name(self, engine):
        """Detection result includes a malware name."""
        result = engine.scan_buffer(EICAR, name="eicar.com")
        assert result.malware_name != "", "Detection missing malware name"
        assert result.signature_id != "", "Detection missing signature ID"


# ── Clean file tests (false positive check) ──────────────────────────

class TestCleanFiles:
    """Known-clean files must not trigger detections (zero FP)."""

    def test_clean_text(self, engine):
        path = os.path.join(TESTDATA, "clean.txt")
        skip_if_missing(path, "clean.txt")
        result = engine.scan_file(path)
        assert result.found is False, f"FP on clean.txt: {result.malware_name}"

    def test_clean_pe_64(self, engine):
        path = os.path.join(TESTDATA, "clean_pe_64.exe")
        skip_if_missing(path, "clean_pe_64.exe")
        result = engine.scan_file(path)
        assert result.found is False, f"FP on clean_pe_64.exe: {result.malware_name}"

    def test_clean_pe_32(self, engine):
        path = os.path.join(TESTDATA, "clean_pe_32.exe")
        skip_if_missing(path, "clean_pe_32.exe")
        result = engine.scan_file(path)
        assert result.found is False, f"FP on clean_pe_32.exe: {result.malware_name}"

    def test_empty_file(self, engine):
        path = os.path.join(TESTDATA, "empty.bin")
        skip_if_missing(path, "empty.bin")
        result = engine.scan_file(path)
        assert result.found is False, f"FP on empty.bin: {result.malware_name}"

    def test_truncated_pe(self, engine):
        path = os.path.join(TESTDATA, "truncated.exe")
        skip_if_missing(path, "truncated.exe")
        result = engine.scan_file(path)
        assert result.found is False, f"FP on truncated.exe: {result.malware_name}"

    def test_clean_buffer(self, engine):
        result = engine.scan_buffer(b"Hello, world! Just a normal string.", name="clean.txt")
        assert result.found is False, f"FP on clean buffer: {result.malware_name}"

    def test_pe_corpus_no_fp(self, engine):
        """Scan all files in pe_corpus/ — none should trigger."""
        corpus_dir = os.path.join(TESTDATA, "pe_corpus")
        if not os.path.isdir(corpus_dir):
            pytest.skip("pe_corpus/ not found")

        fps = []
        for fname in os.listdir(corpus_dir):
            fpath = os.path.join(corpus_dir, fname)
            if not os.path.isfile(fpath):
                continue
            result = engine.scan_file(fpath)
            if result.found:
                fps.append(f"{fname}: {result.malware_name}")

        assert len(fps) == 0, f"False positives in pe_corpus:\n" + "\n".join(fps)


# ── Scan options tests ───────────────────────────────────────────────

class TestScanOptions:
    """Verify scan options affect behavior."""

    def test_archives_disabled_skips_zip(self, engine):
        """With scan_archives=False, EICAR in ZIP is NOT detected."""
        path = os.path.join(TESTDATA, "eicar.zip")
        skip_if_missing(path, "eicar.zip")
        opts = ScanOptions(scan_archives=False)
        result = engine.scan_file(path, options=opts)
        assert result.found is False, "EICAR in ZIP detected with archives disabled"

    def test_archives_enabled_detects_zip(self, engine):
        """With scan_archives=True (default), EICAR in ZIP IS detected."""
        path = os.path.join(TESTDATA, "eicar.zip")
        skip_if_missing(path, "eicar.zip")
        opts = ScanOptions(scan_archives=True)
        result = engine.scan_file(path, options=opts)
        assert result.found is True, "EICAR in ZIP not detected with archives enabled"


# ── CLI scanner integration ──────────────────────────────────────────

class TestCLIScanner:
    """Verify akavscan.exe works end-to-end."""

    AKAVSCAN = os.path.join(PROJECT_ROOT, "build", "Release", "akavscan.exe")

    def test_cli_eicar_detected(self, compiled_db):
        """CLI scanner detects EICAR with exit code 1."""
        skip_if_missing(self.AKAVSCAN, "akavscan.exe")
        eicar_path = os.path.join(TESTDATA, "eicar.com.txt")
        skip_if_missing(eicar_path, "eicar.com.txt")

        code, output = _run_cli([self.AKAVSCAN, "--db", compiled_db, eicar_path])
        assert code == 1, f"Expected exit 1 for EICAR, got {code}\n{output}"

    def test_cli_clean_file(self, compiled_db):
        """CLI scanner reports clean file with exit code 0."""
        skip_if_missing(self.AKAVSCAN, "akavscan.exe")
        clean_path = os.path.join(TESTDATA, "clean.txt")
        skip_if_missing(clean_path, "clean.txt")

        code, output = _run_cli([self.AKAVSCAN, "--db", compiled_db, clean_path])
        assert code == 0, f"Expected exit 0 for clean file, got {code}\n{output}"

    def test_cli_json_output(self, compiled_db):
        """CLI scanner with -j produces valid JSON."""
        skip_if_missing(self.AKAVSCAN, "akavscan.exe")
        eicar_path = os.path.join(TESTDATA, "eicar.com.txt")
        skip_if_missing(eicar_path, "eicar.com.txt")

        code, output = _run_cli([self.AKAVSCAN, "--db", compiled_db, "-j", eicar_path])
        import json
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            pytest.fail(f"CLI -j output is not valid JSON:\n{output}")
        assert "found" in data or "malware_name" in data or "result" in data, \
            f"JSON output missing expected fields: {data}"

    def test_cli_eicar_in_zip(self, compiled_db):
        """CLI scanner detects EICAR inside ZIP archive."""
        skip_if_missing(self.AKAVSCAN, "akavscan.exe")
        zip_path = os.path.join(TESTDATA, "eicar.zip")
        skip_if_missing(zip_path, "eicar.zip")

        code, output = _run_cli([self.AKAVSCAN, "--db", compiled_db, zip_path])
        assert code == 1, f"Expected exit 1 for EICAR in ZIP, got {code}\n{output}"
