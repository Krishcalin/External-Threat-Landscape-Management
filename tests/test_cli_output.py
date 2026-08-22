"""The CLI's two output contracts: --json is JSON, and everything is UTF-8.

Both of these were broken, and both broke in the same way — invisibly when the
output went to a terminal, and only when it was redirected or piped, which is
exactly the case nobody looks at. They are asserted through a REAL subprocess
with redirected pipes, because running main() in-process would restore the tty
conditions that hid the bugs in the first place.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    not (ROOT / "data" / "kev.json").is_file(),
    reason="the vendored catalogue is required; run tools/refresh_intel.py")


@pytest.fixture(scope="module")
def inventory(tmp_path_factory) -> Path:
    """A product that really is in the catalogue, so the output is non-trivial."""
    path = tmp_path_factory.mktemp("cli") / "assets.csv"
    path.write_text("identifier,product,version\n"
                    "vpn.example.com,Ivanti Connect Secure,\n"
                    "unknown-host.example.com,unknown,\n",
                    encoding="utf-8")
    return path


def run(*args) -> subprocess.CompletedProcess:
    """Capture bytes, not text. Decoding here would hide an encoding bug."""
    return subprocess.run([sys.executable, "main.py", *args],
                          cwd=ROOT, capture_output=True, timeout=120)


def test_json_output_is_only_json(inventory):
    """`scan --json > out.json` must produce a file a parser can read.

    It did not: two human-readable progress lines were printed to stdout before
    the document, on the one interface whose entire purpose is being parsed.
    """
    result = run("scan", str(inventory), "--json")
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    document = json.loads(result.stdout.decode("utf-8"))
    assert document["exposures"], "the fixture should match the catalogue"
    assert "notice" in document


def test_json_progress_is_not_discarded_only_moved(inventory):
    """Silencing the context would be the wrong fix; it belongs on stderr."""
    result = run("scan", str(inventory), "--json")
    context = result.stderr.decode("utf-8")
    assert "Catalogue" in context
    assert "asset(s) read" in context


@pytest.mark.parametrize("argv", [
    ("intel",),
    ("scan", "INVENTORY"),
    ("scan", "INVENTORY", "--json"),
])
def test_redirected_output_is_utf8(inventory, argv):
    """Windows falls back to the ANSI code page when stdout is not a tty.

    The em-dashes in this tool's own notices were being written as cp1252 byte
    0x97, producing a file that is not UTF-8 — which every consumer assumes,
    including this tool reading its own CSVs.
    """
    result = run(*[str(inventory) if a == "INVENTORY" else a for a in argv])
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    result.stdout.decode("utf-8")   # raises UnicodeDecodeError if it regressed
    result.stderr.decode("utf-8")


def test_unmatched_assets_are_reported_not_silently_absent(inventory):
    """"0 exposures" and "0 exposures, 1 asset we could not join" differ.

    The second is a naming or fingerprinting problem the operator can act on.
    Reporting only the first reads as a clean estate.
    """
    result = run("scan", str(inventory))
    out = result.stdout.decode("utf-8")
    assert "unknown-host.example.com" in out
    assert "corresponded to nothing" in out
