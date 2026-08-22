"""No module may reach the network except through the one that declares it.

WHY NOT A FILENAME ALLOWLIST
----------------------------
"collect/egress.py and collect/ct.py may do I/O" is the convention `core/gate.py`
exists to reject: a third-party collector author adds their own filename to it,
and the check that was supposed to constrain them becomes a formality.

Instead a module may perform I/O only if it carries
`# NETWORK-BOUNDARY: <operation>` markers, and every marker must name a real key
in `gate.OPERATIONS`. That makes the declaration self-describing and ties it to
the registry the gate actually consults — a module cannot claim a boundary for an
operation the product does not recognise.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Set

import pytest

from core import gate

ROOT = Path(__file__).resolve().parents[1]
SCANNED = ("collect", "core", "api")

MARKER = re.compile(r"#\s*NETWORK-BOUNDARY:\s*([a-z0-9_]+)")

#: Ways to reach the network. Deliberately broader than what is used today —
#: the point is to catch the NEXT one somebody reaches for.
IO_PATTERNS = [
    (re.compile(r"\bsocket\.socket\b"), "socket.socket"),
    (re.compile(r"\bsocket\.create_connection\b"), "socket.create_connection"),
    (re.compile(r"\bsocket\.getaddrinfo\b"), "socket.getaddrinfo"),
    (re.compile(r"\bssl\.wrap_socket\b"), "ssl.wrap_socket"),
    (re.compile(r"\bhttp\.client\b"), "http.client"),
    (re.compile(r"\burllib\.request\b"), "urllib.request"),
    (re.compile(r"\burlopen\b"), "urlopen"),
    (re.compile(r"\basyncio\.open_connection\b"), "asyncio.open_connection"),
    (re.compile(r"\bimport\s+(httpx|requests)\b"), "httpx/requests"),
    (re.compile(r"\b(ftplib|smtplib|telnetlib)\b"), "legacy protocol client"),
    (re.compile(r"subprocess\.[a-z_]+\([^)]*['\"](curl|wget|nc|nmap|dig|host)\b"),
     "subprocess shelling out to a network tool"),
]


def python_files() -> List[Path]:
    found: List[Path] = []
    for package in SCANNED:
        found.extend(sorted((ROOT / package).rglob("*.py")))
    found.append(ROOT / "main.py")
    return [f for f in found if f.is_file() and "__pycache__" not in f.parts]


def declared_operations(text: str) -> Set[str]:
    return set(MARKER.findall(text))


def strip_comments_and_docstrings(text: str) -> str:
    """Crude but sufficient: this test must not fire on prose that mentions I/O.

    A docstring saying "urllib.request" while the module performs no I/O is
    documentation, and a check that cannot tell the difference gets disabled.
    """
    import io
    import tokenize

    out = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        previous = tokenize.INDENT
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                continue
            if tok.type == tokenize.STRING and previous in (
                    tokenize.INDENT, tokenize.NEWLINE, tokenize.NL,
                    tokenize.DEDENT, tokenize.ENCODING):
                continue          # a docstring in statement position
            out.append(tok.string)
            if tok.type not in (tokenize.NL, tokenize.COMMENT):
                previous = tok.type
    except (tokenize.TokenError, IndentationError):   # pragma: no cover
        return text
    return "\n".join(out)


@pytest.mark.parametrize("path", python_files(), ids=lambda p: str(p.name))
def test_only_declared_boundary_modules_perform_io(path: Path):
    raw = path.read_text(encoding="utf-8")
    declared = declared_operations(raw)
    code = strip_comments_and_docstrings(raw)

    offences = [label for pattern, label in IO_PATTERNS if pattern.search(code)]
    if not offences:
        return

    relative = path.relative_to(ROOT).as_posix()
    assert declared, (
        f"{relative} performs network I/O ({', '.join(sorted(set(offences)))}) "
        f"but declares no '# NETWORK-BOUNDARY: <operation>' marker. Route it "
        f"through collect/egress.py, or declare the boundary here so the permit "
        f"check is not left to this module remembering.")


@pytest.mark.parametrize("path", python_files(), ids=lambda p: str(p.name))
def test_every_boundary_marker_names_a_registered_operation(path: Path):
    """A module cannot claim a boundary for an operation the gate does not know.

    Without this the marker becomes a comment that silences the check above, and
    the declaration means nothing.
    """
    declared = declared_operations(path.read_text(encoding="utf-8"))
    unknown = sorted(op for op in declared if op not in gate.OPERATIONS)
    assert not unknown, (
        f"{path.relative_to(ROOT).as_posix()} declares boundary marker(s) for "
        f"{unknown}, which are not in gate.OPERATIONS. classify() would refuse "
        f"them as PROHIBITED, so the marker describes work that cannot run.")


def test_egress_is_the_module_that_declares_the_boundary():
    """Pins the intent, so a future refactor that scatters I/O has to argue."""
    egress = (ROOT / "collect" / "egress.py").read_text(encoding="utf-8")
    declared = declared_operations(egress)
    assert "http_probe" in declared and "dns_resolve_recursive" in declared
    assert declared <= set(gate.OPERATIONS)


def test_the_scan_actually_covers_something():
    """A boundary test over an empty file list passes vacuously forever."""
    files = python_files()
    assert len(files) > 10, f"only {len(files)} files scanned"
    assert any(f.name == "egress.py" for f in files)
    assert any(f.name == "main.py" for f in files)
