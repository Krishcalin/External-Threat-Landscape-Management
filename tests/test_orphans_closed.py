"""The reachability audit, as a test rather than a thing somebody remembers.

P5's W1 found four modules that no user could reach. `docs/P5-SCOPE.md` records
that the pattern "recurred twice more". It then recurred twice again in P8 —
`blocklists` and `leaksites` were built, vendored, tested, and queried by
nothing but the refresher that created them.

Tests passing is not shipped. This file is the check that was being done by
hand, and by memory, and therefore not at all.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

#: Modules that must be reachable from the product, not merely from their tests
#: and the tool that builds their input.
#:
#: `tools/` is EXCLUDED from what counts as reachable, deliberately. A corpus
#: that only the refresher imports is a corpus being built and never read —
#: which is exactly the state `blocklists.py` and `leaksites.py` shipped in.
MUST_BE_REACHABLE = (
    "core/rules.py", "core/refusals.py", "core/blocklists.py",
    "core/candidates.py", "core/certificates.py",
    "collect/internetdb.py", "collect/leaksites.py",
)

#: Reachable from nothing, for a stated reason. An entry here is a DECISION.
KNOWN_UNREACHED = {
    "collect/shadowserver.py": (
        "a parser with no producer until an organisation completes a "
        "Shadowserver subscription — a human act with no API. It cannot be "
        "wired to anything until reports exist to parse."),
}

SEARCH_ROOTS = ("core", "api", "collect")


def _importers(module_path: str) -> list:
    """Files that import this module, excluding itself, tests and tools."""
    stem = pathlib.Path(module_path).stem
    package = pathlib.Path(module_path).parent.name
    patterns = (
        re.compile(rf"from {package} import[^\n]*\b{stem}\b"),
        re.compile(rf"\b{package}\.{stem}\b"),
        re.compile(rf"^\s*import {package}\.{stem}\b", re.M),
    )
    found = []
    for root in SEARCH_ROOTS:
        for path in (ROOT / root).rglob("*.py"):
            if path.relative_to(ROOT).as_posix() == module_path:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if any(p.search(text) for p in patterns):
                found.append(path.relative_to(ROOT).as_posix())
    main = ROOT / "main.py"
    text = main.read_text(encoding="utf-8", errors="replace")
    if any(p.search(text) for p in patterns):
        found.append("main.py")
    return sorted(found)


@pytest.mark.parametrize("module", MUST_BE_REACHABLE)
def test_the_module_is_reachable_from_the_product(module):
    """A module imported only by its own tests is not shipped, however green
    the tests are."""
    importers = _importers(module)
    assert importers, (
        f"{module} is an ORPHAN: nothing in core/, api/, collect/ or main.py "
        f"imports it. Tests passing is not shipped — see docs/P5-SCOPE.md.")


@pytest.mark.parametrize("module", MUST_BE_REACHABLE)
def test_the_module_exists(module):
    assert (ROOT / module).exists(), module


def test_every_unreached_module_has_a_stated_reason():
    """The list of exceptions is a list of decisions, and each one has to say
    why. An empty reason turns this file into a way of silencing itself."""
    for module, reason in KNOWN_UNREACHED.items():
        assert (ROOT / module).exists(), module
        assert len(reason) > 60, module


def test_the_exception_list_has_not_quietly_grown():
    """A guard on the guard. Adding a module here is how somebody makes this
    file stop failing without making the problem stop existing."""
    assert len(KNOWN_UNREACHED) <= 1, (
        "more modules are exempt from the reachability check than when it was "
        "written. Each addition needs to be a deliberate decision, not a way "
        "of getting the suite green.")


# ── the specific closures, asserted where they actually happen ──────────────
def test_the_abuse_corpus_is_read_by_the_lookup_route():
    """Not merely imported somewhere — reached from the route a user hits."""
    from api import app
    import inspect
    source = inspect.getsource(app._attach_abuse)
    assert "Blocklists.load" in source
    assert "check_address" in source and "check_host" in source


def test_a_missing_abuse_corpus_reports_unavailable_rather_than_empty():
    """'We never built the index' and 'nothing matched' are different
    sentences, and only one of them is reassuring."""
    import inspect
    from api import app
    source = inspect.getsource(app._attach_abuse)
    assert "unavailable.append" in source
    assert "NOT a statement that the target is absent" in source


def test_the_leak_corpus_is_read_by_the_lookup_route():
    from api import app
    import inspect
    source = inspect.getsource(app._attach_leak_listings)
    assert "LeakSites.load" in source
    assert "unavailable.append" in source


def test_certificates_are_produced_by_the_ct_collector():
    """core/certificates.py was pure logic with no caller: ct.py still
    discarded issuer and validity."""
    from collect import ct
    assert hasattr(ct, "certificates_from_certspotter")
    import inspect
    source = inspect.getsource(ct.certificates_from_certspotter)
    assert "from core.certificates import Certificate" in source


def test_candidates_are_produced_from_discovery():
    """Nothing wrote a candidate row, so the queue was permanently empty."""
    from core import candidates
    assert hasattr(candidates, "from_discovery")
    main = (ROOT / "main.py").read_text(encoding="utf-8")
    assert "from_discovery" in main, "the discover CLI must produce candidates"


def test_the_reputation_factor_is_actually_populated():
    """P7 declared `Factor.REPUTATION` as 'what third-party scanners and abuse
    feeds say' and left the socket empty."""
    import inspect
    from core import lookup
    source = inspect.getsource(lookup.Lookup.score)
    assert "Factor.REPUTATION.value" in source
    assert "abuse_coverage" in source


def test_reputation_is_not_scored_when_the_corpus_was_never_consulted():
    """Scoring 0.0 on an absent corpus turns 'we never looked' into 'nothing
    was found' — the translation this whole codebase exists to prevent."""
    from core.lookup import Lookup, parse
    found = Lookup(target=parse("example.com"))
    assert found.score().factors.get("reputation") is None


def test_a_neutral_listing_does_not_damage_reputation():
    """Running a Tor exit relay is legal and often admirable."""
    from core.lookup import Lookup, parse
    found = Lookup(target=parse("example.com"))
    found.abuse = [{"sense": "NEUTRAL", "feed": "tor_exit",
                    "publisher": "The Tor Project", "data_age_days": 0,
                    "means": "a Tor exit relay"}]
    found.abuse_coverage = {"absence_means": "nothing adverse matched"}
    assert found.score().factors.get("reputation") == 1.0
