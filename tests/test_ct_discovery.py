"""Passive CT discovery.

NO LIVE NETWORK (SRS §15). Every source is injected, so these run offline and
deterministically. The shapes are taken from real responses — CertSpotter's
`dns_names`/`not_before` and crt.sh's newline-joined `name_value` — captured
while building the collector.

The tests that matter are the ones about DEGRADATION. crt.sh returned HTTP 502
on the first two attempts against it, which is SRS R-01 materialising
immediately, and the whole design of this collector follows from it: a failing
source must contribute nothing, must not fail the run, and must be reported —
because a thin result from a degraded lookup is indistinguishable from a small
estate, and the second is a much more comfortable thing to believe.
"""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collect.ct import (DiscoveryResult, SourceReport, discover,   # noqa: E402
                        to_inventory_rows)


def source(name, rows, ok=True, detail=""):
    """A stand-in collector returning fixed rows."""
    def _source(_apex):
        return rows, SourceReport(name, ok, len({n for n, _ in rows}), detail)
    return _source


GOOD = source("certspotter", [
    ("iana.org", date(2025, 12, 6)),
    ("data.iana.org", date(2026, 5, 29)),
    ("*.iana.org", date(2025, 12, 6)),
])
DOWN = source("crt.sh", [], ok=False, detail="HTTPError")


# ── merging ──────────────────────────────────────────────────────────────────

def test_names_merge_across_sources_with_provenance():
    other = source("crt.sh", [("data.iana.org", date(2026, 1, 1)),
                              ("ftp.iana.org", date(2026, 7, 6))])
    result = discover("iana.org", sources=[GOOD, other])
    by_name = {n.name: n for n in result.names}
    assert set(by_name) == {"iana.org", "data.iana.org", "*.iana.org", "ftp.iana.org"}
    # A name seen by both records both, so a reader can judge corroboration.
    assert by_name["data.iana.org"].sources == {"certspotter", "crt.sh"}


def test_the_earliest_observation_wins():
    """The question is when a name FIRST appeared, not when its certificate was
    last re-issued — and `first_seen` feeds the exposure-age term in §9.1."""
    later = source("crt.sh", [("data.iana.org", date(2026, 8, 1))])
    result = discover("iana.org", sources=[GOOD, later])
    entry = next(n for n in result.names if n.name == "data.iana.org")
    assert entry.first_seen == date(2026, 5, 29)


# ── degradation, which is the point ──────────────────────────────────────────

def test_a_failing_source_does_not_fail_the_run():
    result = discover("iana.org", sources=[GOOD, DOWN])
    assert [n.name for n in result.names] == ["*.iana.org", "data.iana.org", "iana.org"]


def test_a_failing_source_is_reported_not_swallowed():
    result = discover("iana.org", sources=[GOOD, DOWN])
    assert result.degraded is True
    assert any(s.name == "crt.sh" and not s.ok for s in result.sources)


def test_the_coverage_note_says_the_estate_may_be_larger():
    """The sentence that stops a degraded result being read as a clean one."""
    note = discover("iana.org", sources=[GOOD, DOWN]).coverage_note()
    assert "source(s) failed" in note
    assert "may be larger than shown" in note


def test_a_healthy_run_is_not_marked_degraded():
    result = discover("iana.org", sources=[GOOD])
    assert result.degraded is False
    assert "failed" not in result.coverage_note()


def test_every_source_is_queried_even_after_one_fails():
    """Ordering must not decide coverage: a source listed after a broken one
    still runs."""
    result = discover("iana.org", sources=[DOWN, GOOD])
    assert len(result.names) == 3
    assert len(result.sources) == 2


# ── scoping: somebody else's estate is not yours ─────────────────────────────

def test_names_outside_the_apex_are_discarded():
    """Shared-hosting and CDN certificates routinely name dozens of unrelated
    domains. Importing those would attribute another organisation's estate to
    this tenant — wrong, and a governance problem as well."""
    from collect.ct import _clean
    assert _clean("app.iana.org", "iana.org") == "app.iana.org"
    assert _clean("iana.org", "iana.org") == "iana.org"
    assert _clean("*.iana.org", "iana.org") == "*.iana.org"
    assert _clean("evil.com", "iana.org") is None
    # A suffix that merely ENDS with the apex is a different domain.
    assert _clean("notiana.org", "iana.org") is None
    assert _clean("iana.org.attacker.net", "iana.org") is None


# ── handing off to the scan ──────────────────────────────────────────────────

def test_wildcards_never_become_assets():
    """`*.example.com` proves a certificate exists, never that a host does.
    Turning one into an asset would invent infrastructure."""
    rows = to_inventory_rows(discover("iana.org", sources=[GOOD]))
    assert [r["hostname"] for r in rows] == ["data.iana.org", "iana.org"]


def test_discovery_does_not_guess_a_technology():
    """CT finds NAMES. Leaving product unknown means the vulnerability join will
    not match until fingerprinting fills it in, which is the honest state rather
    than a gap papered over with a guess."""
    rows = to_inventory_rows(discover("iana.org", sources=[GOOD]))
    assert {r["product"] for r in rows} == {"unknown"}


def test_rows_carry_their_provenance():
    rows = to_inventory_rows(discover("iana.org", sources=[GOOD]))
    assert all(r["source"].startswith("ct:") for r in rows)
    assert rows[0]["first_seen"] == "2026-05-29"


def test_an_empty_apex_is_refused():
    with pytest.raises(ValueError):
        discover("   ")
