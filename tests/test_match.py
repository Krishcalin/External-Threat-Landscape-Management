"""The matcher, and the two real bugs the first version had.

Both were found by running against the actual CISA catalogue rather than a
fixture, and both are pinned here because they are the two ways this kind of join
fails — one in each direction, and the second is the dangerous one.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import intel, match                                   # noqa: E402
from core.models import Asset, Confidence, MatchBasis           # noqa: E402


@pytest.fixture(scope="module")
def catalogue():
    try:
        return intel.load().entries()
    except intel.IntelUnavailable:
        pytest.skip("no vendored catalogue; run tools/refresh_intel.py")


def products_matched(asset, catalogue):
    return sorted({e.exploited.product for e in match.match_asset(asset, catalogue)})


# ── the false positive ───────────────────────────────────────────────────────

def test_a_more_specific_asset_does_not_match_a_less_specific_entry(catalogue):
    """`Apache Tomcat` must not match catalogue entries whose product is bare
    `Apache`, which are httpd vulnerabilities.

    The first rule matched whichever token set was shorter, so {apache} was
    contained in {apache, tomcat} and an httpd bug was reported against a Tomcat
    host. The extra token IS the identity, and discarding it is what made the
    match wrong."""
    hits = products_matched(Asset("t", product="Apache Tomcat", vendor="Apache"),
                            catalogue)
    assert hits, "Tomcat should match its own entries"
    assert all("tomcat" in p.lower() for p in hits), hits


# ── the false negative, which is the worse one ───────────────────────────────

def test_an_identity_split_across_vendor_and_product_still_matches(catalogue):
    """`Ivanti Connect Secure` must match `Connect Secure and Policy Secure`.

    The catalogue puts `Ivanti` in vendorProject and `Connect Secure and Policy
    Secure` in product. Comparing the asset against the product ALONE finds
    neither set contained in the other — the asset has `ivanti`, the entry has
    `policy` — so the match was refused. Ivanti Connect Secure has dozens of
    entries and is among the most exploited products in the catalogue, so
    missing all of them silently is not a rounding error."""
    hits = products_matched(
        Asset("v", product="Ivanti Connect Secure", vendor="Ivanti"), catalogue)
    assert len(hits) >= 1
    assert any("connect secure" in p.lower() for p in hits), hits


def test_an_unrelated_product_matches_nothing(catalogue):
    """The rule has to refuse as well as accept, or it is not a rule."""
    assert not match.match_asset(
        Asset("x", product="Acme Widget Manager", vendor="Acme Corp"), catalogue)


# ── what the matcher refuses to claim ────────────────────────────────────────

def test_no_exposure_claims_a_version_verdict(catalogue):
    """Every exposure is a worklist entry, because the catalogue carries no
    affected-version data. If this ever fails, either the corpus gained version
    ranges — in which case the claim is now earned — or something started
    asserting one it cannot support."""
    exposures = match.match(
        [Asset("w", product="Apache HTTP Server", vendor="Apache", version="2.4.54")],
        catalogue)
    assert exposures
    assert all(e.basis is MatchBasis.PRODUCT_MATCH for e in exposures)
    assert all(e.needs_verification for e in exposures)


def test_a_declared_cve_outranks_name_matching(catalogue):
    """An inventory that already names a CVE has said something this module
    cannot improve on by guessing at product names."""
    asset = Asset("a", product="Something Unrecognisable",
                  attributes={"notes": "affected by CVE-2021-44228"})
    exposures = match.match_asset(asset, catalogue)
    assert [e.exploited.cve for e in exposures] == ["CVE-2021-44228"]
    assert exposures[0].confidence is Confidence.STRONG
    assert "inventory names" in exposures[0].evidence[0]


# ── ordering, and the boundary ───────────────────────────────────────────────

def test_ransomware_entries_sort_first(catalogue):
    """The one attribute that changes what a breach COSTS rather than how likely
    it is."""
    exposures = match.match(
        [Asset("m", product="Zimbra", vendor="Synacor")], catalogue)
    flags = [e.exploited.known_ransomware for e in exposures]
    assert flags == sorted(flags, reverse=True), "ransomware entries not first"


def test_unmatched_assets_are_reported(catalogue):
    """A fail-closed matcher is only defensible if the misses are visible: an
    inventory where nothing matched is far likelier to be a naming problem than
    a secure estate."""
    assets = [Asset("known", product="Apache HTTP Server", vendor="Apache"),
              Asset("unknown", product="Acme Widget Manager")]
    exposures = match.match(assets, catalogue)
    missed = match.unmatched_assets(assets, exposures)
    assert [a.identifier for a in missed] == ["unknown"]


def test_stopwords_do_not_carry_identity():
    """Without stripping them, every product containing `Server` matches every
    other one."""
    assert match.tokens("Enterprise Server Suite") == set()
    assert match.tokens("Zimbra Collaboration Suite (ZCS)") == {"zimbra",
                                                               "collaboration",
                                                               "zcs"}
