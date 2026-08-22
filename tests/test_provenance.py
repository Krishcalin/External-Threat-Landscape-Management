"""A target must not be able to write into the top of the customer's worklist.

`declared_cves()` promotes a CVE named on an asset row to STRONG confidence with
the evidence line "the inventory names CVE-… on this asset". That is right for a
CMDB column and wrong for a string a collector copied out of somebody else's HTTP
response — and P1 multiplies that third-party text by roughly eight sources.
"""
from __future__ import annotations

import pytest

from core import intel, match, provenance
from core.models import Asset, Confidence
from core.provenance import ProvenanceViolation, observed, redact, tool_authored


@pytest.fixture(scope="module")
def catalogue():
    try:
        return intel.load().entries()
    except intel.IntelUnavailable as exc:      # pragma: no cover
        pytest.skip(str(exc))


# -- the measured attack -----------------------------------------------------
HOSTILE = "Server: EvilWAF blocks cve-2021-44228"


def test_target_controlled_text_no_longer_becomes_a_customer_assertion(catalogue):
    """The exact input that produced a STRONG finding before this existed."""
    asset = Asset(identifier="h.example.com", product="unknown",
                  attributes={observed("fp_evidence"): HOSTILE})
    assert match.declared_cves(asset) == set()
    assert match.match_asset(asset, catalogue) == []


def test_the_same_text_in_a_customer_column_is_still_believed(catalogue):
    """The feature must survive the fix.

    A customer writing a CVE in their own inventory column is making a statement
    this product should act on. Only provenance separates the two cases — the
    text is identical.
    """
    asset = Asset(identifier="h.example.com", product="unknown",
                  attributes={"known_vulns": "CVE-2021-44228"})
    assert match.declared_cves(asset) == {"CVE-2021-44228"}
    hits = match.match_asset(asset, catalogue)
    assert hits and hits[0].confidence is Confidence.STRONG


def test_lowercase_is_covered_because_the_pattern_is_shared():
    """A private copy of the regex is how the original miss happened."""
    assert match.CVE_PATTERN.search("cve-2021-44228")
    assert "cve-2021-44228" not in redact("blocks cve-2021-44228")
    assert "[cve-reference-from-third-party]" in redact("blocks cve-2021-44228")


def test_redaction_marks_rather_than_deletes():
    """The operator should still see that the target mentioned a CVE."""
    assert redact("x CVE-2021-44228 y").startswith("x ")
    assert redact("x CVE-2021-44228 y").endswith(" y")


# -- the provenance boundary itself ------------------------------------------
def test_tool_authored_keys_are_recognised():
    assert tool_authored("obs_server_header")
    assert tool_authored("OBS_Server_Header")
    assert not tool_authored("known_vulns")
    assert not tool_authored("cve")


def test_observed_is_idempotent():
    assert observed("banner") == "obs_banner"
    assert observed("obs_banner") == "obs_banner"


def test_an_unprefixed_collector_column_is_a_loud_error_not_a_quiet_redaction():
    """Quietly cleaning up after a buggy collector ships the bug."""
    with pytest.raises(ProvenanceViolation) as exc:
        provenance.check_row({"identifier": "h.example.com",
                              "fp_evidence": "saw cve-2021-44228"})
    assert "provenance.observed" in str(exc.value)


def test_a_cve_shaped_hostname_in_an_identity_column_is_refused():
    """`cve-2021-44228.example.com` is a name a SaaS tenant can register."""
    with pytest.raises(ProvenanceViolation):
        provenance.check_row({"identifier": "cve-2021-44228.example.com",
                              "product": "nginx"})


def test_correctly_prefixed_rows_pass():
    rows = provenance.write_rows([
        {"identifier": "h.example.com", "product": "nginx",
         observed("source"): "certspotter", observed("evidence"): "Server: nginx"},
    ])
    assert len(rows) == 1


def test_observation_builds_prefixed_and_redacted_payloads():
    payload = provenance.observation(evidence="blocks CVE-2021-44228",
                                     source="http_probe")
    assert set(payload) == {"obs_evidence", "obs_source"}
    assert "CVE-2021-44228" not in payload["obs_evidence"]
    provenance.check_row(payload)      # must not raise


# -- matcher hygiene ---------------------------------------------------------
@pytest.mark.parametrize("placeholder", ["unknown", "unidentified", "none", "null"])
def test_placeholders_cannot_join_anything(placeholder, catalogue):
    """Today `unknown` matches nothing by coincidence — it happens to appear in
    0 of 1,674 entries. One entry carrying the word would join every
    unfingerprinted host in the estate at once."""
    assert match.tokens(placeholder) == set()
    asset = Asset(identifier="h.example.com", product=placeholder)
    assert match.match_asset(asset, catalogue) == []


def test_unmatched_assets_counts_products_not_just_hosts(catalogue):
    """One host serving two products must not hide the miss on the second."""
    joined = Asset(identifier="h.example.com", product="Apache HTTP Server")
    missed = Asset(identifier="h.example.com", product="SomeThingNotInKev")
    exposures = match.match_asset(joined, catalogue)
    assert exposures, "fixture must actually join"

    unmatched = match.unmatched_assets([joined, missed], exposures)
    assert [a.product for a in unmatched] == ["SomeThingNotInKev"]


def test_asset_rejects_a_none_product():
    """str(None) is "None" — truthy, four characters, and it tokenises."""
    with pytest.raises(ValueError):
        Asset(identifier="h.example.com", product=None)
