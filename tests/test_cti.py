"""Ingested third-party intelligence: decay, provenance, and the overclaims.

Every test here passes an explicit `today`. `tests/test_stix_coverage.py` once
shipped a test that passed on the day it was written and failed the next
morning, and a decay model is the single most time-sensitive thing in this
repository — a relative-date test here would be a time bomb by construction.
"""
from __future__ import annotations

import ast
import dataclasses
import inspect
import json
from datetime import date

import pytest

from collect import abusech, misp
from core import cti

TODAY = date(2026, 8, 24)


def indicator(**over):
    base = dict(value="bad.example.com", kind="domain", source="circl_osint",
                publisher="CIRCL", seen_on="2026-08-24", context="OSINT report",
                tags=(), tlp="WHITE", reporter="CIRCL")
    base.update(over)
    return cti.Indicator(**base)


def corpus(*items):
    return cti.CTICorpus({"_meta": {"built_on": "2026-08-24"},
                          "indicators": [dataclasses.asdict(i) for i in items]})


# ── decay: the centrepiece ──────────────────────────────────────────────────
def test_a_fresh_indicator_weighs_one():
    assert indicator(seen_on="2026-08-24").weight(TODAY) == 1.0


def test_an_address_halves_after_its_half_life():
    """30 days for ipv4. The number is a judgement; that it HALVES is the
    model, and the model is what a reader is entitled to reproduce."""
    thirty = indicator(kind="ipv4", seen_on="2026-07-25")
    assert thirty.age_days(TODAY) == 30
    assert thirty.weight(TODAY) == pytest.approx(0.5, abs=0.01)


def test_a_domain_outlives_an_address_at_the_same_age():
    """Addresses are leases, names are owned. Same date, different weight."""
    when = "2026-06-25"
    assert (indicator(kind="domain", seen_on=when).weight(TODAY)
            > indicator(kind="ipv4", seen_on=when).weight(TODAY))


@pytest.mark.parametrize("kind", ["md5", "sha1", "sha256"])
def test_hashes_do_not_decay_at_all(kind):
    """THE ZERO IS A DECISION, NOT A GAP. A file whose hash matched a malicious
    sample in 2014 is still that same file; discounting it would discard true
    information rather than stale information."""
    ancient = indicator(kind=kind, seen_on="2014-01-01")
    assert ancient.weight(TODAY) == 1.0
    assert ancient.decays() is False


def test_a_2016_address_falls_below_the_reporting_floor():
    """The measurement this module exists for: 68% of CIRCL's OSINT feed
    predates 2020. Ingested flat, that is a machine for confident nonsense."""
    assert indicator(kind="ipv4", seen_on="2016-05-01").weight(TODAY) < cti.REPORT_FLOOR


def test_an_undated_indicator_weighs_nothing_rather_than_everything():
    """The failure direction that matters. Treating a corrupt stamp as `today`
    silently promotes junk to fresh intelligence."""
    assert indicator(seen_on="not-a-date").weight(TODAY) == 0.0
    assert indicator(seen_on="").weight(TODAY) == 0.0


def test_a_future_date_is_not_fresher_than_today():
    """Feeds publish these, usually from a timezone error. Rewarding one would
    let a broken publisher outrank a correct one."""
    assert indicator(seen_on="2027-01-01").age_days(TODAY) == 0


def test_an_unknown_kind_decays_on_the_shortest_curve():
    """Guessing generously about something unclassifiable is how a corpus
    fills with indicators nobody can defend."""
    fast = cti.weight("ipv4", 60)
    assert cti.weight("something-new", 60) == pytest.approx(fast)


# ── TLP: the one field with a redistribution consequence ────────────────────
@pytest.mark.parametrize("mark,ok", [
    ("WHITE", True), ("CLEAR", True), ("GREEN", True),
    ("AMBER", False), ("AMBER_STRICT", False), ("RED", False),
    ("TLP:GREEN", True), ("tlp:amber", False),
])
def test_exportability_follows_the_marking(mark, ok):
    assert cti.exportable(mark) is ok


def test_an_unrecognised_marking_is_treated_as_restricted():
    """A feed inventing a marking is far likelier to be tightening than
    loosening, and the failure direction matters more than the convenience."""
    assert cti.exportable("TLP:PURPLE") is False
    assert cti.exportable("") is False


# ── correlation must not overclaim ──────────────────────────────────────────
def test_correlation_is_exact_and_never_matches_a_parent_domain():
    """A suffix match would turn one listed subdomain into a sighting against
    the whole registrable domain — the class of overclaim this product exists
    to avoid."""
    store = corpus(indicator(value="evil.example.com"))
    assert store.correlate(["example.com"], TODAY) == []
    assert len(store.correlate(["evil.example.com"], TODAY)) == 1


def test_correlation_is_case_insensitive():
    store = corpus(indicator(value="Bad.Example.COM"))
    assert len(store.correlate(["bad.example.com"], TODAY)) == 1


def test_a_decayed_indicator_does_not_produce_a_sighting():
    store = corpus(indicator(kind="ipv4", value="1.2.3.4", seen_on="2016-01-01"))
    assert store.correlate(["1.2.3.4"], TODAY) == []


def test_sightings_lead_with_the_freshest_claim():
    store = corpus(indicator(value="a.example", seen_on="2026-01-01"),
                   indicator(value="a.example", source="threatfox",
                             publisher="abuse.ch", seen_on="2026-08-20"))
    got = store.correlate(["a.example"], TODAY)
    assert [s.indicator.source for s in got] == ["threatfox", "circl_osint"]


# ── the refusals ────────────────────────────────────────────────────────────
def test_a_sighting_carries_all_four_disclaimers():
    store = corpus(indicator(value="a.example"))
    payload = store.correlate(["a.example"], TODAY)[0].to_dict(TODAY)
    assert len(payload["not"]) == 4
    joined = " ".join(payload["not"])
    assert "NOT a statement that the asset is compromised" in joined
    assert "NOT a judgement by SKOPOS" in joined


def test_absence_is_never_described_as_clean():
    """A scanner reporting absence as safety teaches its readers to treat
    silence as evidence."""
    text = cti.describe_absence(1000, 3)
    assert "not a clean bill of health" in text.lower()
    assert "clean" not in text.replace("clean bill of health", "")


def test_the_module_holds_no_opinion_field():
    """Parsed, not grepped. There is no field for SKOPOS's own view of an
    indicator, and adding one would be the mistake this module is built to
    avoid — every value is somebody else's claim with their name on it."""
    fields = {f for f in cti.Indicator.__dataclass_fields__}
    for banned in ("score", "verdict", "malicious", "risk", "severity",
                   "skopos_confidence"):
        assert banned not in fields


def test_source_confidence_belongs_to_the_source():
    """ThreatFox's number is a fact ABOUT THE PUBLISHER, so it rides on the
    ingested record rather than becoming a SKOPOS score."""
    entries, _ = abusech.parse_threatfox(json.dumps(
        {"1": [{"ioc_value": "1.2.3.4", "ioc_type": "ip",
                "confidence_level": 100, "malware_printable": "Remcos",
                "first_seen_utc": "2026-08-20 01:00:00"}]}))
    assert entries[0]["source_confidence"] == 100
    assert "confidence" not in cti.Indicator.__dataclass_fields__


# ── coverage tells the truth about its own size ─────────────────────────────
def test_coverage_reports_what_has_already_decayed():
    """A corpus of 60,000 of which 50,000 sit below the floor is a smaller
    corpus than its headline, and the operator should be told which they have."""
    store = corpus(indicator(value="live.example", seen_on="2026-08-20"),
                   indicator(value="old.example", kind="ipv4",
                             seen_on="2015-01-01"))
    report = store.coverage(TODAY)
    assert report["indicators"] == 2
    assert report["live"] == 1
    assert report["decayed_below_floor"] == 1


def test_coverage_publishes_the_half_lives_it_used():
    assert cti.CTICorpus({}).coverage(TODAY)["half_lives"]["sha256"] == 0


def test_excluded_sources_carry_the_measurement_that_excluded_them():
    """Recorded rather than silently omitted — the next person to read a blog
    post recommending OTX should find out here."""
    assert "403" in cti.EXCLUDED["alienvault_otx"]
    assert "401" in cti.EXCLUDED["censys"]


def test_a_missing_corpus_raises_rather_than_scoring_zero():
    with pytest.raises(cti.CTIUnavailable):
        cti.CTICorpus.load(cti.ROOT / "data" / "does-not-exist.json")


# ── MISP parsing ────────────────────────────────────────────────────────────
EVENT = {"Event": {
    "uuid": "e1", "info": "OSINT - Some campaign", "date": "2026-08-13",
    "Orgc": {"name": "CIRCL"},
    "Tag": [{"name": "tlp:clear"},
            {"name": 'misp:automation-level="unsupervised"'}],
    "Attribute": [
        {"type": "domain", "value": "bad.example.com", "to_ids": True},
        {"type": "ip-dst", "value": "203.0.113.9", "to_ids": True},
        {"type": "url", "value": "https://api.github.com/repos/x",
         "to_ids": False},
        {"type": "domain", "value": "gone.example", "to_ids": True,
         "deleted": True},
        {"type": "mutex", "value": "Global\\x", "to_ids": True},
    ]}}


def test_to_ids_false_attributes_are_dropped():
    """THE FILTER. Measured across 42,096 real attributes: every one of the 601
    `to_ids: false` entries was a url, and they are reference links. Without
    this the corpus contains github.com."""
    found, report = misp.indicators_from_event(EVENT)
    assert report.not_to_ids == 1
    assert not any("github" in i["value"] for i in found)


def test_deleted_attributes_are_dropped():
    _, report = misp.indicators_from_event(EVENT)
    assert report.deleted == 1


def test_unmapped_types_are_counted_rather_than_guessed():
    """MISP defines 100+ types; a mutex says nothing about an externally
    observable estate. Counted so the drop is visible."""
    _, report = misp.indicators_from_event(EVENT)
    assert report.unmapped_type == 1
    assert report.unmapped_types_seen == {"mutex": 1}


def test_event_provenance_rides_on_every_indicator():
    found, _ = misp.indicators_from_event(EVENT)
    assert found[0]["reporter"] == "CIRCL"
    assert found[0]["context"] == "OSINT - Some campaign"
    assert found[0]["tlp"] == "CLEAR"
    assert found[0]["automation_level"] == "unsupervised"


def test_an_ip_attribute_resolves_to_its_family():
    """MISP uses one type for both families, and which it is decides the
    half-life."""
    found, _ = misp.indicators_from_event(EVENT)
    kinds = {i["value"]: i["kind"] for i in found}
    assert kinds["203.0.113.9"] == "ipv4"


@pytest.mark.parametrize("misp_type,raw,expected", [
    ("domain|ip", "bad.example|1.2.3.4", "bad.example"),
    ("filename|sha256", "x.exe|" + "a" * 64, "a" * 64),
    ("ip-dst|port", "1.2.3.4|443", "1.2.3.4"),
    ("domain", "plain.example", "plain.example"),
])
def test_composite_values_take_the_correct_half(misp_type, raw, expected):
    """Taking the wrong half yields an indicator that silently never matches."""
    assert misp._value_of(misp_type, raw) == expected


def test_the_horizon_drops_events_that_would_decay_on_load():
    """Measured: only 311 of 1,680 CIRCL events fall inside it. Fetching the
    rest costs 81% of the transfer to produce indicators dropped on load."""
    refs = [misp.EventRef("a", "2026-08-01", "recent"),
            misp.EventRef("b", "2016-01-01", "ancient")]
    kept = misp.within_horizon(refs, today=TODAY)
    assert [r.uuid for r in kept] == ["a"]


def test_an_undated_event_is_kept_rather_than_dropped():
    """A missing date is not evidence of age. Dropping it would silently
    discard a curated report because its publisher omitted a field."""
    kept = misp.within_horizon([misp.EventRef("a", "", "no date")], today=TODAY)
    assert len(kept) == 1


def test_a_malformed_feed_raises_rather_than_returning_nothing():
    """An empty result and an unparseable document look identical to a caller,
    and one of them means the corpus should keep its previous contents."""
    with pytest.raises(misp.FeedMalformed):
        misp.parse_manifest(b"<html>not json</html>")
    with pytest.raises(misp.FeedMalformed):
        misp.indicators_from_event(b"nonsense")


# ── abuse.ch parsing ────────────────────────────────────────────────────────
def test_threatfox_strips_the_port():
    """Stored verbatim, `1.2.3.4:50810` never matches anything: no estate
    inventory records an address with a port glued to it."""
    found, _ = abusech.parse_threatfox(json.dumps(
        {"1": [{"ioc_value": "185.157.163.138:50810", "ioc_type": "ip:port",
                "confidence_level": 100, "first_seen_utc": "2026-08-24 01:00:00"}]}))
    assert found[0]["value"] == "185.157.163.138"
    assert found[0]["kind"] == "ipv4"


def test_threatfox_handles_a_bracketed_ipv6_port():
    """Splitting on the last colon without handling brackets truncates the
    address itself."""
    assert abusech._split_port("[2001:db8::1]:443") == "2001:db8::1"


def test_threatfox_drops_low_confidence_entries():
    _, report = abusech.parse_threatfox(json.dumps(
        {"1": [{"ioc_value": "1.2.3.4", "ioc_type": "ip",
                "confidence_level": 10, "first_seen_utc": "2026-08-24 01:00:00"}]}))
    assert report.below_confidence == 1
    assert report.kept == 0


def test_malwarebazaar_reads_the_publishers_own_date():
    """A fetch date is not a data date — the distinction core/blocklists.py
    learned from Feodo Tracker."""
    raw = ("# Last updated: 2026-08-24 01:27:15 UTC\n#\n" + "a" * 64 + "\n")
    found, _ = abusech.parse_malwarebazaar(raw)
    assert found[0]["seen_on"] == "2026-08-24"


def test_malwarebazaar_rejects_a_header_only_response():
    """A fetch that returned only a header is a failed fetch, and the corpus
    should keep its previous contents rather than empty itself."""
    with pytest.raises(abusech.FeedMalformed):
        abusech.parse_malwarebazaar("# Last updated: 2026-08-24\n#\n")


# ── the parsers must stay parsers ───────────────────────────────────────────
@pytest.mark.parametrize("module", [misp, abusech])
def test_the_parsers_perform_no_network_io(module):
    """Parsed, not grepped — these modules NAME urls in their docstrings and
    constants, so a substring check fires on the documentation.

    `collect/shadowserver.py` set this shape: fetching lives in
    tools/refresh_intel.py so a refresh failure is a refresh failure rather
    than a scan failure, and the parser stays testable against a fixture.
    """
    tree = ast.parse(inspect.getsource(module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    for banned in ("urllib", "http", "socket", "requests", "httpx",
                   "subprocess", "ssl"):
        assert banned not in imported, f"{module.__name__} imports {banned}"
