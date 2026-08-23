"""Vendored abuse feeds, and the ways a blocklist quietly lies.

Three failure modes get most of the attention here: a zero rendered as a
verdict, a stale snapshot rendered as current, and a neutral list summed into a
threat count.
"""
from __future__ import annotations

import json
from datetime import date

import pytest

from core import blocklists as bl

TODAY = date(2026, 8, 23)

CORPUS = {
    "_meta": {"built_on": "2026-08-23", "entries": 6},
    "feeds": {
        "feodo_c2": {
            "kind": "ipv4", "sense": "ABUSE", "fetched_on": "2026-08-23",
            # Fetched today; the publisher's own header says March.
            "publisher_updated": "2026-03-04",
            "entries": ["162.243.103.246", "178.62.3.223"],
        },
        "blocklist_de": {
            "kind": "ipv4", "sense": "ABUSE", "fetched_on": "2026-08-23",
            "entries": ["203.0.113.9"],
        },
        "spamhaus_drop": {
            "kind": "netblock", "sense": "ABUSE", "fetched_on": "2026-08-23",
            "entries": ["198.51.100.0/24"],
        },
        "urlhaus": {
            "kind": "url", "sense": "ABUSE", "fetched_on": "2026-08-23",
            "entries": ["http://bad.example.com/payload.exe",
                        "https://evil.example.org:8080/a/b?c=d"],
        },
        "tor_exit": {
            "kind": "ipv4", "sense": "NEUTRAL", "fetched_on": "2026-08-23",
            "entries": ["171.25.193.25"],
        },
    },
}


@pytest.fixture
def corpus():
    return bl.Blocklists(CORPUS)


# ── the absence problem ─────────────────────────────────────────────────────
def test_no_hits_returns_an_empty_list(corpus):
    assert corpus.check_address("8.8.8.8") == []


def test_absence_is_described_rather_than_left_as_a_zero(corpus):
    """A zero on a screen reads as a verdict. This one is not one."""
    text = corpus.coverage(TODAY)["absence_means"]
    assert "absence is not evidence of safety" in text
    assert "tiny" in text


def test_the_absence_note_carries_the_corpus_size():
    """'Checked and found nothing' means something very different against 61,000
    entries than against the internet."""
    assert "61,660" in bl.describe_absence(61660)


def test_coverage_is_available_beside_any_result(corpus):
    cov = corpus.coverage(TODAY)
    assert cov["entries"] == 7
    assert {f["feed"] for f in cov["feeds"]} == set(CORPUS["feeds"])


# ── staleness: the publisher's date beats the fetch date ────────────────────
def test_a_fetch_date_is_not_a_data_date(corpus):
    """Feodo Tracker served a list on 2026-08-23 whose own header said
    2026-03-04. Reporting the fetch alone presents it as same-day."""
    hit = corpus.check_address("162.243.103.246")[0]
    assert hit.days_old == 0, "fetched today"
    assert hit.effective_age_days > 150, "but the DATA is months old"
    assert hit.to_dict()["stale"] is True


def test_a_feed_with_no_publisher_date_falls_back_to_the_fetch(corpus):
    hit = corpus.check_address("203.0.113.9")[0]
    assert hit.publisher_updated == ""
    assert hit.effective_age_days == hit.days_old


def test_a_stale_feed_is_named_in_coverage(corpus):
    assert corpus.coverage(TODAY)["stale_feeds"] == ["feodo_c2"]


def test_an_unreadable_fetch_date_counts_as_ancient_not_fresh():
    """The one direction this must never fail in: a corrupt stamp promoted to
    'current' would make a broken snapshot look authoritative."""
    assert bl._age("not-a-date") == bl.UNDATED
    assert bl._age("") == bl.UNDATED
    assert bl._age(None) == bl.UNDATED


# ── neutral is not abuse ────────────────────────────────────────────────────
def test_a_tor_exit_is_neutral_not_abuse(corpus):
    """Running a relay is legal and often admirable. Scoring it as malicious
    would be a political claim this product has no basis for."""
    hits = corpus.check_address("171.25.193.25")
    assert len(hits) == 1
    assert hits[0].sense == "NEUTRAL"
    assert "NOT abuse" in hits[0].means


def test_the_tor_feed_is_declared_neutral_in_the_table():
    assert bl.BY_NAME["tor_exit"].sense == "NEUTRAL"
    assert all(f.sense == "ABUSE" for f in bl.FEEDS if f.name != "tor_exit")


def test_sense_is_carried_on_every_hit_so_it_cannot_be_summed_blindly(corpus):
    for address in ("162.243.103.246", "171.25.193.25"):
        for hit in corpus.check_address(address):
            assert hit.to_dict()["sense"] in {"ABUSE", "NEUTRAL"}


# ── matching ────────────────────────────────────────────────────────────────
def test_a_netblock_entry_matches_a_host_inside_it(corpus):
    """Spamhaus DROP lists ranges, not hosts. Matching only exact addresses
    would silently never fire."""
    hits = corpus.check_address("198.51.100.77")
    assert [h.feed for h in hits] == ["spamhaus_drop"]
    assert hits[0].matched == "198.51.100.0/24"


def test_a_host_outside_the_netblock_does_not_match(corpus):
    assert corpus.check_address("198.51.101.77") == []


def test_a_url_feed_is_matched_on_its_host(corpus):
    hits = corpus.check_host("bad.example.com")
    assert [h.feed for h in hits] == ["urlhaus"]


def test_url_hosts_are_matched_without_scheme_port_or_path(corpus):
    """The feed line is `https://evil.example.org:8080/a/b?c=d`."""
    assert corpus.check_host("evil.example.org")


def test_host_matching_is_case_and_dot_insensitive(corpus):
    assert corpus.check_host("BAD.Example.COM.")


def test_an_unrelated_host_does_not_match(corpus):
    assert corpus.check_host("example.com") == []


def test_a_malformed_address_returns_nothing_rather_than_raising(corpus):
    assert corpus.check_address("not-an-ip") == []
    assert corpus.check_address("") == []


def test_an_empty_hostname_returns_nothing(corpus):
    assert corpus.check_host("") == []


@pytest.mark.parametrize("line,expected", [
    ("http://bad.example.com/x", "bad.example.com"),
    ("https://evil.example.org:8080/a?b=c", "evil.example.org"),
    ("bad.example.com/x", "bad.example.com"),
    ("http://user:pw@bad.example.com/x", "bad.example.com"),
    ("http://[2606:4700::1]:443/x", "2606:4700::1"),
    ("", ""),
])
def test_host_extraction(line, expected):
    assert bl._host_of(line) == expected


# ── the corpus reporting on itself ──────────────────────────────────────────
def test_a_missing_corpus_is_an_error_not_an_empty_result(tmp_path):
    """The distinction that stops 'we never built the corpus' from rendering as
    'we checked and found nothing'."""
    with pytest.raises(bl.CorpusUnavailable) as caught:
        bl.Blocklists.load(tmp_path / "nope.json")
    assert "--only-blocklists" in str(caught.value)


def test_a_corrupt_corpus_is_an_error_too(tmp_path):
    path = tmp_path / "blocklists.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(bl.CorpusUnavailable):
        bl.Blocklists.load(path)


def test_a_feed_this_build_does_not_know_is_skipped_not_fatal():
    payload = {"_meta": {}, "feeds": dict(
        CORPUS["feeds"], invented={"kind": "ipv4", "entries": ["1.2.3.4"]})}
    corpus = bl.Blocklists(payload)
    assert corpus.unknown_feeds() == ["invented"]
    assert corpus.check_address("1.2.3.4") == []


def test_a_feed_absent_from_the_corpus_is_reported(corpus):
    """Seven feeds are declared; this fixture carries five."""
    assert set(corpus.missing_feeds()) == {"cins_army", "openphish"}


def test_noncommercial_parts_are_named_so_they_can_be_dropped(corpus):
    """A commercial deployment should not have to read seven licence pages."""
    assert "openphish" in bl.NONCOMMERCIAL
    assert bl.BY_NAME["openphish"].licence.endswith("non-commercial")


# ── the dead feed ───────────────────────────────────────────────────────────
def test_the_deprecated_feed_is_recorded_rather_than_silently_dropped():
    """SSLBL still answers HTTP 200 with a deprecation notice, so a naive
    fetcher vendors an empty list and every lookup reads as clean. It is widely
    still recommended — including by the article that prompted this work."""
    assert "sslbl_c2" in bl.REJECTED
    assert "sslbl_c2" not in bl.BY_NAME
    assert "deprecated on 2025-01-03" in bl.REJECTED["sslbl_c2"]


# ── the vendored corpus actually in the repo ────────────────────────────────
def test_the_shipped_corpus_loads_and_covers_every_declared_feed():
    corpus = bl.Blocklists.load()
    coverage = corpus.coverage()
    assert coverage["entries"] > 10_000, "a corpus this small is a failed refresh"
    assert corpus.missing_feeds() == [], "every declared feed must be present"
    assert corpus.unknown_feeds() == []


def test_no_shipped_feed_is_empty():
    """An empty feed is how a dead publisher looks from the inside."""
    payload = json.loads(bl.DEFAULT_PATH.read_text(encoding="utf-8"))
    for name, block in payload["feeds"].items():
        assert block.get("entries"), f"{name} vendored with zero entries"
