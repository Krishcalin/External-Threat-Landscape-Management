"""Leak-site monitoring, and the line FR-GOV-003 draws through the middle of it.

Half of this file is about what the module must not do. The other half is about
name matching, because a product that tells somebody their supplier was breached
on the strength of a matching string will be believed, and should not be.
"""
from __future__ import annotations

import json
from datetime import date

import pytest

from collect import leaksites as ls

TODAY = date(2026, 8, 23)

CORPUS = {
    "_meta": {"built_on": "2026-08-23", "source": "ransomware.live"},
    "listings": [
        {"victim": "Northwind Traders Ltd", "group": "kazu",
         "published": "2026-08-21", "domain": "northwind.example",
         "claim": "500GB exfiltrated", "country": "GB"},
        {"victim": "Acme", "group": "lockbit", "published": "2026-05-01",
         "domain": "", "claim": "", "country": "US"},
        {"victim": "Delta", "group": "kazu", "published": "2026-08-01",
         "domain": "", "claim": "", "country": "US"},
    ],
}


@pytest.fixture
def corpus():
    return ls.LeakSites(CORPUS)


# ── the governance line ─────────────────────────────────────────────────────
def test_reading_an_index_is_permitted_and_the_rest_is_not():
    """The whole reason this module exists is that these three sit on
    different sides of FR-GOV-003."""
    from core import gate
    assert gate.OPERATIONS["leak_index_read"] is gate.Exposure.PASSIVE
    assert gate.OPERATIONS["forum_authenticate"] is gate.Exposure.PROHIBITED
    assert gate.OPERATIONS["leak_data_download"] is gate.Exposure.PROHIBITED


def test_the_module_carries_no_field_pointing_at_stolen_material():
    """Knowing a victim was listed is the finding. The archive is not — it is
    stolen, it routinely contains personal data belonging to people who are not
    this product's customers, and no question here requires possessing it.

    Asserted against the SHAPED OUTPUT rather than the source text, because a
    grep over source is defeated by a comment and proves nothing about
    behaviour. The aggregator offers all four of these; the shaper drops them.
    """
    shaped = ls.shape(json.dumps([{
        "victim": "X", "group": "g", "domain": "x.example",
        "screenshot": "https://leak.example/shot.png",
        "claim_url": "http://abc.onion/victim/x",
        "data_size": "500GB", "ransom": "1000000",
    }]))
    row = shaped["listings"][0]
    for forbidden in ("screenshot", "claim_url", "data_size", "ransom", "url"):
        assert forbidden not in row, forbidden


def test_no_onion_address_survives_into_the_corpus():
    """A public aggregator has already done the indexing. Nothing here should
    end up holding a hidden-service address, let alone contacting one."""
    from collect import egress
    assert not any(h.endswith(".onion") for h in egress.ALLOWED_HTTP_HOSTS)
    assert ".onion" not in ls.SOURCE_URL

    shaped = ls.shape(json.dumps([{
        "victim": "X", "group": "g", "domain": "x.example",
        "claim_url": "http://abcdefgh.onion/x",
    }]))
    assert ".onion" not in json.dumps(shaped)


def test_the_vendored_corpus_holds_no_onion_address():
    """The property that matters, checked against what actually shipped."""
    assert ".onion" not in ls.DEFAULT_PATH.read_text(encoding="utf-8")


def test_the_aggregator_is_allowlisted_and_the_operation_is_declared():
    from collect import egress
    assert "api.ransomware.live" in egress.ALLOWED_HTTP_HOSTS
    assert ls.OPERATION == "leak_index_read"
    import pathlib
    source = pathlib.Path(ls.__file__).read_text(encoding="utf-8")
    assert "# NETWORK-BOUNDARY: leak_index_read" in source


def test_only_one_function_touches_the_network():
    """Everything else reads the vendored corpus, so a lookup is a dictionary
    lookup rather than a fetch from criminal-adjacent infrastructure."""
    import inspect
    assert "http_get" in inspect.getsource(ls.fetch)
    for name in ("shape", "compare", "compare_domain", "normalise",
                 "describe_absence"):
        assert "http_get" not in inspect.getsource(getattr(ls, name))


# ── domain matching, which is the strong one ────────────────────────────────
def test_a_domain_match_outranks_every_name_match(corpus):
    """Domain compares like with like. Name matching compares a company name to
    a company name and hopes."""
    matches = corpus.check(["northwind.example"])
    assert matches[0].confidence == ls.DOMAIN


def test_a_subdomain_in_scope_matches_the_listed_domain(corpus):
    """A scope register holds hosts; the aggregator records the main domain.
    Requiring equality would miss most real matches."""
    assert corpus.check(["mail.northwind.example"])[0].confidence == ls.DOMAIN


@pytest.mark.parametrize("other", ["notnorthwind.example", "northwind.example.co",
                                   "example", ""])
def test_a_near_miss_domain_does_not_match(other):
    """`acme.com` must not match `notacme.com`. The boundary is a label, not a
    substring."""
    assert ls.compare_domain("northwind.example", other) is None


def test_a_listing_with_no_domain_falls_back_to_the_name(corpus):
    """94 of 100 real listings carried a domain when this was built. The other
    six still have to be checkable."""
    matches = corpus.check(["Acme Ltd"])
    assert matches and matches[0].confidence in {ls.EXACT, ls.STRONG}


# ── name matching, which is the weak one ────────────────────────────────────
def test_corporate_suffixes_are_stripped_before_comparing():
    """A group writes ACME where the register says Acme Holdings Ltd."""
    assert ls.normalise("Acme Holdings Ltd") == "acme"
    assert ls.normalise("Northwind Traders Limited") == "northwind traders"


def test_a_case_difference_alone_is_still_strong_not_exact():
    """EXACT is reserved for strings that are actually identical, so the word
    keeps meaning something."""
    assert ls.compare("ACME LIMITED", "Acme Ltd") == ls.STRONG
    assert ls.compare("Acme", "Acme") == ls.EXACT


def test_a_short_name_never_produces_a_substring_match():
    """'Delta' appears inside a great many real company names. Allowing a
    four-character substring would make every listing a partial match."""
    assert ls.compare("Foo", "Foobar Industries") is None
    assert ls.compare("Delta", "Delta Air Lines") == ls.PARTIAL


def test_every_confidence_level_explains_itself():
    for level in (ls.DOMAIN, ls.EXACT, ls.STRONG, ls.PARTIAL):
        assert len(ls.CONFIDENCE_MEANING[level]) > 60


def test_confidence_is_not_orderable_as_a_number():
    """An ordering invites a threshold, and a threshold invites somebody to
    alert on '>= partial'. These are meant to be read."""
    for level in (ls.DOMAIN, ls.EXACT, ls.STRONG, ls.PARTIAL):
        assert isinstance(level, str) and not level.isdigit()


# ── what a match says, and what it does not ─────────────────────────────────
def test_a_match_states_that_it_is_the_group_s_claim(corpus):
    """Groups exaggerate, recycle old data, and occasionally list victims they
    never reached."""
    payload = corpus.check(["northwind.example"])[0].to_dict()
    assert "CLAIM BY THAT GROUP" in payload["basis"]
    assert "not a confirmed breach" in payload["basis"].lower()
    assert "does not download" in payload["basis"]


def test_a_match_carries_its_age_and_recency(corpus):
    payload = corpus.check(["northwind.example"], TODAY)[0].to_dict()
    assert payload["days_old"] == 2
    assert payload["recent"] is True


def test_an_old_listing_is_reported_not_dropped(corpus):
    """'Listed 14 months ago' is still a fact about a supplier, and its absence
    from a report would be the worse error."""
    matches = corpus.check(["Acme Ltd"], TODAY)
    assert matches and matches[0].days_old > ls.RECENT_DAYS
    assert matches[0].to_dict()["recent"] is False


def test_matches_are_ordered_strongest_and_newest_first(corpus):
    matches = corpus.check(["northwind.example", "Acme Ltd", "Delta"], TODAY)
    assert matches[0].confidence == ls.DOMAIN


def test_the_group_s_own_words_are_carried_verbatim(corpus):
    """Never paraphrased into a finding — the distinction between what was
    claimed and what is true is the entire content of the record."""
    assert corpus.check(["northwind.example"])[0].to_dict()["claim"] == (
        "500GB exfiltrated")


# ── absence ─────────────────────────────────────────────────────────────────
def test_no_match_is_not_reassurance(corpus):
    assert corpus.check(["nothing.example"]) == []
    text = corpus.coverage(TODAY)["absence_means"]
    assert "normal state of a breached organisation" in text
    assert "never be shown as reassurance" in text


def test_absence_names_what_is_structurally_invisible(corpus):
    text = corpus.coverage(TODAY)["absence_means"]
    assert "paid before publication" in text
    assert "not ransomware" in text


def test_a_missing_corpus_is_an_error_not_an_empty_result(tmp_path):
    with pytest.raises(ls.CorpusUnavailable, match="--only-leaksites"):
        ls.LeakSites.load(tmp_path / "nope.json")


# ── shaping a real response ─────────────────────────────────────────────────
REAL = json.dumps([{
    "victim": "PappyJoe: Healthcare Management System",
    "group": "kazu", "domain": "pappyjoe.com", "country": "US",
    "attackdate": "2026-08-23T08:10:23.648355+00:00",
    "discovered": "2026-08-23T08:10:25.071995+00:00",
    "description": "x" * 900, "screenshot": "", "ransom": None,
}])


def test_the_real_field_names_are_the_ones_used():
    """Taken from an actual response. The live records carry `attackdate` and
    `discovered` and no `published` at all — a shaper written from the docs
    would have dated every listing to the empty string."""
    shaped = ls.shape(REAL)
    row = shaped["listings"][0]
    assert row["published"] == "2026-08-23"
    assert row["domain"] == "pappyjoe.com"
    assert row["group"] == "kazu"


def test_the_claim_is_truncated_hard():
    """These descriptions carry boasting and occasionally fragments of stolen
    data. A few hundred characters is enough to show what was claimed."""
    assert len(ls.shape(REAL)["listings"][0]["claim"]) <= 400


def test_a_row_with_no_victim_is_skipped():
    shaped = ls.shape(json.dumps([{"group": "x", "domain": "y.example"}]))
    assert shaped["listings"] == []


def test_an_unparseable_body_is_an_error_not_an_empty_corpus():
    with pytest.raises(ls.CorpusUnavailable):
        ls.shape("<html>")


def test_the_corpus_metadata_states_the_refusal():
    meta = ls.shape(REAL)["_meta"]
    assert "CLAIM BY THAT GROUP" in meta["note"]
    assert "never downloads" in meta["note"]


# ── the vendored corpus in the repo ─────────────────────────────────────────
def test_the_shipped_corpus_loads_and_carries_domains():
    corpus = ls.LeakSites.load()
    coverage = corpus.coverage()
    assert coverage["listings"] > 10
    assert coverage["groups"] > 1
    payload = json.loads(ls.DEFAULT_PATH.read_text(encoding="utf-8"))
    with_domain = sum(1 for l in payload["listings"] if l.get("domain"))
    # Measured at 94/100 when this was built. The domain-first design depends
    # on this staying high; if it collapses, the matching is back to names.
    assert with_domain / len(payload["listings"]) > 0.5
