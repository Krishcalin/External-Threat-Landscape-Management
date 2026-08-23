"""Brand imitation from certificate transparency.

Two failures would make this feature worse than not having it: reporting a
legitimate reseller as an impersonator, and reporting "nothing found" when the
source was down. The second is the dangerous one, because zero is exactly what a
customer hopes to see and they will believe it.
"""
from __future__ import annotations

from datetime import date

import pytest

from core import lookalike
from core.lookalike import Brand, BrandError, Signal

TODAY = date(2026, 8, 23)
RECENT = date(2026, 8, 1)
OLD = date(2020, 1, 1)


def brand(terms=("hdfcbank",), owned=("hdfcbank.com",)):
    return Brand(terms=terms, owned=owned, declared_by="ciso@example.com")


# ── the declaration ─────────────────────────────────────────────────────────
def test_a_brand_is_declared_never_inferred():
    """Guessing which words are somebody's brand would put unrelated companies
    on a takedown list."""
    for banned in ("infer_brand", "detect_brand", "guess_terms"):
        assert not hasattr(lookalike, banned), banned


def test_a_short_term_is_refused():
    """A term under four characters matches a substantial fraction of every
    domain ever registered."""
    with pytest.raises(BrandError) as exc:
        Brand(terms=("abc",), declared_by="a@b.c")
    assert "unreadable" in str(exc.value)


def test_a_brand_must_be_attributed():
    """These results get used to file takedown requests."""
    with pytest.raises(BrandError) as exc:
        Brand(terms=("hdfcbank",), declared_by="")
    assert "takedown" in str(exc.value)


def test_owned_domains_are_never_reported_against_themselves():
    """Without `owned`, the first screen is a list of the customer's own
    websites."""
    for name in ("hdfcbank.com", "netbanking.hdfcbank.com", "*.hdfcbank.com"):
        assert lookalike.assess(name, brand(), RECENT, TODAY) is None, name


# ── signals ─────────────────────────────────────────────────────────────────
def test_a_name_that_merely_contains_the_letters_is_not_a_candidate():
    """'tata' matches 'potato-farm.com', and a screen full of those is a screen
    nobody opens twice."""
    b = Brand(terms=("tata",), owned=("tata.com",), declared_by="a@b.c")
    assert lookalike.assess("potato-farm.com", b, OLD, TODAY) is None


@pytest.mark.parametrize("name,expected", [
    ("hdfcbank-secure-login.xyz", Signal.HARVEST_WORD),
    ("hdfcbank.online", Signal.CHEAP_TLD),
    ("hdfcbank.com.verify.top", Signal.BRAND_AS_SUBDOMAIN),
    ("xn--hdfcbank-x1a.com", Signal.PUNYCODE),
])
def test_each_signal_fires_on_its_own_shape(name, expected):
    found = lookalike.assess(name, brand(), RECENT, TODAY)
    assert found is not None and expected in found.signals


def test_a_typo_registration_is_caught_by_edit_distance():
    found = lookalike.assess("hdfobank.com", brand(), RECENT, TODAY)
    assert found is not None and Signal.EDIT_DISTANCE in found.signals


def test_a_homoglyph_substitution_is_caught():
    b = Brand(terms=("paypal",), owned=("paypal.com",), declared_by="a@b.c")
    found = lookalike.assess("paypa1-secure.xyz", b, RECENT, TODAY)
    assert found is not None
    assert Signal.HOMOGLYPH in found.signals or Signal.EXACT_TERM in found.signals


def test_a_cctld_variant_does_not_gain_a_subdomain_signal():
    """Without a suffix list, hdfcbank.co.uk read as the brand being a subdomain
    of somebody else's `co.uk` and gained a signal it had not earned —
    inflating a legitimate variant toward the reporting threshold."""
    found = lookalike.assess("hdfcbank.co.uk", brand(), RECENT, TODAY)
    assert found is not None
    assert Signal.BRAND_AS_SUBDOMAIN not in found.signals


def test_a_genuine_subdomain_of_somebody_else_still_fires():
    found = lookalike.assess("login.hdfcbank.evil.xyz", brand(), RECENT, TODAY)
    assert found is not None and Signal.BRAND_AS_SUBDOMAIN in found.signals


def test_recency_is_a_signal_and_age_is_not():
    fresh = lookalike.assess("hdfcbank.online", brand(), RECENT, TODAY)
    stale = lookalike.assess("hdfcbank.online", brand(), OLD, TODAY)
    assert Signal.RECENT in fresh.signals
    assert Signal.RECENT not in stale.signals


def test_a_single_signal_is_not_enough():
    """Convergence, not any one indicator — the same shape as the Crosshair."""
    assert lookalike.MIN_SIGNALS >= 2
    b = Brand(terms=("hdfcbank",), owned=("hdfcbank.com",), declared_by="a@b.c")
    # Exact term only: no harvest word, ordinary TLD, not recent.
    assert lookalike.assess("hdfcbankgroup.net", b, OLD, TODAY) is None


def test_every_signal_explains_itself():
    for signal in Signal:
        assert signal.means and len(signal.means) > 20


# ── it never renders a verdict ──────────────────────────────────────────────
def test_every_candidate_row_carries_the_disclaimer():
    """A row is what gets copied into a takedown request."""
    found = lookalike.assess("hdfcbank-login.xyz", brand(), RECENT, TODAY)
    payload = found.to_dict()
    assert "NOT established as phishing" in payload["not_a_verdict"]
    assert "partner, a reseller" in payload["not_a_verdict"]


def test_the_report_states_what_it_cannot_decide():
    report = lookalike.build(brand(), [], searched=True)
    text = report.to_dict()["never_a_verdict"]
    assert "does not establish impersonation" in text
    assert "worse than a missed phishing domain" in text


def test_there_is_no_verdict_field_anywhere():
    found = lookalike.assess("hdfcbank-login.xyz", brand(), RECENT, TODAY)
    for banned in ("verdict", "malicious", "phishing", "confirmed"):
        assert banned not in found.to_dict(), banned


# ── the failure that matters most ───────────────────────────────────────────
def test_an_outage_does_not_render_as_nothing_found():
    """Measured for real: crt.sh returned 502 on every request including its own
    homepage while this was being written. A brand screen reporting zero
    lookalikes during that outage is the worst failure available here, because
    zero is what the customer hopes to see."""
    report = lookalike.build(brand(), [], searched=False, unavailable=[
        {"source": "crt.sh", "why": "HTTP 502", "cost": "…"}])
    assert report.candidates == []
    assert "NO SOURCE COULD BE SEARCHED" in report.headline()
    assert "different answers" in report.headline()


def test_a_successful_search_finding_nothing_reads_differently():
    report = lookalike.build(brand(), [("unrelated.com", OLD)], searched=True)
    assert "none cleared" in report.headline()
    assert "NO SOURCE" not in report.headline()


def test_searched_survives_into_the_payload():
    payload = lookalike.build(brand(), [], searched=False).to_dict()
    assert payload["searched"] is False


def test_the_collector_reports_the_cost_of_the_missing_source():
    """The sentence that stops a reader taking silence for safety."""
    import inspect

    from collect import lookalike_scan
    source = inspect.getsource(lookalike_scan.observe)
    assert "ONLY way to find a name" in source
    assert "nothing was asked, not that nothing" in source


# ── the whole report ────────────────────────────────────────────────────────
def test_candidates_are_ranked_by_strength():
    names = [("hdfcbank.co.uk", RECENT),
             ("hdfcbank.com.verify-account.top", RECENT),
             ("hdfcbanklogin.click", RECENT)]
    report = lookalike.build(brand(), names, searched=True, today=TODAY)
    strengths = [c["strength"] for c in report.to_dict()["candidates"]]
    assert strengths == sorted(strengths, reverse=True)


def test_a_name_is_reported_once_however_many_terms_match():
    b = Brand(terms=("hdfcbank", "hdfc"), owned=("hdfcbank.com",),
              declared_by="a@b.c")
    report = lookalike.build(b, [("hdfcbank-login.xyz", RECENT)] * 3,
                             searched=True, today=TODAY)
    assert len(report.candidates) == 1


def test_the_examined_count_is_the_whole_input():
    """So a reader can tell a thin result from a thin search."""
    names = [(f"unrelated{i}.com", OLD) for i in range(50)]
    report = lookalike.build(brand(), names, searched=True, today=TODAY)
    assert report.examined == 50 and report.candidates == []


# ── secrets scanning is deferred, and says so ───────────────────────────────
def test_secrets_scanning_defers_rather_than_duplicating():
    """Two products disagreeing about whether a string is a live credential is
    worse than one product answering."""
    import inspect

    from api import app as api_app
    source = inspect.getsource(api_app.secrets_scanning)
    assert "Secrets Scanner" in source
    assert "second corpus here would drift" in source
