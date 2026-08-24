"""The four things an operator can hand SKOPOS, and what each honestly buys.

The property most of these defend is that the four are NOT equivalent. A screen
presenting them as four interchangeable boxes would be lying by layout, so the
difference has to survive in the data the screen renders from.
"""
from __future__ import annotations

import json

import pytest

from core import lookup, seeds

K = seeds.SeedKind


# ── the four kinds ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,kind,expected", [
    ("www.somename.com", K.DOMAIN, "www.somename.com"),
    ("198.51.100.5", K.ADDRESS, "198.51.100.5"),
    ("203.0.113.0/24", K.ADDRESS, "203.0.113.0/24"),
    ("Acme Corporation", K.ORGANISATION, "Acme Corporation"),
])
def test_each_kind_parses_to_its_value(raw, kind, expected):
    assert seeds.parse_seed(raw, kind).value == expected


def test_only_a_domain_expands():
    """The single most consequential difference between the four. Certificate
    transparency turns one apex into hosts nobody remembered; nothing else
    here discovers an asset the operator did not type."""
    assert seeds.parse_seed("example.com", K.DOMAIN).expands is True
    for raw, kind in [("198.51.100.5", K.ADDRESS), ("Acme", K.ORGANISATION),
                      ("a@example.com", K.EMAIL)]:
        assert seeds.parse_seed(raw, kind).expands is False


# ── the mailbox is discarded, not hidden ────────────────────────────────────
def test_an_email_seed_keeps_only_the_domain():
    seed = seeds.parse_seed("jane.doe@somename.com", K.EMAIL)
    assert seed.value == "somename.com"


def test_the_mailbox_appears_nowhere_in_the_record():
    """Not redacted at render time — never stored. A pipeline carrying
    someone@example.com through to a report has created a document about a
    person, and the reliable way not to do that is to not hold the string."""
    seed = seeds.parse_seed("jane.doe@somename.com", K.EMAIL)
    blob = json.dumps(seed.to_dict()).lower()
    assert "jane" not in blob and "doe" not in blob


def test_an_email_seed_says_why_individuals_are_refused():
    caps = seeds.parse_seed("a@example.com", K.EMAIL).capabilities()
    assert "never for an individual address" in caps["limits"]
    assert "declared gap" in caps["limits"]


def test_an_email_seed_states_what_it_requires():
    """HIBP answers domain search only for a domain you have proven you
    control, and SKOPOS reuses its own ownership proof rather than inventing a
    second one. An operator should learn that before running, not after."""
    caps = seeds.parse_seed("a@example.com", K.EMAIL).capabilities()
    assert any("ownership verification" in r for r in caps["requires"])
    assert any("HIBP API key" in r for r in caps["requires"])


def test_a_malformed_email_is_refused():
    with pytest.raises(seeds.SeedRefused):
        seeds.parse_seed("not-an-address", K.EMAIL)


# ── an organisation name is a question, never scope ─────────────────────────
def test_an_organisation_produces_only_candidates():
    caps = seeds.parse_seed("Acme Corporation", K.ORGANISATION).capabilities()
    assert caps["produces"] == "candidates for the triage queue"
    assert "not a unique key" in caps["limits"]


def test_the_organisation_limit_says_nothing_enters_scope():
    """`core/candidates.py`: nothing in this product decides what it is
    allowed to scan."""
    assert "Nothing found this way enters scope" in seeds.WHY_ORG_IS_ONLY_A_QUESTION


@pytest.mark.parametrize("raw", ["a", "x" * 121])
def test_an_unusable_organisation_name_is_refused(raw):
    with pytest.raises(seeds.SeedRefused):
        seeds.parse_seed(raw, K.ORGANISATION)


# ── the wrong field is refused, not silently obeyed ─────────────────────────
def test_an_address_typed_into_the_domain_field_is_refused():
    """Putting one there would promise certificate expansion that cannot
    happen."""
    with pytest.raises(seeds.SeedRefused) as exc:
        seeds.parse_seed("198.51.100.5", K.DOMAIN)
    assert "is an address, not a name" in str(exc.value)


def test_a_name_typed_into_the_address_field_is_refused():
    with pytest.raises(seeds.SeedRefused) as exc:
        seeds.parse_seed("example.com", K.ADDRESS)
    assert "is a name, not an address" in str(exc.value)


# ── bulk input ──────────────────────────────────────────────────────────────
def test_one_bad_seed_does_not_discard_the_good_ones():
    """A screen that drops ten good seeds because the eleventh had a typo
    teaches the operator to paste less, and a smaller estate is the opposite
    of the point."""
    accepted, refused = seeds.parse_many([
        {"value": "example.com", "kind": "domain"},
        {"value": "!!! nonsense !!!", "kind": "address"},
        {"value": "198.51.100.5", "kind": "address"},
    ])
    assert [s.value for s in accepted] == ["example.com", "198.51.100.5"]
    assert len(refused) == 1 and refused[0]["input"] == "!!! nonsense !!!"


def test_duplicate_seeds_are_collapsed():
    accepted, _ = seeds.parse_many([
        {"value": "example.com", "kind": "domain"},
        {"value": "example.com", "kind": "domain"},
    ])
    assert len(accepted) == 1


def test_an_unknown_kind_is_refused_with_its_name():
    _, refused = seeds.parse_many([{"value": "x", "kind": "telepathy"}])
    assert "telepathy" in refused[0]["why"]


def test_untyped_free_text_falls_back_to_organisation():
    """The conservative direction: free text is what an organisation name is,
    and guessing 'domain' would send a nonsense string to a resolver."""
    assert seeds.parse_seed("Some Company Ltd").kind is K.ORGANISATION


def test_untyped_input_still_classifies_the_obvious_cases():
    assert seeds.parse_seed("example.com").kind is K.DOMAIN
    assert seeds.parse_seed("198.51.100.5").kind is K.ADDRESS
    assert seeds.parse_seed("a@example.com").kind is K.EMAIL


# ── the summary is what stops a small result reading as a small estate ──────
def test_a_set_with_no_domain_is_told_that_nothing_expands():
    """THE MOST IMPORTANT LINE ON THE SCREEN. A landscape seeded from
    addresses and organisation names contains exactly what was typed."""
    accepted, _ = seeds.parse_many([
        {"value": "198.51.100.5", "kind": "address"},
        {"value": "Acme", "kind": "organisation"},
    ])
    summary = seeds.summarise(accepted)
    assert summary["expanding_seeds"] == 0
    assert any("NOTHING HERE EXPANDS" in n for n in summary["notes"])


def test_a_set_with_a_domain_is_not_warned():
    accepted, _ = seeds.parse_many([{"value": "example.com", "kind": "domain"}])
    summary = seeds.summarise(accepted)
    assert summary["expanding_seeds"] == 1
    assert not any("NOTHING HERE EXPANDS" in n for n in summary["notes"])


def test_an_empty_set_is_not_warned_about_expansion():
    """No seeds is not the same failure as seeds that cannot expand, and
    warning about the second when the first happened is noise."""
    assert seeds.summarise([])["notes"] == []


def test_the_summary_carries_the_passive_only_statement():
    """`core/lookup.py:PASSIVE_ONLY` — the constraint is architectural, not a
    setting, and it belongs on the screen that starts a landscape."""
    assert seeds.summarise([])["passive_only"] == lookup.PASSIVE_ONLY


# ── the API contract the console renders from ───────────────────────────────
def test_the_seed_kind_catalogue_is_served_rather_than_hard_coded():
    """A console promising certificate expansion for an address seed would be
    making a claim the backend does not make. Serving the catalogue keeps the
    promise and the code enforcing it from drifting apart."""
    from fastapi.testclient import TestClient

    from api import app as api_app
    payload = TestClient(api_app.app).get("/api/v1/landscape/seed-kinds").json()
    kinds = {k["kind"]: k for k in payload["kinds"]}
    assert set(kinds) == {"domain", "address", "organisation", "email"}
    assert kinds["domain"]["expands"] is True
    assert all(not kinds[k]["expands"] for k in ("address", "organisation", "email"))


def test_the_plan_endpoint_returns_refusals_as_data_not_a_400():
    from fastapi.testclient import TestClient

    from api import app as api_app
    response = TestClient(api_app.app).post("/api/v1/landscape/plan", json={
        "actor": "tester",
        "seeds": [{"value": "example.com", "kind": "domain"},
                  {"value": "!!!", "kind": "address"}]})
    assert response.status_code == 200
    body = response.json()
    assert len(body["seeds"]) == 1 and len(body["refused"]) == 1


def test_the_plan_endpoint_requires_an_actor():
    """Every permit names one, and an unattributed query against somebody
    else's estate is not something this product will do."""
    from fastapi.testclient import TestClient

    from api import app as api_app
    response = TestClient(api_app.app).post("/api/v1/landscape/plan", json={
        "actor": "  ", "seeds": [{"value": "example.com", "kind": "domain"}]})
    assert response.status_code == 400


def test_the_plan_endpoint_never_echoes_a_mailbox():
    from fastapi.testclient import TestClient

    from api import app as api_app
    response = TestClient(api_app.app).post("/api/v1/landscape/plan", json={
        "actor": "tester",
        "seeds": [{"value": "jane.doe@somename.com", "kind": "email"}]})
    assert "jane" not in response.text.lower()


def test_both_routes_are_registered():
    from api import app as api_app
    paths = {r.path for r in api_app.app.routes}
    assert "/api/v1/landscape/plan" in paths
    assert "/api/v1/landscape/seed-kinds" in paths


# ── the run, and the honesty of what it could not do ────────────────────────
def _client():
    from fastapi.testclient import TestClient

    from api import app as api_app
    return TestClient(api_app.app)


def test_an_organisation_seed_reports_the_source_as_down_not_as_empty():
    """crt.sh is the only keyless source that can search BY organisation, and
    it answered 502 on three attempts on 2026-08-24 — `collect/ct.py` records
    the same outage. CertSpotter, which is answering, indexes by domain and
    cannot answer this question at all.

    So an empty candidate list would read as "nobody matched" when the truth is
    "nothing was asked", which is the substitution this codebase exists to
    refuse.
    """
    body = _client().post("/api/v1/landscape/run", json={
        "actor": "tester",
        "seeds": [{"value": "Acme Corporation", "kind": "organisation"}]}).json()
    unavailable = body["outcomes"][0]["unavailable"]
    assert len(unavailable) == 1
    assert "502" in unavailable[0]["why"]
    assert "NOT a finding that no organisation matches" in unavailable[0]["cost"]


def test_an_email_seed_says_which_precondition_is_missing():
    """"Unavailable" with no reason sends somebody to buy a key they may
    already have."""
    body = _client().post("/api/v1/landscape/run", json={
        "actor": "tester",
        "seeds": [{"value": "a@example.com", "kind": "email"}]}).json()
    why = body["outcomes"][0]["unavailable"][0]["why"]
    assert "ownership verification" in why


def test_the_run_never_echoes_a_mailbox():
    response = _client().post("/api/v1/landscape/run", json={
        "actor": "tester",
        "seeds": [{"value": "jane.doe@somename.com", "kind": "email"}]})
    assert "jane" not in response.text.lower()


def test_the_run_requires_an_actor():
    assert _client().post("/api/v1/landscape/run", json={
        "actor": "", "seeds": [{"value": "a@b.example", "kind": "email"}]}
    ).status_code == 400


def test_the_landscape_states_it_is_a_floor_not_a_census():
    """An operator reading an asset count as "this is my estate" has been
    misled by a number rather than by a sentence."""
    body = _client().post("/api/v1/landscape/run", json={
        "actor": "tester",
        "seeds": [{"value": "Acme", "kind": "organisation"}]}).json()
    assert "FLOOR, NEVER A CENSUS" in body["landscape"]["coverage_means"]


def test_a_failed_seed_is_a_result_rather_than_a_failed_request():
    """One unreachable source must not discard the work done for the others."""
    outcome = seeds.Outcome(
        seed=seeds.parse_seed("example.com", K.DOMAIN), error="boom")
    combined = seeds.combine([outcome])
    assert combined["failed_seeds"] == [{"seed": "example.com", "why": "boom"}]
    assert any("not a landscape where they were clean" in n
               for n in combined["notes"])


def test_the_run_cap_is_announced_rather_than_applied_quietly():
    combined = seeds.combine([], dropped_by_cap=3)
    assert combined["dropped_by_cap"] == 3
    assert any("were not attempted" in n for n in combined["notes"])


def test_assets_are_deduplicated_across_seeds():
    a = seeds.Outcome(seed=seeds.parse_seed("example.com", K.DOMAIN),
                      assets=("example.com", "www.example.com"))
    b = seeds.Outcome(seed=seeds.parse_seed("other.example", K.DOMAIN),
                      assets=("WWW.EXAMPLE.COM", "other.example"))
    combined = seeds.combine([a, b])
    assert combined["asset_count"] == 3


def test_what_you_supplied_is_not_counted_as_discovered():
    """The discovered count is the one an operator reads as "things I did not
    know about", so counting the seed in it would inflate exactly the number
    that matters."""
    outcome = seeds.Outcome(seed=seeds.parse_seed("example.com", K.DOMAIN),
                            assets=("example.com", "www.example.com"))
    combined = seeds.combine([outcome])
    assert combined["discovered"] == ["www.example.com"]


def test_an_expanding_seed_that_found_nothing_says_why():
    """CT only holds names a CA has issued for, so a domain with no public
    certificates expands to nothing — a fact about the certificate record, not
    about the estate."""
    outcome = seeds.Outcome(seed=seeds.parse_seed("example.com", K.DOMAIN),
                            assets=("example.com",))
    assert any("fact about the certificate record" in n
               for n in seeds.combine([outcome])["notes"])


def test_the_run_route_is_registered():
    from api import app as api_app
    assert "/api/v1/landscape/run" in {r.path for r in api_app.app.routes}
