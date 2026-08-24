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
