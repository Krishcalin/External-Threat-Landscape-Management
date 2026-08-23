"""The CII register and the notification draft.

CII status is conferred by gazette notification under Section 70 of the IT Act,
2000 — by the appropriate Government, on NCIIPC's recommendation. Neither this
product nor the customer's security team can confer it, so most of these tests
are about the register recording what somebody STATED rather than concluding
anything.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from core import cert_in, cii
from core.cert_in import Category, Clock, Declaration, notification_draft
from core.cii import Basis, Designation, Register, RegisterError, Sector

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)


def gazette(asset="fw-01.example.com"):
    return Designation(asset, Sector.POWER_ENERGY, Basis.GAZETTE,
                       gazette_reference="S.O. 1234(E) 2024-03-11",
                       declared_by="ciso@example.com")


def assessed(asset="web-01.example.com"):
    return Designation(asset, Sector.POWER_ENERGY, Basis.ORGANISATION_ASSESSED,
                       declared_by="ciso@example.com")


def finding(asset, basis="product_match", evidence=None):
    return {"asset": asset, "basis": basis, "evidence": evidence or []}


# ── the product does not designate ──────────────────────────────────────────
def test_there_is_no_function_that_infers_cii_status():
    """A tool that guessed CII status from a hostname would be inventing a
    legal status, and an organisation acting on the guess would either
    over-report to a national agency or believe itself covered when it is not.
    """
    for banned in ("infer", "detect_cii", "classify", "is_cii", "guess"):
        assert not hasattr(cii, banned), banned


def test_the_register_states_that_it_does_not_designate():
    text = Register().to_dict()["skopos_does_not_designate"]
    assert "does not and cannot determine" in text
    assert "notification in the Official Gazette" in text
    assert "inventing a legal status" in text


def test_the_authority_and_definition_are_cited():
    payload = Register().to_dict()
    assert "Section 70A" in payload["authority"]
    assert "debilitating impact on national security" in payload["cii_definition"]
    assert payload["reviewed_on"]


# ── the basis is the thing an assessor cares about ──────────────────────────
def test_a_gazette_claim_without_a_reference_is_refused():
    """The single claim in this register that could mislead a regulator."""
    with pytest.raises(RegisterError) as exc:
        Designation("a.example.com", Sector.TELECOM, Basis.GAZETTE,
                    declared_by="ciso@example.com")
    assert "notification reference" in str(exc.value)
    assert "mislead a regulator" in str(exc.value)


def test_an_organisation_assessment_is_not_a_legal_designation():
    assert "NOT a legal designation" in Basis.ORGANISATION_ASSESSED.weight
    assert "only the appropriate Government confers that" in \
        Basis.ORGANISATION_ASSESSED.weight


def test_a_designation_must_record_who_recorded_it():
    with pytest.raises(RegisterError) as exc:
        Designation("a.example.com", Sector.TELECOM,
                    Basis.ORGANISATION_ASSESSED, declared_by="")
    assert "who recorded it" in str(exc.value)


def test_an_undeclared_entry_needs_no_declarer():
    """It is a question, not an assertion, so nobody has to own it."""
    entry = Designation("a.example.com", Sector.TELECOM, Basis.UNDECLARED)
    assert entry.basis is Basis.UNDECLARED


def test_an_asset_is_required():
    with pytest.raises(RegisterError):
        Designation("  ", Sector.TELECOM, Basis.UNDECLARED)


# ── undeclared assets are a question, not a finding ─────────────────────────
def test_undeclared_assets_are_phrased_as_a_question():
    """The answer may legitimately be 'that one is out of scope and always was'."""
    register = cii.build([gazette()],
                         [finding("fw-01.example.com"),
                          finding("shadow.example.com")])
    assert register.undeclared == ["shadow.example.com"]
    assert "a question for you, not a finding" in register.headline()


def test_undeclared_assets_are_kept_out_of_the_register_proper():
    register = cii.build([gazette()], [finding("shadow.example.com")])
    assert [e.designation.asset for e in register.entries] == ["fw-01.example.com"]


def test_the_undeclared_basis_says_it_may_be_out_of_scope():
    assert "may legitimately be" in Basis.UNDECLARED.weight
    assert "out of scope" in Basis.UNDECLARED.weight


# ── what SKOPOS contributes ─────────────────────────────────────────────────
def test_findings_are_joined_and_split_by_basis():
    register = cii.build(
        [gazette()],
        [finding("fw-01.example.com", "version_range"),
         finding("fw-01.example.com", "product_match")])
    entry = register.entries[0]
    assert entry.determinations == 1
    assert entry.worklist == 1


def test_a_retired_finding_is_not_counted_as_a_determination():
    register = cii.build(
        [gazette()],
        [finding("fw-01.example.com", "version_range",
                 ["RETIRED: 9.9 falls outside every range"])])
    assert register.entries[0].determinations == 0


def test_first_observed_is_our_sighting_not_a_claim_about_exposure():
    register = cii.build([gazette()], [finding("fw-01.example.com")],
                         observed={"fw-01.example.com": date(2026, 1, 5)})
    row = register.entries[0].to_dict()
    assert row["first_observed_by_skopos"] == "2026-01-05"
    assert "first_observed_by_skopos" in row, "the field name carries the caveat"


def test_gazette_entries_sort_first():
    register = cii.build([assessed(), gazette()], [])
    assert register.entries[0].designation.basis is Basis.GAZETTE


def test_the_six_sectors_are_the_published_ones():
    labels = {s.label for s in Sector}
    assert "Power & Energy" in labels
    assert "Banking, Financial Services & Insurance" in labels
    assert len(labels) == 6


# ── the notification draft ──────────────────────────────────────────────────
def declaration(**kw):
    base = dict(category=Category.CRITICAL_SYSTEM_COMPROMISE,
                became_aware_at=NOW - timedelta(hours=2),
                declared_by="soc-lead@example.com",
                summary="Unauthorised access observed on the perimeter VPN.")
    base.update(kw)
    return Declaration(**base)


def test_a_draft_cannot_be_produced_without_a_human_declaration():
    """There is no path from a finding to a regulatory document."""
    import inspect
    signature = inspect.signature(notification_draft)
    assert "declaration" in signature.parameters


def test_the_draft_says_it_is_not_filed():
    draft = notification_draft(declaration(), now=NOW)
    assert "DRAFT — NOT A FILED REPORT" in draft
    assert "has not been submitted to anybody" in draft
    assert "Nothing has been sent" in draft


def test_the_draft_defers_to_the_directive_not_to_itself():
    draft = notification_draft(declaration(), now=NOW)
    assert "is the authority, not this draft" in draft
    assert "20(3)/2022-CERT-In" in draft


def test_judgements_are_left_blank_and_marked():
    """A pre-filled guess would be submitted verbatim by somebody working
    against a six-hour deadline."""
    draft = notification_draft(declaration(), now=NOW)
    for field in ("Impact on operations", "Root cause",
                  "Remedial action taken", "Contact for follow-up"):
        assert field in draft
        line = [l for l in draft.splitlines() if field in l][0]
        assert cert_in.TO_COMPLETE in line, field


def test_the_draft_says_which_fields_it_cannot_supply_and_why():
    draft = notification_draft(declaration(), now=NOW)
    assert "FIELDS SKOPOS CANNOT SUPPLY" in draft
    assert "a pre-filled guess would be filed verbatim" in draft


def test_a_worklist_entry_is_not_described_as_confirmed():
    """Overstating to a regulator is worse than overstating on a dashboard."""
    draft = notification_draft(
        declaration(related_findings=[finding("a.example.com", "product_match")]),
        now=NOW)
    assert "was NOT compared" in draft
    assert "not a confirmed vulnerable version" in draft


def test_a_determination_is_described_as_one():
    draft = notification_draft(
        declaration(related_findings=[finding("a.example.com", "version_range")]),
        now=NOW)
    assert "compared against a published affected range (determination)" in draft


def test_the_draft_carries_the_deadline_and_remaining_time():
    draft = notification_draft(declaration(), now=NOW)
    assert "Deadline" in draft
    assert "4h remaining" in draft


def test_an_overdue_draft_does_not_soften_it():
    draft = notification_draft(declaration(became_aware_at=NOW - timedelta(hours=9)),
                               now=NOW)
    assert "closed 3h ago" in draft


# ── the routes ──────────────────────────────────────────────────────────────
STORED = [{"asset": "fw-01.example.com", "cve": "CVE-2018-13379",
           "product": "FortiOS", "basis": "product_match", "evidence": [],
           "vulnerability": "Path Traversal", "owner": "Network Team"}]


@pytest.fixture
def client(monkeypatch):
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    from api import app as api_app

    class _Store:
        def findings(self, **kw):
            return list(STORED)

    monkeypatch.setattr(api_app, "_findings_store", lambda: _Store())
    return fastapi_testclient.TestClient(api_app.app)


def body(**kw):
    base = {"category": "compromise_of_critical_systems_or_information",
            "became_aware_at": "2026-08-23T09:30:00+05:30",
            "declared_by": "soc-lead@example.com",
            "summary": "Unauthorised access observed on the perimeter VPN."}
    base.update(kw)
    return base


def test_the_register_route_carries_its_caveats(client):
    payload = client.get("/api/v1/compliance/cii").json()
    assert "Section 70A" in payload["authority"]
    assert "inventing a legal status" in payload["skopos_does_not_designate"]


def test_an_empty_register_is_not_an_estate_with_no_critical_assets(client):
    """The empty state a customer sees on day one, and the wrong reading of it."""
    payload = client.get("/api/v1/compliance/cii").json()
    assert payload["entries"] == []
    assert "is not an estate with no critical infrastructure" in payload["note"]
    assert payload["undeclared_assets"] == ["fw-01.example.com"]


def test_there_is_no_route_that_designates_an_asset(client):
    """A POST that recorded a gazette notification without one would be the
    product manufacturing a legal status."""
    paths = {r.path: getattr(r, "methods", set())
             for r in client.app.routes if hasattr(r, "path")}
    assert "POST" not in paths.get("/api/v1/compliance/cii", set())


def test_the_draft_route_produces_text_and_files_nothing(client):
    payload = client.post("/api/v1/compliance/cert-in/draft",
                          json=body()).json()
    assert payload["filed"] is False
    assert payload["transmitted_to"] is None
    assert "SKOPOS does not file with CERT-In" in payload["note"]
    assert "DRAFT — NOT A FILED REPORT" in payload["draft"]


def test_the_draft_route_is_a_post_because_the_input_is_a_statement(client):
    """A declaration is something somebody makes, not a resource that exists —
    so there is no GET that hands back a notification for an asset."""
    methods = {r.path: getattr(r, "methods", set()) or set()
               for r in client.app.routes if hasattr(r, "path")}
    assert methods["/api/v1/compliance/cert-in/draft"] & {"POST"}
    assert not methods["/api/v1/compliance/cert-in/draft"] & {"GET"}


def test_the_route_will_not_accept_a_basis_from_the_caller(client):
    """The integrity property: a caller cannot post basis=version_range and get
    a regulator-facing document describing a worklist entry as confirmed."""
    payload = client.post("/api/v1/compliance/cert-in/draft", json=body(
        related=[{"asset": "fw-01.example.com", "cve": "CVE-2018-13379",
                  "basis": "version_range"}])).json()
    assert "was NOT compared" in payload["draft"]
    assert "not a confirmed vulnerable version" in payload["draft"]


def test_a_finding_we_cannot_evidence_is_not_citable(client):
    response = client.post("/api/v1/compliance/cert-in/draft", json=body(
        related=[{"asset": "nope.example.com", "cve": "CVE-2021-44228"}]))
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["unresolved"] == ["nope.example.com/CVE-2021-44228"]
    assert "cannot produce evidence for" in detail["why"]


def test_an_unpatched_service_is_not_an_incident_category(client):
    """The category a user reaches for when they mistake a finding for an
    incident. It is not on CERT-In's list, and the refusal says why."""
    response = client.post("/api/v1/compliance/cert-in/draft",
                           json=body(category="unpatched_service"))
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "unknown category" in detail["error"]
    assert "the data does not support" in detail["note"]


@pytest.mark.parametrize("bad,expected", [
    ({"became_aware_at": "2026-08-23T09:30:00"}, "timezone"),
    ({"declared_by": "  "}, "who made it"),
    ({"summary": " "}, "cannot write that sentence for you"),
])
def test_the_route_refuses_what_the_declaration_refuses(client, bad, expected):
    response = client.post("/api/v1/compliance/cert-in/draft", json=body(**bad))
    assert response.status_code == 422
    assert expected in response.json()["detail"]["error"]
