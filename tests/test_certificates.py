"""Certificate posture and lineage.

The distinction under test throughout: a Certificate Transparency entry records
that a certificate was ISSUED, which is not the same as it being in service.
Almost every wrong conclusion available in this module comes from collapsing
those two.
"""
from __future__ import annotations

from datetime import date

import pytest

from core import certificates as certs

TODAY = date(2026, 8, 23)


def cert(host="a.example", not_after="2027-01-01", **kw):
    base = dict(host=host, issuer="Let's Encrypt", not_before="2026-06-01",
                not_after=not_after)
    base.update(kw)
    return certs.Certificate(**base)


# ── expiry ──────────────────────────────────────────────────────────────────
def test_an_expired_certificate_fires():
    fired = certs.assess([cert(not_after="2026-08-01")], TODAY)
    assert [f["rule"] for f in fired] == ["cert.expired"]
    assert fired[0]["days_ago"] == 22


def test_a_certificate_expiring_soon_fires():
    fired = certs.assess([cert(not_after="2026-09-10")], TODAY)
    assert [f["rule"] for f in fired] == ["cert.expiring"]
    assert fired[0]["days_left"] == 18


def test_a_healthy_certificate_fires_nothing():
    assert certs.assess([cert(not_after="2027-06-01")], TODAY) == []


def test_expiry_is_judged_on_the_newest_certificate_only():
    """A host accumulates expired certificates as a matter of course — that is
    what renewal looks like in a log. Firing on each would make the rule
    permanently true everywhere and therefore useless."""
    history = [cert(not_after="2024-01-01"), cert(not_after="2025-01-01"),
               cert(not_after="2027-06-01")]
    assert certs.assess(history, TODAY) == []


def test_an_unparseable_expiry_produces_no_firing_rather_than_a_crash():
    assert certs.assess([cert(not_after="soon")], TODAY) == []
    assert cert(not_after="soon").days_until_expiry(TODAY) is None


# ── the other rules ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("algorithm", ["sha1WithRSAEncryption", "md5WithRSA",
                                       "SHA1", "sha-1", "MD5-RSA",
                                       "ecdsa-with-SHA1"])
def test_broken_signature_algorithms_fire(algorithm):
    fired = certs.assess([cert(signature_algorithm=algorithm)], TODAY)
    assert "cert.weak_signature" in [f["rule"] for f in fired]


@pytest.mark.parametrize("algorithm", ["sha256WithRSAEncryption",
                                       "ecdsa-with-SHA384", "sha512", ""])
def test_current_algorithms_do_not_fire(algorithm):
    fired = certs.assess([cert(signature_algorithm=algorithm)], TODAY)
    assert "cert.weak_signature" not in [f["rule"] for f in fired]


def test_a_very_broad_san_set_fires_as_context():
    many = tuple(f"h{i}.example" for i in range(150))
    fired = certs.assess([cert(sans=many)], TODAY)
    assert "cert.broad_san" in [f["rule"] for f in fired]


def test_an_ordinary_san_set_does_not():
    few = tuple(f"h{i}.example" for i in range(5))
    assert certs.assess([cert(sans=few)], TODAY) == []


def test_every_rule_emitted_here_exists_in_the_catalogue():
    """The whole reason W1 was built first: these land in the catalogue like
    every other check rather than as free text."""
    from core import rules
    many = tuple(f"h{i}.example" for i in range(150))
    fired = certs.assess([cert(not_after="2026-08-01",
                               signature_algorithm="sha1", sans=many)], TODAY)
    assert fired
    for finding in fired:
        assert rules.get(finding["rule"]) is not None, finding["rule"]


# ── issued is not deployed ──────────────────────────────────────────────────
def test_a_ct_entry_says_it_records_issuance_not_deployment():
    payload = cert().to_dict(TODAY)
    assert payload["observed"] == "issued"
    assert "may never have been deployed" in payload["observed_means"]


def test_a_live_handshake_says_the_certificate_is_in_service():
    payload = cert(observed=certs.Observed.PRESENTED).to_dict(TODAY)
    assert "actually in service" in payload["observed_means"]


def test_coverage_states_the_limit_plainly():
    text = certs.coverage([cert()])["limits"]
    assert "records ISSUANCE, not" in text
    assert "cannot tell those apart" in text


def test_coverage_separates_log_entries_from_live_observations():
    rows = [cert(), cert(observed=certs.Observed.PRESENTED)]
    summary = certs.coverage(rows)
    assert summary["from_ct_logs"] == 1
    assert summary["from_live_handshake"] == 1


# ── lineage: what a handshake cannot show ───────────────────────────────────
def test_lineage_counts_issuer_changes():
    """A live probe returns today's certificate. A CT log returns all of them,
    so an issuer that changed three times is visible here and nowhere else."""
    history = [
        cert(issuer="DigiCert", not_before="2025-01-01"),
        cert(issuer="Let's Encrypt", not_before="2025-06-01"),
        cert(issuer="DigiCert", not_before="2026-01-01"),
    ]
    result = certs.lineage(history, TODAY)
    assert result["issuer_changes"] == 2
    assert result["issuer_sequence"] == ["DigiCert", "Let's Encrypt", "DigiCert"]
    assert result["distinct_issuers"] == ["DigiCert", "Let's Encrypt"]


def test_consecutive_renewals_by_the_same_ca_are_not_changes():
    history = [cert(not_before="2025-01-01"), cert(not_before="2025-04-01"),
               cert(not_before="2025-07-01")]
    assert certs.lineage(history, TODAY)["issuer_changes"] == 0


def test_lineage_is_reported_not_scored():
    """Changing CA is a normal procurement decision, and a migration in
    progress looks identical to something worse."""
    text = certs.lineage([cert()], TODAY)["means"]
    assert "reported and not scored" in text
    assert "handshake cannot show" in text


def test_lineage_of_nothing_does_not_crash():
    result = certs.lineage([], TODAY)
    assert result["certificates"] == 0 and result["issuer_changes"] == 0


# ── subsidiary candidates ───────────────────────────────────────────────────
def test_a_validated_organisation_becomes_a_candidate():
    """An OV or EV certificate carries a CA-validated organisation name, so a
    company's certificates name the company."""
    rows = [cert(organisation="Northwind Holdings Ltd")]
    proposals = certs.candidate_organisations(rows)
    assert proposals[0]["organisation"] == "Northwind Holdings Ltd"


def test_an_organisation_already_known_is_not_proposed_again():
    rows = [cert(organisation="Acme Ltd")]
    assert certs.candidate_organisations(rows, known=["acme ltd"]) == []


def test_dv_certificates_carry_no_organisation_and_propose_nothing():
    assert certs.candidate_organisations([cert()]) == []


def test_a_candidate_says_it_is_a_question_not_evidence():
    """Nothing is added to scope on the strength of a certificate field."""
    proposal = certs.candidate_organisations([cert(organisation="X Ltd")])[0]
    assert "worth ASKING about" in proposal["basis"]
    assert "not evidence" in proposal["basis"]


def test_candidates_are_ordered_by_how_much_evidence_supports_them():
    rows = [cert(host="a.example", organisation="Big Ltd"),
            cert(host="b.example", organisation="Big Ltd"),
            cert(host="c.example", organisation="Small Ltd")]
    proposals = certs.candidate_organisations(rows)
    assert proposals[0]["organisation"] == "Big Ltd"
    assert proposals[0]["hosts"] == ["a.example", "b.example"]


def test_this_module_adds_nothing_to_scope():
    import inspect
    source = inspect.getsource(certs)
    for forbidden in ("ScopeRule", "add_scope", "scope.add"):
        assert forbidden not in source, forbidden
