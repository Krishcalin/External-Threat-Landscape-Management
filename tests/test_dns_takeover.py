"""DNS wire parsing, change tracking, and the takeover ceiling.

No live network. The DNS responses are built with the module's own encoder from
shapes captured against real resolvers while writing it.
"""
from __future__ import annotations

import struct
from datetime import date, timedelta

import pytest

from collect.dns_records import Agreement, DnsSweep, Refusal
from collect.dns_wire import (Answer, RRType, Rcode, Response, build_query,
                              parse_response)
from core.dns_state import (ChangeKind, Comparison, Observation, diff,
                            supersede)
from core.takeover import (Corroboration, RegistrationStatus, TakeoverEvidence,
                           TakeoverFinding, TakeoverVerdict, TAKEOVER_MEANING)

TODAY = date(2026, 8, 23)


def response(name, rrtype, rcode, values=(), resolver="1.1.1.1"):
    return Response(name=name, rrtype=rrtype, rcode=rcode,
                    answers=[Answer(name, rrtype, v) for v in values],
                    resolver=resolver)


# -- the wire parser ---------------------------------------------------------
def test_nxdomain_and_nodata_have_the_same_digest_but_different_state():
    """The measurement the whole comparand rests on.

    Both produce an empty answer set and therefore the same sha256, so a digest
    alone makes a zone deletion and a name creation invisible.
    """
    nxdomain = response("gone.example.com", RRType.A, Rcode.NXDOMAIN)
    nodata = response("gone.example.com", RRType.A, Rcode.NOERROR)
    assert nxdomain.digest == nodata.digest
    assert nxdomain.state != nodata.state


def test_ttl_is_excluded_from_the_digest():
    """Including it makes every record set 'change' every run as it counts down,
    burying real changes under noise."""
    early = Response(name="a.example.com", rrtype=RRType.A, rcode=Rcode.NOERROR,
                     answers=[Answer("a.example.com", RRType.A, "1.2.3.4", 300)])
    late = Response(name="a.example.com", rrtype=RRType.A, rcode=Rcode.NOERROR,
                    answers=[Answer("a.example.com", RRType.A, "1.2.3.4", 12)])
    assert early.digest == late.digest


def test_value_order_is_not_a_change():
    a = response("x.example.com", RRType.A, Rcode.NOERROR, ("1.1.1.1", "2.2.2.2"))
    b = response("x.example.com", RRType.A, Rcode.NOERROR, ("2.2.2.2", "1.1.1.1"))
    assert a.digest == b.digest


def test_servfail_is_not_conclusive_but_nxdomain_is():
    """getaddrinfo collapses these into one gaierror; that is why this exists."""
    assert response("x", RRType.A, Rcode.NXDOMAIN).conclusive
    assert not response("x", RRType.A, Rcode.SERVFAIL).conclusive
    assert not response("x", RRType.A, Rcode.REFUSED).conclusive


def test_a_mismatched_transaction_id_is_refused():
    """A predictable id is what makes off-path spoofing practical."""
    packet, txid = build_query("example.com", RRType.A)
    reply = struct.pack(">HHHHHH", (txid + 1) % 65536, 0x8180, 0, 0, 0, 0)
    parsed = parse_response(reply, "example.com", RRType.A, txid)
    assert parsed.unreadable
    assert "transaction id" in parsed.detail


def test_an_unreadable_packet_is_not_an_empty_result():
    """Conflating them makes a parser bug look like a deleted zone."""
    parsed = parse_response(b"\x00\x01", "example.com", RRType.A)
    assert parsed.unreadable
    assert not parsed.conclusive


def test_a_compression_pointer_loop_does_not_hang():
    header = struct.pack(">HHHHHH", 1, 0x8180, 0, 1, 0, 0)
    body = b"\xc0\x0c"          # a pointer to itself
    parsed = parse_response(header + body, "x", RRType.A, 1)
    assert parsed.unreadable


def test_transaction_ids_are_not_sequential():
    ids = {build_query("example.com", RRType.A)[1] for _ in range(20)}
    assert len(ids) > 15, "ids must not be predictable"


# -- quorum ------------------------------------------------------------------
def test_two_of_three_resolvers_reach_quorum():
    agreement = Agreement("a.example.com", RRType.A, [
        response("a.example.com", RRType.A, Rcode.NOERROR, ("1.1.1.1",), "1.1.1.1"),
        response("a.example.com", RRType.A, Rcode.NOERROR, ("1.1.1.1",), "8.8.8.8"),
        response("a.example.com", RRType.A, Rcode.NOERROR, ("9.9.9.9",), "9.9.9.9"),
    ])
    assert agreement.agreed
    assert agreement.winning.values == ["1.1.1.1"]


def test_three_disjoint_answers_reach_no_quorum():
    """Measured live: www.microsoft.com returns three disjoint address sets.
    That is geo-balancing, and it must not be silently discarded."""
    agreement = Agreement("cdn.example.com", RRType.A, [
        response("cdn.example.com", RRType.A, Rcode.NOERROR, ("1.1.1.1",), "1.1.1.1"),
        response("cdn.example.com", RRType.A, Rcode.NOERROR, ("2.2.2.2",), "8.8.8.8"),
        response("cdn.example.com", RRType.A, Rcode.NOERROR, ("3.3.3.3",), "9.9.9.9"),
    ])
    assert not agreement.agreed
    assert agreement.winning is None


def test_agreement_is_per_rrtype_not_per_name():
    """A routine A-record disagreement must not suppress a solid CNAME finding."""
    sweep = DnsSweep(agreements=[
        Agreement("x.example.com", RRType.A, [
            response("x.example.com", RRType.A, Rcode.NOERROR, ("1.1.1.1",), "1.1.1.1"),
            response("x.example.com", RRType.A, Rcode.NOERROR, ("2.2.2.2",), "8.8.8.8"),
        ]),
        Agreement("x.example.com", RRType.CNAME, [
            response("x.example.com", RRType.CNAME, Rcode.NOERROR,
                     ("t.provider.net",), "1.1.1.1"),
            response("x.example.com", RRType.CNAME, Rcode.NOERROR,
                     ("t.provider.net",), "8.8.8.8"),
        ]),
    ])
    assert sweep.observed == 1
    assert sweep.quorum_failed == 1


def test_counters_are_per_name_rrtype_pair():
    """Per-name counting lets a name with 5 of 6 rrtypes failed report as fully
    observed."""
    sweep = DnsSweep(agreements=[
        Agreement("x.example.com", rt, [
            response("x.example.com", rt, Rcode.SERVFAIL, (), "1.1.1.1")])
        for rt in (RRType.A, RRType.AAAA, RRType.CNAME)
    ])
    assert sweep.attempted == 3
    assert sweep.unobserved == 3
    assert sweep.observed == 0


# -- change tracking ---------------------------------------------------------
def agreed(name, rrtype, rcode, values=()):
    return Agreement(name, rrtype, [
        response(name, rrtype, rcode, values, "1.1.1.1"),
        response(name, rrtype, rcode, values, "8.8.8.8"),
    ])


def test_the_first_run_is_a_named_baseline_not_a_wall_of_changes():
    """Reporting everything as new makes run one the noisiest report the
    customer ever gets, on a day when none of it is actionable."""
    sweep = DnsSweep(agreements=[
        agreed("a.example.com", RRType.A, Rcode.NOERROR, ("1.1.1.1",)),
        agreed("b.example.com", RRType.A, Rcode.NOERROR, ("2.2.2.2",)),
    ])
    report = diff(sweep, {}, TODAY)
    assert report.comparison is Comparison.BASELINE
    assert report.established == 2
    assert all(c.kind is ChangeKind.FIRST_OBSERVED for c in report.changes)
    assert "First observation of 2 of 2" in report.headline()


def test_a_degraded_baseline_says_how_many_it_actually_established():
    """A sentence asserting 412 first observations against 32 real ones is a
    false claim about coverage."""
    sweep = DnsSweep(agreements=[
        agreed("a.example.com", RRType.A, Rcode.NOERROR, ("1.1.1.1",)),
        Agreement("b.example.com", RRType.A, [
            response("b.example.com", RRType.A, Rcode.SERVFAIL, (), "1.1.1.1"),
            response("b.example.com", RRType.A, Rcode.SERVFAIL, (), "8.8.8.8")]),
    ])
    report = diff(sweep, {}, TODAY)
    assert report.established == 1
    headline = report.headline()
    assert "First observation of 1 of 2" in headline
    assert "will baseline on the first run that can see them" in headline


def test_an_unchanged_record_produces_no_change():
    prior = {("a.example.com", "A"): Observation(
        "a.example.com", "A", "NOERROR",
        response("a.example.com", RRType.A, Rcode.NOERROR, ("1.1.1.1",)).digest,
        ("1.1.1.1",), TODAY - timedelta(days=7))}
    sweep = DnsSweep(agreements=[
        agreed("a.example.com", RRType.A, Rcode.NOERROR, ("1.1.1.1",))])
    report = diff(sweep, prior, TODAY)
    assert report.of_kind(ChangeKind.MODIFIED) == []


def test_a_modified_record_names_the_gap_since_it_was_last_seen():
    prior = {("a.example.com", "A"): Observation(
        "a.example.com", "A", "NOERROR",
        response("a.example.com", RRType.A, Rcode.NOERROR, ("1.1.1.1",)).digest,
        ("1.1.1.1",), TODAY - timedelta(days=9))}
    sweep = DnsSweep(agreements=[
        agreed("a.example.com", RRType.A, Rcode.NOERROR, ("9.9.9.9",))])
    report = diff(sweep, prior, TODAY)
    change = report.of_kind(ChangeKind.MODIFIED)[0]
    assert change.gap_days == 9
    assert "the last time we could see it" not in change.explain()   # phrasing
    assert change.previous_observed_at == TODAY - timedelta(days=9)


def test_a_deleted_zone_is_visible_because_rcode_is_part_of_the_state():
    """NODATA -> NXDOMAIN. Invisible if the comparand were the digest alone."""
    prior = {("a.example.com", "A"): Observation(
        "a.example.com", "A", "NOERROR",
        response("a.example.com", RRType.A, Rcode.NOERROR, ("1.1.1.1",)).digest,
        ("1.1.1.1",), TODAY - timedelta(days=3))}
    sweep = DnsSweep(agreements=[
        agreed("a.example.com", RRType.A, Rcode.NXDOMAIN)])
    report = diff(sweep, prior, TODAY)
    assert report.of_kind(ChangeKind.DISAPPEARED)


def test_our_outage_is_unobserved_and_never_supersedes_what_we_knew():
    """Otherwise a resolver outage reads as the customer's DNS being deleted."""
    known = Observation("a.example.com", "A", "NOERROR", "abc", ("1.1.1.1",),
                        TODAY - timedelta(days=2))
    prior = {("a.example.com", "A"): known}
    sweep = DnsSweep(agreements=[
        Agreement("a.example.com", RRType.A, [
            response("a.example.com", RRType.A, Rcode.SERVFAIL, (), "1.1.1.1"),
            response("a.example.com", RRType.A, Rcode.SERVFAIL, (), "8.8.8.8")])])
    report = diff(sweep, prior, TODAY)
    assert report.of_kind(ChangeKind.UNOBSERVED)
    assert not report.of_kind(ChangeKind.DISAPPEARED)
    assert supersede(prior, report)[("a.example.com", "A")] is known


def test_an_exclusion_is_not_looked_at_never_disappeared():
    """Adding an exclusion on Monday must not report 40 deletions on Tuesday."""
    sweep = DnsSweep(refusals=[Refusal("legacy.example.com",
                                       "excluded by wildcard rule", "NotInScope")])
    report = diff(sweep, {("legacy.example.com", "A"): Observation(
        "legacy.example.com", "A", "NOERROR", "abc", ("1.1.1.1",), TODAY)}, TODAY)
    assert report.of_kind(ChangeKind.NOT_LOOKED_AT)
    assert not report.of_kind(ChangeKind.DISAPPEARED)
    assert "gate refused" in report.headline()


def test_quorum_failure_is_reported_not_dropped():
    """Otherwise 'observed 400/400, 0 changes' reads as a quiet night while the
    noisiest names were silently discarded."""
    sweep = DnsSweep(agreements=[
        Agreement("cdn.example.com", RRType.A, [
            response("cdn.example.com", RRType.A, Rcode.NOERROR, ("1.1.1.1",), "1.1.1.1"),
            response("cdn.example.com", RRType.A, Rcode.NOERROR, ("2.2.2.2",), "8.8.8.8"),
        ])])
    report = diff(sweep, {}, TODAY)
    assert report.quorum_failed == 1
    change = report.of_kind(ChangeKind.INDETERMINATE)[0]
    assert "1.1.1.1=" in change.detail


def test_every_change_kind_has_a_meaning_string():
    from core.dns_state import CHANGE_MEANING
    assert set(CHANGE_MEANING) == {k.value for k in ChangeKind}


# -- takeover ----------------------------------------------------------------
def evidence(**overrides):
    base = dict(name="shop.example.com", target="bucket.s3.amazonaws.com",
                target_rcode="NXDOMAIN", resolvers_agreeing=2,
                resolvers_queried=3)
    base.update(overrides)
    return TakeoverEvidence(**base)


def test_evidence_cannot_omit_the_target():
    """A claim that a name is hijackable without saying what it points at is not
    reviewable, so the type refuses to hold one."""
    with pytest.raises(ValueError) as exc:
        TakeoverEvidence(name="shop.example.com", target="  ",
                         target_rcode="NXDOMAIN", resolvers_agreeing=2,
                         resolvers_queried=3)
    assert "must record the CNAME target" in str(exc.value)


def test_a_finding_needs_reasons():
    with pytest.raises(ValueError):
        TakeoverFinding(TakeoverVerdict.INCONCLUSIVE, Corroboration.NONE,
                        evidence(), ())


def test_a_single_resolver_cannot_manufacture_a_finding():
    """One resolver can be poisoned, censored, or simply wrong."""
    with pytest.raises(ValueError) as exc:
        TakeoverFinding(TakeoverVerdict.INCONCLUSIVE, Corroboration.NONE,
                        evidence(resolvers_agreeing=1), ("dangles",))
    assert "at least two agreeing resolvers" in str(exc.value)


def test_claimable_looking_is_refused_in_this_phase():
    """The ceiling you approved, enforced by the type rather than by discipline."""
    with pytest.raises(ValueError) as exc:
        TakeoverFinding(TakeoverVerdict.CLAIMABLE_LOOKING, Corroboration.NONE,
                        evidence(), ("looks claimable",))
    assert "not reachable in this phase" in str(exc.value)


def test_the_headline_finding_requires_an_rdap_answer():
    with pytest.raises(ValueError) as exc:
        TakeoverFinding(TakeoverVerdict.REGISTRABLE_DOMAIN_UNREGISTERED,
                        Corroboration.REGISTRATION_OPEN,
                        evidence(registration_status=RegistrationStatus.UNKNOWN),
                        ("target does not resolve",))
    assert "requires an RDAP answer" in str(exc.value)


def test_the_headline_finding_is_constructible_with_evidence():
    finding = TakeoverFinding(
        TakeoverVerdict.REGISTRABLE_DOMAIN_UNREGISTERED,
        Corroboration.REGISTRATION_OPEN,
        evidence(target="abandoned-vendor.com",
                 registrable_domain="abandoned-vendor.com",
                 registration_status=RegistrationStatus.UNREGISTERED,
                 rdap_response="404 Not Found"),
        ("CNAME target does not resolve", "RDAP reports the domain unregistered"))
    assert "price of a domain" in finding.explain()


def test_registration_open_cannot_corroborate_anything_else():
    """Otherwise it is dead vocabulary advertising a tier we refuse to reach."""
    with pytest.raises(ValueError) as exc:
        TakeoverFinding(TakeoverVerdict.PROVIDER_GUARDED,
                        Corroboration.REGISTRATION_OPEN, evidence(),
                        ("provider reserves released names",))
    assert "corroborates exactly one verdict" in str(exc.value)


def test_no_claim_signal_found_does_not_assert_safety():
    """It would render identically to a resource an attacker already claimed."""
    text = TAKEOVER_MEANING[TakeoverVerdict.NO_CLAIM_SIGNAL_FOUND.value]
    assert "NOT the same as safe" in text
    assert "already claimed" in text


def test_inconclusive_states_the_capability_boundary():
    """A future contributor must read the ceiling as a decision, not a gap."""
    text = TAKEOVER_MEANING[TakeoverVerdict.INCONCLUSIVE.value]
    assert "capability boundary, not caution" in text


def test_provider_guarded_interpolates_when_the_rules_were_reviewed():
    """'guarded' alone is not defensible; 'guarded per catalogue v7, policy
    reviewed 2026-02-11' is."""
    from core.takeover import meaning
    text = meaning(TakeoverVerdict.PROVIDER_GUARDED,
                   evidence(rule_catalogue_version="v7",
                            rule_last_reviewed="2026-02-11"))
    assert "v7" in text and "2026-02-11" in text


def test_probes_unavailable_is_counted_not_hidden():
    from core.takeover import TakeoverReport
    report = TakeoverReport(findings=[], probes_unavailable=4, assessed=6)
    assert "by design rather than by omission" in report.note()
