"""The supplier register, and the two claims it must never make.

A third-party risk screen is built to make somebody feel covered. The two ways
this one could lie are: reporting vulnerabilities for a supplier it is
structurally unable to assess, and turning its own coverage gap into the
supplier's finding. Most of these tests keep both impossible.
"""
from __future__ import annotations

from datetime import date

import pytest

from core import gate, suppliers
from core.scope import Scope, ScopeKind, ScopeRule
from core.suppliers import RegisterError, Signal, Supplier, Tier

TODAY = date(2026, 8, 23)


def supplier(name="Acme", domain="acme.example", tier=Tier.CRITICAL):
    return Supplier(name=name, domain=domain, tier=tier,
                    dependency="card processing", declared_by="ciso@example.com")


# ── the gate decided this, not the module ───────────────────────────────────
def test_every_active_operation_is_refused_against_an_unverified_supplier():
    """The measurement the whole module is shaped by. A customer cannot prove
    ownership of a supplier's domain, so this is not configurable."""
    scope = Scope([ScopeRule(kind=ScopeKind.DOMAIN, value="supplier.example")])
    for operation in ("http_probe", "tls_handshake", "port_scan",
                      "service_banner_read"):
        with pytest.raises(gate.OwnershipNotVerified):
            gate.authorise(asset="supplier.example", operation=operation,
                           actor="k@example.com", scope=scope, verification=None)


def test_the_passive_operations_a_supplier_assessment_needs_are_allowed():
    scope = Scope([ScopeRule(kind=ScopeKind.DOMAIN, value="supplier.example")])
    for operation in ("ct_log_search", "passive_dns", "rdap_lookup",
                      "dns_resolve_recursive", "whois_lookup"):
        gate.authorise(asset="supplier.example", operation=operation,
                       actor="k@example.com", scope=scope, verification=None)


def test_there_is_no_way_to_produce_a_supplier_cve_count():
    """No active probe, no fingerprint, no product name, no CVE join. A supplier
    vulnerability count on a screen would be a fabrication."""
    for banned in ("vulnerabilities", "cves", "findings_for", "cve_count",
                   "join", "match"):
        assert not hasattr(suppliers, banned), banned
    text = suppliers.Register().to_dict()["no_cve_join"]
    assert "PASSIVE ONLY, and not by choice" in text
    assert "cannot and does not report vulnerabilities for a supplier" in text


# ── the register is declared, never inferred ────────────────────────────────
def test_there_is_no_function_that_infers_a_supplier_relationship():
    """Inventing the wrong commercial fact is worse than an empty register."""
    for banned in ("discover_suppliers", "infer", "detect_suppliers", "guess"):
        assert not hasattr(suppliers, banned), banned


def test_a_supplier_must_be_attributed():
    with pytest.raises(RegisterError) as exc:
        Supplier(name="Acme", domain="acme.example", tier=Tier.ROUTINE,
                 declared_by="")
    assert "who declared the relationship" in str(exc.value)


@pytest.mark.parametrize("bad", ["", "   ", "not a domain", "http://acme.example",
                                 "acme", "-acme.example"])
def test_a_supplier_without_a_usable_domain_is_refused(bad):
    """A supplier with no domain cannot be assessed at all, and that is better
    recorded than silently skipped."""
    with pytest.raises(RegisterError):
        Supplier(name="Acme", domain=bad, tier=Tier.ROUTINE, declared_by="a@b.c")


def test_the_tier_is_the_customers_judgement_not_ours():
    for tier in Tier:
        assert "the organisation states" in tier.meaning


# ── our blind spot is not their finding ─────────────────────────────────────
def test_a_signal_never_looked_up_is_unobserved_not_absent():
    """Collapsing these into 'not configured' turns our coverage gap into their
    gap, which is the commonest lie in this product category."""
    posture = suppliers.assess(supplier(), records={}, today=TODAY)
    assert posture.absent == []
    assert set(posture.unobserved) >= {Signal.SPF, Signal.DMARC, Signal.CAA,
                                       Signal.MTA_STS}


def test_a_signal_looked_up_and_missing_is_absent():
    posture = suppliers.assess(supplier(), records={"TXT": []}, today=TODAY)
    assert Signal.SPF in posture.absent
    assert Signal.SPF not in posture.unobserved


def test_unobserved_survives_into_the_payload_separately():
    payload = suppliers.assess(supplier(), records={}, today=TODAY).to_dict()
    assert payload["unobserved"] and payload["absent"] == []


# ── the signals ─────────────────────────────────────────────────────────────
def test_a_monitoring_only_dmarc_is_not_counted_as_enforcement():
    """`p=none` is the commonest DMARC state, and reporting it as 'has DMARC'
    is how a register goes green while nothing is enforced."""
    posture = suppliers.assess(
        supplier(), records={"_dmarc": ["v=DMARC1; p=none; rua=mailto:a@b.c"]},
        today=TODAY)
    assert Signal.DMARC in posture.present
    assert Signal.DMARC_ENFORCED in posture.absent


@pytest.mark.parametrize("policy", ["p=quarantine", "p = reject", "P=REJECT"])
def test_an_enforced_dmarc_is_recognised(policy):
    posture = suppliers.assess(
        supplier(), records={"_dmarc": [f"v=DMARC1; {policy}"]}, today=TODAY)
    assert Signal.DMARC_ENFORCED in posture.present


def test_every_signal_states_what_it_does_not_mean():
    for signal in Signal:
        assert signal.means and signal.does_not_mean
        assert "does NOT" in signal.does_not_mean


def test_a_permissive_spf_is_still_reported_as_present_and_the_caveat_says_so():
    """The signal is presence. The caveat carries the rest, rather than this
    module quietly grading a record it cannot fully evaluate."""
    posture = suppliers.assess(supplier(), records={"TXT": ["v=spf1 +all"]},
                               today=TODAY)
    assert Signal.SPF in posture.present
    assert "+all" in Signal.SPF.does_not_mean


def test_an_expiring_certificate_is_an_observation_not_a_prediction():
    posture = suppliers.assess(
        supplier(), certificates=[{"not_after": date(2026, 9, 1)}],
        records={}, today=TODAY)
    assert Signal.CERT_EXPIRING in posture.present
    assert any("not a prediction" in n for n in posture.notes)


def test_a_certificate_with_room_left_is_absent_not_unobserved():
    posture = suppliers.assess(
        supplier(), certificates=[{"not_after": date(2027, 1, 1)}],
        records={}, today=TODAY)
    assert Signal.CERT_EXPIRING in posture.absent


# ── concentration ───────────────────────────────────────────────────────────
def register_of(n, provider="shared.example", critical=0):
    out = []
    for i in range(n):
        tier = Tier.CRITICAL if i < critical else Tier.ROUTINE
        out.append(suppliers.assess(
            supplier(name=f"S{i}", domain=f"s{i}.example", tier=tier),
            records={"MX": [f"mx.{provider}"], "NS": [f"ns{i}.own{i}.example"]},
            today=TODAY))
    return out


def test_a_small_register_refuses_rather_than_concluding():
    """Five suppliers sharing one mail provider is a small company using the
    obvious product, not a concentration."""
    found, refusal = suppliers.concentrations(register_of(5))
    assert found == []
    assert refusal and "not a concentration" in refusal


def test_a_large_enough_register_reports_the_shared_provider():
    found, refusal = suppliers.concentrations(register_of(10))
    assert refusal is None
    assert found and found[0].provider == "shared.example"
    assert found[0].kind == "mail"
    assert len(found[0].suppliers) == 10


def test_a_provider_serving_one_supplier_is_not_a_concentration():
    found, _ = suppliers.concentrations(register_of(10))
    assert all(len(c.suppliers) >= suppliers.MIN_SUPPLIERS_PER_PROVIDER
               for c in found)


def test_critical_suppliers_outrank_breadth():
    """A provider carrying three critical suppliers matters more than one
    carrying nine routine ones."""
    postures = register_of(10, provider="wide.example")
    postures += [suppliers.assess(
        supplier(name=f"C{i}", domain=f"c{i}.example", tier=Tier.CRITICAL),
        records={"MX": ["mx.narrow.example"]}, today=TODAY) for i in range(3)]
    found, _ = suppliers.concentrations(postures)
    assert found[0].provider == "narrow.example"
    assert found[0].critical == 3


def test_hosts_of_one_provider_are_not_counted_as_several():
    posture = suppliers.assess(
        supplier(), records={"NS": ["ns1.dnsco.example", "ns2.dnsco.example"]},
        today=TODAY)
    assert posture.providers["dns"] == "dnsco.example"
    assert not posture.notes


def test_genuinely_split_providers_are_recorded_as_a_note():
    posture = suppliers.assess(
        supplier(), records={"NS": ["ns1.a-dns.example", "ns1.b-dns.example"]},
        today=TODAY)
    assert any("2 distinct providers" in n for n in posture.notes)


def test_the_concentration_claim_is_bounded_where_it_is_rendered():
    text = suppliers.CONCENTRATION_MEANING
    assert "AVAILABILITY and BLAST RADIUS" in text
    assert "NOT evidence of a shared vulnerability" in text
    assert "not a judgement about the provider" in text


# ── the register as a whole ─────────────────────────────────────────────────
def test_an_empty_register_is_not_a_supply_chain_with_no_third_parties():
    assert "nobody has written down" in suppliers.Register().headline()


def test_critical_suppliers_sort_first():
    register = suppliers.build(
        [supplier(name="Routine", domain="r.example", tier=Tier.ROUTINE),
         supplier(name="Critical", domain="c.example", tier=Tier.CRITICAL)],
        observations={}, today=TODAY)
    assert register.postures[0].supplier.name == "Critical"


def test_the_refusal_reaches_the_payload_rather_than_an_empty_list():
    """'Your register is too small to say' is an answer the screen must render,
    not an absence it has to infer."""
    register = suppliers.build([supplier()], observations={}, today=TODAY)
    payload = register.to_dict()
    assert payload["concentration_refused"]
    assert payload["concentrations"] == []


def test_the_headline_names_the_largest_concentration():
    declared = [Supplier(name=f"S{i}", domain=f"s{i}.example",
                         tier=Tier.CRITICAL, declared_by="a@b.c")
                for i in range(9)]
    observations = {f"s{i}.example": {"records": {"MX": ["mx.oneprovider.example"]}}
                    for i in range(9)}
    register = suppliers.build(declared, observations, today=TODAY)
    assert "oneprovider.example" in register.headline()
    assert register.refusal is None


# ── truncation: our transport limit is not their configuration ──────────────
def test_a_truncated_response_is_not_conclusive():
    """Found against a real domain. github.com's apex TXT set does not fit in a
    datagram; the resolver returns TC with ancount=0, which is byte-identical
    to NODATA. Before the TC bit was carried, the posture assessment reported
    that GitHub publishes no SPF record. It does.

    This was never supplier-specific: TXT is in DEFAULT_RRTYPES, so the
    customer's own sweep recorded large TXT sets as absent and change tracking
    treated that as an observation.
    """
    from collect.dns_wire import Rcode, Response, RRType
    truncated = Response(name="a.example", rrtype=RRType.TXT, rcode=Rcode.NOERROR,
                         answers=[], truncated=True)
    genuine_nodata = Response(name="a.example", rrtype=RRType.TXT,
                              rcode=Rcode.NOERROR, answers=[])
    assert truncated.conclusive is False
    assert genuine_nodata.conclusive is True, "a real NODATA is still a result"


def test_the_parser_reads_the_tc_bit():
    import struct

    from collect.dns_wire import RRType, build_query, parse_response
    query, txid = build_query("a.example", RRType.TXT)
    # Header echo with QR + TC set, no answers — what a resolver actually sends.
    header = struct.pack(">HHHHHH", txid, 0x8380, 1, 0, 0, 0)
    response = parse_response(header + query[12:], "a.example", RRType.TXT,
                              txid, "1.1.1.1")
    assert response.truncated is True
    assert response.conclusive is False


def test_a_failed_tcp_retry_leaves_the_record_unobserved_not_absent():
    """The retry can fail. What it must never do is report an empty answer."""
    from collect import dns_records
    from collect.dns_wire import RRType

    # An unroutable resolver: whatever the failure, the outcome must be the same.
    response = dns_records.resolve_over_tcp(
        permit=None, name="a.example", rrtype=RRType.TXT,
        resolver="203.0.113.1", budget=None, limiter=None)
    assert response.unreadable is True
    assert response.conclusive is False


def test_passive_tcp_may_only_reach_a_declared_resolver():
    """The TCP retry gained an allowlist for the same reason udp has one: a
    passive permit proved no ownership, so its destination must not be a
    free-form argument."""
    from collect import egress
    with pytest.raises(egress.PermitMismatch) as exc:
        with egress.tcp(permit=None, operation="dns_resolve_recursive",
                        address="198.51.100.9", port=53):
            pass
    assert "may only connect to the declared" in str(exc.value)


# ── which signals actually discriminate, measured in the wild ───────────────
def test_the_module_records_that_presence_signals_are_near_universal():
    """Measured across 8 real domains: SPF 8/8 and DMARC 8/8, so PRESENCE of
    either separates nobody. Enforcement 7/8, CAA 3/8, MTA-STS 1/8 do. A screen
    that leads with an SPF column shows a column of 'yes' and teaches the reader
    the whole panel is decorative."""
    assert "8/8" in suppliers.DISCRIMINATION
    assert "presence of either separates nobody" in suppliers.DISCRIMINATION.lower()
    for signal in suppliers.DISCRIMINATING:
        assert signal in Signal
    assert Signal.SPF not in suppliers.DISCRIMINATING
    assert Signal.DMARC not in suppliers.DISCRIMINATING
    assert Signal.DMARC_ENFORCED in suppliers.DISCRIMINATING
