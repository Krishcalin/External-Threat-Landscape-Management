"""FR-M0-007: tampering with any audit record breaks chain verification.

And the honest counterpart: what the chain cannot see.
"""
from __future__ import annotations

import dataclasses

import pytest

from core.audit import GENESIS, AuditChain, AuditRecord, compute_hash
from core.ownership import Method, Verification
from core.scope import ScopeKind, ScopeRule
from core.store import MemoryStore


def chain_of(n: int) -> AuditChain:
    chain = AuditChain()
    for i in range(n):
        chain.append("k.de", "scope.rule.added", {"value": f"host{i}.example.com"})
    return chain


# -- the acceptance criterion ------------------------------------------------
def test_an_intact_chain_verifies():
    verdict = chain_of(5).verify()
    assert verdict.ok
    assert verdict.records == 5
    assert verdict.head_seq == 5


def test_altering_a_payload_breaks_the_chain_at_that_record():
    chain = chain_of(5)
    records = list(chain.records)
    records[2] = dataclasses.replace(records[2], payload={"value": "attacker.net"})
    verdict = AuditChain(records).verify()
    assert not verdict.ok
    assert verdict.broken_at == 3
    assert "do not match the recorded hash" in verdict.reason


def test_altering_the_actor_breaks_the_chain():
    chain = chain_of(3)
    records = list(chain.records)
    records[0] = dataclasses.replace(records[0], actor="somebody-else")
    assert not AuditChain(records).verify().ok


def test_removing_a_middle_record_breaks_the_chain():
    chain = chain_of(5)
    records = [r for r in chain.records if r.seq != 3]
    verdict = AuditChain(records).verify()
    assert not verdict.ok
    assert "a record was removed" in verdict.reason


def test_rechaining_after_tampering_still_fails_against_a_known_head():
    """The realistic attack: edit a record and recompute every hash after it.

    The chain alone cannot catch this — a fully recomputed chain is internally
    consistent. What catches it is that the head hash no longer matches what an
    external observer recorded, which is exactly why `head` is exposed.
    """
    original = chain_of(4)
    witnessed_seq, witnessed_hash = original.head

    forged = AuditChain()
    for record in original.records:
        payload = ({"value": "attacker.net"} if record.seq == 2 else record.payload)
        forged.append(record.actor, record.action, payload, at=record.at)

    assert forged.verify().ok, "a recomputed chain is internally consistent"
    forged_seq, forged_hash = forged.head
    assert forged_seq == witnessed_seq
    assert forged_hash != witnessed_hash, "which is what the external anchor sees"


# -- what the chain cannot see, stated as a test -----------------------------
def test_tail_truncation_passes_verification_unless_a_head_is_known():
    """Documented limitation, not an oversight. See core/audit.py."""
    chain = chain_of(6)
    truncated = AuditChain(list(chain.records)[:4])
    assert truncated.verify().ok, "nothing in a chain commits to its own length"

    caught = truncated.verify(expected_seq=6)
    assert not caught.ok
    assert "truncated from the end" in caught.reason


# -- construction details that matter ---------------------------------------
def test_field_boundaries_cannot_be_shifted():
    """Length-prefixing: ('a','bc') and ('ab','c') must not hash alike."""
    one = compute_hash(1, "t", "a", "bc", {}, GENESIS)
    two = compute_hash(1, "t", "ab", "c", {}, GENESIS)
    assert one != two


def test_key_order_does_not_change_the_hash():
    """A verification that cries wolf on dict reordering is one nobody runs."""
    first = compute_hash(1, "t", "k.de", "x", {"a": 1, "b": 2}, GENESIS)
    second = compute_hash(1, "t", "k.de", "x", {"b": 2, "a": 1}, GENESIS)
    assert first == second


def test_empty_chain_has_a_defined_head():
    chain = AuditChain()
    assert chain.head == (0, GENESIS)
    assert chain.verify().ok


def test_first_record_commits_to_genesis():
    record = AuditChain().append("k.de", "boot")
    assert record.prev_hash == GENESIS
    assert record.seq == 1
    assert record.intact


def test_a_record_needs_an_actor_and_an_action():
    chain = AuditChain()
    with pytest.raises(ValueError):
        chain.append("  ", "scope.rule.added")
    with pytest.raises(ValueError):
        chain.append("k.de", "")


def test_a_record_with_no_hash_is_not_intact():
    """Guards the `bool(record_hash)` check — an empty hash must not pass."""
    hollow = AuditRecord(seq=1, at="t", actor="k.de", action="x",
                         payload={}, prev_hash=GENESIS, record_hash="")
    assert not hollow.intact


# -- the store keeps the same guarantees ------------------------------------
def test_memory_store_chains_across_appends():
    store = MemoryStore()
    store.append_audit("k.de", "scope.rule.added", {"value": "example.com"})
    store.append_audit("k.de", "ownership.verified", {"asset": "example.com"})
    verdict = store.verify_audit()
    assert verdict.ok and verdict.head_seq == 2


def test_store_returns_the_newest_live_verification():
    """Re-proving ownership extends the window; a stale row must not shorten it."""
    from datetime import date, timedelta

    today = date(2026, 8, 22)
    store = MemoryStore()
    older = Verification.granted("example.com", Method.DNS_TXT,
                                 on=today - timedelta(days=100))
    newer = Verification.granted("example.com", Method.DNS_TXT, on=today)
    store.record_verification(older)
    store.record_verification(newer)
    live = store.live_verification("example.com", today)
    assert live is not None and live.expires_at == newer.expires_at


def test_store_ignores_expired_verifications():
    from datetime import date, timedelta

    today = date(2026, 8, 22)
    store = MemoryStore()
    store.record_verification(
        Verification.granted("example.com", Method.DNS_TXT,
                             on=today - timedelta(days=400)))
    assert store.live_verification("example.com", today) is None


def test_scope_round_trips_through_the_store():
    store = MemoryStore()
    store.add_scope_rule(ScopeRule(kind=ScopeKind.WILDCARD, value="example.com"),
                         actor="k.de")
    store.add_scope_rule(ScopeRule(kind=ScopeKind.DOMAIN, value="vpn.example.com",
                                   is_exclude=True), actor="k.de")
    scope = store.load_scope()
    assert scope.includes("api.example.com")
    assert not scope.includes("vpn.example.com")
