"""Append-only audit log with a hash chain.

SRS FR-M0-007. Every state change, scope edit, verification event, export and
acknowledgement lands here, and the acceptance criterion is that tampering with
any row breaks chain verification.

WHAT A HASH CHAIN ACTUALLY PROVES, AND WHAT IT DOES NOT
-------------------------------------------------------
It proves that no record has been ALTERED and that none has been REMOVED FROM
THE MIDDLE: each entry commits to its predecessor, so changing or deleting entry
N invalidates every hash from N onward.

It does not prove the log is COMPLETE. An attacker with write access can truncate
from the end — delete the last k entries — and the remaining chain verifies
perfectly, because nothing in a chain commits to its own length. This is a
property of the construction, not a defect in this implementation, and pretending
otherwise would be worse than the gap.

Three things narrow it, and they are stated rather than implied:

  * `verify()` returns the sequence number and hash of the head, so an external
    observer that records the head periodically detects truncation back to any
    point it has already witnessed. Anchoring is the caller's job; this module
    makes it possible by exposing the head.
  * the sequence is dense and gap-checked, so removal from the middle is caught
    twice over — by the chain and by the numbering.
  * `expected_seq` on verify() lets a caller who knows how many records there
    should be assert it, which is the only way to catch tail truncation from
    inside.

Append-only is not left to this module's good manners. In `db/001_schema.sql`
the `audit_log` table carries DO-INSTEAD-NOTHING rules on UPDATE and DELETE, and
the application role is granted only SELECT and INSERT on it. So a bug here, or
an injected statement anywhere in SKOPOS, cannot rewrite history and re-chain it
to match. A superuser can still drop those rules — that is inherent to running a
database, and the answer is that the app does not connect as one.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: The hash of the record before the first. A fixed, published constant so an
#: empty log has a well-defined head rather than a special case.
GENESIS = "0" * 64


def _canonical(payload: Any) -> str:
    """A byte-stable rendering of a payload.

    `sort_keys` and fixed separators matter: a chain over a rendering that
    depends on dict ordering would break whenever Python, a library, or a
    round-trip through JSON reordered a key, and the breakage would look exactly
    like tampering. A verification that cries wolf is a verification nobody runs.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def compute_hash(seq: int, at: str, actor: str, action: str,
                 payload: Any, prev_hash: str) -> str:
    """The record's commitment to itself and its predecessor.

    Fields are length-prefixed rather than concatenated. Without that, an actor
    named `a` acting on `bc` and one named `ab` acting on `c` would hash
    identically, and a log is exactly the place someone would try it.
    """
    parts = [str(seq), at, actor, action, _canonical(payload), prev_hash]
    material = "|".join(f"{len(p)}:{p}" for p in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    at: str
    actor: str
    action: str
    payload: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS
    record_hash: str = ""

    def recompute(self) -> str:
        return compute_hash(self.seq, self.at, self.actor, self.action,
                            self.payload, self.prev_hash)

    @property
    def intact(self) -> bool:
        return bool(self.record_hash) and self.record_hash == self.recompute()


@dataclass(frozen=True)
class ChainVerdict:
    ok: bool
    records: int
    head_seq: int
    head_hash: str
    #: Populated only on failure, and specific enough to act on.
    broken_at: Optional[int] = None
    reason: str = ""

    def explain(self) -> str:
        if self.ok:
            return (f"chain intact over {self.records} record(s); "
                    f"head seq {self.head_seq} hash {self.head_hash[:16]}…")
        return f"chain BROKEN at seq {self.broken_at}: {self.reason}"


class AuditChain:
    """Builds and verifies the chain. Storage is somebody else's job."""

    def __init__(self, records: Sequence[AuditRecord] = ()) -> None:
        self._records: List[AuditRecord] = list(records)

    def __len__(self) -> int:
        return len(self._records)

    @property
    def records(self) -> Sequence[AuditRecord]:
        return tuple(self._records)

    @property
    def head(self) -> Tuple[int, str]:
        """`(seq, hash)` of the last record — the value to anchor externally."""
        if not self._records:
            return 0, GENESIS
        last = self._records[-1]
        return last.seq, last.record_hash

    def append(self, actor: str, action: str,
               payload: Optional[Dict[str, Any]] = None,
               at: Optional[str] = None) -> AuditRecord:
        """Add a record. There is deliberately no update and no delete."""
        if not str(actor).strip():
            raise ValueError("an audit record with no actor is not an audit record")
        if not str(action).strip():
            raise ValueError("an audit record needs an action")
        prev_seq, prev_hash = self.head
        seq = prev_seq + 1
        stamp = at or datetime.now(timezone.utc).isoformat(timespec="seconds")
        body = dict(payload or {})
        record = AuditRecord(
            seq=seq, at=stamp, actor=str(actor), action=str(action),
            payload=body, prev_hash=prev_hash,
            record_hash=compute_hash(seq, stamp, str(actor), str(action),
                                     body, prev_hash),
        )
        self._records.append(record)
        return record

    def verify(self, expected_seq: Optional[int] = None) -> ChainVerdict:
        """Walk the chain.

        `expected_seq` is how a caller who independently knows the head detects
        TAIL TRUNCATION, which the chain alone cannot see. Pass the value from a
        previous anchor.
        """
        prev_hash = GENESIS
        prev_seq = 0
        for record in self._records:
            if record.seq != prev_seq + 1:
                return ChainVerdict(False, len(self._records), prev_seq, prev_hash,
                                    record.seq,
                                    f"sequence jumped from {prev_seq} to "
                                    f"{record.seq}; a record was removed")
            if record.prev_hash != prev_hash:
                return ChainVerdict(False, len(self._records), prev_seq, prev_hash,
                                    record.seq,
                                    "does not commit to the previous record's hash")
            if not record.intact:
                return ChainVerdict(False, len(self._records), prev_seq, prev_hash,
                                    record.seq,
                                    "contents do not match the recorded hash")
            prev_hash, prev_seq = record.record_hash, record.seq

        if expected_seq is not None and prev_seq < expected_seq:
            # The one truncation case detectable from inside, and only because
            # the caller brought outside knowledge.
            return ChainVerdict(False, len(self._records), prev_seq, prev_hash,
                                prev_seq + 1,
                                f"log ends at seq {prev_seq} but seq "
                                f"{expected_seq} was previously witnessed; "
                                f"{expected_seq - prev_seq} record(s) truncated "
                                f"from the end")
        return ChainVerdict(True, len(self._records), prev_seq, prev_hash)
