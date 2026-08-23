"""What the fingerprint run establishes about outside-in reachability.

Until P1 there was nothing in the product that could answer "can an outsider
reach this?", so `engine.score_exposure` was always called with
`external_reachable=None` and every finding reconciled to UNKNOWN. The
reconciliation matrix existed and never had both of its inputs.

THREE STATES, AND THE THIRD IS THE IMPORTANT ONE
------------------------------------------------
    True   a port answered. We connected; there is no ambiguity.
    False  we probed and nothing answered on any port we were allowed to try.
    None   we never probed — no verification, out of scope, or not attempted.

`False` and `None` must never be merged. "We looked and it is closed" is a
finding; "we never looked" is an absence of evidence, and `reconcile()` treats
them completely differently — the first can contradict OverWatch's inside-out
verdict and produce a real disagreement banner, the second cannot contradict
anything.

WHAT `False` DOES NOT MEAN
--------------------------
It does not mean "not exposed". We probe a deliberately narrow port set — the
ports on which a name-based ownership proof actually covers what answers — so a
service on some other port is invisible to us and is reported as such rather
than as absence.
"""
from __future__ import annotations

from typing import Dict, Iterable, Optional, Sequence, Set, Tuple


def from_row(row) -> Tuple[Optional[bool], Tuple[int, ...]]:
    """`(external_reachable, observed_ports)` from a fingerprinted inventory row.

    Reads `obs_open_ports` and `obs_probed_ports`, both written by
    `core/identity.py`. A row that carries neither was never fingerprinted, so
    reachability is None — not False.
    """
    probed = _ports(row.get("obs_probed_ports"))
    if not probed:
        return None, ()
    open_ports = _ports(row.get("obs_open_ports"))
    return (bool(open_ports), open_ports)


def _ports(value) -> Tuple[int, ...]:
    out = []
    for part in str(value or "").split(","):
        part = part.strip()
        if part.isdigit():
            out.append(int(part))
    return tuple(sorted(set(out)))


def explain(reachable: Optional[bool], probed: Sequence[int],
            open_ports: Sequence[int]) -> str:
    if reachable is None:
        return ("not probed, so outside-in reachability is unknown — which is "
                "not the same as unreachable")
    if reachable:
        return (f"answered on {', '.join(str(p) for p in open_ports)}; we "
                f"connected, so this is reachable from outside")
    return (f"probed {', '.join(str(p) for p in probed)} and nothing answered. "
            f"That is not 'not exposed' — a service on any other port is "
            f"outside what a name-based ownership proof lets us try")


__all__ = ["from_row", "explain"]
