"""What we think a service is, and how much that claim is worth.

Fingerprinting is the load-bearing feature of P1. Certificate transparency finds
NAMES, not technologies, so discovery writes `product="unknown"` — which matches
0 of the catalogue's 1,674 entries. A 400-host discovery therefore produces zero
findings today. Filling `product` is what connects discovery to scoring.

THREE ATTESTATIONS, NO SCORE
----------------------------
    SELF_REPORTED  the asset said so — `Server:`, `X-Powered-By:`
    INFERRED       concluded from behaviour the asset did not intend as a claim
                   — a certificate subject, a default error page's byte pattern
    OPERATOR       the customer's own record

They are not points on a scale, they fail in different ways. A SELF_REPORTED
banner is switched off by one line of configuration and edited freely by anyone
who owns the box. An INFERRED signal is a side effect of running the software,
so suppressing it means changing the software's behaviour. Collapsing them into
a number would invite a threshold, the threshold would be tuned until the list
looked reasonable, and the tuning would quietly become the product's real
opinion — the argument `core/models.py:Confidence` already makes.

A FINGERPRINT CAN NEVER JUSTIFY A VERSION DETERMINATION
------------------------------------------------------
`core/models.py` draws the line between PRODUCT_MATCH (a worklist) and
VERSION_RANGE (a determination). A banner version is not an outside fact about
the build — it is the assertion of the party whose patch state is the entire
question, and it fails both ways: distribution backporting makes it a false
positive, header suppression a false negative.

The danger is not hypothetical. `core/engine.py:score_exposure` sets
`basis = VERSION_RANGE` for NOT_AFFECTED as well as AFFECTED, and NOT_AFFECTED
RETIRES the finding. A spoofed high version would therefore delete entries from
the customer's worklist. It is inert today only because `affected_versions` is
never passed — and it would become determination-grade the day CNA ranges are
wired, with no code change and no review.

So the refusal is structural rather than a rule somebody has to remember: the
observed version is written to `obs_version`, which normalises to `obsversion`
and is NOT in `inventory.ALIASES["version"]` (measured). It lands in
`attributes`, where `affected.evaluate()` — which reads `asset.version` only —
cannot reach it.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.provenance import observed, redact


class Attestation(str, enum.Enum):
    SELF_REPORTED = "self_reported"
    INFERRED = "inferred"
    OPERATOR = "operator"

    @property
    def can_determine_version(self) -> bool:
        """Only the customer's own record may set the field a range is
        evaluated against. See the module docstring."""
        return self is Attestation.OPERATOR

    @property
    def meaning(self) -> str:
        return {
            Attestation.SELF_REPORTED:
                "the service said so; anyone who controls it can say otherwise, "
                "and one line of configuration removes the claim entirely",
            Attestation.INFERRED:
                "concluded from behaviour the service did not intend as a claim, "
                "so suppressing it would mean changing how the software behaves",
            Attestation.OPERATOR:
                "the customer's own record, not something we observed",
        }[self]


@dataclass(frozen=True)
class IdentitySignal:
    """One observation that bears on what a service is."""

    #: Where it came from: "http.server_header", "tls.subject", "body.pattern".
    source: str
    value: str
    attestation: Attestation
    port: Optional[int] = None

    def __post_init__(self) -> None:
        if not str(self.source).strip():
            raise ValueError("a signal must say where it came from")

    @property
    def safe_value(self) -> str:
        """Target-controlled text, with CVE references neutralised.

        A `Server:` header is written by whoever owns the box. Without this, a
        header reading `blocks cve-2021-44228` reaches `declared_cves()` and is
        promoted to a STRONG finding attributed to the customer's inventory.
        See core/provenance.py, which carries the measurement.
        """
        return redact(self.value)


@dataclass
class Fingerprint:
    """What one host is, as far as this product is willing to say."""

    host: str
    #: The catalogue's spelling, from a reviewed table — never a raw banner.
    product: str = "unidentified"
    vendor: Optional[str] = None
    #: Observed version. Deliberately NOT written to Asset.version. See above.
    observed_version: Optional[str] = None
    attestation: Optional[Attestation] = None
    signals: List[IdentitySignal] = field(default_factory=list)
    #: Ports that answered, for the reachability half of the reconciliation.
    open_ports: Tuple[int, ...] = ()
    #: Ports tried that did not answer. Distinguishes "closed" from "not tried".
    probed_ports: Tuple[int, ...] = ()

    @property
    def identified(self) -> bool:
        return self.product not in ("unidentified", "unknown", "")

    def inventory_row(self) -> Dict[str, Any]:
        """The row the scan reads.

        `product` carries the canonical name; everything observed goes into
        prefixed columns so `declared_cves()` cannot mistake a third party's
        text for the customer's assertion, and `obs_version` cannot reach the
        field a published range is evaluated against.
        """
        row: Dict[str, Any] = {
            "identifier": self.host,
            # 'unidentified' is NOT 'unknown'. `unknown` means never probed;
            # `unidentified` means probed and no signature fired. Both are in
            # match.STOPWORDS, so neither can join anything — but an operator
            # reading the sidecar needs to know which action to take, and only
            # one of them is "run the fingerprinter".
            "product": self.product,
        }
        if self.vendor:
            row["vendor"] = self.vendor
        row[observed("version")] = self.observed_version or ""
        row[observed("attestation")] = (self.attestation.value
                                        if self.attestation else "")
        row[observed("open_ports")] = ",".join(str(p) for p in self.open_ports)
        row[observed("probed_ports")] = ",".join(str(p) for p in self.probed_ports)
        row[observed("signals")] = "; ".join(
            f"{s.source}={s.safe_value}" for s in self.signals)[:500]
        return row


@dataclass
class FingerprintRun:
    """A whole run, and the counts that keep its gaps visible."""

    fingerprints: List[Fingerprint] = field(default_factory=list)
    #: Hosts the gate refused, with the reason. Never silently skipped.
    refused: List[Tuple[str, str]] = field(default_factory=list)
    #: Hosts not attempted because a budget ran out.
    unattempted: List[str] = field(default_factory=list)

    @property
    def identified(self) -> int:
        return sum(1 for f in self.fingerprints if f.identified)

    @property
    def probed_unidentified(self) -> int:
        return sum(1 for f in self.fingerprints if not f.identified)

    def note(self) -> str:
        """The sentence that keeps a partial run from reading as a whole one."""
        parts = [f"{len(self.fingerprints)} host(s) probed: "
                 f"{self.identified} identified, "
                 f"{self.probed_unidentified} answered but matched no signature"]
        if self.refused:
            parts.append(
                f"{len(self.refused)} refused by the gate "
                f"({'; '.join(f'{h}: {why[:60]}' for h, why in self.refused[:3])}"
                + (" ..." if len(self.refused) > 3 else "") + ")")
        if self.unattempted:
            parts.append(
                f"{len(self.unattempted)} NOT ATTEMPTED — the run's budget was "
                f"spent before reaching them. They are not 'nothing found'.")
        return ". ".join(parts) + "."


#: Served rather than hard-coded in the console, on the RECONCILIATION_MEANING
#: precedent, so the API, the CLI and the UI cannot drift.
ATTESTATION_MEANING: Dict[str, str] = {a.value: a.meaning for a in Attestation}

__all__ = ["Attestation", "IdentitySignal", "Fingerprint", "FingerprintRun",
           "ATTESTATION_MEANING"]
