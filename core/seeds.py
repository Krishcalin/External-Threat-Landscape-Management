"""The four things you can hand SKOPOS to start from, and what each can answer.

`core/lookup.py:parse` refuses an email address, and gives this reason:

    breach exposure for an address is a different question with a different
    source, and answering it here would mean one box quietly doing two
    unrelated things

That objection is about ONE BOX, not about the question. A typed seed — where
the operator says which kind of thing they are supplying and the screen says
what that kind can answer before anything runs — is the shape that objection
was asking for. So this module does not weaken that refusal; it satisfies it.

WHAT EACH SEED HONESTLY BUYS
-------------------------------
The four are not equivalent, and a screen that presented them as four
interchangeable boxes would be lying by layout.

**DOMAIN** — the strongest seed by a distance. Certificate transparency,
passive DNS, RDAP, the vendored abuse feeds, leak-site listings and CTI
correlation all key on names, and CT alone routinely turns one apex into
hundreds of hosts nobody remembered.

**ADDRESS** — strong but narrow. Reverse DNS, RDAP, abuse-feed membership and
CTI correlation all work. What it cannot do is expand: an address does not
tell you the other addresses, so a seed of five IPs stays five IPs.

**ORGANISATION** — the weakest, and the one most likely to be misread. It
produces CANDIDATES for the triage queue and NOTHING ELSE. An organisation name
is not a unique key: "Acme" is a hundred companies, a CA-validated `O=` field
is whoever paid for the certificate, and neither is evidence that anything
found belongs to the estate. `core/candidates.py` already holds the right
shape — a question a person answers, never an addition to scope.

**EMAIL** — split in two, and only one half exists.

  * The DOMAIN half — breach exposure across a domain — is real, and
    `collect/keyed_sources.py:hibp_domain` implements it. It needs an API key
    AND a live ownership verification, because HIBP only answers domain search
    for a domain you have proven you control. SKOPOS reuses its own ownership
    proof rather than inventing a second one.
  * The INDIVIDUAL half — "is this person in a breach" — is refused. It is a
    declared gap (`core/refusals.py`: "monitoring a million external identities
    is not" planned), and an arbitrary address belongs to a person who is not
    the operator's customer. `WHY_NOT_INDIVIDUAL` says so on the seed itself.

SO THE LOCAL PART OF AN ADDRESS IS DISCARDED IMMEDIATELY
-----------------------------------------------------------
`Seed.value` for an email holds the DOMAIN, never the mailbox. Not redacted at
render time — never stored. A pipeline that carries `someone@example.com`
through to a report has created a document about a person, and the only
reliable way not to do that is to not have the string.
"""
from __future__ import annotations

import enum
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from core import lookup as _lookup

#: A deliberately permissive shape check. Validating an address properly is
#: RFC 5322 and pointless here, because the mailbox is discarded either way —
#: all this decides is "did the operator mean an email".
_EMAIL = re.compile(r"^[^@\s]+@([^@\s]+)$")

#: An organisation name is free text, so the only real limits are practical.
MAX_ORG_LEN = 120
MIN_ORG_LEN = 2


class SeedKind(str, enum.Enum):
    DOMAIN = "domain"
    ADDRESS = "address"
    ORGANISATION = "organisation"
    EMAIL = "email"


class SeedRefused(ValueError):
    """The input cannot be used as a seed of the kind it was offered as."""


#: Rendered on any email seed, and on the refusal if somebody asks for the
#: individual form.
WHY_NOT_INDIVIDUAL = (
    "SKOPOS answers breach exposure for a DOMAIN YOU HAVE VERIFIED, never for "
    "an individual address. Two reasons, and either alone is enough: "
    "monitoring individual identities is a declared gap rather than something "
    "half-built, and an arbitrary address belongs to a person who is not your "
    "customer. The mailbox is discarded at input — only the domain is kept, so "
    "no report this produces can name anybody."
)

#: Rendered on any organisation seed.
WHY_ORG_IS_ONLY_A_QUESTION = (
    "An organisation name produces CANDIDATES for the triage queue and nothing "
    "else. It is not a unique key — 'Acme' is a hundred companies, and a "
    "CA-validated organisation field names whoever bought the certificate. "
    "Nothing found this way enters scope, because nothing in this product "
    "decides what it is allowed to scan."
)


@dataclass(frozen=True)
class Seed:
    """One validated starting point, and what it is honestly good for."""

    kind: SeedKind
    #: For EMAIL this is the DOMAIN. The mailbox is never stored — see the
    #: module docstring.
    value: str
    #: What the operator typed, minus anything personal. Kept so the screen can
    #: show them what became of their input rather than silently rewriting it.
    as_entered: str = ""
    note: str = ""

    @property
    def expands(self) -> bool:
        """Whether this seed can discover assets beyond itself."""
        return self.kind is SeedKind.DOMAIN

    def capabilities(self) -> Dict[str, Any]:
        """What will run for this seed, and what will not. Rendered BEFORE the
        run, because an expectation set afterwards is an excuse."""
        if self.kind is SeedKind.DOMAIN:
            return {
                "runs": ["certificate transparency", "passive DNS", "RDAP",
                         "abuse feeds", "leak-site listings",
                         "CTI correlation"],
                "expands_to_new_assets": True,
                "limits": ("Passive only. Nothing here contacts the domain, so "
                           "it reports what the domain PUBLISHES, not what it "
                           "runs. Fingerprinting is active and needs verified "
                           "ownership."),
            }
        if self.kind is SeedKind.ADDRESS:
            return {
                "runs": ["reverse DNS", "RDAP", "abuse feeds",
                         "CTI correlation"],
                "expands_to_new_assets": False,
                "limits": ("An address does not tell you the other addresses, "
                           "so a seed of five stays five. Shared hosting and "
                           "CDN ranges put unrelated tenants behind one "
                           "address, so a hit is about the address and not "
                           "necessarily about you."),
            }
        if self.kind is SeedKind.ORGANISATION:
            return {
                "runs": ["certificate organisation search"],
                "expands_to_new_assets": False,
                "produces": "candidates for the triage queue",
                "limits": WHY_ORG_IS_ONLY_A_QUESTION,
            }
        return {
            "runs": ["domain breach exposure (HIBP)"],
            "expands_to_new_assets": False,
            "requires": ["a HIBP API key", "a live ownership verification for "
                         "this domain"],
            "limits": WHY_NOT_INDIVIDUAL,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "value": self.value,
            "as_entered": self.as_entered,
            "note": self.note,
            "expands": self.expands,
            "capabilities": self.capabilities(),
        }


def _domain_of_email(raw: str) -> str:
    match = _EMAIL.match(str(raw or "").strip())
    if not match:
        raise SeedRefused(
            "that does not look like an email address. Expected something of "
            "the form name@example.com")
    return match.group(1).strip().lower().rstrip(".")


def parse_seed(raw: str, kind: Optional[SeedKind] = None) -> Seed:
    """One input, classified. `kind` is what the operator SAID it was.

    Passing `kind` is the point of this module: the screen offers four labelled
    fields, so the classification is a stated intent rather than a guess. It is
    still validated — an operator who types a hostname into the address field
    should be told, not quietly obeyed.

    With no `kind`, a best-effort classification runs. That path exists for
    pasted lists and is deliberately conservative: anything that is not
    obviously an address, a domain or an email is an ORGANISATION, because free
    text is what an organisation name is.
    """
    text = str(raw or "").strip()
    if not text:
        raise SeedRefused("nothing to look up")

    if kind is SeedKind.EMAIL or (kind is None and "@" in text):
        domain = _domain_of_email(text)
        # The mailbox is discarded HERE. See the module docstring: the reliable
        # way not to produce a document about a person is to not hold the
        # string in the first place.
        try:
            target = _lookup.parse(domain)
        except _lookup.TargetError as exc:
            raise SeedRefused(
                f"the domain part of that address is not usable: {exc}") from exc
        return Seed(SeedKind.EMAIL, target.value, as_entered=f"…@{domain}")

    if kind is SeedKind.ORGANISATION:
        if len(text) < MIN_ORG_LEN:
            raise SeedRefused("that is too short to be an organisation name")
        if len(text) > MAX_ORG_LEN:
            raise SeedRefused("that is too long to be an organisation name")
        return Seed(SeedKind.ORGANISATION, text, as_entered=text)

    if kind in (SeedKind.DOMAIN, SeedKind.ADDRESS, None):
        try:
            target = _lookup.parse(text)
        except _lookup.TargetError as exc:
            if kind is None:
                # Free text is what an organisation name is.
                if MIN_ORG_LEN <= len(text) <= MAX_ORG_LEN:
                    return Seed(SeedKind.ORGANISATION, text, as_entered=text)
            raise SeedRefused(str(exc)) from exc

        is_address = target.kind in (_lookup.Kind.ADDRESS, _lookup.Kind.BLOCK)
        # An operator who typed a hostname into the address field is told,
        # rather than quietly obeyed — the two seeds do very different things
        # and silently reinterpreting one as the other hides that.
        if kind is SeedKind.ADDRESS and not is_address:
            raise SeedRefused(
                f"{text!r} is a name, not an address. Names go in the domain "
                "field, where certificate transparency can expand them — an "
                "address seed cannot.")
        if kind is SeedKind.DOMAIN and is_address:
            raise SeedRefused(
                f"{text!r} is an address, not a name. Addresses go in the "
                "address field; putting one here would promise certificate "
                "expansion that cannot happen.")
        resolved = SeedKind.ADDRESS if is_address else SeedKind.DOMAIN
        return Seed(resolved, target.value, as_entered=text)

    raise SeedRefused(f"{kind!r} is not a seed kind")


def parse_many(raw: Sequence[Any]) -> Tuple[List[Seed], List[Dict[str, str]]]:
    """Many inputs at once. Returns (accepted, refused-with-reasons).

    REFUSALS ARE RETURNED, NOT RAISED. A screen that discards ten good seeds
    because the eleventh had a typo teaches the operator to paste less, and a
    smaller estate is the opposite of the point.
    """
    accepted: List[Seed] = []
    refused: List[Dict[str, str]] = []
    seen = set()
    for item in raw or ():
        if isinstance(item, dict):
            text, kind_name = item.get("value"), item.get("kind")
        else:
            text, kind_name = item, None
        try:
            kind = SeedKind(kind_name) if kind_name else None
        except ValueError:
            refused.append({"input": str(text), "why": f"unknown kind {kind_name!r}"})
            continue
        try:
            seed = parse_seed(str(text or ""), kind)
        except SeedRefused as exc:
            refused.append({"input": str(text or ""), "why": str(exc)})
            continue
        key = (seed.kind, seed.value)
        if key in seen:
            continue
        seen.add(key)
        accepted.append(seed)
    return accepted, refused


def summarise(seeds: Sequence[Seed]) -> Dict[str, Any]:
    """What this set of seeds can and cannot reach, before anything runs.

    The counts matter more than they look. A landscape built from ten addresses
    and no domain cannot expand at all, and an operator who does not know that
    reads a small result as a small estate.
    """
    by_kind: Dict[str, int] = {}
    for seed in seeds:
        by_kind[seed.kind.value] = by_kind.get(seed.kind.value, 0) + 1
    expanding = sum(1 for s in seeds if s.expands)
    notes: List[str] = []
    if seeds and not expanding:
        notes.append(
            "NOTHING HERE EXPANDS. Only a domain seed can discover assets you "
            "did not supply. A landscape built from addresses, organisation "
            "names and email domains alone will contain exactly what you typed "
            "— which is not the same as an estate having nothing else in it.")
    if by_kind.get("organisation"):
        notes.append(WHY_ORG_IS_ONLY_A_QUESTION)
    if by_kind.get("email"):
        notes.append(WHY_NOT_INDIVIDUAL)
    return {
        "seeds": len(seeds),
        "by_kind": dict(sorted(by_kind.items())),
        "expanding_seeds": expanding,
        "notes": notes,
        "passive_only": _lookup.PASSIVE_ONLY,
    }


# ── assembling a landscape from per-seed outcomes ───────────────────────────
#: Seeds contacted in one run. Each one performs several outbound lookups, so
#: this is a wall-clock bound as much as a politeness one.
#:
#: REPORTED, never applied quietly — `core/validation.py` and `core/itsm.py`
#: announce their caps for the same reason: a truncated result that does not
#: say it was truncated reads as a complete one.
MAX_SEEDS_PER_RUN = 12


@dataclass
class Outcome:
    """What one seed produced, or why it produced nothing.

    A FAILED SEED IS A RESULT, not an exception. One unreachable source must
    not discard the work done for every other seed — and a landscape that
    silently omits the seed that failed is indistinguishable from one where
    that seed found nothing.
    """

    seed: "Seed"
    assets: Tuple[str, ...] = ()
    candidates: Tuple[Dict[str, Any], ...] = ()
    findings: Tuple[Dict[str, Any], ...] = ()
    #: Sources consulted that could not answer, each with what its absence
    #: costs. Never dropped: a result missing a source reads as a clean one.
    unavailable: Tuple[Dict[str, Any], ...] = ()
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seed": self.seed.to_dict(),
            "assets": list(self.assets),
            "discovered": max(0, len(self.assets) - (1 if self.seed.expands else 0)),
            "candidates": [dict(c) for c in self.candidates],
            "findings": [dict(f) for f in self.findings],
            "unavailable": [dict(u) for u in self.unavailable],
            "error": self.error or None,
        }


def combine(outcomes: Sequence[Outcome],
            dropped_by_cap: int = 0) -> Dict[str, Any]:
    """Per-seed outcomes into one landscape, with its own limits attached.

    THE COVERAGE STATEMENT IS THE POINT. An estate view assembled from passive
    sources is a floor, never a census: it contains what the seeds could reach,
    and an operator reading it as "this is my estate" has been misled by a
    number rather than by a sentence.
    """
    assets: List[str] = []
    seen = set()
    candidates: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    unavailable: List[Dict[str, Any]] = []
    failed: List[Dict[str, str]] = []

    for outcome in outcomes:
        for asset in outcome.assets:
            key = asset.lower()
            if key not in seen:
                seen.add(key)
                assets.append(asset)
        candidates.extend(dict(c) for c in outcome.candidates)
        findings.extend(dict(f) for f in outcome.findings)
        for item in outcome.unavailable:
            if item not in unavailable:
                unavailable.append(dict(item))
        if outcome.error:
            failed.append({"seed": outcome.seed.value, "why": outcome.error})

    supplied = {s.seed.value.lower() for s in outcomes}
    discovered = [a for a in assets if a.lower() not in supplied]

    notes: List[str] = []
    if dropped_by_cap:
        notes.append(
            f"{dropped_by_cap} seed(s) were not run: this stops at "
            f"{MAX_SEEDS_PER_RUN} per run. Run the rest separately — they were "
            "not judged uninteresting, they were not attempted.")
    if failed:
        notes.append(
            f"{len(failed)} seed(s) failed and contributed nothing. A "
            "landscape missing them is not a landscape where they were clean.")
    if not discovered and any(o.seed.expands for o in outcomes):
        notes.append(
            "No assets were discovered beyond what you supplied. Certificate "
            "transparency only holds names a CA has issued for, so a domain "
            "with no public certificates expands to nothing — which is a fact "
            "about the certificate record, not about the estate.")

    return {
        "assets": assets,
        "asset_count": len(assets),
        "discovered": discovered,
        "discovered_count": len(discovered),
        "candidates": candidates,
        "findings": findings,
        "unavailable": unavailable,
        "failed_seeds": failed,
        "dropped_by_cap": dropped_by_cap,
        "notes": notes,
        "coverage_means": (
            "A FLOOR, NEVER A CENSUS. This is what the seeds you supplied "
            "could reach through passive sources. Certificate transparency "
            "finds names a CA issued for; passive DNS finds names somebody "
            "else resolved. Neither enumerates an estate, and an asset absent "
            "here has not been shown not to exist."),
        "passive_only": _lookup.PASSIVE_ONLY,
    }
