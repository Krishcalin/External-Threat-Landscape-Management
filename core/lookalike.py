"""Names that borrow somebody's brand, found in certificate transparency.

WHY THIS WORKS AT ALL
----------------------
A password-harvesting site needs to look legitimate, which in 2026 means HTTPS,
which means a certificate, which means a public log entry. The operator cannot
avoid that without the padlock their victims are told to check for. So the same
CT machinery this product already reads for asset discovery finds names that
imitate a brand — with no cooperation from the impersonator and no packet sent
to them.

WHAT THIS NEVER SAYS
---------------------
That a name is phishing. It says a name BORROWS A TERM the customer declared and
sits outside the domains the customer declared owning. Whether that is
impersonation, a partner, a reseller, a fan site or an unrelated company that
happens to share a word is a judgement about the customer's business, and this
product does not have the facts to make it.

The distinction matters commercially: a takedown request filed against a
legitimate reseller is worse than a missed phishing domain, because it is an
action the customer took on our say-so.

WHAT MAKES THIS DIFFERENT FROM `grep` OVER CT
-----------------------------------------------
Substring matching alone is unusable. "tata" matches `potato-farm.com`, and a
screen full of those teaches its reader to close the screen. So a candidate is
reported only when it clears `MIN_SIGNALS` INDEPENDENT confusability signals —
the same shape as `core/crosshair.py`, which counts convergence rather than
trusting any single indicator.

A SOURCE OUTAGE MUST NEVER RENDER AS "NO IMPERSONATION FOUND"
--------------------------------------------------------------
Measured while building this: crt.sh — the only source that can answer "names
anywhere containing this term" — was returning 502 on every request including
its own homepage, while certspotter answered normally. A brand-protection screen
reporting zero lookalikes during that outage would be the worst failure this
feature can have, because zero is exactly what the customer hopes to see.

So the collector reports source availability separately from results, and
`Report.searched` is false when nothing could be asked. Zero results and zero
coverage are different answers and are rendered differently.
"""
from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

#: How many independent signals a name needs before it is worth showing.
#: Substring matching alone returns `potato-farm.com` for "tata", and a screen
#: full of those is a screen nobody opens twice.
MIN_SIGNALS = 2

#: Characters people substitute to make a name read the same at a glance. Not a
#: full Unicode confusables table — this is the ASCII subset that appears in
#: registered domains, because an internationalised homograph is a different
#: attack with a different detection (punycode), handled separately below.
HOMOGLYPHS: Dict[str, Tuple[str, ...]] = {
    "a": ("4", "@"), "b": ("6", "8"), "e": ("3"), "g": ("9", "q"),
    "i": ("1", "l", "!"), "l": ("1", "i"), "o": ("0"), "s": ("5", "$"),
    "t": ("7", "+"), "z": ("2"), "m": ("rn",), "w": ("vv",), "d": ("cl",),
}

#: Words that appear in a credential-harvesting hostname far more often than in
#: an ordinary one. Presence is a signal, never a verdict — plenty of legitimate
#: sites have a login page.
HARVEST_WORDS = (
    "login", "signin", "sign-in", "secure", "verify", "verification", "account",
    "update", "confirm", "portal", "auth", "recovery", "unlock", "wallet",
    "support", "helpdesk", "billing", "payment", "netbanking", "onlinebanking",
)

#: TLDs disproportionately used for throwaway registrations. A signal only —
#: legitimate businesses use every one of these.
CHEAP_TLDS = ("xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link",
              "live", "online", "site", "website", "space", "icu", "cyou",
              "buzz", "monster", "quest", "rest", "shop", "store")


#: Multi-part public suffixes common enough that ignoring them produces a WRONG
#: SIGNAL rather than a cosmetic one. Without this, `hdfcbank.co.uk` reads as the
#: brand being a subdomain of somebody else's `co.uk` and gains a signal it has
#: not earned — inflating a legitimate ccTLD variant toward the reporting
#: threshold.
#:
#: Deliberately a short list rather than the full Public Suffix List: that is a
#: ~15,000-line vendored file needing its own refresh discipline, for a
#: heuristic that only changes how a candidate is EXPLAINED. The limitation is
#: stated where it bites: a suffix outside this list can still produce the
#: spurious signal, which costs one signal on an otherwise-innocent name.
MULTI_PART_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "com.cn", "com.sg", "com.my", "com.hk", "com.tw",
    "co.za", "co.nz", "co.kr", "co.id", "co.th",
    "com.mx", "com.ar", "com.tr", "com.sa", "com.eg", "com.ng",
})


class Signal(str, enum.Enum):
    """One independent reason a name looks like an imitation."""

    EXACT_TERM = "exact_term"
    HOMOGLYPH = "homoglyph"
    EDIT_DISTANCE = "edit_distance"
    HARVEST_WORD = "harvest_word"
    CHEAP_TLD = "cheap_tld"
    BRAND_AS_SUBDOMAIN = "brand_as_subdomain"
    PUNYCODE = "punycode"
    RECENT = "recent"

    @property
    def means(self) -> str:
        return {
            Signal.EXACT_TERM: "the declared term appears in the name verbatim",
            Signal.HOMOGLYPH: "a character was substituted for one that reads "
                              "the same at a glance (rn for m, 0 for o)",
            Signal.EDIT_DISTANCE: "one insertion, deletion or transposition away "
                                  "from the declared term — the classic typo "
                                  "registration",
            Signal.HARVEST_WORD: "carries a word that appears in "
                                 "credential-harvesting hostnames far more "
                                 "often than in ordinary ones",
            Signal.CHEAP_TLD: "registered in a TLD disproportionately used for "
                              "throwaway registrations",
            Signal.BRAND_AS_SUBDOMAIN: "the brand appears as a SUBDOMAIN of "
                                       "somebody else's domain, so the "
                                       "left-hand side of the address bar reads "
                                       "correctly",
            Signal.PUNYCODE: "an internationalised name, which can render as "
                             "Latin characters it does not contain",
            Signal.RECENT: "the certificate was issued recently; impersonation "
                           "infrastructure is usually new",
        }[self]


class BrandError(ValueError):
    """A brand declaration that would produce unusable results."""


@dataclass(frozen=True)
class Brand:
    """What the ORGANISATION declares about itself. Never inferred.

    `owned` is as load-bearing as `terms`: without it every legitimate domain
    the customer runs is reported as an imitation of itself, and the first
    screen is a list of their own websites.
    """

    terms: Tuple[str, ...]
    owned: Tuple[str, ...] = ()
    declared_by: str = ""

    def __post_init__(self) -> None:
        cleaned = tuple(t.strip().lower() for t in self.terms if t.strip())
        if not cleaned:
            raise BrandError("declare at least one brand term")
        for term in cleaned:
            if len(term) < 4:
                raise BrandError(
                    f"{term!r} is too short. A term under four characters "
                    f"matches a substantial fraction of every domain ever "
                    f"registered, and the result would be unreadable")
        if not str(self.declared_by).strip():
            raise BrandError(
                "a brand declaration must record who made it — these results "
                "get used to file takedown requests")
        object.__setattr__(self, "terms", cleaned)
        object.__setattr__(self, "owned", tuple(
            o.strip().lower().lstrip("*.") for o in self.owned if o.strip()))

    def owns(self, name: str) -> bool:
        candidate = str(name).strip().lower().lstrip("*.")
        return any(candidate == own or candidate.endswith("." + own)
                   for own in self.owned)


def _distance_within(candidate: str, term: str, limit: int = 1) -> bool:
    """Is `candidate` within `limit` edits of `term`? Bounded, not full
    Levenshtein — one edit is the typo-registration case and anything looser
    matches half the dictionary."""
    if abs(len(candidate) - len(term)) > limit:
        return False
    if candidate == term:
        return False                        # exact is a different signal
    # One substitution.
    if len(candidate) == len(term):
        return sum(1 for a, b in zip(candidate, term) if a != b) <= limit
    # One insertion or deletion.
    shorter, longer = sorted((candidate, term), key=len)
    for i in range(len(longer)):
        if longer[:i] + longer[i + 1:] == shorter:
            return True
    return False


def _dehomoglyph(label: str) -> str:
    """Map obvious substitutions back, so `t4ta` and `tata` compare equal."""
    out = label
    for real, fakes in HOMOGLYPHS.items():
        for fake in (fakes if isinstance(fakes, tuple) else (fakes,)):
            out = out.replace(fake, real)
    return out


@dataclass
class Candidate:
    """One name that borrows a term, with the signals that flagged it."""

    name: str
    term: str
    signals: List[Signal] = field(default_factory=list)
    first_seen: Optional[date] = None

    @property
    def strength(self) -> int:
        return len(self.signals)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "term": self.term,
            "signals": [s.value for s in self.signals],
            "signal_meaning": {s.value: s.means for s in self.signals},
            "strength": self.strength,
            "first_seen": str(self.first_seen) if self.first_seen else None,
            # Repeated on EVERY row, because a row is what gets copied into a
            # takedown request.
            "not_a_verdict": (
                "This name borrows a term you declared and is not under a "
                "domain you declared owning. It is NOT established as phishing "
                "— it may be a partner, a reseller, or an unrelated company. "
                "Confirm before acting."),
        }


def assess(name: str, brand: Brand, first_seen: Optional[date] = None,
           today: Optional[date] = None) -> Optional[Candidate]:
    """Score one CT-observed name against a brand. None means not a candidate."""
    candidate = str(name or "").strip().lower().lstrip("*.")
    if not candidate or brand.owns(candidate):
        return None

    labels = candidate.split(".")
    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else candidate
    tld = labels[-1] if len(labels) >= 2 else ""
    stem = re.sub(r"[^a-z0-9]", "", registrable.rsplit(".", 1)[0])

    for term in brand.terms:
        signals: List[Signal] = []
        flat = re.sub(r"[^a-z0-9]", "", candidate)

        if term in flat:
            signals.append(Signal.EXACT_TERM)
        if term not in flat and term in _dehomoglyph(flat):
            signals.append(Signal.HOMOGLYPH)
        if term not in flat and _distance_within(stem, term):
            signals.append(Signal.EDIT_DISTANCE)

        if not signals:
            continue                        # this term is not implicated at all

        if any(word in candidate for word in HARVEST_WORDS):
            signals.append(Signal.HARVEST_WORD)
        if tld in CHEAP_TLDS:
            signals.append(Signal.CHEAP_TLD)
        # The brand as a SUBDOMAIN of somebody else: tata.com.secure-login.xyz
        # reads correctly from the left, which is how most people read a URL.
        #
        # The suffix check keeps hdfcbank.co.uk out of this: it is a registrable
        # domain under a multi-part suffix, not a subdomain of anybody. Without
        # it, every legitimate ccTLD variant gained a signal it had not earned.
        suffix_labels = 3 if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES else 2
        if (len(labels) > suffix_labels
                and term in ".".join(labels[:-suffix_labels])):
            signals.append(Signal.BRAND_AS_SUBDOMAIN)
        if "xn--" in candidate:
            signals.append(Signal.PUNYCODE)
        if first_seen and today and (today - first_seen).days <= 90:
            signals.append(Signal.RECENT)

        if len(signals) >= MIN_SIGNALS:
            return Candidate(name=candidate, term=term, signals=signals,
                             first_seen=first_seen)
    return None


@dataclass
class Report:
    brand: Optional[Brand] = None
    candidates: List[Candidate] = field(default_factory=list)
    examined: int = 0
    #: False when NO source could be asked. Distinct from finding nothing, and
    #: rendered differently — zero results is what a customer hopes to see, so
    #: an outage that produces zero is the most dangerous state this has.
    searched: bool = False
    unavailable: List[Dict[str, str]] = field(default_factory=list)

    def headline(self) -> str:
        if not self.searched:
            return ("NO SOURCE COULD BE SEARCHED, so this is not a result. "
                    "Zero names found and zero names looked at are different "
                    "answers, and this is the second one.")
        if not self.candidates:
            return (f"{self.examined} name(s) examined; none cleared "
                    f"{MIN_SIGNALS} independent signals.")
        strongest = max(c.strength for c in self.candidates)
        return (f"{len(self.candidates)} name(s) borrow a declared term and sit "
                f"outside your declared domains, from {self.examined} examined. "
                f"The strongest carries {strongest} signals.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "headline": self.headline(),
            "searched": self.searched,
            "examined": self.examined,
            "candidates": [c.to_dict() for c in
                           sorted(self.candidates,
                                  key=lambda c: (-c.strength, c.name))],
            "minimum_signals": MIN_SIGNALS,
            "unavailable_sources": list(self.unavailable),
            "signal_meaning": {s.value: s.means for s in Signal},
            "never_a_verdict": (
                "This finds names that BORROW A TERM you declared. It does not "
                "establish impersonation, and it cannot: whether a name is a "
                "phishing site, a partner, a reseller or an unrelated business "
                "is a judgement about your commercial relationships, which this "
                "product has no facts about. A takedown filed against a "
                "legitimate reseller is worse than a missed phishing domain, "
                "because it is an action you took on our say-so."),
        }


def build(brand: Brand, names: Sequence[Tuple[str, Optional[date]]],
          searched: bool = True,
          unavailable: Optional[Sequence[Dict[str, str]]] = None,
          today: Optional[date] = None) -> Report:
    """Assess every observed name against the brand."""
    day = today or date.today()
    seen: Set[str] = set()
    candidates: List[Candidate] = []
    for name, first_seen in names:
        found = assess(name, brand, first_seen=first_seen, today=day)
        if found and found.name not in seen:
            seen.add(found.name)
            candidates.append(found)
    return Report(brand=brand, candidates=candidates, examined=len(names),
                  searched=searched, unavailable=list(unavailable or ()))


__all__ = ["Signal", "Brand", "BrandError", "Candidate", "Report", "assess",
           "MULTI_PART_SUFFIXES",
           "build", "MIN_SIGNALS", "HARVEST_WORDS", "CHEAP_TLDS", "HOMOGLYPHS"]
