"""Working exploit code that somebody published, and when.

WHAT THIS IS FOR, HONESTLY
--------------------------
It does NOT change a score today, and the module says so rather than letting a
reader assume otherwise. Measured: `scoring.Exploitability` short-circuits to
1.0 on KEV membership, every entry in this product's corpus IS a KEV entry, and
`poc_public` is referenced nowhere outside `core/scoring.py`. Artefact data
therefore cannot move a TEPS while the corpus is KEV-only.

It buys three things instead:

  1. WEAPONISATION LATENCY — the gap between an artefact appearing and CISA
     adding the CVE to KEV. That is the signal P3's forecaster is built on, and
     it is computable only if artefacts are tracked from now: the dates are
     published, but the *pairing* is what has to be recorded.

  2. EVIDENCE A DEFENDER CAN ACT ON. "A Metasploit module exists" means
     commodity exploitation by anyone who can run a console, which is a
     different operational problem from a proof-of-concept in a blog post. The
     score is the same; the response is not.

  3. IT BECOMES SCORE-RELEVANT if non-KEV advisories are ever ingested (W7),
     where `in_kev` is False and `poc_public` is the difference between
     X = 0.305 and X = 0.705.

EPSS IS A FORECAST; AN ARTEFACT IS AN OBSERVATION
-------------------------------------------------
Conflating them double-counts one signal. EPSS predicts that exploitation will
happen. An artefact is evidence that code to do it exists. They are correlated
and they are not the same claim, which is why this is a separate term with its
own attestation rather than a nudge to the EPSS input.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import date
from typing import Dict, Iterable, List, Optional, Sequence


class ArtefactKind(str, enum.Enum):
    #: A packaged, weaponised module. The strongest single signal: it means
    #: exploitation needs no skill, only a download.
    METASPLOIT = "metasploit"
    #: Published exploit code. Working, but usually needs adapting.
    EXPLOITDB = "exploitdb"
    #: A detection template. Does not exploit anything, but it means finding
    #: vulnerable hosts at internet scale is a single command.
    NUCLEI = "nuclei"

    @property
    def meaning(self) -> str:
        return {
            ArtefactKind.METASPLOIT:
                "a packaged Metasploit module exists, so exploitation requires "
                "no exploit-development skill — only a download",
            ArtefactKind.EXPLOITDB:
                "exploit code is published on Exploit-DB. Usually needs "
                "adapting to a target, but the hard part is done",
            ArtefactKind.NUCLEI:
                "a Nuclei detection template exists. It does not exploit "
                "anything, but it means scanning the internet for vulnerable "
                "hosts is one command",
        }[self]


@dataclass(frozen=True)
class Artefact:
    kind: ArtefactKind
    cve: str
    #: When the artefact was published. None where the source does not say —
    #: and a missing date is recorded rather than guessed, because latency
    #: computed from a guess is worse than no latency.
    published: Optional[date] = None
    reference: str = ""

    def explain(self) -> str:
        when = f" ({self.published})" if self.published else " (date unstated)"
        return f"{self.kind.value}{when}: {self.kind.meaning}"


@dataclass
class ArtefactSet:
    """Every artefact known for one CVE."""

    cve: str
    artefacts: List[Artefact] = field(default_factory=list)

    @property
    def kinds(self) -> List[ArtefactKind]:
        return sorted({a.kind for a in self.artefacts}, key=lambda k: k.value)

    @property
    def weaponised(self) -> bool:
        """Packaged for use by anyone, not merely demonstrated."""
        return any(a.kind is ArtefactKind.METASPLOIT for a in self.artefacts)

    @property
    def earliest(self) -> Optional[date]:
        dates = [a.published for a in self.artefacts if a.published]
        return min(dates) if dates else None

    def latency_days(self, kev_added: Optional[date]) -> Optional[int]:
        """Days from the first artefact to KEV addition.

        NEGATIVE means the artefact appeared AFTER CISA listed the CVE, which is
        common and is not an error — it means exploitation was observed before
        public code existed. Returned signed rather than clamped, because the
        sign is the interesting part and clamping it to zero would erase the
        distinction between "code first" and "attacks first".
        """
        first = self.earliest
        if first is None or kev_added is None:
            return None
        return (kev_added - first).days

    def evidence(self) -> List[str]:
        return [a.explain() for a in sorted(
            self.artefacts, key=lambda a: (a.kind.value, str(a.published or "")))]


def index(artefacts: Iterable[Artefact]) -> Dict[str, ArtefactSet]:
    """`{cve: ArtefactSet}` from a flat list."""
    out: Dict[str, ArtefactSet] = {}
    for artefact in artefacts:
        cve = str(artefact.cve).strip().upper()
        if not cve:
            continue
        out.setdefault(cve, ArtefactSet(cve=cve)).artefacts.append(artefact)
    return out


#: Latency computed over ALL of KEV is dominated by the catalogue's launch
#: backfill and is badly misleading. KEV opened in November 2021 and admitted a
#: decade of historical CVEs at once, so a 2014 vulnerability with 2014 exploit
#: code contributes eight years of "latency" that describes CISA's cataloguing
#: schedule rather than any warning period. Measured against the real corpus:
#:
#:     all KEV entries    n=637  median 777 days   <- the backfill
#:     KEV-added 2023+    n=228  median  47 days
#:     KEV-added 2025+    n=101  median  18 days   <- the actual signal
#:
#: So the window is restricted by default, and a caller asking for the whole
#: catalogue has to say so.
DEFAULT_LATENCY_SINCE = date(2023, 1, 1)


def summarise_latency(sets: Sequence[ArtefactSet],
                      kev_dates: Dict[str, date],
                      since: Optional[date] = DEFAULT_LATENCY_SINCE
                      ) -> Dict[str, object]:
    """The weaponisation-latency distribution, and what it excludes.

    `since` filters on the KEV ADDITION date, not the artefact date — see
    DEFAULT_LATENCY_SINCE for why the unfiltered median is a number about
    CISA's backlog rather than about warning time. Pass `since=None` for the
    whole catalogue, knowingly.

    Reports the count with no computable latency alongside the distribution. A
    median over the subset that happened to carry dates, presented as if it
    covered everything, is the kind of number this product exists not to print.
    """
    latencies: List[int] = []
    uncomputable = 0
    excluded_by_window = 0
    for artefact_set in sets:
        kev_added = kev_dates.get(artefact_set.cve)
        if since is not None and (kev_added is None or kev_added < since):
            excluded_by_window += 1
            continue
        value = artefact_set.latency_days(kev_added)
        if value is None:
            uncomputable += 1
        else:
            latencies.append(value)
    latencies.sort()
    median: Optional[float] = None
    if latencies:
        mid = len(latencies) // 2
        median = (float(latencies[mid]) if len(latencies) % 2
                  else (latencies[mid - 1] + latencies[mid]) / 2)
    return {
        "with_latency": len(latencies),
        "no_computable_latency": uncomputable,
        # Stated, so a restricted window cannot be read as the whole catalogue.
        "excluded_by_window": excluded_by_window,
        "window_since": str(since) if since else "all",
        "median_days": median,
        "code_before_kev": sum(1 for v in latencies if v > 0),
        "kev_before_code": sum(1 for v in latencies if v < 0),
    }


ARTEFACT_MEANING: Dict[str, str] = {k.value: k.meaning for k in ArtefactKind}

__all__ = ["ArtefactKind", "Artefact", "ArtefactSet", "index",
           "summarise_latency", "ARTEFACT_MEANING"]
