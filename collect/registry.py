"""Which sources exist, what their terms allow, and which are on by default.

A source is not just a URL. It has an operation the gate must recognise, a data
class that decides what its dates mean, and TERMS — which are the customer's
legal exposure, not ours to decide for them.

TERMS ARE A DEFAULT, NOT A LOCK
-------------------------------
SKOPOS may be run commercially. HackerTarget's free tier reads as excluding
commercial use (they sell memberships for volume), so it is off unless the
operator passes `--allow-noncommercial` and makes that call themselves. Shipping
it on by default would quietly make a licensing decision on behalf of every
user.

A CREDENTIALED source with no credential reports `UNCONFIGURED`, never `OK` with
zero results. AlienVault OTX additionally reports `PARTIAL` if queried
anonymously — its documentation says unauthenticated requests return public data
only, and a silent subset is the worst failure mode available: it looks exactly
like a complete answer.
"""
from __future__ import annotations

import enum
import os
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from collect.report import Outcome, SourceReport


class DataClass(str, enum.Enum):
    """What KIND of fact a source produces. Decides what its dates mean."""

    #: A certificate was issued naming this host.
    CT = "ct"
    #: A resolver actually observed this name resolve.
    PASSIVE_DNS = "pdns"
    #: A third party lists this name; provenance unstated.
    NAME_INDEX = "index"
    #: A crawler fetched a page at this name at some point.
    WEB_ARCHIVE = "archive"


class Terms(str, enum.Enum):
    OPEN = "open"
    NONCOMMERCIAL = "noncommercial"
    CREDENTIALED = "credentialed"


#: When the terms in this table were last read by a human. A terms field with no
#: review date is an assertion about someone else's licence that ages silently.
TERMS_REVIEWED_ON = "2026-08-22"


@dataclass(frozen=True)
class Source:
    name: str
    operation: str
    data_class: DataClass
    terms: Terms = Terms.OPEN
    default_on: bool = True
    #: Environment variable carrying the credential, for CREDENTIALED sources.
    credential_env: Optional[str] = None
    note: str = ""

    @property
    def configured(self) -> bool:
        if self.terms is not Terms.CREDENTIALED:
            return True
        return bool(os.environ.get(self.credential_env or ""))


REGISTRY: Tuple[Source, ...] = (
    Source("certspotter", "ct_log_search", DataClass.CT),
    Source("crt.sh", "ct_log_search", DataClass.CT),
    Source("mnemonic", "passive_dns", DataClass.PASSIVE_DNS,
           note="100/min, 1000/day anonymous. Measured: exact-name lookup, NOT "
                "wildcard enumeration — a liveness source that dates "
                "resolutions rather than a source that finds new names"),
    Source("anubis", "subdomain_index_read", DataClass.NAME_INDEX,
           note="returned HTTP 403 when tested 2026-08-23; may answer from "
                "another network, so it reports FAILED rather than being "
                "quietly dropped"),
    Source("wayback", "web_archive_search", DataClass.WEB_ARCHIVE,
           default_on=False,
           note="off by default: whether an old crawl timestamp EXCLUDES a name "
                "or merely annotates it is unsettled, and a source cannot ship "
                "on by default while its own risk register says that blocks it"),
    Source("otx", "passive_dns", DataClass.PASSIVE_DNS, Terms.CREDENTIALED,
           default_on=False, credential_env="SKOPOS_OTX_API_KEY",
           note="anonymous queries return public data only — a silent subset, "
                "so anonymous is PARTIAL and never OK"),
    Source("hackertarget", "subdomain_index_read", DataClass.NAME_INDEX,
           Terms.NONCOMMERCIAL, default_on=False,
           note="free tier reads as excluding commercial use; SKOPOS must not "
                "make that call for the operator"),
)

BY_NAME: Dict[str, Source] = {s.name: s for s in REGISTRY}


def enabled(requested: Optional[Sequence[str]] = None,
            allow_noncommercial: bool = False
            ) -> Tuple[List[Source], List[SourceReport]]:
    """`(sources to query, reports for the ones we are not querying)`.

    The second value is why this returns a tuple. A source left out because
    nobody supplied a key, or because its terms exclude commercial use, has to
    reach the coverage note — otherwise an install querying 5 of 7 registered
    sources reports as fully covered, and `narrowed` is structurally dead for
    the two states it was invented for.
    """
    chosen: List[Source] = []
    prereports: List[SourceReport] = []

    for source in REGISTRY:
        asked_for = requested is not None and source.name in requested
        if requested is not None and not asked_for:
            continue
        if requested is None and not source.default_on:
            prereports.append(SourceReport(
                source.name, Outcome.DISABLED, 0, 0,
                f"not on by default; enable with --source {source.name}"
                + (f" ({source.note})" if source.note else "")))
            continue
        if source.terms is Terms.NONCOMMERCIAL and not allow_noncommercial:
            prereports.append(SourceReport(
                source.name, Outcome.DISABLED, 0, 0,
                f"terms reviewed {TERMS_REVIEWED_ON} read as excluding "
                f"commercial use; pass --allow-noncommercial to accept that"))
            continue
        if not source.configured:
            prereports.append(SourceReport(
                source.name, Outcome.UNCONFIGURED, 0, 0,
                f"set {source.credential_env} to query it"))
            continue
        chosen.append(source)

    return chosen, prereports


def unknown_names(requested: Sequence[str]) -> List[str]:
    """Names in --source that no registered source answers to.

    Returned so a typo fails loudly. A misspelled --source that silently
    narrows the run to nothing is the failure this whole module exists against.
    """
    return [name for name in requested if name not in BY_NAME]


__all__ = ["DataClass", "Terms", "Source", "REGISTRY", "BY_NAME",
           "TERMS_REVIEWED_ON", "enabled", "unknown_names"]
