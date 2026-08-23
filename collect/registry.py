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
        """Whether this source can actually be called right now.

        A CREDENTIALED source needs its key. A NONCOMMERCIAL source that
        declares an env var needs that too — it is an ACKNOWLEDGEMENT rather
        than a credential (see `collect/internetdb.py`), but a source nobody has
        acknowledged is exactly as inert as one nobody has paid for, and
        reporting it as configured would put "available" on a lookup panel for
        something that will refuse every call.

        A NONCOMMERCIAL source with no env var declared — `hackertarget` — is
        unchanged: it has no switch, so there is nothing to check.
        """
        if self.credential_env:
            return bool(os.environ.get(self.credential_env, "").strip())
        return self.terms is not Terms.CREDENTIALED


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

    # ── keyed sources, registered so their ABSENCE is reportable ────────────
    # These are the only route to service-level data about a target whose
    # ownership cannot be proven: SKOPOS may not probe it, so the alternative is
    # a third party who already did. Each is off until a key exists, and a
    # lookup running without one says so rather than returning a clean result.
    #
    # Registering them while unimplemented is deliberate. `unavailable` on a
    # lookup is built from this table, so "we cannot see open ports because
    # nobody supplied a Shodan key" is a fact the product can state today.
    # Shodan's OWN free endpoint, and the reason the paid entry below may not be
    # needed. Same crawl, five fields, no credential — so what gates it is not a
    # key but the operator's answer to "is this deployment commercial", which
    # SKOPOS must not answer for them. Same treatment as `hackertarget` above.
    Source("internetdb", "advisory_lookup", DataClass.NAME_INDEX,
           Terms.NONCOMMERCIAL, default_on=False,
           credential_env="SKOPOS_INTERNETDB_ACK",
           note="free for NON-COMMERCIAL use; commercial needs a Shodan "
                "enterprise licence. Returns ports, CVE claims and versioned "
                "CPEs for an IPv4 address. Index refreshed WEEKLY, so an answer "
                "is up to seven days old and says so. No banners, so no product "
                "is tied to a port. The env var is an acknowledgement, not a "
                "credential"),
    Source("shodan", "advisory_lookup", DataClass.NAME_INDEX, Terms.CREDENTIALED,
           default_on=False, credential_env="SKOPOS_SHODAN_API_KEY",
           note="the only passive route to OPEN PORTS AND SERVICES for a target "
                "this product may not probe. Paid tiers; terms restrict "
                "redistribution, which the operator accepts, not SKOPOS. "
                "Adds over `internetdb`: live rather than weekly, and banners "
                "that tie a product to a specific port"),
    Source("virustotal", "advisory_lookup", DataClass.NAME_INDEX,
           Terms.CREDENTIALED, default_on=False,
           credential_env="SKOPOS_VIRUSTOTAL_API_KEY",
           note="free tier is 4 requests/minute and reads as non-commercial. "
                "Reputation is an OBSERVATION with a source and a date, never "
                "an attribution of intent"),
    Source("hibp", "advisory_lookup", DataClass.NAME_INDEX, Terms.CREDENTIALED,
           default_on=False, credential_env="SKOPOS_HIBP_API_KEY",
           note="breach corpus membership. Paid key, rate limited. Says an "
                "address appeared in a published breach, never that an account "
                "is compromised now"),
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
