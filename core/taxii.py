"""TAXII 2.1, over the STIX this product already produces.

WHY A TAXII SERVER AND NOT JUST THE EXPORT ROUTE
------------------------------------------------
`/api/v1/export/stix` hands back a bundle. That is enough for a human with curl
and not enough for anything that runs on a schedule: a consumer polling for what
is NEW needs stable object identities, a stable notion of when each object
entered the collection, and a way to say "give me what arrived after this".
TAXII 2.1 (OASIS Standard, June 2021) is the interoperable spelling of exactly
that, and every threat-intel platform already speaks it.

THE ONE THING THAT MAKES INCREMENTAL POLLING HONEST
----------------------------------------------------
`date_added` must not move. The obvious implementation regenerates the bundle
per request with `now()` on every object, and then `added_after` either returns
everything forever or nothing ever — the consumer's incremental poll silently
stops working while the server keeps answering 200.

So `date_added` here is the SCAN RUN's `scanned_at`, not the moment of the
request. Every object from run N carries run N's timestamp; a consumer that
polls after run N sees exactly what run N+1 added. Object ids are already
deterministic (`stix._id` is a uuid5 over a fixed namespace), so re-exporting
the same finding produces the same id and a consumer deduplicates rather than
accumulating copies of one fact.

READ-ONLY, AND NOT AS A LIMITATION
-----------------------------------
`can_write` is false on every collection and there is no POST. Accepting
objects would mean ingesting third-party claims into a product whose entire
discipline is that every statement carries who made it and how it was learned.
An inbound STIX object arrives with none of that, and the honest place to put it
would be a table this product does not have. It is a refusal, not a gap.

WHAT A CONSUMER STILL HAS TO CARRY
-----------------------------------
The worklist/determination distinction. STIX has no vocabulary for "this
product matches but nobody compared the version", so the bundle encodes it as
`confidence` (40 vs 90) and ships a `note` object stating it in words. Both
travel through TAXII unchanged, and `collection.description` repeats it — a
caveat that stays behind in the console is not a caveat.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: OASIS TAXII 2.1, §1.6.8. Consumers content-negotiate on this exact string,
#: including the version parameter — a bare `application/json` is a different
#: media type and a conforming client will reject it.
MEDIA_TYPE = "application/taxii+json;version=2.1"

#: STIX 2.1 §C. What the objects inside an envelope are.
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"

SPEC_VERSION = "2.1"

#: The single API root. One is deliberate: API roots exist to separate
#: populations with different access rules, and this server has one population.
#: Inventing `/trusted/` and `/public/` roots that resolve to the same rows
#: would describe an access model that does not exist.
API_ROOT = "skopos"

#: The single collection id. Stable across restarts and deployments, because a
#: consumer stores it in its own configuration and a regenerated uuid would
#: silently orphan every existing subscription.
FINDINGS_COLLECTION = "1f1b4b6e-0e4a-5a9c-9b7d-0d2f6c8a1e30"

#: TAXII 2.1 §3.4: a server MAY cap what it returns. The cap is announced in
#: the envelope's `more` flag rather than applied silently, because a truncated
#: page that does not say it was truncated reads as a complete collection.
DEFAULT_PAGE = 100
MAX_PAGE = 1000

_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


class TaxiiError(ValueError):
    """A request this server will not answer, with the reason a client sees."""

    def __init__(self, title: str, description: str, status: int = 400) -> None:
        super().__init__(f"{title}: {description}")
        self.title = title
        self.description = description
        self.status = status

    def to_dict(self) -> Dict[str, Any]:
        # TAXII 2.1 §3.6. `http_status` is a STRING in the error object, which
        # reads like a typo and is what the specification says.
        return {"title": self.title, "description": self.description,
                "http_status": str(self.status)}


def discovery(base_url: str = "/taxii2/") -> Dict[str, Any]:
    """TAXII 2.1 §4.1. What this server is and where its API roots live."""
    root = f"{base_url.rstrip('/')}/{API_ROOT}/"
    return {
        "title": "SKOPOS External Threat Landscape Management",
        "description": (
            "Exposed assets joined to known-exploited vulnerabilities. Objects "
            "carry a confidence that distinguishes a WORKLIST ENTRY (the "
            "product name corresponds; the version was never compared) from a "
            "DETERMINATION (an observed version was compared against a "
            "published affected range). Do not treat the first as the second."),
        "contact": "the operator of this SKOPOS instance",
        "default": root,
        "api_roots": [root],
    }


def api_root() -> Dict[str, Any]:
    """TAXII 2.1 §4.2."""
    return {
        "title": "SKOPOS findings",
        "description": (
            "One API root, because API roots separate populations with "
            "different access rules and this server has one population."),
        "versions": [MEDIA_TYPE],
        # Nothing is accepted, so the write limit is the smallest legal value
        # rather than a number implying an upload path exists.
        "max_content_length": 1,
    }


def collections(catalog_version: str = "",
                counts: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    return {"collections": [collection(catalog_version, counts)]}


def collection(catalog_version: str = "",
               counts: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """TAXII 2.1 §5.1.

    The description carries the corpus version and the worklist/determination
    split, because a consumer federating several feeds sees this string and
    nothing else about where the objects came from.
    """
    counts = counts or {}
    worklist = counts.get("worklist")
    determinations = counts.get("determinations")
    split = ""
    if worklist is not None and determinations is not None:
        split = (f" Currently {determinations} determination(s) and {worklist} "
                 f"worklist entr(ies).")
    version = f" Catalogue {catalog_version}." if catalog_version else ""
    return {
        "id": FINDINGS_COLLECTION,
        "title": "Exposed assets matched to exploited vulnerabilities",
        "description": (
            "Relationship confidence 90 is a DETERMINATION: an observed version "
            "was compared against a published affected range. Confidence 40 is a "
            "WORKLIST ENTRY: the product corresponds, the version was NOT "
            "compared, and it is not a claim that the asset is vulnerable. "
            "Confidence 5 is a RETIRED entry, kept so a consumer can withdraw "
            "it." + version + split),
        "can_read": True,
        # No POST exists. Accepting objects would mean ingesting third-party
        # claims into a product whose discipline is that every statement carries
        # who made it and how it was learned.
        "can_write": False,
        "media_types": [STIX_MEDIA_TYPE],
    }


def _check_timestamp(value: str, field: str) -> str:
    if not _TIMESTAMP.match(value):
        raise TaxiiError(
            "Invalid filter",
            f"{field} must be a TAXII timestamp such as "
            f"2026-08-23T00:00:00Z, not {value!r}", 400)
    return value


def filter_objects(objects: Sequence[Dict[str, Any]],
                   date_added: Dict[str, str],
                   match_type: Optional[str] = None,
                   match_id: Optional[str] = None,
                   match_version: Optional[str] = None,
                   match_spec_version: Optional[str] = None,
                   added_after: Optional[str] = None
                   ) -> List[Dict[str, Any]]:
    """TAXII 2.1 §3.4 filtering.

    `added_after` is STRICTLY after, per the specification. Making it inclusive
    would hand a polling consumer the last object of the previous page on every
    request forever.
    """
    out = list(objects)
    if match_type:
        wanted = {t.strip() for t in match_type.split(",") if t.strip()}
        out = [o for o in out if o.get("type") in wanted]
    if match_id:
        wanted = {i.strip() for i in match_id.split(",") if i.strip()}
        out = [o for o in out if o.get("id") in wanted]
    if match_spec_version:
        wanted = {v.strip() for v in match_spec_version.split(",") if v.strip()}
        # Every object this server produces is 2.1; a request for anything else
        # returns nothing rather than pretending to have converted it.
        out = [o for o in out
               if str(o.get("spec_version") or SPEC_VERSION) in wanted]
    if match_version:
        wanted = {v.strip() for v in match_version.split(",") if v.strip()}
        if not wanted <= {"last", "first", "all"}:
            raise TaxiiError(
                "Invalid filter",
                "match[version] accepts last, first or all here. This server "
                "keeps one version of each object — a finding is re-exported "
                "with the same id rather than versioned — so all three select "
                "the same object and an explicit timestamp selects none.", 400)
    if added_after:
        cutoff = _check_timestamp(added_after, "added_after")
        out = [o for o in out
               if date_added.get(str(o.get("id")), "") > cutoff]
    return out


def paginate(objects: Sequence[Dict[str, Any]], limit: int = DEFAULT_PAGE,
             offset: int = 0) -> Tuple[List[Dict[str, Any]], bool, Optional[str]]:
    """Returns (page, more, next). `next` is the offset a client sends back."""
    if limit < 1 or limit > MAX_PAGE:
        raise TaxiiError(
            "Invalid limit",
            f"limit must be between 1 and {MAX_PAGE}", 400)
    page = list(objects)[offset:offset + limit]
    more = (offset + limit) < len(objects)
    return page, more, (str(offset + limit) if more else None)


def envelope(objects: Sequence[Dict[str, Any]], more: bool = False,
             next_token: Optional[str] = None) -> Dict[str, Any]:
    """TAXII 2.1 §3.5. `more` and `next` are omitted when false/absent, which
    is what the specification requires — a `more: false` with a `next` present
    is a contradiction a strict client will reject."""
    out: Dict[str, Any] = {"objects": list(objects)}
    if more:
        out["more"] = True
        if next_token:
            out["next"] = next_token
    return out


def manifest(objects: Sequence[Dict[str, Any]], date_added: Dict[str, str],
             more: bool = False, next_token: Optional[str] = None
             ) -> Dict[str, Any]:
    """TAXII 2.1 §5.3. What is in the collection, without the objects.

    A consumer uses this to decide what it needs before transferring anything,
    which matters most for the consumers that poll often and change rarely.
    """
    entries = []
    for obj in objects:
        identifier = str(obj.get("id"))
        stamp = date_added.get(identifier) or str(obj.get("created") or "")
        entries.append({
            "id": identifier,
            "date_added": stamp,
            # STIX `modified` is the object version. This server keeps one
            # version per object, so version == modified == created.
            "version": str(obj.get("modified") or obj.get("created") or stamp),
            "media_type": STIX_MEDIA_TYPE,
        })
    out: Dict[str, Any] = {"objects": entries}
    if more:
        out["more"] = True
        if next_token:
            out["next"] = next_token
    return out


def date_added_index(objects: Sequence[Dict[str, Any]],
                     stamp: str) -> Dict[str, str]:
    """Every object in one run shares that run's timestamp.

    Not `now()`. See the module docstring: a `date_added` that moves per request
    breaks `added_after` polling while the server keeps returning 200.
    """
    return {str(o.get("id")): stamp for o in objects}


__all__ = ["MEDIA_TYPE", "STIX_MEDIA_TYPE", "SPEC_VERSION", "API_ROOT",
           "FINDINGS_COLLECTION", "DEFAULT_PAGE", "MAX_PAGE", "TaxiiError",
           "discovery", "api_root", "collections", "collection",
           "filter_objects", "paginate", "envelope", "manifest",
           "date_added_index"]
