"""Vendored abuse feeds, and the four things membership of one does not mean.

WHY THIS IS A VENDORED CORPUS AND NOT AN API CLIENT
-----------------------------------------------------
Measured on 2026-08-22: every one of these publishers still serves its BULK
download without authentication, while the per-query APIs — abuse.ch's URLhaus
and ThreatFox lookups, CIRCL's passive SSL — now all require a key. The free
thing is the file; the keyed thing is the question.

That is the shape D1 already chose for the vulnerability corpus, for reasons
that apply here unchanged: a scan that depends on a network round trip depends
on a rate limit and on whatever the publisher served in that second, so two
people scanning the same estate an hour apart get different answers and neither
can say why. Vendoring makes these a VERSIONED INPUT, refreshed deliberately by
`tools/refresh_intel.py --only-blocklists`.

It also removes a failure mode `collect/keyed_sources.py` warns about in its own
docstring — a vendor renaming a field breaks a refresh, loudly, rather than a
customer's lookup.

WHAT A HIT MEANS, AND FOUR THINGS IT DOES NOT
-----------------------------------------------
A hit means: *this exact address or host appears on this named list, in the
snapshot fetched on this date.* That is an observation with a source and a date,
which is the only kind of statement this product makes.

It does **not** mean:

1. **That the asset is compromised.** Shared hosting, CDNs and cloud egress
   ranges put innocent tenants on the same address as an abusive one. A hit on a
   Cloudflare address says something about Cloudflare's customers.
2. **That the asset is compromised NOW.** These lists are snapshots, and several
   of them never remove entries. `days_old` is carried on every hit for this
   reason.
3. **Anything about who.** These name infrastructure, not actors. P3 measured
   what CVE-to-actor attribution is worth here — a median of 57 groups per CVE —
   and closed it. A C2 list does not reopen it.
4. **That absence is safety.** These lists are small. `URLhaus` held 16,253 URLs
   when this was written; the web has rather more. Not being on a list is the
   overwhelmingly common case for both good and bad hosts, and
   `describe_absence` exists so a caller cannot render "no hits" as "clean".

WHY TOR IS HERE AND WHY IT IS NOT AN ABUSE LIST
-------------------------------------------------
The exit-relay list is carried because knowing traffic arrived from one is
genuinely useful context, and it is tagged `NEUTRAL` rather than `ABUSE`
precisely so it cannot be summed into a threat count. Running a relay is legal
and often admirable. A product that quietly scored it as malicious would be
making a political claim it has no basis for.
"""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATH = ROOT / "data" / "blocklists.json"

#: Above this, a snapshot is old enough that a hit says more about the fetch
#: date than about the asset. Not a hard refusal — a stated caveat, because a
#: stale hit is still a fact about a published list.
STALE_AFTER_DAYS = 14


@dataclass(frozen=True)
class Feed:
    """One publisher's list, and what its entries actually are."""

    name: str
    url: str
    #: "ipv4" | "url" | "netblock"
    kind: str
    #: ABUSE or NEUTRAL. Neutral entries are never counted as abuse — see the
    #: module docstring on Tor.
    sense: str
    publisher: str
    licence: str
    means: str
    #: Comment prefixes to strip. Publishers differ and a '#' left in produces a
    #: "feed" whose first entry is a copyright notice.
    comment: str = "#"


FEEDS: Sequence[Feed] = (
    Feed("urlhaus", "https://urlhaus.abuse.ch/downloads/text_recent/", "url",
         "ABUSE", "abuse.ch", "CC0",
         "a URL abuse.ch recorded as distributing malware"),
    Feed("blocklist_de", "https://lists.blocklist.de/lists/all.txt", "ipv4",
         "ABUSE", "blocklist.de", "free for non-commercial and commercial use",
         "an address reported by participating sysadmins for attacking their "
         "hosts (ssh, mail, web)"),
    Feed("cins_army", "https://cinsscore.com/list/ci-badguys.txt", "ipv4",
         "ABUSE", "CINS / Sentinel IPS", "free with attribution",
         "an address CINS scored as poor based on observed attacks"),
    Feed("spamhaus_drop", "https://www.spamhaus.org/drop/drop_v4.json",
         "netblock", "ABUSE", "Spamhaus", "free, redistribution restricted",
         "a netblock Spamhaus believes is hijacked or leased to a criminal "
         "operation — the whole range, not one host"),
    Feed("feodo_c2", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
         "ipv4", "ABUSE", "abuse.ch", "CC0",
         "an address abuse.ch tracked as botnet command and control"),
    Feed("openphish", "https://openphish.com/feed.txt", "url",
         "ABUSE", "OpenPhish", "free community feed, non-commercial",
         "a URL OpenPhish's community feed listed as phishing"),
    Feed("tor_exit", "https://check.torproject.org/torbulkexitlist", "ipv4",
         # NEUTRAL on purpose. Running an exit relay is legal and often
         # admirable; scoring it as abuse would be a political claim.
         "NEUTRAL", "The Tor Project", "free",
         "a Tor exit relay. NOT abuse — context about where traffic "
         "originated, nothing more"),
)

BY_NAME: Dict[str, Feed] = {f.name: f for f in FEEDS}

#: Feeds evaluated and NOT carried, with the measurement that excluded each.
#: Recorded rather than silently omitted: a list of eight feeds that used to be
#: nine is a decision, and the next person to read a blog post recommending
#: SSLBL should find out here that it is dead rather than by shipping it.
REJECTED: Dict[str, str] = {
    "sslbl_c2": (
        "abuse.ch SSL Blacklist (https://sslbl.abuse.ch/blacklist/"
        "sslipblacklist.txt). Fetched 2026-08-23: HTTP 200, 527 bytes, ZERO "
        "entries — the body is a header reading 'This list has been deprecated "
        "on 2025-01-03'. It still answers 200, so a naive fetcher vendors an "
        "empty list and every lookup against it reports no hits. Widely still "
        "recommended, including by the article that prompted this work."),
}

#: A publisher's own 'Last updated' line, where it publishes one. abuse.ch does.
#:
#: THE DISTINCTION THIS EXISTS FOR: a fetch date is not a data date. Feodo
#: Tracker was fetched fresh on 2026-08-23 and its own header said it was last
#: updated 2026-03-04. Reporting only the fetch date would present a five-month-
#: old list as same-day intelligence.
PUBLISHER_DATE = "last updated:"

#: The feeds whose licence terms exclude commercial use, mirroring
#: `collect/registry.py`'s treatment. Carried so a corpus can report which of
#: its parts a commercial deployment should drop, rather than the operator
#: having to read eight licence pages.
NONCOMMERCIAL = frozenset({"openphish"})


class CorpusUnavailable(RuntimeError):
    """No vendored corpus. Distinct from an empty one."""


@dataclass(frozen=True)
class Hit:
    feed: str
    publisher: str
    matched: str
    means: str
    sense: str
    fetched_on: str
    days_old: int
    #: What the PUBLISHER says it last updated the list, where it says so at
    #: all. Empty when the feed publishes no such line.
    publisher_updated: str = ""

    @property
    def effective_age_days(self) -> int:
        """Age of the DATA, not of the download.

        The publisher's own date wins when it exists and is older. Feodo Tracker
        served a list on 2026-08-23 whose header said 2026-03-04; reporting the
        fetch date alone would present five-month-old intelligence as same-day.
        """
        if not self.publisher_updated:
            return self.days_old
        return max(self.days_old, _age(self.publisher_updated))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feed": self.feed, "publisher": self.publisher,
            "matched": self.matched, "means": self.means, "sense": self.sense,
            "fetched_on": self.fetched_on, "days_old": self.days_old,
            "publisher_updated": self.publisher_updated or None,
            "data_age_days": self.effective_age_days,
            "stale": self.effective_age_days > STALE_AFTER_DAYS,
        }


def _today() -> date:
    return datetime.now(timezone.utc).date()


#: What an unreadable fetch date counts as. Deliberately enormous: the
#: alternative — treating a corrupt stamp as 0 days old — silently promotes a
#: broken snapshot to "fresh", which is the one direction this must not fail in.
UNDATED = 10 ** 6


def _age(fetched_on: str, today: Optional[date] = None) -> int:
    try:
        then = date.fromisoformat(str(fetched_on)[:10])
    except (TypeError, ValueError):
        return UNDATED
    return ((today or _today()) - then).days


class Blocklists:
    """The vendored corpus, loaded once and queried in process.

    No network. That is the point: a lookup does not depend on a publisher being
    up, on a rate limit, or on what was served in a particular second.
    """

    def __init__(self, payload: Dict[str, Any]) -> None:
        self._meta: Dict[str, Any] = payload.get("_meta") or {}
        self._feeds: Dict[str, Dict[str, Any]] = payload.get("feeds") or {}
        self._addresses: Dict[str, List[str]] = {}
        self._hosts: Dict[str, List[str]] = {}
        self._networks: List[tuple] = []
        for name, block in self._feeds.items():
            feed = BY_NAME.get(name)
            if feed is None:
                # A corpus naming a feed this build does not know is a version
                # skew, not a crash. Skipped, and reported by `unknown_feeds`.
                continue
            for entry in block.get("entries") or []:
                if feed.kind == "ipv4":
                    self._addresses.setdefault(entry, []).append(name)
                elif feed.kind == "url":
                    host = _host_of(entry)
                    if host:
                        self._hosts.setdefault(host, []).append(name)
                elif feed.kind == "netblock":
                    try:
                        self._networks.append(
                            (ipaddress.ip_network(entry, strict=False), name))
                    except ValueError:
                        continue

    # ── loading ─────────────────────────────────────────────────────────────
    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Blocklists":
        target = Path(path or os.environ.get("SKOPOS_BLOCKLISTS_PATH")
                      or DEFAULT_PATH)
        if not target.exists():
            raise CorpusUnavailable(
                f"no vendored blocklist corpus at {target}. Run "
                f"`python tools/refresh_intel.py --only-blocklists` to build "
                f"one. Until then SKOPOS reports abuse-feed coverage as ABSENT "
                f"rather than as clean.")
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CorpusUnavailable(f"{target} could not be read: {exc}") from exc
        return cls(payload)

    # ── querying ────────────────────────────────────────────────────────────
    def check_address(self, address: str,
                      today: Optional[date] = None) -> List[Hit]:
        """Every list this address appears on. Empty is not 'clean'."""
        try:
            parsed = ipaddress.ip_address(str(address).strip())
        except ValueError:
            return []
        text = str(parsed)
        hits: List[Hit] = []
        for name in self._addresses.get(text, []):
            hits.append(self._hit(name, text, today))
        for network, name in self._networks:
            if parsed.version == network.version and parsed in network:
                hits.append(self._hit(name, str(network), today))
        return sorted(hits, key=lambda h: h.feed)

    def check_host(self, hostname: str,
                   today: Optional[date] = None) -> List[Hit]:
        """Every list a URL on this hostname appears on.

        Matched on the HOST, not the full URL. A phishing page at
        `example.com/login` is a fact about `example.com` worth surfacing when
        somebody asks about that name — but the hit records which host matched
        so nobody reads it as "this specific page".
        """
        host = str(hostname or "").strip().lower().rstrip(".")
        if not host:
            return []
        return sorted((self._hit(name, host, today)
                       for name in self._hosts.get(host, [])),
                      key=lambda h: h.feed)

    def _hit(self, name: str, matched: str, today: Optional[date]) -> Hit:
        feed = BY_NAME[name]
        block = self._feeds.get(name) or {}
        fetched = str(block.get("fetched_on") or "")
        return Hit(feed=name, publisher=feed.publisher, matched=matched,
                   means=feed.means, sense=feed.sense, fetched_on=fetched,
                   days_old=_age(fetched, today),
                   publisher_updated=str(block.get("publisher_updated") or ""))

    # ── reporting on itself ─────────────────────────────────────────────────
    @property
    def built_on(self) -> str:
        return str(self._meta.get("built_on") or "")

    def unknown_feeds(self) -> List[str]:
        return sorted(set(self._feeds) - set(BY_NAME))

    def missing_feeds(self) -> List[str]:
        return sorted(set(BY_NAME) - set(self._feeds))

    def coverage(self, today: Optional[date] = None) -> Dict[str, Any]:
        """What this corpus contains and how old each part is.

        Rendered beside any result, because the size of these lists is the
        reason an absence proves nothing.
        """
        feeds = []
        for name, block in sorted(self._feeds.items()):
            feed = BY_NAME.get(name)
            fetched_age = _age(str(block.get("fetched_on") or ""), today)
            published = str(block.get("publisher_updated") or "")
            age = (max(fetched_age, _age(published, today)) if published
                   else fetched_age)
            feeds.append({
                "feed": name,
                "publisher": feed.publisher if feed else "unknown to this build",
                "sense": feed.sense if feed else "unknown",
                "kind": feed.kind if feed else "unknown",
                "entries": len(block.get("entries") or []),
                "fetched_on": block.get("fetched_on"),
                "publisher_updated": published or None,
                "days_since_fetch": fetched_age,
                "data_age_days": age,
                "stale": age > STALE_AFTER_DAYS,
                "stale_reason": block.get("stale_reason"),
                "noncommercial": name in NONCOMMERCIAL,
            })
        total = sum(f["entries"] for f in feeds)
        return {
            "built_on": self.built_on,
            "feeds": feeds,
            "entries": total,
            "stale_feeds": [f["feed"] for f in feeds if f["stale"]],
            "missing_feeds": self.missing_feeds(),
            "unknown_feeds": self.unknown_feeds(),
            "noncommercial_feeds": sorted(
                f["feed"] for f in feeds if f["noncommercial"]),
            "absence_means": describe_absence(total),
        }


def describe_absence(entries: int) -> str:
    """What 'no hits' is worth. Called wherever a zero is displayed.

    Exists because a zero on a screen reads as a verdict, and this one is not
    one. Stating the corpus size next to it is the only thing that stops
    "checked against 61,000 entries and found nothing" from being heard as
    "checked the internet and found nothing".
    """
    return (
        f"No hits across {entries:,} vendored entries. That is the normal "
        f"result for almost every host, good or bad: these lists name a tiny "
        f"and specific slice of the internet — infrastructure somebody reported "
        f"— so absence is not evidence of safety and must not be shown as one.")


def _host_of(url: str) -> str:
    """The hostname inside a feed line, without importing a URL parser's
    opinions about schemes these feeds do not always include."""
    text = str(url or "").strip()
    if not text:
        return ""
    for scheme in ("http://", "https://"):
        if text.lower().startswith(scheme):
            text = text[len(scheme):]
            break
    text = text.split("/", 1)[0].split("?", 1)[0]
    if "@" in text:                       # user:pass@host
        text = text.rsplit("@", 1)[1]
    # A bracketed IPv6 literal, or host:port. Splitting on ':' first would
    # truncate the former to nothing useful.
    if text.startswith("["):
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text.lower().rstrip(".")


__all__ = ["Blocklists", "Feed", "Hit", "FEEDS", "BY_NAME", "NONCOMMERCIAL",
           "REJECTED",
           "CorpusUnavailable", "DEFAULT_PATH", "STALE_AFTER_DAYS",
           "describe_absence"]
