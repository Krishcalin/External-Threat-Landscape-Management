"""The vendored corpus, and how old it is.

STALENESS IS REPORTED, NOT AVOIDED
----------------------------------
The corpus is a versioned input (see `tools/refresh_intel.py`), which buys
reproducibility and offline operation at the cost of going out of date. That cost
is only acceptable if the age is visible: a result computed against a corpus from
March, read in September, is a different claim from the same result computed
today, and nothing in the numbers themselves says which one you are holding.

So every load carries the catalogue version, its release date and its age, and
the CLI prints them beside the results rather than in a footnote. A reader who
ignores a stated age has made a decision; a reader who was never told has been
misled.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import Exploited

DATA = Path(__file__).resolve().parents[1] / "data"


class IntelUnavailable(RuntimeError):
    """The corpus is missing or unreadable.

    Raised rather than degraded-to-empty. An empty catalogue produces a clean
    report — no exposures found — which is indistinguishable from a genuinely
    clean estate and is the single most dangerous failure this product could
    have.
    """


def _parse_date(value: Any) -> Optional[date]:
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(text.replace("Z", "+0000"), fmt).date()
        except ValueError:
            continue
    # An unreadable date is left as None rather than guessed. It costs an
    # ordering, never a verdict.
    return None


class Corpus:
    """The exploited-vulnerability catalogue, loaded once.

    Not a dataclass on purpose: it holds a lazily-built index and a
    deliberately small public surface, and a dataclass would invite callers to
    reach past `entries()` into internals that are free to change.
    """

    def __init__(self, kev: Dict[str, Any], epss: Dict[str, Any],
                 affected: Optional[Dict[str, Any]] = None,
                 ssvc: Optional[Dict[str, Any]] = None) -> None:
        self._kev = kev
        self._epss = epss
        self._affected = affected or {}
        self._ssvc = ssvc or {}
        self._entries: Optional[List[Exploited]] = None

    # ── provenance ──────────────────────────────────────────────────────────
    @property
    def catalog_version(self) -> str:
        return str(self._kev.get("_meta", {}).get("catalog_version") or "unknown")

    @property
    def released(self) -> Optional[date]:
        return _parse_date(self._kev.get("_meta", {}).get("date_released"))

    @property
    def retrieved(self) -> Optional[date]:
        return _parse_date(self._kev.get("_meta", {}).get("retrieved_at"))

    def age_days(self, today: Optional[date] = None) -> Optional[int]:
        """How stale the corpus is, in days since CISA released it."""
        released = self.released
        if released is None:
            return None
        return ((today or datetime.now(timezone.utc).date()) - released).days

    @property
    def epss_scope(self) -> str:
        """`all` or `KEV subset` — a stated boundary, so a caller asking for a
        score outside it gets None rather than a silent zero."""
        return str(self._epss.get("_meta", {}).get("scope") or "unknown")

    # ── affected version ranges ─────────────────────────────────────────────
    @property
    def has_affected(self) -> bool:
        """Is there any CNA range data at all?

        Without it every result is a worklist entry, which is P1's behaviour and
        remains correct — it is simply less useful, and the caller should be
        able to say which of the two situations it is in.
        """
        return bool(self._affected.get("affected"))

    @property
    def determinable_share(self) -> Optional[float]:
        """Fraction of the catalogue that CAN reach a version determination.

        Measured at refresh time and carried in the artefact, because a reader
        needs to know that roughly a third of the catalogue carries no
        comparable version data at all and will stay a worklist permanently —
        rather than inferring that the product is being timid.
        """
        value = self._affected.get("_meta", {}).get("determinable_share")
        return float(value) if isinstance(value, (int, float)) else None

    @property
    def affected_retrieved(self) -> Optional[date]:
        return _parse_date(self._affected.get("_meta", {}).get("retrieved_at"))

    def affected_for(self, cve: str) -> List[Dict[str, Any]]:
        """CNA affected-product statements for one CVE.

        An empty list means one of two different things and the caller must not
        conflate them: either the CNA published no comparable version data, or
        this corpus has no range data at all. `has_affected` tells them apart.
        """
        records = self._affected.get("affected") or {}
        return list(records.get(str(cve).strip().upper()) or [])

    def version_ranges_for(self, cve: str) -> List[Dict[str, Any]]:
        """Flattened version entries, ready for `core.affected.evaluate()`."""
        return [v for product in self.affected_for(cve)
                for v in (product.get("versions") or [])]

    # ── SSVC ────────────────────────────────────────────────────────────────
    def ssvc_for(self, cve: str) -> Dict[str, Any]:
        """CISA's SSVC decision points for one CVE, or an empty mapping."""
        return dict((self._ssvc.get("ssvc") or {}).get(
            str(cve).strip().upper()) or {})

    def automatable(self, cve: str) -> Optional[bool]:
        """Can this be exploited at scale without human effort?

        None rather than False when CISA has not decided. "Not automatable" and
        "nobody has assessed it" order differently, and collapsing them would
        quietly push the unassessed down the worklist.
        """
        value = self.ssvc_for(cve).get("automatable")
        if value is None:
            return None
        return str(value).strip().lower() == "yes"

    @property
    def has_ssvc(self) -> bool:
        return bool(self._ssvc.get("ssvc"))

    # ── content ─────────────────────────────────────────────────────────────
    def entries(self) -> List[Exploited]:
        if self._entries is None:
            scores = self._epss.get("scores") or {}
            out: List[Exploited] = []
            for raw in self._kev.get("vulnerabilities") or []:
                cve = str(raw.get("cveID") or "").strip().upper()
                if not cve:
                    continue
                score = scores.get(cve) or {}
                out.append(Exploited(
                    cve=cve,
                    vendor_project=str(raw.get("vendorProject") or "").strip(),
                    product=str(raw.get("product") or "").strip(),
                    name=str(raw.get("vulnerabilityName") or "").strip(),
                    date_added=_parse_date(raw.get("dateAdded")) or date.min,
                    short_description=str(raw.get("shortDescription") or "").strip(),
                    required_action=str(raw.get("requiredAction") or "").strip(),
                    due_date=_parse_date(raw.get("dueDate")),
                    # CISA writes "Known"/"Unknown"; anything that is not an
                    # explicit "known" is treated as not known, because the
                    # claim only runs one way.
                    known_ransomware=str(
                        raw.get("knownRansomwareCampaignUse") or ""
                    ).strip().lower() == "known",
                    notes=str(raw.get("notes") or "").strip(),
                    cwes=[str(c) for c in (raw.get("cwes") or [])],
                    epss=score.get("epss"),
                    epss_percentile=score.get("percentile"),
                ))
            self._entries = out
        return self._entries

    def __len__(self) -> int:
        return len(self.entries())


@lru_cache(maxsize=1)
def load(data_dir: Optional[str] = None) -> Corpus:
    """The vendored corpus. Raises rather than returning an empty one."""
    base = Path(data_dir) if data_dir else DATA
    kev_path, epss_path = base / "kev.json", base / "epss.json"
    if not kev_path.exists():
        raise IntelUnavailable(
            f"no exploited-vulnerability catalogue at {kev_path}. Run "
            "`python tools/refresh_intel.py` to vendor one. This is an error "
            "rather than an empty result because an empty catalogue produces a "
            "clean report, and a clean report is what a real one looks like.")
    kev = json.loads(kev_path.read_text(encoding="utf-8"))
    if not kev.get("vulnerabilities"):
        raise IntelUnavailable(f"{kev_path} carries no entries")
    epss: Dict[str, Any] = {}
    if epss_path.exists():
        # EPSS is optional: it orders the results and settles nothing, so its
        # absence degrades the ranking and not the answer.
        epss = json.loads(epss_path.read_text(encoding="utf-8"))

    # Affected ranges are optional too, and for a stronger reason: without them
    # every result is a PRODUCT_MATCH worklist entry, which is exactly what P1
    # shipped and is still correct. Their absence costs precision, never
    # correctness, so it must not stop a scan.
    affected: Dict[str, Any] = {}
    affected_path = base / "affected.json"
    if affected_path.exists():
        affected = json.loads(affected_path.read_text(encoding="utf-8"))

    # SSVC is optional for the same reason: without it the worklist orders on
    # the signals it already had, which is P2 behaviour and still correct.
    ssvc: Dict[str, Any] = {}
    ssvc_path = base / "ssvc.json"
    if ssvc_path.exists():
        ssvc = json.loads(ssvc_path.read_text(encoding="utf-8"))
    return Corpus(kev, epss, affected, ssvc)
