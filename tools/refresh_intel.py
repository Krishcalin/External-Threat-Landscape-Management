"""Regenerate `data/` from the published sources.

WHY THE CORPUS IS VENDORED AND NOT FETCHED AT SCAN TIME
-------------------------------------------------------
A scan has to be reproducible and has to run where there is no internet. Fetching
at scan time makes every result depend on a network round trip, a rate limit and
whatever the upstream published in the seconds the scan happened to run — so two
people scanning the same estate an hour apart get different answers and neither
can say why. Vendoring the corpus makes the intelligence a VERSIONED INPUT: the
catalogue version is recorded in the output, a scan is repeatable, and updating
the intelligence is a deliberate, reviewable act rather than a side effect.

It also means the tool works offline, which matters because the people who most
need this run it inside networks that will not let it out.

The cost is staleness, and staleness is handled by saying so: every record
carries the catalogue version and release date it came from, and `etlm scan`
reports the age of the corpus rather than letting a reader assume it is current.

WHAT IS TAKEN, AND FROM WHOM
-----------------------------
    CISA KEV    the authoritative list of vulnerabilities KNOWN to be exploited.
                Public domain, published by the US government, ~1,700 entries.
                This is the strongest signal in the product: not "could be
                exploited" but "is being exploited".

    FIRST EPSS  the probability a CVE will be exploited in the next 30 days.
                Used to RANK within KEV, never to claim exploitation on its own —
                a high EPSS score is a forecast and KEV is an observation, and
                presenting a forecast as an observation is the error this whole
                product exists to avoid.

EPSS IS VENDORED FOR THE KEV SUBSET ONLY, and that is a stated boundary rather
than an oversight. The full feed is 363,000 rows and ~10 MB uncompressed; all but
a few thousand of them concern CVEs that no asset inventory will ever mention.
Carrying it would inflate the repository by two orders of magnitude to answer a
question this phase does not ask. `--full-epss` takes the lot for anyone who
needs to score beyond KEV.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import sys
import urllib.request
from datetime import datetime, timezone
import time
from datetime import date
from pathlib import Path
from typing import Dict, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.affected import affected_products, parse_version  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

#: One CVE per request. The full cvelistV5 repository is ~2.6 GB and this needs
#: 1,674 records — the KEV subset — so the API is both smaller and current.
CVE_API = "https://cveawg.mitre.org/api/cve/{cve}"

#: Courtesy interval between CVE requests. This is public infrastructure funded
#: by nobody's subscription, and a refresh is a human-initiated act with no
#: deadline attached to it.
CVE_INTERVAL = 0.12

#: Deliberately generous. These are large files from public infrastructure and a
#: refresh is a human-initiated act, not something on a scan's critical path.
TIMEOUT = 120


def _get(url: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": "etlm-refresh-intel/0.1 (+open-source ETLM)"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read()


def fetch_kev() -> Dict:
    """CISA's Known Exploited Vulnerabilities catalogue, as published."""
    payload = json.loads(_get(KEV_URL).decode("utf-8"))
    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise SystemExit("KEV payload carried no vulnerabilities; refusing to "
                         "overwrite the vendored copy with an empty one")
    # The count is published beside the list. Where they disagree the feed is
    # mid-write or truncated, and a truncated KEV silently REMOVES exploited
    # CVEs from the corpus — the one direction of error this must never take.
    declared = payload.get("count")
    if isinstance(declared, int) and declared != len(vulns):
        raise SystemExit(f"KEV declares {declared} entries and carries "
                         f"{len(vulns)}; refusing a partial catalogue")
    return payload


def fetch_epss(only: Iterable[str] | None = None) -> Dict[str, Dict[str, float]]:
    """`{cve: {epss, percentile}}`, optionally narrowed to a set of CVEs."""
    wanted = set(only) if only is not None else None
    raw = _get(EPSS_URL)
    text = gzip.decompress(raw).decode("utf-8")
    out: Dict[str, Dict[str, float]] = {}
    model = ""
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        if row[0].startswith("#"):
            model = row[0].lstrip("#").strip()
            continue
        if row[0] == "cve":
            continue
        cve = row[0].strip().upper()
        if wanted is not None and cve not in wanted:
            continue
        try:
            out[cve] = {"epss": float(row[1]), "percentile": float(row[2])}
        except (IndexError, ValueError):
            # A malformed row is skipped rather than guessed at. EPSS is a
            # ranking input; a row we cannot read costs an ordering, not a
            # verdict.
            continue
    return {"_model": model, "scores": out}


def fetch_affected(cves: Iterable[str], interval: float = CVE_INTERVAL) -> Dict:
    """CNA `affected[]` statements for a set of CVEs.

    WHY ONLY THE CNA CONTAINER. ADP containers carry enrichment — SSVC decision
    points, CWE mappings — and are authoritative for that. The affected-product
    statement belongs to the party that published the vulnerability, and taking
    a range from an enricher would attribute somebody else's judgement to the
    vendor.

    MOST OF THIS DATA CANNOT BE COMPARED, AND THAT IS RECORDED RATHER THAN
    DISCARDED. Measured over a 40-CVE sample: ~30% carry a structured range
    (`lessThan`), ~37.5% carry exact versions, and ~32.5% carry a placeholder
    like "n/a" or a prose blob listing versions in a sentence. The last group is
    fetched, counted and stored as empty, so the product can state how much of
    the catalogue is permanently beyond determination instead of implying the
    worklist will eventually empty.
    """
    wanted = [str(c).strip().upper() for c in cves if str(c).strip()]
    records: Dict[str, list] = {}
    counts = {"structured": 0, "exact": 0, "uncomparable": 0, "unavailable": 0}
    failures: list = []

    for index, cve in enumerate(wanted):
        if index:
            time.sleep(interval)
        try:
            raw = _get(CVE_API.format(cve=cve))
            record = json.loads(raw.decode("utf-8"))
        except Exception as exc:                      # noqa: BLE001
            # A CVE we could not fetch is NOT a CVE with no version data. The
            # difference decides whether a finding stays a worklist entry or is
            # wrongly reported as undeterminable, so the failure is recorded.
            counts["unavailable"] += 1
            failures.append({"cve": cve, "reason": type(exc).__name__})
            continue

        products = affected_products(record)
        kept = []
        for product in products:
            versions = [v for v in product["versions"]
                        if _is_usable_version(v)]
            if versions:
                kept.append({**product, "versions": versions})

        if not kept:
            counts["uncomparable"] += 1
        elif any(any(k in v for k in ("lessThan", "lessThanOrEqual"))
                 for p in kept for v in p["versions"]):
            counts["structured"] += 1
        else:
            counts["exact"] += 1
        records[cve] = kept

        if (index + 1) % 100 == 0:
            print(f"    {index + 1}/{len(wanted)} CVEs")

    if not records and wanted:
        raise SystemExit("no CVE records could be fetched; refusing to "
                         "overwrite the vendored copy with an empty one")

    reached = len(records)
    if wanted and reached < len(wanted) * 0.8:
        # A partial corpus here silently downgrades determinations to worklist
        # entries across the estate, which looks like the product getting more
        # cautious rather than the refresh having failed.
        raise SystemExit(f"only {reached} of {len(wanted)} CVE records were "
                         f"fetched; refusing a partial affected-range corpus")

    return {
        "retrieved": date.today().isoformat(),
        "source": "CVE Program (cveawg.mitre.org), CNA container only",
        "requested": len(wanted),
        "counts": counts,
        # Stated in the artefact itself so a reader does not have to recompute
        # it to know what fraction of the catalogue can never be determined.
        "determinable_share": (round((counts["structured"] + counts["exact"])
                                     / max(1, reached), 4)),
        "failures": failures[:50],
        "affected": records,
    }


def _is_usable_version(entry: Dict) -> bool:
    """Can `core/affected.py` do anything with this entry?

    Rejects the placeholders the CVE Program uses when a CNA declined to give
    structured data — `n/a`, `unspecified`, an empty string — and prose blobs
    such as "Access 21.08.0.1, 21.08.0.0. Identity Manager 3.3.6, 3.3.5." which
    are a sentence rather than a version.
    """
    if not isinstance(entry, dict):
        return False
    if any(k in entry for k in ("lessThan", "lessThanOrEqual")):
        return True
    version = str(entry.get("version") or "").strip()
    if not version or version.lower() in ("n/a", "unspecified", "unknown", "*"):
        return False
    # A version with a space or a comma in it is prose, not a version.
    if " " in version or "," in version:
        return False
    return parse_version(version) is not None


def write(path: Path, payload: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=1, ensure_ascii=False, sort_keys=False)
        handle.write("\n")
    size = path.stat().st_size
    print(f"  wrote {path.relative_to(ROOT)}  ({size:,} bytes)")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--full-epss", action="store_true",
                        help="vendor every EPSS score, not only the KEV subset "
                             "(~10 MB; see the module docstring)")
    parser.add_argument("--skip-affected", action="store_true",
                        help="do not refresh data/affected.json (it takes a "
                             "few minutes: one request per KEV CVE)")
    parser.add_argument("--check", action="store_true",
                        help="report whether the vendored copy is current "
                             "without writing anything")
    args = parser.parse_args(argv)

    print("Fetching CISA KEV…")
    kev = fetch_kev()
    version = kev.get("catalogVersion", "")
    released = kev.get("dateReleased", "")
    print(f"  catalogue {version}  released {released}  "
          f"{len(kev['vulnerabilities'])} entries")

    cves = {v["cveID"].strip().upper() for v in kev["vulnerabilities"]
            if v.get("cveID")}

    print("Fetching FIRST EPSS…")
    epss = fetch_epss(None if args.full_epss else cves)
    print(f"  model {epss['_model']}  {len(epss['scores']):,} scores"
          f"{'' if args.full_epss else ' (KEV subset)'}")

    if args.check:
        existing = DATA / "kev.json"
        if not existing.exists():
            print("\nNo vendored catalogue present.")
            return 1
        current = json.loads(existing.read_text(encoding="utf-8"))
        same = current.get("catalogVersion") == version
        print(f"\nvendored {current.get('catalogVersion')} vs published {version}"
              f" — {'current' if same else 'STALE'}")
        return 0 if same else 1

    write(DATA / "kev.json", {
        "_meta": {
            "source": KEV_URL,
            "licence": "Public domain (US Government work)",
            "catalog_version": version,
            "date_released": released,
            "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "count": len(kev["vulnerabilities"]),
            "note": "Verbatim from CISA. Fields are theirs; nothing is added, "
                    "reworded or inferred here.",
        },
        "vulnerabilities": kev["vulnerabilities"],
    })

    if not args.skip_affected:
        print(f"Fetching CNA affected ranges for {len(cves):,} KEV CVEs…")
        affected = fetch_affected(sorted(cves))
        counts = affected["counts"]
        print(f"  {counts['structured']:,} structured range(s), "
              f"{counts['exact']:,} exact-version, "
              f"{counts['uncomparable']:,} uncomparable, "
              f"{counts['unavailable']:,} unavailable")
        print(f"  {affected['determinable_share']:.1%} of the catalogue can "
              f"reach a version determination")
        write(DATA / "affected.json", {
            "_meta": {
                "source": CVE_API.format(cve="<CVE>"),
                "licence": "CVE Program — CVE List is free to use",
                "container": "cna",
                "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "scope": "KEV subset",
                "requested": affected["requested"],
                "counts": counts,
                "determinable_share": affected["determinable_share"],
                "note": "CNA affected[] statements only. ADP containers carry "
                        "enrichment and are authoritative for that, but the "
                        "affected-product statement belongs to the party that "
                        "published the vulnerability. Entries whose versions "
                        "are placeholders or prose are stored EMPTY rather than "
                        "dropped, so the share of the catalogue that can never "
                        "reach a determination stays visible.",
            },
            "failures": affected["failures"],
            "affected": affected["affected"],
        })

    write(DATA / "epss.json", {
        "_meta": {
            "source": EPSS_URL,
            "licence": "FIRST.org EPSS — free for any use with attribution",
            "model": epss["_model"],
            "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "scope": "all" if args.full_epss else "KEV subset",
            "count": len(epss["scores"]),
            "note": "EPSS is a FORECAST of exploitation and KEV is an "
                    "OBSERVATION of it. This product ranks with EPSS and never "
                    "claims exploitation from it.",
        },
        "scores": epss["scores"],
    })
    print("\nDone. Commit the result: the corpus is a versioned input, and a "
          "scan records which version answered it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
