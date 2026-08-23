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
import re
import sys
import urllib.request
from datetime import datetime, timezone
import time
from datetime import date, datetime
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

#: Exploit-artefact indexes. Each is a single file, so these are cheap compared
#: with the per-CVE affected fetch.
EXPLOITDB_URL = ("https://gitlab.com/exploit-database/exploitdb/-/raw/main/"
                 "files_exploits.csv")
METASPLOIT_URL = ("https://raw.githubusercontent.com/rapid7/"
                  "metasploit-framework/master/db/modules_metadata_base.json")
NUCLEI_URL = ("https://raw.githubusercontent.com/projectdiscovery/"
              "nuclei-templates/main/cves.json")

#: GitHub PoC search is deliberately NOT a source. Repositories named for a CVE
#: routinely contain nothing, the search needs an authenticated and rate-limited
#: API, and Exploit-DB, Metasploit and Nuclei already carry the observation that
#: working code exists. Adding a noisy fourth source would degrade the signal
#: the other three provide.

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
    # SSVC comes out of the SAME response as the affected ranges — the CISA-ADP
    # container of the very record already being fetched — so it costs no extra
    # request. Extracting it here rather than in a second pass is the whole
    # reason this function returns two things.
    ssvc: Dict[str, dict] = {}
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

        decision = _ssvc_from(record)
        if decision:
            ssvc[cve] = decision

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
        "ssvc": ssvc,
    }


def _ssvc_from(record: Dict) -> Dict:
    """CISA's SSVC decision points, from the ADP container.

    Only the CISA-ADP provider is read. SSVC is a DECISION made by a
    coordinator, and taking one from an arbitrary enricher would attribute
    somebody else's judgement to CISA.
    """
    for container in (record.get("containers") or {}).get("adp") or []:
        provider = (container.get("providerMetadata") or {}).get("shortName")
        if provider != "CISA-ADP":
            continue
        for metric in container.get("metrics") or []:
            other = metric.get("other") or {}
            if other.get("type") != "ssvc":
                continue
            content = other.get("content") or {}
            flat = {}
            for option in content.get("options") or []:
                for key, value in option.items():
                    flat[str(key).strip().lower().replace(" ", "_")] = str(value)
            if flat:
                flat["timestamp"] = str(content.get("timestamp") or "")[:10]
                return flat
    return {}



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


_CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _artefact_date(text) -> str:
    """An ISO date from a source's own field, or empty.

    Never inferred. A weaponisation latency computed from a guessed date is
    worse than no latency at all, because it looks like a measurement.
    """
    raw = str(text or "").strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d"):
        try:
            return datetime.strptime(raw[:19] if "T" in raw else raw,
                                     fmt).date().isoformat()
        except ValueError:
            continue
    return ""


def fetch_artefacts(only: Iterable[str] | None = None) -> Dict:
    """Published exploit code and detection templates, per CVE.

    Scoped to the KEV subset by default, for the same reason EPSS is: the join
    only ever asks about catalogue entries, and a vendored artefact index for
    every CVE ever published would be large and almost entirely unused.
    """
    wanted = {str(c).strip().upper() for c in only} if only is not None else None
    artefacts: Dict[str, list] = {}
    reports: Dict[str, str] = {}

    def add(cve: str, kind: str, published: str, reference: str) -> None:
        key = str(cve).strip().upper()
        if not key or (wanted is not None and key not in wanted):
            return
        entries = artefacts.setdefault(key, [])
        if any(e["kind"] == kind for e in entries):
            return                      # one row per kind per CVE
        entries.append({"kind": kind, "published": published,
                        "reference": reference[:200]})

    # ---- Exploit-DB: a CSV index with its own codes column ----------------
    try:
        text = _get(EXPLOITDB_URL).decode("utf-8", "replace")
        rows = list(csv.DictReader(io.StringIO(text)))
        for row in rows:
            for cve in _CVE_IN_TEXT.findall(str(row.get("codes") or "")):
                add(cve, "exploitdb", _artefact_date(row.get("date_published")),
                    f"https://www.exploit-db.com/exploits/{row.get('id','')}")
        reports["exploitdb"] = f"ok ({len(rows):,} rows)"
    except Exception as exc:                       # noqa: BLE001
        reports["exploitdb"] = f"FAILED: {type(exc).__name__}"

    # ---- Metasploit: module metadata, `references` carries CVE ids --------
    try:
        modules = json.loads(_get(METASPLOIT_URL).decode("utf-8", "replace"))
        for path, module in modules.items():
            refs = module.get("references") or []
            for ref in refs:
                text = str(ref)
                if text.upper().startswith("CVE-"):
                    add(text.split(",")[0], "metasploit",
                        _artefact_date(module.get("disclosure_date")),
                        f"metasploit:{path}")
        reports["metasploit"] = f"ok ({len(modules):,} modules)"
    except Exception as exc:                       # noqa: BLE001
        reports["metasploit"] = f"FAILED: {type(exc).__name__}"

    # ---- Nuclei: one JSON object per line, keyed by CVE id ----------------
    try:
        body = _get(NUCLEI_URL).decode("utf-8", "replace")
        count = 0
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            count += 1
            add(str(entry.get("ID") or ""), "nuclei",
                _artefact_date((entry.get("Info") or {}).get("Classification", {})
                               .get("published") if isinstance(
                                   (entry.get("Info") or {}).get("Classification"),
                                   dict) else ""),
                f"nuclei:{entry.get('File') or entry.get('ID')}")
        reports["nuclei"] = f"ok ({count:,} templates)"
    except Exception as exc:                       # noqa: BLE001
        reports["nuclei"] = f"FAILED: {type(exc).__name__}"

    if all(r.startswith("FAILED") for r in reports.values()):
        raise SystemExit("every artefact source failed; refusing to overwrite "
                         "the vendored copy with an empty one")

    return {"sources": reports, "artefacts": artefacts}


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
    parser.add_argument("--skip-artefacts", action="store_true",
                        help="do not refresh data/artefacts.json")
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
        decisions = affected.get("ssvc") or {}
        automatable = sum(1 for d in decisions.values()
                          if d.get("automatable") == "yes")
        print(f"  SSVC decision points for {len(decisions):,} CVE(s); "
              f"{automatable:,} automatable")
        write(DATA / "ssvc.json", {
            "_meta": {
                "source": "CVE Program, CISA-ADP container",
                "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "scope": "KEV subset",
                "count": len(decisions),
                "automatable": automatable,
                "note": "SSVC is CISA's own decision record. `exploitation` is "
                        "an OBSERVATION and `automatable` says whether mass "
                        "exploitation is feasible without human effort. "
                        "Automatable does NOT change the exploitability factor "
                        "for a KEV entry — KEV membership already short-circuits "
                        "that to 1.0 — so it is used where it can actually "
                        "matter: the order the worklist is worked in.",
            },
            "ssvc": decisions,
        })

    if not args.skip_artefacts:
        print("Fetching exploit artefacts (Exploit-DB, Metasploit, Nuclei)…")
        artefacts = fetch_artefacts(cves)
        for name, state in artefacts["sources"].items():
            print(f"  {name:12} {state}")
        covered = len(artefacts["artefacts"])
        print(f"  {covered:,} of {len(cves):,} KEV CVEs have a published artefact")
        write(DATA / "artefacts.json", {
            "_meta": {
                "sources": {"exploitdb": EXPLOITDB_URL,
                            "metasploit": METASPLOIT_URL,
                            "nuclei": NUCLEI_URL},
                "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "scope": "KEV subset",
                "reports": artefacts["sources"],
                "covered": covered,
                "note": "An artefact is an OBSERVATION that working code "
                        "exists; EPSS is a FORECAST that exploitation will "
                        "happen. They are correlated and are not the same "
                        "claim. This does not change a TEPS while the corpus "
                        "is KEV-only — Exploitability short-circuits to 1.0 on "
                        "KEV membership — and is carried for weaponisation "
                        "latency and for evidence a defender can act on.",
            },
            "artefacts": artefacts["artefacts"],
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
