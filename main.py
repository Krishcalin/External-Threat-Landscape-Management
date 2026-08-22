"""ETLM — connect what you expose to what adversaries are exploiting.

Phase 1 answers one question and states its own boundaries while doing it:
which of your assets run software that is being exploited in the wild right now?
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import intel, inventory, match          # noqa: E402
from core.models import Confidence                # noqa: E402

#: Said on every run, not in a footnote. Every exposure this phase produces is a
#: worklist entry, because the catalogue carries no affected-version data — see
#: core/match.py. A reader who takes these as verdicts will work a list that is
#: partly wrong and then distrust all of it.
WORKLIST_NOTICE = (
    "These are WORKLIST entries, not verdicts. The exploited-vulnerability "
    "catalogue carries no affected-version data, so a match means 'this asset "
    "runs a product with an exploited vulnerability' and never 'this asset is "
    "vulnerable'. Somebody has to check the version."
)


def _fmt_age(days):
    if days is None:
        return "age unknown"
    if days == 0:
        return "released today"
    return f"{days} day{'s' if days != 1 else ''} old"


def cmd_scan(args) -> int:
    corpus = intel.load()
    assets, rejected = inventory.load(Path(args.inventory))

    # Progress goes to STDERR when --json is set, so stdout carries nothing but
    # the document. It used to go to stdout unconditionally, which meant
    # `scan x.csv --json > out.json` produced two human-readable lines followed
    # by a JSON object — a file no parser can read, on the one interface whose
    # entire purpose is being parsed. Losing the context entirely would be the
    # wrong fix: it is still printed, just on the stream meant for it.
    progress = sys.stderr if args.json else sys.stdout
    print(f"Catalogue {corpus.catalog_version} "
          f"({len(corpus)} exploited vulnerabilities, {_fmt_age(corpus.age_days())})",
          file=progress)
    print(f"Inventory {args.inventory}: {len(assets)} asset(s) read", end="",
          file=progress)
    print(f", {len(rejected)} row(s) unreadable" if rejected else "", file=progress)

    exposures = match.match(assets, corpus.entries())
    unmatched = match.unmatched_assets(assets, exposures)

    if args.json:
        print(json.dumps({
            "catalogue": {"version": corpus.catalog_version,
                          "released": str(corpus.released),
                          "age_days": corpus.age_days(),
                          "entries": len(corpus)},
            "notice": WORKLIST_NOTICE,
            "assets_read": len(assets),
            "rows_rejected": len(rejected),
            "assets_unmatched": [a.identifier for a in unmatched],
            "exposures": [{
                "asset": e.asset.identifier,
                "owner": e.asset.owner,
                "product": e.asset.product,
                "version": e.asset.version,
                "cve": e.exploited.cve,
                "vulnerability": e.exploited.name,
                "known_ransomware": e.exploited.known_ransomware,
                "due_date": str(e.exploited.due_date) if e.exploited.due_date else None,
                "epss": e.exploited.epss,
                "required_action": e.exploited.required_action,
                "basis": e.basis.value,
                "confidence": e.confidence.value,
                "evidence": e.evidence,
            } for e in exposures],
        }, indent=1))
        return 0

    print()
    if not exposures:
        print("No asset corresponds to anything in the exploited catalogue.")
    else:
        ransom = sum(1 for e in exposures if e.exploited.known_ransomware)
        print(f"{len(exposures)} exposure(s) across "
              f"{len({e.asset.identifier for e in exposures})} asset(s)"
              f"{f' — {ransom} used in ransomware campaigns' if ransom else ''}\n")
        for e in exposures[:args.limit]:
            x = e.exploited
            flags = "RANSOMWARE " if x.known_ransomware else ""
            print(f"  {x.cve}  {flags}{x.product}")
            print(f"     asset      {e.asset.identifier}"
                  f"{f'  (owner: {e.asset.owner})' if e.asset.owner else ''}")
            print(f"     match      {e.confidence.value} — {'; '.join(e.evidence)}")
            if x.epss is not None:
                print(f"     epss       {x.epss:.5f}"
                      f"  (percentile {x.epss_percentile:.3f})"
                      if x.epss_percentile is not None else "")
            if x.due_date:
                print(f"     cisa due   {x.due_date}")
            print(f"     action     {x.required_action[:140]}")
            print()
        if len(exposures) > args.limit:
            # Never truncate silently. A capped list that does not say it was
            # capped reads as a complete one.
            print(f"  … {len(exposures) - args.limit} more "
                  f"(--limit {len(exposures)} to see all)\n")

    # THE HONEST COUNTERPART. A fail-closed matcher misses joins when an
    # inventory spells a product differently, so the misses are stated here
    # rather than left to be noticed. "0 exposures, 400 unmatched" is a naming
    # problem; "0 exposures, 0 unmatched" is a clean estate.
    if unmatched:
        print(f"{len(unmatched)} asset(s) corresponded to nothing in the "
              f"catalogue. That is not the same as being unaffected — a product "
              f"named differently here than by CISA will not match:")
        for asset in unmatched[:10]:
            print(f"     {asset.identifier}  ({asset.product})")
        if len(unmatched) > 10:
            print(f"     … {len(unmatched) - 10} more")
        print()

    if rejected:
        print(f"{len(rejected)} inventory row(s) could not be read "
              f"(first reason: {rejected[0]['reason']}). They were NOT scanned.")
        print()

    print(WORKLIST_NOTICE)
    return 0


def cmd_intel(args) -> int:
    corpus = intel.load()
    print(f"catalogue version : {corpus.catalog_version}")
    print(f"released          : {corpus.released}  ({_fmt_age(corpus.age_days())})")
    print(f"retrieved         : {corpus.retrieved}")
    print(f"entries           : {len(corpus)}")
    print(f"epss scope        : {corpus.epss_scope}")
    ransom = sum(1 for e in corpus.entries() if e.known_ransomware)
    print(f"ransomware-linked : {ransom}")
    return 0


def cmd_discover(args) -> int:
    """Passive CT discovery -> an inventory file the scan reads.

    DISCOVERY WRITES A FILE AND THE SCAN READS IT. Keeping the network off the
    scan path is what makes a scan reproducible and runnable offline, and it
    means a discovery run can be reviewed before anything is scored against it.
    """
    import csv
    from collect import ct

    result = ct.discover(args.domain)
    rows = ct.to_inventory_rows(result)

    print(f"Certificate transparency for {args.domain}")
    for report in result.sources:
        state = "ok" if report.ok else "FAILED"
        print(f"  {report.name:14} {state:7} {report.names_found:4} name(s)"
              f"{'  ' + report.detail if report.detail else ''}")
    print()
    print(result.coverage_note())

    if not rows:
        print('\nNothing to write.')
        return 0

    with open(args.out, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    wildcards = len(result.names) - len(rows)
    excluded = (f" ({wildcards} wildcard(s) excluded: a wildcard proves a "
                f"certificate exists, never a host)" if wildcards else "")
    print(f"\nWrote {len(rows)} host(s) to {args.out}{excluded}")
    print("Product is left `unknown` — CT finds names, not technologies, so the "
          "vulnerability join will not match until fingerprinting fills it in.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="etlm", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="join an inventory against the catalogue")
    scan.add_argument("inventory", help="a CSV or JSON asset inventory")
    scan.add_argument("--limit", type=int, default=20,
                      help="exposures to print (default 20; the count is always "
                           "stated in full)")
    scan.add_argument("--json", action="store_true", help="machine-readable output")
    scan.set_defaults(fn=cmd_scan)

    show = sub.add_parser("intel", help="what the vendored catalogue is, and how old")
    show.set_defaults(fn=cmd_intel)

    disc = sub.add_parser(
        "discover",
        help="passive certificate-transparency discovery (touches nothing you own)")
    disc.add_argument("domain", help="apex domain, e.g. example.com")
    disc.add_argument("-o", "--out", default="discovered.csv",
                      help="inventory CSV to write (default discovered.csv)")
    disc.set_defaults(fn=cmd_discover)
    return parser


def _force_utf8_output() -> None:
    """Write UTF-8 regardless of the console's locale.

    On Windows, a redirected stdout falls back to the ANSI code page, so the
    em-dashes in this tool's own notices were being written as cp1252 byte 0x97.
    The resulting file is not UTF-8, and anything reading it as UTF-8 — which is
    what every consumer does, including this tool when it reads its own CSVs —
    fails on it. Nothing here is worth making the output encoding depend on
    which machine ran the scan.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                # A stream that refuses to be reconfigured is not a reason to
                # fail the run; the output is merely as good as the console.
                pass


def main(argv=None) -> int:
    _force_utf8_output()
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except intel.IntelUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
