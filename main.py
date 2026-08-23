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

from core import gate, intel, inventory, match   # noqa: E402
from core.models import Confidence                # noqa: E402
from core.ownership import Method, Verification   # noqa: E402
from core.scope import ScopeKind, ScopeRule       # noqa: E402
from core.store import StoreUnavailable, open_store  # noqa: E402
from collect import ct as ct_module                # noqa: E402
from collect import run as _run_module             # noqa: E402

#: Said wherever an actor is taken. The audit chain attributes a CLAIM, not an
#: identity — there is no authentication behind this string, and a reader who
#: believes otherwise will over-trust the chain.
ACTOR_NOTE = ("the actor string is asserted, not authenticated; the audit chain "
              "records who claimed to do this")

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
    """Passive multi-source discovery -> an inventory file the scan reads.

    DISCOVERY WRITES A FILE AND THE SCAN READS IT. Keeping the network off the
    scan path is what makes a scan reproducible and runnable offline, and it
    means a discovery run can be reviewed before anything is scored against it.
    """
    import csv

    from collect import discovery, registry, run as discovery_run

    store = _store()
    scope = store.load_scope()
    requested = list(args.source) if args.source else None

    if args.list_sources:
        print(f"Terms last reviewed {registry.TERMS_REVIEWED_ON}\n")
        for source in registry.REGISTRY:
            state = "on" if source.default_on else "off"
            print(f"  {source.name:14} {source.data_class.value:8} "
                  f"{source.terms.value:14} default {state}")
            if source.note:
                print(f"                 {source.note}")
        return 0

    if args.dry_run:
        preview = discovery_run.plan(args.domain, args.actor, scope, requested,
                                     args.allow_noncommercial)
        print(f"Would query {len(preview['sources'])} source(s) for "
              f"{args.domain}: {', '.join(preview['sources'])}")
        print(f"  operations: {', '.join(preview['operations'])}")
        print(f"  {preview['rationale']}")
        if preview["not_querying"]:
            print("\n  NOT querying:")
            for name, outcome, detail in preview["not_querying"]:
                print(f"    {name:14} {outcome:13} {detail}")
        print("\nNothing was contacted.")
        return 0

    store.append_audit(args.actor, "discovery.authorised",
                       {"apex": args.domain, "sources": requested or "default"})

    result = discovery_run.run_sources(args.domain, args.actor, scope, requested,
                                       args.allow_noncommercial)

    print(f"Passive discovery for {args.domain}")
    for report in result.sources:
        print("  " + report.line())
    print()
    print(result.coverage_note(scope))

    store.append_audit(args.actor, "discovery.completed",
                       {"apex": args.domain, "names": len(result.names),
                        "excluded": len(result.excluded),
                        "sources": [{"name": r.name, "outcome": r.outcome.value,
                                     "contributed": r.contributed,
                                     "returned": r.returned, "detail": r.detail}
                                    for r in result.sources]})

    if result.excluded:
        print(f"\n{len(result.excluded)} name(s) matched an exclusion and were "
              f"NOT written:")
        for item in result.excluded[:10]:
            print(f"  {item.name}: {item.reason[:100]}")
        if len(result.excluded) > 10:
            print(f"  ... {len(result.excluded) - 10} more")

    if result.blackout:
        raise discovery_run.DiscoveryUnavailable(result.coverage_note(scope))

    rows = discovery.to_inventory_rows(result)
    if not rows:
        print("\nNo names in scope were found, and at least one source "
              "answered. That is a real result, not an outage.")
        return 0

    fields: list = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with open(args.out, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    # Counted separately rather than inferred from a subtraction. The old
    # `len(names) - len(rows)` attributed every absent name to wildcards, so a
    # run with one wildcard and two exclusions printed a confident claim about
    # three wildcards that was true of one.
    wildcards = sum(1 for n in result.names if n.is_wildcard)
    print(f"\nWrote {len(rows)} host(s) to {args.out}")
    if wildcards:
        print(f"  {wildcards} wildcard(s) excluded: a wildcard proves a "
              f"certificate exists, never a host")
    print("Product is left `unknown` — these sources find names, not "
          "technologies. Run `fingerprint` to fill it, or the vulnerability "
          "join cannot fire.")
    return 0


def _store():
    """The store, or a refusal an operator can act on.

    Deliberately no file-based fallback and no --assume-verified. Running
    without a store means running without the scope and ownership records the
    gate consults, and a YAML the operator wrote thirty seconds earlier makes
    FR-GOV-001 a formality rather than a control.
    """
    try:
        return open_store()
    except StoreUnavailable as exc:
        raise StoreUnavailable(
            f"{exc}\n\nScope, ownership and the audit log live in the database. "
            f"Bring it up with `docker compose up -d` and export "
            f"SKOPOS_DATABASE_URL, or run `scan`/`intel`, which stay offline.")


def cmd_scope_add(args) -> int:
    """Put a rule in scope. Without this command nothing else can run.

    On a fresh install there is no way to create a scope rule — the schema seeds
    none, no API route makes one, and every gate check therefore refuses. An
    operator would have had to hand-write an INSERT.
    """
    store = _store()
    rule = ScopeRule(kind=ScopeKind(args.kind), value=args.value,
                     is_exclude=args.exclude, note=args.note or "")
    store.add_scope_rule(rule, actor=args.actor)
    store.append_audit(args.actor, "scope.rule.added",
                       {"kind": rule.kind.value, "value": rule.canonical,
                        "is_exclude": rule.is_exclude, "note": rule.note})
    verb = "EXCLUDED" if rule.is_exclude else "included"
    print(f"{verb}: {rule.kind.value} {rule.canonical}"
          + (f"  ({rule.note})" if rule.note else ""))
    if rule.is_exclude:
        print("An exclusion wins over every include, whatever its specificity "
              "or the order rules were added in.")
    return 0


def cmd_scope_list(args) -> int:
    store = _store()
    rules = list(store.load_scope().rules)
    if not rules:
        print("Scope is empty. Nothing can be collected until something is in "
              "it — every gate check refuses an unscoped asset.")
        print("\n  etlm scope add example.com --kind wildcard --actor you@example.com")
        return 0
    includes = [r for r in rules if not r.is_exclude]
    excludes = [r for r in rules if r.is_exclude]
    print(f"{len(includes)} include(s), {len(excludes)} exclusion(s)\n")
    for rule in includes + excludes:
        marker = "EXCLUDE" if rule.is_exclude else "include"
        print(f"  {marker:8} {rule.kind.value:14} {rule.canonical}"
              + (f"   {rule.note}" if rule.note else ""))
    return 0


def cmd_verify(args) -> int:
    """Record proof of ownership. Required before any active collection."""
    store = _store()
    method = Method(args.method)
    if method is Method.MANUAL and not (args.approved_by or "").strip():
        print("error: a manual attestation must record who approved it "
              "(--approved-by). An unattributed assertion of ownership is not "
              "evidence.", file=sys.stderr)
        return 1

    verification = Verification.granted(args.asset, method,
                                        approved_by=args.approved_by,
                                        evidence=args.evidence or "")
    store.record_verification(verification)
    store.append_audit(args.actor, "ownership.verified",
                       {"asset": verification.asset,
                        "method": method.value,
                        "expires_at": str(verification.expires_at),
                        "approved_by": args.approved_by})
    print(verification.explain())
    print(f"\nRecorded. {ACTOR_NOTE}.")
    print("Verification expires because domains change hands and subdomains get "
          "delegated; it proves control when it was checked, not today.")
    return 0


def cmd_scope_check(args) -> int:
    """Why would this asset be allowed or refused? The preview that tells the
    truth — see gate.plan()."""
    store = _store()
    scope = store.load_scope()
    verdict = scope.resolve(args.asset)
    print(f"{args.asset}: {verdict.decision.value.upper()}")
    print(f"  {verdict.explain()}")

    verification = store.live_verification(args.asset)
    print(f"  ownership: "
          + (verification.explain() if verification else "never verified"))
    print()
    for operation in sorted(gate.OPERATIONS):
        exposure = gate.OPERATIONS[operation]
        if exposure is gate.Exposure.PROHIBITED:
            continue
        would, refused = gate.plan([args.asset], operation, args.actor, scope,
                                   {args.asset: verification})
        state = "would run" if would else "REFUSED"
        print(f"  {operation:28} {exposure.value:8} {state}")
    return 0


def cmd_fingerprint(args) -> int:
    """Identify what each host runs, so the vulnerability join can fire.

    THE LOAD-BEARING COMMAND. Certificate transparency finds names, not
    technologies, so discovery writes product="unknown" — which matches 0 of the
    catalogue's 1,674 entries. Until this runs, a 400-host discovery produces
    zero findings and one number in a warning banner.
    """
    import csv

    from collect import egress, fingerprint, http_probe
    from core.identity import ATTESTATION_MEANING

    store = _store()
    scope = store.load_scope()

    with open(args.inventory, encoding="utf-8", newline="") as handle:
        base = list(csv.DictReader(handle))
    hosts = [str(r.get("identifier") or r.get("hostname") or "").strip()
             for r in base]
    hosts = [h for h in hosts if h]
    if not hosts:
        print(f"error: no identifier/hostname column in {args.inventory}",
              file=sys.stderr)
        return 1

    ports = (http_probe.WEB_PORTS if args.ports == "web"
             else tuple(int(p) for p in args.ports.split(",")))
    verifications = {h: store.live_verification(h) for h in hosts}

    if args.dry_run:
        # gate.plan(), not refusal_reasons(): the latter passes
        # verification=None and would report every host as unverified by
        # construction, telling the operator nothing will be touched and then
        # watching the real run touch things.
        would, refusals = gate.plan(hosts, http_probe.OPERATION, args.actor,
                                    scope, verifications)
        print(f"Would probe {len(would)} of {len(hosts)} host(s) on ports "
              f"{', '.join(str(p) for p in ports)}")
        for host in would[:20]:
            print(f"  {host}")
        if len(would) > 20:
            print(f"  ... {len(would) - 20} more")
        if refusals:
            print(f"\n{len(refusals)} refused:")
            for line in refusals[:20]:
                print(f"  {line[:150]}")
            if len(refusals) > 20:
                print(f"  ... {len(refusals) - 20} more")
        print("\nNothing was contacted.")
        return 0

    budget = egress.Budget(concurrency=min(args.concurrency,
                                           egress.MAX_CONCURRENCY),
                           run_seconds=args.budget)
    store.append_audit(args.actor, "fingerprint.started",
                       {"hosts": len(hosts), "ports": list(ports)})

    outcome, coverage = fingerprint.run(hosts, args.actor, scope, verifications,
                                        ports, budget)

    store.append_audit(args.actor, "fingerprint.completed",
                       {"probed": len(outcome.fingerprints),
                        "identified": outcome.identified,
                        "refused": len(outcome.refused),
                        "unattempted": len(outcome.unattempted)})

    print(outcome.note())
    if outcome.refused:
        print()
        for host, why in outcome.refused[:10]:
            print(f"  REFUSED {host}: {why[:120]}")
        if len(outcome.refused) > 10:
            print(f"  ... {len(outcome.refused) - 10} more")

    rows = fingerprint.to_inventory_rows(outcome, base)
    if rows:
        fields: list = []
        for row in rows:
            for key in row:
                if key not in fields:
                    fields.append(key)
        with open(args.out, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nWrote {len(rows)} row(s) to {args.out}")

    identified = [f for f in outcome.fingerprints if f.identified]
    if identified:
        print()
        for f in identified[:15]:
            print(f"  {f.host:42} {f.product}"
                  + (f" ({f.vendor})" if f.vendor else "")
                  + f"  [{f.attestation.value}]")
        print()
        kinds = {f.attestation for f in identified if f.attestation}
        for kind in sorted(kinds, key=lambda a: a.value):
            print(f"  {kind.value}: {ATTESTATION_MEANING[kind.value]}")

    print("\nAn observed version is recorded in obs_version and is NEVER used "
          "as a version determination: a banner is the assertion of the party "
          "whose patch state is the question.")
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
    disc.add_argument("--actor", required=True,
                      help=f"who is running this ({ACTOR_NOTE})")
    disc.add_argument("--dry-run", action="store_true",
                      help="resolve scope and report what would be contacted, "
                           "without contacting anything")
    disc.add_argument("--source", action="append", default=None,
                      help="query only this source (repeatable); "
                           "--list-sources shows them all")
    disc.add_argument("--list-sources", action="store_true",
                      help="every registered source, its terms and its default")
    disc.add_argument("--allow-noncommercial", action="store_true",
                      help="accept sources whose terms read as excluding "
                           "commercial use; SKOPOS will not make that call "
                           "for you")
    disc.set_defaults(fn=cmd_discover)

    # -- scope -------------------------------------------------------------
    scope_cmd = sub.add_parser(
        "scope", help="what this product may look at (nothing runs until set)")
    scope_sub = scope_cmd.add_subparsers(dest="scope_command", required=True)

    add = scope_sub.add_parser("add", help="add an include or an exclusion")
    add.add_argument("value", help="e.g. example.com, 203.0.113.0/24, AS64500")
    add.add_argument("--kind", required=True,
                     choices=[k.value for k in ScopeKind])
    add.add_argument("--exclude", action="store_true",
                     help="never touch this — beats every include, whatever "
                          "its specificity or order")
    add.add_argument("--note", default="", help="why, for whoever reads it later")
    add.add_argument("--actor", required=True,
                     help=f"who is adding it ({ACTOR_NOTE})")
    add.set_defaults(fn=cmd_scope_add)

    listing = scope_sub.add_parser("list", help="every rule currently in scope")
    listing.set_defaults(fn=cmd_scope_list)

    check = scope_sub.add_parser(
        "check", help="what would be permitted against one asset, and why")
    check.add_argument("asset")
    check.add_argument("--actor", required=True, help=f"({ACTOR_NOTE})")
    check.set_defaults(fn=cmd_scope_check)

    # -- ownership ---------------------------------------------------------
    verify = sub.add_parser(
        "verify", help="record proof of ownership (required for active work)")
    verify.add_argument("asset")
    verify.add_argument("--method", required=True,
                        choices=[m.value for m in Method])
    verify.add_argument("--approved-by", default=None,
                        help="required for --method manual")
    verify.add_argument("--evidence", default="",
                        help="the TXT record, the file URL, or the ticket")
    verify.add_argument("--actor", required=True, help=f"({ACTOR_NOTE})")
    verify.set_defaults(fn=cmd_verify)

    # -- active fingerprinting --------------------------------------------
    fp = sub.add_parser(
        "fingerprint",
        help="identify what each host runs (ACTIVE — verified assets only)")
    fp.add_argument("inventory", help="a CSV carrying identifier/hostname")
    fp.add_argument("-o", "--out", default="fingerprinted.csv")
    fp.add_argument("--actor", required=True, help=f"({ACTOR_NOTE})")
    fp.add_argument("--ports", default="web",
                    help="'web' (443,80,8443,8080 — the ports a name-based "
                         "ownership proof actually covers) or a comma list")
    fp.add_argument("--concurrency", type=int, default=8)
    fp.add_argument("--budget", type=float, default=900.0,
                    help="seconds; when spent, remaining hosts are reported "
                         "UNATTEMPTED rather than counted as nothing found")
    fp.add_argument("--dry-run", action="store_true",
                    help="show what would be probed, contacting nothing")
    fp.set_defaults(fn=cmd_fingerprint)
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
    except PermissionError as exc:
        # Every gate refusal — OperationRefused, NotInScope, OwnershipNotVerified
        # and PermitMismatch — lands here with its own sentence, and exits 3
        # rather than 2. A governance refusal is NOT a coverage gap: filing it as
        # one hands the operator the wrong remedy, and an unregistered operation
        # would arrive as a footnote next to "you didn't set an API key" instead
        # of failing loudly on its first run.
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    except StoreUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except intel.IntelUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (ct_module.DiscoveryUnavailable,
            _run_module.DiscoveryUnavailable) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
