"""Re-scan the estate on a schedule. Run daily.

WHY THIS EXISTS
----------------
Until now nothing re-checked the estate without a person. `tools/daily.sh` kept
the forecast record alive — an EPSS snapshot and forecast resolution — but never
scanned, so run-over-run diff, alerting and ticketing all existed and all only
fired when somebody remembered to POST. Measured on the running instance: every
scan_run row traced to a named human.

For a product whose own README says run-over-run diff "is most of what makes a
monitoring product worth running continuously", that was the gap.

IT CALLS THE SAME CODE THE ROUTE CALLS
---------------------------------------
`core.scan.execute`, not a reimplementation. Those 178 lines carry the alerting
decision, the ticketing decision and the forecast record; a second copy here
would agree on the day it was written and drift afterwards.

It does NOT go through HTTP. The console requires a session, and a cron job
holding a login would need a credential stored somewhere for a machine — which
is a worse thing to own than a direct call as the unprivileged database role it
already runs as.

WHAT IT STILL WILL NOT DECIDE
------------------------------
Whether alerts are delivered or tickets are filed. Both are read from the
environment inside `core/scan.py`, so switching this scheduler on does not
switch those on. Running a scan describes your estate to yourself; the other two
describe it to somebody else, and each keeps its own consent.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# The repository root, ahead of whatever else is on sys.path. Every other tool
# here does the same, and the reason showed up immediately without it: another
# project in the same workspace has its own top-level `core` package, and the
# import resolved to THAT one.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

#: The inventory to re-scan. Unset means this job does nothing and says so —
#: a scheduler with no inventory is a misconfiguration, not a quiet estate.
INVENTORY_ENV = "SKOPOS_SCAN_INVENTORY"
OVERWATCH_ENV = "SKOPOS_SCAN_OVERWATCH_GRAPH"
ACTOR_ENV = "SKOPOS_SCAN_ACTOR"


def main() -> int:
    from core import scan

    inventory = os.environ.get(INVENTORY_ENV, "").strip()
    if not inventory:
        print(f"{INVENTORY_ENV} is not set, so there is nothing to scan. "
              f"This job did NOT run — that is a misconfiguration to fix, not "
              f"an estate with nothing in it.")
        return 0

    actor = os.environ.get(ACTOR_ENV, "").strip() or "scheduled-scan"
    overwatch = os.environ.get(OVERWATCH_ENV, "").strip() or None
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"{started} scanning {inventory} as {actor}")

    try:
        result = scan.execute(inventory_path=inventory,
                              overwatch_graph=overwatch, actor=actor)
    except scan.ScanInputError as exc:
        print(f"  input error: {exc}", file=sys.stderr)
        return 2
    except scan.ScanUnavailable as exc:
        print(f"  unavailable: {exc}", file=sys.stderr)
        return 3

    summary = result.get("summary") or {}
    diff = result.get("since_last_run") or {}
    print(f"  run {result.get('run')}: {summary.get('findings')} finding(s), "
          f"{summary.get('determinations')} determined, "
          f"{summary.get('worklist')} worklist")
    # The honest counterpart to the finding count, on every run.
    print(f"  {result.get('rows_rejected')} row(s) rejected, "
          f"{summary.get('assets_matched_nothing')} asset(s) matched nothing — "
          f"which is NOT the same as being unaffected")
    print(f"  since last run: {diff.get('headline')}")

    alerting = result.get("alerting") or {}
    ticketing = result.get("ticketing") or {}
    print(f"  alerting : {alerting.get('reason')}")
    print(f"  ticketing: {ticketing.get('reason')}")

    forecasts = result.get("forecasts_recorded")
    if forecasts in (0, -1, None):
        # Surfaced loudly: a scan that completes while the record is not
        # accumulating looks identical to one that is, and the difference is
        # only visible months later when there is nothing to score.
        print(f"  WARNING: forecasts_recorded={forecasts} — the accuracy "
              f"record is NOT accumulating", file=sys.stderr)
    else:
        print(f"  {forecasts} forecast(s) recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
