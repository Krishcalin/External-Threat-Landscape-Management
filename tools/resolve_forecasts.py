"""Mark forecasts resolved against what actually happened. Run daily.

WHAT CAN AND CANNOT RESOLVE A FORECAST HERE
-------------------------------------------
`EPSS_CROSSED` is the resolvable outcome on a KEV-only corpus. A forecast says a
band, a band claims a probability, and an EPSS score crossing a high threshold
after the forecast was issued is an observable event that either happened or did
not.

`KEV_ADDED` is NOT resolvable here, and the reason is structural. SKOPOS learns
of a CVE when CISA lists it, so a forecast about a KEV entry is always issued
after the addition it would be scored against — measured, every lead time in the
record is negative. It stays in the vocabulary because the advisory path will
make it reachable: a CVE flagged from OSV or EUVD that LATER enters KEV is a
genuine early warning, and that is the case worth measuring.

`NO_EVENT` is a SUCCESS for a low-band forecast and a miss for a high one. That
asymmetry is the whole point of a Brier score, and it is why the window has to
close before anything is marked — resolving early would score the model against
an event that may still happen.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import backtest                                  # noqa: E402
from core.forecast import OBSERVATION_WINDOW_DAYS, Outcome  # noqa: E402
from core.forecast_store import open_forecast_store         # noqa: E402
from core.store import StoreUnavailable                     # noqa: E402

#: EPSS at or above this is treated as the event a high-band forecast predicted.
#: Stated here rather than buried, because changing it changes what every
#: published accuracy figure means.
EPSS_EVENT_THRESHOLD = 0.5


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--window", type=int, default=OBSERVATION_WINDOW_DAYS,
                        help="days a forecast waits before NO_EVENT is fair")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    try:
        store = open_forecast_store()
    except StoreUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    everything = store.all_forecasts()
    open_ones = [f for f in everything if not f.resolved]
    due = backtest.due_for_resolution(everything, window_days=args.window)

    print(f"{len(everything)} forecast(s) on record, {len(open_ones)} open, "
          f"{len(due)} past their {args.window}-day window")

    crossed = closed = ineligible = 0
    for forecast in open_ones:
        series = store.epss_series(forecast.cve, days=args.window + 1)
        issued = (forecast.issued_at.date()
                  if hasattr(forecast.issued_at, "date") else forecast.issued_at)

        # A CROSSING, not a level. Measured before this check existed: 80 of 128
        # forecasts already had EPSS >= 0.5 at issue time, and resolving on the
        # level marked every one of them a correct prediction the instant it was
        # made. EPSS at issue is IN the input vector, so that is validating the
        # model against its own input and it manufactures a hit rate out of
        # nothing. A forecast that was already above the threshold can never be
        # resolved by this signal, and it is counted as ineligible rather than
        # quietly treated as a miss.
        at_issue = float((forecast.inputs or {}).get("epss") or 0.0)
        eligible = at_issue < EPSS_EVENT_THRESHOLD
        after = [(d, v) for d, v in series
                 if issued is None or (d > issued if eligible else False)]

        if not eligible:
            ineligible += 1
            if forecast in due and not args.dry_run:
                store.resolve(forecast.asset, forecast.cve,
                              forecast.model_version, Outcome.NO_EVENT,
                              f"{args.window}-day window closed; EPSS was "
                              f"already >= {EPSS_EVENT_THRESHOLD} at issue, so "
                              f"a crossing could never resolve it")
            if forecast in due:
                closed += 1
            continue

        if any(v >= EPSS_EVENT_THRESHOLD for _d, v in after):
            if not args.dry_run:
                store.resolve(forecast.asset, forecast.cve,
                              forecast.model_version, Outcome.EPSS_CROSSED,
                              f"EPSS >= {EPSS_EVENT_THRESHOLD}")
            crossed += 1
        elif forecast in due:
            # The window closed with nothing observed. For a low-band forecast
            # this is a CORRECT prediction, which is exactly why it must be
            # recorded rather than left open.
            if not args.dry_run:
                store.resolve(forecast.asset, forecast.cve,
                              forecast.model_version, Outcome.NO_EVENT,
                              f"{args.window}-day window closed")
            closed += 1

    print(f"  {crossed} resolved EPSS_CROSSED, {closed} resolved NO_EVENT, "
          f"{ineligible} cannot be resolved by an EPSS crossing (already above "
          f"the threshold when forecast)"
          + ("  (dry run — nothing written)" if args.dry_run else ""))

    board = backtest.score(store.all_forecasts(), "teps-1.0.0")
    print()
    print(board.headline())
    if not board.publishable:
        print(f"  ({board.resolved}/{backtest.MIN_RESOLVED_TO_PUBLISH} resolved "
              f"needed before any figure is published)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
