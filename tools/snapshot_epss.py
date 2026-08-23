"""Record today's EPSS scores. Run daily.

WHY THIS IS A SEPARATE TOOL FROM refresh_intel
----------------------------------------------
`refresh_intel.py` regenerates the vendored corpus — a human-initiated act, done
when somebody wants newer data. This is a cron job, and it must run whether or
not anybody is thinking about SKOPOS that day.

EPSS publishes today's scores and does not publish yesterday's. A day not
recorded is a permanent hole in every velocity figure computed afterwards, and
no amount of later effort fills it. That is the same argument that puts the
forecast record first in this phase, applied to a second dataset — and it is why
this is a tiny tool rather than a flag on a bigger one that might not be run.

Idempotent: running it twice on the same day writes one row, because a second
reading for a day would silently weight that day twice in every velocity.
"""
from __future__ import annotations

import argparse
import sys
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.forecast_store import open_forecast_store   # noqa: E402
from core.store import StoreUnavailable               # noqa: E402
from tools.refresh_intel import fetch_epss            # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--all", action="store_true",
                        help="record every EPSS score, not only the KEV subset")
    parser.add_argument("--day", default=None,
                        help="record under this date instead of today "
                             "(for replaying a downloaded file)")
    args = parser.parse_args(argv)

    try:
        store = open_forecast_store()
    except StoreUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    wanted = None
    if not args.all:
        from core import intel
        try:
            wanted = {e.cve for e in intel.load().entries()}
        except intel.IntelUnavailable as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    payload = fetch_epss(wanted)
    scores = payload["scores"]
    if not scores:
        # An empty EPSS response written as a day's reading would put a
        # zero-score row against every CVE and read as the world losing
        # interest in all of them at once.
        print("error: EPSS returned no scores; refusing to record an empty day",
              file=sys.stderr)
        return 2

    day = date.fromisoformat(args.day) if args.day else datetime.now(timezone.utc).date()
    written = store.record_epss(day, scores, payload.get("_model", ""))
    print(f"{day}: {len(scores):,} score(s) fetched, {written:,} recorded "
          f"({len(scores) - written:,} already present for this day)")
    if written == 0:
        print("Nothing new — today is already on record. That is the idempotent "
              "path, not a failure.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
