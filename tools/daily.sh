#!/bin/sh
# The two jobs whose missed days can never be refilled, run once a day.
#
# WHY A LOOP AND NOT CRON. The image carries no cron daemon, and adding one
# would mean a second process supervisor, its own log destination, and a way for
# the container to look healthy while the job silently stopped. A foreground
# loop is visible to `docker compose ps`, its output goes to `docker compose
# logs`, and if it dies the restart policy is the supervisor.
#
# WHY IT RUNS IMMEDIATELY ON START. A scheduler that waits 24 hours before its
# first run is indistinguishable from one that is broken, and the operator who
# started it has no way to tell which they have.
set -u

INTERVAL="${SKOPOS_SCHEDULE_SECONDS:-86400}"

while true; do
  STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "[skopos-scheduler] ${STARTED} snapshot_epss"
  # Not `set -e`: a failed snapshot must not take the loop down with it, because
  # tomorrow's run is still worth attempting. The failure is printed, and the
  # exit code is reported rather than swallowed.
  python -u tools/snapshot_epss.py || echo "[skopos-scheduler] snapshot_epss FAILED ($?)"

  echo "[skopos-scheduler] $(date -u +%Y-%m-%dT%H:%M:%SZ) resolve_forecasts"
  python -u tools/resolve_forecasts.py || echo "[skopos-scheduler] resolve_forecasts FAILED ($?)"

  # RUN ONCE AND EXIT when the interval is 0 or "once". Kubernetes has its own
  # scheduler, so the Helm chart runs this as a CronJob and a container that
  # looped forever would never complete the Job — the CronJob would then refuse
  # every subsequent run under concurrencyPolicy: Forbid, and the failure would
  # look like "the schedule stopped firing".
  case "${INTERVAL}" in
    0|once)
      echo "[skopos-scheduler] single run complete"
      exit 0
      ;;
  esac

  echo "[skopos-scheduler] sleeping ${INTERVAL}s"
  sleep "${INTERVAL}"
done
