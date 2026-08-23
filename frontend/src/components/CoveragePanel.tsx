import type { DnsRun } from '../api/types'

/**
 * What this run could NOT see.
 *
 * The console's standing rule is that it never shows a finding count without
 * also showing what was not assessed. This is where that rule is kept for the
 * DNS sweep: "0 changes" across 400 names means one thing when 400 were
 * observed and something completely different when 66 were, and the number that
 * tells them apart has to be on the same screen as the reassuring one — not a
 * click away, and not in a tooltip.
 *
 * The three states are deliberately not merged into one "health" indicator.
 * A resolver outage, a resolver disagreement and an operator's exclusion are
 * different facts with different remedies, and an aggregate would hide which
 * one you are looking at.
 */
export function CoveragePanel({ run }: { run: DnsRun | null }) {
  if (!run) {
    return (
      <section className="panel">
        <h2>DNS coverage</h2>
        <p className="muted">
          No sweep has run. That is not an estate with no DNS — it is no
          evidence either way.
        </p>
      </section>
    )
  }

  const gaps = [
    {
      label: 'no quorum',
      value: run.quorum_failed,
      tone: 'banner-warn',
      why: 'the resolvers disagreed and none reached a majority. Reported rather than dropped — a discarded disagreement makes a noisy name look like a quiet one.',
    },
    {
      label: 'unobserved',
      value: run.unobserved,
      tone: 'banner-crit',
      why: 'we could not look. Our outage, not a change in their DNS — and it never supersedes what we last saw.',
    },
    {
      label: 'not looked at',
      value: run.refused,
      tone: 'banner-info',
      why: 'the gate refused these because somebody excluded them on purpose. Not a failure, and emphatically not a disappearance.',
    },
  ].filter((gap) => gap.value > 0)

  const pct = run.attempted > 0
    ? Math.round((run.observed / run.attempted) * 100)
    : 0

  return (
    <section className="panel">
      <h2>DNS coverage</h2>
      <p className="lede">
        <strong>{run.observed}</strong> of <strong>{run.attempted}</strong>{' '}
        (name, record-type) pairs observed across {run.resolvers.length}{' '}
        resolver{run.resolvers.length === 1 ? '' : 's'} — {pct}%.
      </p>

      {gaps.length === 0 ? (
        <p className="banner banner-ok">
          Every pair was observed. A change count from this run is a complete one.
        </p>
      ) : (
        <ul className="gap-list">
          {gaps.map((gap) => (
            <li key={gap.label} className={`banner ${gap.tone}`}>
              <span className="gap-count">{gap.value}</span>
              <span className="gap-label">{gap.label}</span>
              <span className="gap-why">{gap.why}</span>
            </li>
          ))}
        </ul>
      )}

      {run.degraded && (
        <p className="muted">
          This run is marked degraded, so a low change count may reflect what we
          could not see rather than a quiet night.
        </p>
      )}
    </section>
  )
}
