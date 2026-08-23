import type { CrosshairView, AimedEntry, LatencyReport } from '../api/types'

/**
 * Convergence — what is being fired at the internet that you stand in front of.
 *
 * THE NAME IS BORROWED AND THE MEANING IS NOT. The competitor's screen of this
 * name answers "who is targeting you". SKOPOS cannot answer that: the one open
 * CVE-to-actor mapping implicates a median of 57 threat groups per CVE, 139 at
 * the extreme out of 191, so naming your attackers would be the least honest
 * thing this product could put on a screen. The disclaimer is rendered, not
 * tucked into a tooltip, because a screen called Crosshair invites exactly the
 * reading it has to refuse.
 *
 * WHY COVERAGE GAPS SIT AT THE TOP RATHER THAN THE BOTTOM. A finding reaches
 * the converged tier partly because somebody supplied a version and probed the
 * host. An identical finding on an uninstrumented host sits lower for a reason
 * that is about OUR coverage, not the customer's risk — so an empty top tier on
 * an unprobed estate is not good news, and this panel refuses to let it read
 * as good news.
 */

const TIER_TONE: Record<string, string> = {
  converged: 'banner-crit',
  elevated: 'banner-warn',
  present: 'banner',
}

export function CrosshairPanel({ view, latency }: {
  view: CrosshairView | null
  latency: LatencyReport | null
}) {
  if (!view) {
    return (
      <section className="panel">
        <h2>Crosshair</h2>
        <p className="muted">
          No scan on record. That is not an estate with nothing in the
          crosshair — it is no evidence either way.
        </p>
      </section>
    )
  }

  const converged = view.tiers.converged ?? []
  const elevated = view.tiers.elevated ?? []
  const gaps = Object.entries(view.coverage_gaps ?? {})

  return (
    <section className="panel">
      <h2>Crosshair</h2>

      <p className="banner banner-info">
        <strong>This does not say who is targeting you.</strong>{' '}
        {view.not_targeting}
      </p>

      <p className="lede">{view.headline}</p>

      {gaps.length > 0 && (
        <div className="banner banner-warn">
          <strong>What we could not establish.</strong> These are gaps in this
          product&rsquo;s coverage, not findings about your estate — and they
          hold entries out of the top tier:
          <ul className="gap-list">
            {gaps.map(([gap, count]) => (
              <li key={gap}>
                <span className="gap-count">{count}</span>
                <span className="gap-why">{gap}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {converged.length === 0 && elevated.length === 0 && (
        <p className="muted">
          Nothing above the floor. Every finding here is exploited somewhere in
          the world and nothing further is known about it, which is not the same
          as safe.
        </p>
      )}

      <BaseRate report={latency} />

      <Tier title="Converged" tone={TIER_TONE.converged} entries={converged}
            note="Several independent signals agree. This is where to start." />
      <Tier title="Elevated" tone={TIER_TONE.elevated} entries={elevated}
            note="More than exploitation alone, but not a convergence." />
    </section>
  )
}


/**
 * The one reference class that can answer, and the three that cannot.
 *
 * RENDERED AT PANEL LEVEL, NOT PER ROW. The median is the middle of a
 * population of past vulnerabilities; putting it in a table cell would read as
 * "this asset has 8 days left", which is a forecast about one estate and is not
 * what was measured. The refusing classes are shown alongside because a screen
 * that displayed only the class with a number would imply the product has a
 * general answer to "how long do I have". It has one answer out of four.
 */
function BaseRate({ report }: { report: LatencyReport | null }) {
  if (!report) return null
  const classes = Object.values(report.classes)
  const usable = classes.filter((c) => c.usable)
  const refused = classes.length - usable.length

  return (
    <div className="banner banner-info">
      <strong>How long comparable vulnerabilities took.</strong>{' '}
      {usable.length === 0 ? (
        <>
          No reference class here has data narrow enough to say anything at all.
          Nothing is estimated.
        </>
      ) : (
        <>
          {usable.map((c) => (
            <span key={c.reference_class}>
              For <em>{c.reference_class}</em>, exploitation followed public
              code by a median of <strong>{c.median} days</strong> across{' '}
              {c.samples} past vulnerabilities (middle half {c.p25}&ndash;
              {c.p75}).
            </span>
          ))}
        </>
      )}
      {refused > 0 && (
        <>
          {' '}
          The other {refused} of {report.total_classes} reference classes span
          years, so no estimate is offered for them.
        </>
      )}
      <p className="muted" style={{ marginTop: 6 }}>
        {report.not_a_forecast}
      </p>
    </div>
  )
}


function Tier({ title, tone, entries, note }: {
  title: string
  tone: string
  entries: AimedEntry[]
  note: string
}) {
  if (entries.length === 0) return null
  return (
    <div className="stack">
      <h3>
        <span className={`banner ${tone}`}>{title}</span> {entries.length}
      </h3>
      <p className="muted">{note}</p>
      <table className="table">
        <thead>
          <tr>
            <th>Asset</th>
            <th>CVE</th>
            <th>Product</th>
            <th>Owner</th>
            <th className="num">TEPS</th>
            <th>Why</th>
          </tr>
        </thead>
        <tbody>
          {entries.slice(0, 20).map((e) => (
            <tr key={`${e.asset}-${e.cve}`}>
              <td className="mono">{e.asset}</td>
              <td className="mono">{e.cve}</td>
              <td>{e.product}</td>
              {/* An exposure with no owner is a fact nobody is going to act on. */}
              <td>{e.owner ?? <span className="muted">unassigned</span>}</td>
              <td className="num">{e.teps}</td>
              <td>
                {e.signals
                  .filter((s) => s !== 'exploited')
                  .map((s) => (
                    <span key={s} className="chip">{s}</span>
                  ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {entries.length > 20 && (
        <p className="muted">
          Showing 20 of {entries.length}. The count above is the whole tier.
        </p>
      )}
    </div>
  )
}
