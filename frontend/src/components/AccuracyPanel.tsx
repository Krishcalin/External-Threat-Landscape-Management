import type { Accuracy } from '../api/types'

/**
 * Whether this product's predictions have been any good.
 *
 * THE INTERESTING STATE IS THE EMPTY ONE, and it will be the state for months.
 * A forecast resolves when the thing it predicted either happens or provably
 * does not, and that takes calendar time no amount of engineering shortens. So
 * the screen that matters is this one: N issued, 0 resolved, NO FIGURE SHOWN.
 *
 * The temptation is to fill it — a spinner, a "coming soon", a provisional
 * number with an asterisk. A provisional accuracy figure is the worst of those,
 * because it will be screenshotted and the asterisk will not travel with it. So
 * the panel states the count, the threshold, and nothing else.
 *
 * LEAD TIME IS RENDERED AS PROSE, not as a metric with an em-dash. It is
 * structurally unmeasurable on a KEV-only corpus — SKOPOS learns of a CVE when
 * CISA lists it, so every forecast is issued after the event it would be scored
 * against. A blank tile invites somebody to go and fix the pipeline that is not
 * broken.
 */

export function AccuracyPanel({ accuracy }: { accuracy: Accuracy | null }) {
  if (!accuracy) {
    return (
      <section className="stack">
        <h2 className="section">Forecast accuracy</h2>
        <div className="empty">
          No forecast record yet. It begins with the first scan — and history
          cannot be backfilled, so every day without one is evidence that cannot
          be recovered.
        </div>
      </section>
    )
  }

  const pct = accuracy.minimum_to_publish > 0
    ? Math.min(100, (accuracy.resolved / accuracy.minimum_to_publish) * 100)
    : 0

  return (
    <section className="stack">
      <h2 className="section">
        Forecast accuracy
        <span className="text-ink3"> — model {accuracy.model_version}</span>
      </h2>

      <div className={`banner ${accuracy.publishable ? 'banner-ok' : 'banner-info'}`}>
        <strong>
          {accuracy.publishable
            ? 'Scored against what actually happened.'
            : 'No accuracy figure exists yet, and none is shown.'}
        </strong>{' '}
        {accuracy.headline}
      </div>

      <div className="grid grid-4">
        <div className="card">
          <p className="card-title">Forecasts issued</p>
          <div className="kpi">{accuracy.issued.toLocaleString()}</div>
          <p className="kpi-note">
            each written with its full input vector at the moment it was made
          </p>
        </div>

        <div className="card">
          <p className="card-title">Resolved</p>
          <div className="kpi">{accuracy.resolved.toLocaleString()}</div>
          <p className="kpi-note">
            {accuracy.resolved} of {accuracy.minimum_to_publish} needed before
            any figure is published
          </p>
          {/* Progress toward a threshold, not a score. Deliberately not styled
              as an accuracy gauge — it measures elapsed calendar time. */}
          <div className="teps-bar" aria-hidden="true">
            <div className="teps-seg teps-seg-exposure" style={{ width: `${pct}%` }} />
          </div>
        </div>

        <div className="card">
          <p className="card-title">Brier score</p>
          <div className="kpi">
            {accuracy.brier === null
              ? <span className="text-ink3" style={{ fontSize: 18 }}>not published</span>
              : accuracy.brier.toFixed(3)}
          </div>
          <p className="kpi-note">
            {accuracy.brier === null
              ? 'withheld until enough forecasts resolve — a provisional figure gets screenshotted without its asterisk'
              : 'lower is better; 0 is perfect'}
          </p>
        </div>

        <div className="card">
          <p className="card-title">Skill vs climatology</p>
          <div className="kpi">
            {accuracy.skill_vs_climatology === null
              ? <span className="text-ink3" style={{ fontSize: 18 }}>not published</span>
              : accuracy.skill_vs_climatology.toFixed(3)}
          </div>
          <p className="kpi-note">
            whether the model beats simply predicting the base rate every time
          </p>
        </div>
      </div>

      {/* Prose, not a metric tile. The pipeline is not broken. */}
      <div className="banner banner-warn">
        <strong>Lead time is unmeasurable here.</strong> {accuracy.lead_time}
      </div>

      <div className="grid grid-2">
        <div className="card">
          <p className="card-title">Outcomes</p>
          <table>
            <tbody>
              {Object.entries(accuracy.outcomes).map(([name, count]) => (
                <tr key={name}>
                  <td style={{ textTransform: 'capitalize' }}>
                    {name.replace(/_/g, ' ')}
                  </td>
                  <td className="num mono" style={{ textAlign: 'right' }}>
                    {count.toLocaleString()}
                  </td>
                </tr>
              ))}
              {Object.keys(accuracy.outcomes).length === 0 && (
                <tr><td className="empty">Nothing has resolved yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="card">
          <p className="card-title">Calibration</p>
          {accuracy.calibration.length === 0 ? (
            <p className="text-ink3" style={{ fontSize: 13 }}>
              Calibration compares what each band CLAIMED would happen against
              what did. It needs resolved outcomes, so it stays empty until
              there are some — an empty chart is more honest than a smooth one
              drawn through no data.
            </p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Band</th>
                  <th style={{ textAlign: 'right' }}>Claimed</th>
                  <th style={{ textAlign: 'right' }}>Observed</th>
                  <th style={{ textAlign: 'right' }}>n</th>
                </tr>
              </thead>
              <tbody>
                {accuracy.calibration.map((b) => (
                  <tr key={b.band}>
                    <td><span className={`pill sev-${b.band}`}>{b.band}</span></td>
                    <td className="mono" style={{ textAlign: 'right' }}>
                      {(b.forecast * 100).toFixed(0)}%
                    </td>
                    <td className="mono" style={{ textAlign: 'right' }}>
                      {b.observed === null ? '—' : `${(b.observed * 100).toFixed(0)}%`}
                    </td>
                    <td className="mono" style={{ textAlign: 'right' }}>{b.n}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </section>
  )
}
