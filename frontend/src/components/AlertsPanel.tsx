import type { AlertsView } from '../api/types'

/**
 * What would be worth interrupting somebody for — decided, and not sent.
 *
 * THE SUPPRESSED COUNTS ARE NOT A DETAIL. An operator who sees five alerts
 * needs to know whether five was everything or a cap, because a cap that does
 * not announce itself is a silent filter on their view of their own estate.
 * They sit beside the list, not under it.
 *
 * NO SEND BUTTON, AND THAT IS THE POINT. Delivery is switched on in the
 * environment by whoever runs the service, once. A button here would mean
 * anyone who can reach the console could choose the moment the estate is
 * described to a third party — and "describe my estate to a webhook" is not an
 * action a dashboard should offer casually.
 *
 * THE STATE THIS SCREEN EXISTS FOR is delivery switched on with no channel
 * configured. From the outside it is indistinguishable from a quiet run, and a
 * silent alerting integration is worse than none because it is mistaken for
 * coverage. It gets a banner, not a footnote.
 */

export function AlertsPanel({ view }: { view: AlertsView | null }) {
  if (!view) {
    return (
      <section className="stack">
        <h2 className="section">Alerts</h2>
        <div className="empty">
          No scan on record. That is not a quiet estate — it is no evidence
          either way.
        </div>
      </section>
    )
  }

  const misconfigured = view.delivery.includes('NO CHANNEL IS CONFIGURED')

  return (
    <section className="stack">
      <h2 className="section">
        Alerts
        {view.previous_run !== null && (
          <span className="text-ink3"> — since run {view.previous_run}</span>
        )}
      </h2>

      <div className={`banner ${misconfigured ? 'banner-crit' : 'banner-info'}`}>
        <strong>
          {misconfigured
            ? 'Delivery is on and no channel is configured.'
            : 'Computed here, delivered elsewhere.'}
        </strong>{' '}
        {view.delivery}
      </div>

      {view.is_baseline && (
        <div className="banner banner-warn">
          <strong>This is a baseline run.</strong> Everything is new because
          there is nothing to compare against, which is why nothing is treated
          as newly appeared.
        </div>
      )}

      <div className="grid grid-4">
        <div className="card">
          <p className="card-title">Would alert</p>
          <div className={view.alerts.length ? 'kpi text-crit' : 'kpi'}>
            {view.alerts.length}
          </div>
          <p className="kpi-note">at or above <strong>{view.minimum_band}</strong></p>
        </div>
        <div className="card">
          <p className="card-title">Suppressed: below band</p>
          <div className="kpi">{view.suppressed_below_band}</div>
          <p className="kpi-note">
            real findings, deliberately not sent — they are on the worklist
          </p>
        </div>
        <div className="card">
          <p className="card-title">Suppressed: by cap</p>
          <div className={view.suppressed_by_cap ? 'kpi text-med' : 'kpi'}>
            {view.suppressed_by_cap}
          </div>
          <p className="kpi-note">
            {view.suppressed_by_cap
              ? 'a cap that did not announce itself would be a silent filter'
              : 'nothing was capped this run'}
          </p>
        </div>
        <div className="card">
          <p className="card-title">Delivered</p>
          <div className="kpi text-ink2" style={{ fontSize: 20 }}>
            {view.delivered ? 'yes' : 'no'}
          </div>
          <p className="kpi-note">
            this screen never sends anything; a scan does, if switched on
          </p>
        </div>
      </div>

      {view.alerts.length === 0 ? (
        <div className="banner banner-ok">
          <strong>{view.note}</strong>{' '}
          A quiet run is a result, not a failure — but read the suppressed
          counts above before treating it as a quiet estate.
        </div>
      ) : (
        <div className="table-card">
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 150 }}>Trigger</th>
                  <th>What happened</th>
                  <th style={{ width: 220 }}>Asset</th>
                </tr>
              </thead>
              <tbody>
                {view.alerts.map((a, i) => (
                  <tr key={`${a.trigger}-${i}`}>
                    <td>
                      <span className="pill sev-high">
                        {a.trigger.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{a.subject}</div>
                      {/* Enough to act on without opening the console — which
                          is the difference between an alert and a prompt to go
                          and look. */}
                      <div className="text-ink2" style={{ fontSize: 12, marginTop: 4,
                        whiteSpace: 'pre-wrap' }}>
                        {a.body}
                      </div>
                    </td>
                    <td className="mono">
                      {String(a.detail.asset ?? '—')}
                      <div className="text-ink3" style={{ marginTop: 4 }}>
                        {String(a.detail.owner ?? 'unassigned')}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {view.triggers_off_by_default.length > 0 && (
        <p className="text-ink3" style={{ fontSize: 12 }}>
          Off by default:{' '}
          {view.triggers_off_by_default.map((t) => t.replace(/_/g, ' ')).join(', ')}.
          A band change is not a trigger because EPSS moves daily, and a feed
          that fires whenever a score crosses a boundary trains its reader to
          ignore it.
        </p>
      )}
    </section>
  )
}
