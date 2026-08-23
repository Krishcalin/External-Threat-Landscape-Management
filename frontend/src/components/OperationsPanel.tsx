import type { ChangesView, Finding } from '../api/types'

/**
 * What is on my desk this week.
 *
 * THE PROJECTION IS BY OWNER AND CLOCK, NOT BY SCORE. Management ranks by TEPS
 * because it answers "what matters most". This answers "what is mine and what
 * is late", which sorts differently: a medium-band finding overdue by two years
 * and assigned to a named team beats a critical one nobody owns, because the
 * second is a queue problem and the first is a work problem.
 *
 * UNASSIGNED IS A ROW, NOT A FILTER. A finding nobody owns is the one most
 * likely to go nowhere, so it appears at the top of the queue rather than
 * disappearing from a per-team view. Every operations screen that groups by
 * owner quietly hides the ones with no owner, which are exactly the ones that
 * need a person.
 *
 * THE DUE DATE IS CISA'S, NOT OURS. It comes from the KEV catalogue's remediation
 * deadline for federal agencies. Most readers are not a US federal agency, so it
 * is rendered as what it is — a published deadline for somebody else, useful as
 * a severity-weighted clock and not as a compliance obligation.
 */

const UNASSIGNED = ' unassigned'

export function OperationsPanel({ findings, changes }: {
  findings: Finding[]
  changes: ChangesView | null
}) {
  const today = new Date().toISOString().slice(0, 10)

  const byOwner = new Map<string, Finding[]>()
  for (const f of findings) {
    const key = f.owner?.trim() || UNASSIGNED
    byOwner.set(key, [...(byOwner.get(key) ?? []), f])
  }

  const overdue = (f: Finding) => Boolean(f.due_date && f.due_date < today)
  const queues = [...byOwner.entries()].sort((a, b) => {
    // Unassigned first: the queue problem outranks any team's work problem.
    if (a[0] === UNASSIGNED) return -1
    if (b[0] === UNASSIGNED) return 1
    const late = b[1].filter(overdue).length - a[1].filter(overdue).length
    return late !== 0 ? late : b[1].length - a[1].length
  })

  const totalOverdue = findings.filter(overdue).length

  return (
    <section className="stack">
      <h2 className="section">Operations</h2>

      {changes && (
        <div className={`banner ${changes.new > 0 ? 'banner-warn' : 'banner-info'}`}>
          <strong>{changes.headline}</strong>{' '}
          {changes.is_baseline
            ? 'This is a baseline run — everything is new because there is nothing to compare against.'
            : `${changes.resolved} resolved, ${changes.changed_band} changed band.`}
        </div>
      )}

      <div className="grid grid-4">
        <div className="card">
          <p className="card-title">In the queue</p>
          <div className="kpi">{findings.length}</div>
          <p className="kpi-note">across {byOwner.size} owner(s)</p>
        </div>
        <div className="card">
          <p className="card-title">Past their due date</p>
          <div className={totalOverdue ? 'kpi text-crit' : 'kpi text-low'}>
            {totalOverdue}
          </div>
          <p className="kpi-note">
            CISA&rsquo;s published remediation deadline — see the note below
          </p>
        </div>
        <div className="card">
          <p className="card-title">Unassigned</p>
          <div className={byOwner.has(UNASSIGNED) ? 'kpi text-crit' : 'kpi text-low'}>
            {byOwner.get(UNASSIGNED)?.length ?? 0}
          </div>
          <p className="kpi-note">
            a finding nobody owns is the one most likely to go nowhere
          </p>
        </div>
        <div className="card">
          <p className="card-title">New since last run</p>
          <div className={changes?.new ? 'kpi text-crit' : 'kpi'}>
            {changes?.new ?? '—'}
          </div>
          <p className="kpi-note">
            identity is (asset, cve) — a score moving is not a new finding
          </p>
        </div>
      </div>

      {queues.map(([owner, queue]) => {
        const late = queue.filter(overdue)
        return (
          <div key={owner}>
            <h3 style={{ fontSize: 14, fontWeight: 650, margin: '0 0 8px' }}>
              {owner === UNASSIGNED
                ? <span className="pill sev-critical">unassigned</span>
                : owner}
              <span className="text-ink3"> — {queue.length} item(s)</span>
              {late.length > 0 && (
                <span className="pill sev-high" style={{ marginLeft: 8 }}>
                  {late.length} overdue
                </span>
              )}
            </h3>
            <div className="table-card">
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: 140 }}>Due</th>
                      <th style={{ width: 150 }}>CVE</th>
                      <th>Asset</th>
                      <th style={{ width: 110 }}>Band</th>
                      <th>What to do</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[...queue]
                      .sort((a, b) => String(a.due_date ?? '9999')
                        .localeCompare(String(b.due_date ?? '9999')))
                      .slice(0, 12)
                      .map((f) => (
                        <tr key={`${f.asset}-${f.cve}`}>
                          <td className="mono">
                            {f.due_date ?? <span className="text-ink3">none</span>}
                            {overdue(f) && (
                              <div className="text-crit" style={{ fontSize: 11 }}>
                                overdue
                              </div>
                            )}
                          </td>
                          <td className="mono">{f.cve}</td>
                          <td className="mono">{f.asset}</td>
                          <td><span className={`pill sev-${f.band}`}>{f.band}</span></td>
                          <td className="text-ink2" style={{ fontSize: 12 }}>
                            {f.required_action ?? '—'}
                            {/* Carried into the queue, because a ticket that
                                says "CVE-x on host-y" reads as a determination
                                to whoever picks it up. */}
                            {f.basis === 'product_match' && (
                              <div className="text-ink3" style={{ marginTop: 4 }}>
                                version not compared — confirm before patching
                              </div>
                            )}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
            {queue.length > 12 && (
              <p className="text-ink3" style={{ fontSize: 12, marginTop: 8 }}>
                Showing 12 of {queue.length}. The count above is the whole queue.
              </p>
            )}
          </div>
        )
      })}

      {findings.length === 0 && (
        <div className="empty">
          Nothing in the queue. Run a scan to populate this view.
        </div>
      )}

      <p className="text-ink3" style={{ fontSize: 12 }}>
        The due date is CISA&rsquo;s published remediation deadline for US
        federal agencies, carried from the KEV catalogue. Unless you are one, it
        is not an obligation you hold — it is a severity-weighted clock somebody
        else set, and it is shown because it is the only externally-published
        deadline attached to these vulnerabilities.
      </p>
    </section>
  )
}
