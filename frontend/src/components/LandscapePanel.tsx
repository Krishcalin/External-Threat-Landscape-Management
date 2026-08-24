import { useEffect, useState } from 'react'
import { ApiError, landscapePlan, landscapeRun, seedKinds } from '../api/client'
import type { LandscapeRun, SeedKindCatalogue, SeedKindInfo, SeedPlan, SeedRow } from '../api/types'

/**
 * Start a threat landscape from what the operator actually has.
 *
 * FOUR LABELLED FIELDS, NOT ONE BOX. `core/lookup.py:parse` refuses an email
 * address with the reason that answering it there "would mean one box quietly
 * doing two unrelated things". That objection is about the box, not the
 * question — so the kind is chosen explicitly, and the screen says what that
 * kind can answer before anything is contacted.
 *
 * THE FOUR ARE NOT EQUIVALENT, AND THE LAYOUT MUST NOT IMPLY THEY ARE. Only a
 * domain expands: certificate transparency turns one apex into hosts nobody
 * remembered. An address seed stays exactly what was typed. An organisation
 * name produces questions for the triage queue and nothing else. An email is
 * answerable only for a domain whose ownership has been verified.
 *
 * Presenting those as four identical inputs would be lying by layout, so each
 * carries its own capability text — served by the API rather than written here,
 * so the promise and the code that keeps it cannot drift apart.
 *
 * THE "NOTHING EXPANDS" WARNING IS THE MOST IMPORTANT THING ON THIS SCREEN, and
 * it is a banner rather than a footnote. A landscape seeded with addresses and
 * organisation names alone contains exactly what was typed, and an operator who
 * does not know that reads a small result as a small estate.
 */

const KIND_ORDER = ['domain', 'address', 'organisation', 'email']

let nextId = 1

export function LandscapePanel({ actor }: { actor: string }) {
  const [catalogue, setCatalogue] = useState<SeedKindCatalogue | null>(null)
  const [rows, setRows] = useState<SeedRow[]>([{ id: nextId++, kind: 'domain', value: '' }])
  const [plan, setPlan] = useState<SeedPlan | null>(null)
  const [run, setRun] = useState<LandscapeRun | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [running, setRunning] = useState(false)

  useEffect(() => {
    seedKinds().then(setCatalogue).catch(() => setCatalogue(null))
  }, [])

  function update(id: number, patch: Partial<SeedRow>) {
    setRows(current => current.map(r => (r.id === id ? { ...r, ...patch } : r)))
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    const filled = rows.filter(r => r.value.trim())
    if (!filled.length) { setError('Add at least one seed.'); return }
    setBusy(true); setError(''); setPlan(null); setRun(null)
    try {
      setPlan(await landscapePlan(
        filled.map(r => ({ value: r.value.trim(), kind: r.kind })), actor))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'the plan could not be built')
    } finally {
      setBusy(false)
    }
  }

  async function startRun() {
    const filled = rows.filter(r => r.value.trim())
    setRunning(true); setError(''); setRun(null)
    try {
      setRun(await landscapeRun(
        filled.map(r => ({ value: r.value.trim(), kind: r.kind })), actor))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'the run failed')
    } finally {
      setRunning(false)
    }
  }

  const byKind = new Map<string, SeedKindInfo>(
    (catalogue?.kinds ?? []).map(k => [k.kind, k]))
  const ordered = KIND_ORDER
    .map(k => byKind.get(k))
    .filter((k): k is SeedKindInfo => Boolean(k))

  return (
    <div className="stack">
      <div className="card">
        <div className="card-title">Threat landscape</div>
        <p className="lede">
          Supply what you have. Each kind of seed answers a different question,
          and this says which before anything is contacted.
        </p>
        {catalogue && <div className="banner banner-info">{catalogue.passive_only}</div>}
      </div>

      <div className="card">
        <div className="card-title">Seeds</div>
        <form onSubmit={submit}>
          {rows.map(row => {
            const meta = byKind.get(row.kind)
            return (
              <div key={row.id} className="stack" style={{ marginBottom: '0.9rem' }}>
                <div className="lookup-form">
                  <select
                    className="lookup-input"
                    style={{ maxWidth: '14rem' }}
                    value={row.kind}
                    aria-label="Seed kind"
                    onChange={e => update(row.id, { kind: e.target.value })}
                  >
                    {ordered.map(k => (
                      <option key={k.kind} value={k.kind}>{k.label}</option>
                    ))}
                  </select>
                  <input
                    className="lookup-input"
                    value={row.value}
                    placeholder={meta?.example ?? ''}
                    aria-label={meta?.label ?? 'Seed value'}
                    autoComplete="off"
                    spellCheck={false}
                    onChange={e => update(row.id, { value: e.target.value })}
                  />
                  <button
                    type="button"
                    className="btn"
                    disabled={rows.length === 1}
                    onClick={() => setRows(c => c.filter(r => r.id !== row.id))}
                  >
                    Remove
                  </button>
                </div>
                {/* The capability text sits WITH the field it describes, not in
                    a legend somebody scrolls past. */}
                {meta && (
                  <div className="gap-why">
                    <strong>
                      {meta.expands
                        ? 'Expands — certificate transparency can find assets you did not supply. '
                        : 'Does not expand — reports on exactly what you type. '}
                    </strong>
                    {meta.capabilities.limits}
                  </div>
                )}
              </div>
            )
          })}

          <div className="lookup-form">
            <button
              type="button"
              className="btn"
              onClick={() => setRows(c => [...c, { id: nextId++, kind: 'domain', value: '' }])}
            >
              Add another
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Checking…' : 'Check what this can answer'}
            </button>
          </div>
        </form>
        {error && <div className="banner banner-crit" role="alert">{error}</div>}
      </div>

      {plan && (
        <>
          {/* THE WARNINGS THAT MATTER MOST, rendered as prominently as a result
              would be rather than as a footnote. */}
          {plan.summary.notes.map((note, i) => (
            <div key={i} className="banner banner-warn" role="note">{note}</div>
          ))}

          <div className="table-card">
            <div className="card-title">
              {plan.summary.seeds} accepted · {plan.summary.expanding_seeds} can
              discover assets you did not supply
            </div>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr><th>Kind</th><th>Seed</th><th>Runs</th><th>Expands</th></tr>
                </thead>
                <tbody>
                  {plan.seeds.map((seed, i) => (
                    <tr key={i}>
                      <td>{byKind.get(seed.kind)?.label ?? seed.kind}</td>
                      <td>
                        <span className="mono">{seed.value}</span>
                        {/* An email is shown as the domain it became, so nobody
                            wonders where their mailbox went. It was discarded at
                            input and never stored. */}
                        {seed.as_entered !== seed.value && (
                          <span className="text-ink2"> (from {seed.as_entered})</span>
                        )}
                      </td>
                      <td>{seed.capabilities.runs.join(', ')}</td>
                      <td>{seed.expands ? 'yes' : 'no'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card">
            <div className="card-title">Run it</div>
            <p className="lede">
              Contacts third-party sources for each seed. Nothing is sent to the
              assets themselves — this reports what they PUBLISH.
            </p>
            <button className="btn btn-primary" onClick={startRun} disabled={running}>
              {running ? 'Running…' : `Run ${plan.summary.seeds} seed(s)`}
            </button>
          </div>

          {plan.refused.length > 0 && (
            <div className="card">
              <div className="card-title">Not usable as seeds</div>
              {/* Returned as data rather than failing the request: ten good
                  seeds and one typo is a normal paste, and rejecting the lot
                  teaches people to paste less. */}
              <ul className="gap-list">
                {plan.refused.map((item, i) => (
                  <li key={i}>
                    <span className="mono">{item.input}</span>
                    <div className="gap-why">{item.why}</div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}

      {run && (
        <>
          {/* Every limit on the assembled view, as prominently as the counts. */}
          {run.landscape.notes.map((note, i) => (
            <div key={i} className="banner banner-warn" role="note">{note}</div>
          ))}

          <div className="card">
            <div className="card-title">Landscape</div>
            <div className="grid grid-2">
              <div className="kpi">
                <div className="num">{run.landscape.asset_count}</div>
                <div className="kpi-note">assets reached</div>
              </div>
              <div className="kpi">
                <div className="num">{run.landscape.discovered_count}</div>
                <div className="kpi-note">found that you did not supply</div>
              </div>
            </div>
            {/* NOT A CENSUS, and said where the counts are rather than
                underneath them. */}
            <div className="banner banner-info">{run.landscape.coverage_means}</div>
          </div>

          {run.landscape.assets.length > 0 && (
            <div className="table-card">
              <div className="card-title">Assets</div>
              <div className="table-scroll">
                <table>
                  <thead><tr><th>Asset</th><th>Origin</th></tr></thead>
                  <tbody>
                    {run.landscape.assets.map((asset, i) => (
                      <tr key={i}>
                        <td className="mono">{asset}</td>
                        <td>
                          {run.landscape.discovered.includes(asset)
                            ? 'discovered'
                            : 'you supplied it'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {run.landscape.unavailable.length > 0 && (
            <div className="card">
              <div className="card-title">Sources that could not answer</div>
              {/* UNAVAILABLE IS NOT CLEAN — the single most consequential thing
                  this panel can get wrong, so it is a section and not a
                  footnote. LookupPanel gives the same reason for its banner. */}
              <ul className="gap-list">
                {run.landscape.unavailable.map((item, i) => (
                  <li key={i}>
                    <strong>{item.source}</strong>
                    <div className="gap-why">{item.why}</div>
                    <div className="gap-why">{item.cost}</div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {run.landscape.failed_seeds.length > 0 && (
            <div className="card">
              <div className="card-title">Seeds that failed</div>
              <ul className="gap-list">
                {run.landscape.failed_seeds.map((item, i) => (
                  <li key={i}>
                    <span className="mono">{item.seed}</span>
                    <div className="gap-why">{item.why}</div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  )
}
