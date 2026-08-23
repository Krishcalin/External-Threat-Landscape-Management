import { useEffect, useState } from 'react'
import { accountBreaches, ApiError, brandLookalikes, secretsScanning }
  from '../api/client'
import type { BreachReport, LookalikeReport } from '../api/types'

/**
 * Names that borrow your brand, and addresses that appear in breach corpora.
 *
 * THE ONE THING THIS SCREEN MUST NEVER DO is show an empty list when nothing
 * was searched. Zero lookalike domains is exactly what a customer hopes to see,
 * so they will believe it — and while this was being built, crt.sh (the only
 * source that can answer "names anywhere containing this term") was returning
 * 502 on every request including its own homepage.
 *
 * So `searched: false` gets a red banner and NO empty-state list. A grey "no
 * results" panel would be indistinguishable from a clean bill of health.
 *
 * EVERY ROW CARRIES ITS OWN DISCLAIMER, not one at the top. A row is what gets
 * copied into a takedown request, and a takedown filed against a legitimate
 * reseller is worse than a missed phishing domain — it is an action the
 * customer took on our say-so.
 *
 * ROWS ARE REGISTRATIONS, NOT HOSTNAMES. Measured: 823 real hostnames collapse
 * to 6 registrable domains, and "is this domain yours?" is a question somebody
 * can answer at 6 and cannot at 823.
 */

export function BrandPanel({ actor }: { actor: string }) {
  const [terms, setTerms] = useState('')
  const [owned, setOwned] = useState('')
  const [report, setReport] = useState<LookalikeReport | null>(null)
  const [address, setAddress] = useState('')
  const [breach, setBreach] = useState<BreachReport | null>(null)
  const [secrets, setSecrets] = useState<{ reason: string; integration: string } | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    secretsScanning().then(setSecrets).catch(() => setSecrets(null))
  }, [])

  const split = (value: string) =>
    value.split(/[,\s]+/).map((v) => v.trim()).filter(Boolean)

  async function search(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true); setError(''); setReport(null)
    try {
      setReport(await brandLookalikes(split(terms), split(owned), actor))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally { setBusy(false) }
  }

  async function checkAddress(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true); setError(''); setBreach(null)
    try {
      setBreach(await accountBreaches(address, actor))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally { setBusy(false) }
  }

  return (
    <section className="stack">
      <h2 className="section">Brand &amp; identity</h2>

      {error && <div className="banner banner-crit" role="alert">{error}</div>}

      {/* ── lookalikes ──────────────────────────────────────────────────── */}
      <div>
        <h3 className="lookup-h3">Names borrowing your brand</h3>
        <form onSubmit={search} className="stack">
          <label className="field">
            <span>Brand terms — comma separated, four characters or more</span>
            <input className="lookup-input" value={terms}
                   onChange={(e) => setTerms(e.target.value)}
                   placeholder="acme, acmebank" />
          </label>
          <label className="field">
            <span>
              Domains you own — everything under these is excluded. Without them
              the first result is a list of your own websites.
            </span>
            <input className="lookup-input" value={owned}
                   onChange={(e) => setOwned(e.target.value)}
                   placeholder="acme.com, acme.co.in" />
          </label>
          <button className="btn btn-primary" disabled={busy || !terms.trim()}>
            {busy ? 'Searching…' : 'Search certificate transparency'}
          </button>
        </form>
        <p className="text-ink3" style={{ fontSize: 12 }}>
          A password-harvesting site needs HTTPS to look convincing, which needs
          a certificate, which lands in a public log. Nothing here contacts the
          imitator.
        </p>
      </div>

      {report && !report.searched && (
        /* The failure this panel exists to prevent. No list is rendered at all
           — an empty table beside this banner would still read as "none". */
        <div className="banner banner-crit" role="alert">
          <strong>No source could be searched, so this is not a result.</strong>{' '}
          Zero names found and zero names looked at are different answers, and
          this is the second one.
          <ul className="gap-list">
            {report.unavailable_sources.map((s) => (
              <li key={s.source}>
                <span className="gap-count">{s.source}</span>
                <span className="gap-why">{s.why} — {s.cost}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {report && report.searched && (
        <>
          <p className="lede">{report.headline}</p>

          <div className="banner banner-info">
            <strong>This establishes nothing.</strong> {report.never_a_verdict}
          </div>

          {report.candidates.length > 0 ? (
            <div className="table-card">
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: 220 }}>Registration</th>
                      <th style={{ width: 90 }} className="num">Signals</th>
                      <th>Why it was flagged</th>
                      <th style={{ width: 130 }}>First seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.candidates.map((c) => (
                      <tr key={c.registration}>
                        <td>
                          <div className="mono" style={{ fontWeight: 600 }}>
                            {c.registration}
                          </div>
                          {/* The strongest hostname, as evidence for the row. */}
                          <div className="mono text-ink3" style={{ fontSize: 11 }}>
                            seen as {c.name}
                          </div>
                        </td>
                        <td className="num">
                          <span className={`pill ${c.strength >= 4
                            ? 'sev-critical' : c.strength >= 3
                              ? 'sev-high' : 'sev-medium'}`}>
                            {c.strength}
                          </span>
                        </td>
                        <td>
                          {c.signals.map((s) => (
                            <div key={s} style={{ marginBottom: 4 }}>
                              <span className="chip">{s.replace(/_/g, ' ')}</span>{' '}
                              <span className="text-ink2" style={{ fontSize: 12 }}>
                                {c.signal_meaning[s]}
                              </span>
                            </div>
                          ))}
                        </td>
                        <td className="mono text-ink2">{c.first_seen ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="banner banner-ok">
              <strong>
                {report.examined} name(s) examined; none cleared{' '}
                {report.minimum_signals} independent signals.
              </strong>{' '}
              This is a real answer — a source was searched. It is not a
              guarantee: a name that has never had a certificate is invisible
              here.
            </div>
          )}

          {report.candidates.length > 0 && (
            <p className="text-ink3" style={{ fontSize: 12 }}>
              Rows are REGISTRATIONS, not hostnames — one registration is one
              decision. Confirm each is not yours, a partner or a reseller
              before acting on it.
            </p>
          )}
        </>
      )}

      {/* ── breach exposure ─────────────────────────────────────────────── */}
      <div>
        <h3 className="lookup-h3">Breach exposure for an address</h3>
        <form onSubmit={checkAddress} className="lookup-form">
          <input className="lookup-input" value={address} type="email"
                 onChange={(e) => setAddress(e.target.value)}
                 placeholder="someone@example.com" />
          <button className="btn" disabled={busy || !address.trim()}>Check</button>
        </form>
      </div>

      {breach && (
        <div className={`banner ${breach.available ? 'banner-info' : 'banner-warn'}`}>
          <strong>{breach.detail}</strong>
          <div className="text-ink2" style={{ fontSize: 13, marginTop: 6 }}>
            {breach.what_this_does_not_say}
          </div>
          {breach.available && breach.caveat && (
            <div className="text-ink3" style={{ fontSize: 12, marginTop: 6 }}>
              {breach.caveat}
            </div>
          )}
          {breach.observations.length > 0 && (
            <ul className="gap-list">
              {breach.observations.map((o, i) => (
                <li key={i}>
                  <span className="gap-count">{String(o.breach_date ?? '')}</span>
                  <span className="gap-why">
                    {String(o.title ?? o.name)} —{' '}
                    {(o.data_classes as string[] | undefined)?.join(', ')}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* ── the deliberate gap ──────────────────────────────────────────── */}
      {secrets && (
        <div className="card">
          <p className="card-title">Exposed keys and tokens</p>
          <p className="text-ink2" style={{ fontSize: 13, marginTop: 0 }}>
            {secrets.reason}
          </p>
          <p className="text-ink3" style={{ fontSize: 12, marginBottom: 0 }}>
            {secrets.integration}
          </p>
        </div>
      )}
    </section>
  )
}
