import { useEffect, useState } from 'react'
import { ApiError, lookupSources, lookupTarget } from '../api/client'
import type { LookupResult, ScoreFactor, SourceCatalogue } from '../api/types'

/**
 * Type a domain or a block and see what the public record says.
 *
 * THE SCORE NEVER APPEARS WITHOUT ITS FACTORS. Not in a tooltip, not behind an
 * expander, not on a second request. A number whose decomposition is one click
 * away is a number that travels alone in a screenshot, and this is the screen
 * most likely to be screenshotted — somebody types a competitor, a supplier or
 * an acquisition target into it and pastes the result into a deck.
 *
 * SO THE REFUSAL IS RENDERED AS PROMINENTLY AS A SCORE WOULD BE. With fewer
 * than three observed factors there is no number at all, and the space where it
 * would have been says why. A greyed-out "—" invites somebody to read it as
 * zero.
 *
 * UNAVAILABLE IS NOT CLEAN. Without a Shodan key this cannot see open ports at
 * all. That is the single most consequential thing this panel can get wrong, so
 * it is a banner rather than a footnote: a result that omits Shodan silently
 * reads as "nothing is listening".
 */

const FACTOR_LABEL: Record<string, string> = {
  surface: 'Surface',
  posture: 'Published posture',
  registration: 'Registration',
  reputation: 'Reputation',
}

export function LookupPanel({ actor }: { actor: string }) {
  const [target, setTarget] = useState('')
  const [result, setResult] = useState<LookupResult | null>(null)
  const [catalogue, setCatalogue] = useState<SourceCatalogue | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    lookupSources().then(setCatalogue).catch(() => setCatalogue(null))
  }, [])

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true); setError(''); setResult(null)
    try {
      setResult(await lookupTarget(target, actor))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const unconfigured = catalogue?.sources.filter(
    (s) => s.terms === 'credentialed' && !s.configured) ?? []

  return (
    <section className="stack">
      <h2 className="section">Lookup</h2>

      <form onSubmit={submit} className="lookup-form">
        <input
          className="lookup-input"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="example.com, www.example.com, 203.0.113.4, or 203.0.113.0/24"
          aria-label="Domain, host, address or CIDR block"
        />
        <button className="btn btn-primary" disabled={busy || !target.trim()}>
          {busy ? 'Looking…' : 'Look up'}
        </button>
      </form>

      {/* Stated before any result, so nobody reads a thin answer as a clean
          one. The constraint is architectural, not a setting. */}
      <p className="text-ink3" style={{ fontSize: 12, marginTop: 0 }}>
        Passive only: this reads public records and asks third-party resolvers.
        No packet reaches the target, and no result here describes what it runs.
      </p>

      {unconfigured.length > 0 && (
        <div className="banner banner-warn">
          <strong>
            {unconfigured.length} licensed source{unconfigured.length > 1 ? 's are' : ' is'} not
            configured.
          </strong>{' '}
          Without them this lookup cannot see open ports, services or
          third-party reputation at all — and a quiet result is not a clean one.
          <ul className="gap-list">
            {unconfigured.map((s) => (
              <li key={s.name}>
                <span className="gap-count">{s.name}</span>
                <span className="gap-why">
                  set <span className="mono">{s.credential_env}</span> — {s.note}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {error && <div className="banner banner-crit" role="alert">{error}</div>}

      {result && (
        <>
          <p className="lede">{result.headline}</p>

          <div className="grid grid-2">
            <ScoreCard score={result.score} />
            <div className="card">
              <p className="card-title">What this cannot tell you</p>
              <p className="text-ink2" style={{ fontSize: 13, margin: 0 }}>
                {result.passive_only}
              </p>
            </div>
          </div>

          <div>
            <h3 className="lookup-h3">Factors</h3>
            <div className="grid grid-2">
              {Object.entries(result.score.factors).map(([name, factor]) => (
                <FactorCard key={name} name={name} factor={factor} />
              ))}
            </div>
          </div>

          {result.keyed_sources.length > 0 && (
            <div>
              <h3 className="lookup-h3">Licensed sources</h3>
              {result.keyed_sources.map((source) => (
                <div key={source.source}
                     className={`banner ${source.available ? 'banner-info' : 'banner-warn'}`}
                     style={{ marginBottom: 8 }}>
                  <strong>{source.source}</strong> — {source.detail}
                  {/* Never hidden. These paths have not been run against the
                      live service, and a reader trusting a result deserves to
                      know that before they act on it. */}
                  {source.available && source.caveat && (
                    <div className="text-ink3" style={{ fontSize: 12, marginTop: 6 }}>
                      {source.caveat}
                    </div>
                  )}
                  {source.observations.length > 0 && (
                    <ul className="gap-list">
                      {source.observations.slice(0, 8).map((o, i) => (
                        <li key={i} className="mono" style={{ fontSize: 12 }}>
                          {JSON.stringify(o)}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          )}

          {result.names.length > 0 && (
            <div>
              <h3 className="lookup-h3">
                Names in certificate transparency
                <span className="text-ink3"> — {result.names.length}</span>
              </h3>
              <div className="chip-wrap">
                {result.names.slice(0, 60).map((n) => (
                  <span key={n} className="chip mono">{n}</span>
                ))}
              </div>
              {result.names.length > 60 && (
                <p className="text-ink3" style={{ fontSize: 12 }}>
                  Showing 60 of {result.names.length}. The count above is all of
                  them.
                </p>
              )}
              <p className="text-ink3" style={{ fontSize: 12 }}>
                A wildcard proves a certificate exists, never that a host does.
                A name that has never had a certificate is invisible here.
              </p>
            </div>
          )}

          {Object.keys(result.reverse_dns).length > 0 && (
            <div>
              <h3 className="lookup-h3">Reverse DNS</h3>
              <div className="table-card">
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr><th style={{ width: 180 }}>Address</th><th>PTR</th></tr>
                    </thead>
                    <tbody>
                      {Object.entries(result.reverse_dns).map(([a, n]) => (
                        <tr key={a}>
                          <td className="mono">{a}</td>
                          <td className="mono">{n}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              <p className="text-ink3" style={{ fontSize: 12 }}>
                An address with no PTR record is normal and is not evidence it
                is unused.
              </p>
            </div>
          )}

          {result.unavailable_sources.length > 0 && (
            <div className="banner banner-warn">
              <strong>Sources that did not answer.</strong> Each is something
              this result does not know:
              <ul className="gap-list">
                {result.unavailable_sources.map((s) => (
                  <li key={s.source}>
                    <span className="gap-count">{s.source}</span>
                    <span className="gap-why">{s.why} — {s.cost}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </section>
  )
}

/** The number, or the reason there is not one — in the same place, at the same
 *  size. A greyed-out dash reads as zero. */
function ScoreCard({ score }: { score: LookupResult['score'] }) {
  return (
    <div className="card">
      <p className="card-title">Observable posture</p>
      {score.publishable ? (
        <>
          <div className="kpi">{score.value}<span className="text-ink3"
            style={{ fontSize: 16, fontWeight: 500 }}> / 100</span></div>
          <p className="kpi-note">
            across {Object.keys(score.factors).length - score.unobserved.length}{' '}
            observed factor(s); {score.unobserved.length} could not be observed
            and {score.unobserved.length === 1 ? 'is' : 'are'} not counted as
            zero.
          </p>
        </>
      ) : (
        <>
          <div className="kpi text-ink3" style={{ fontSize: 20 }}>
            no score
          </div>
          <p className="kpi-note">{score.refusal}</p>
        </>
      )}
      <p className="text-ink3" style={{ fontSize: 12, marginTop: 10 }}>
        {score.not_a_grade}
      </p>
    </div>
  )
}

function FactorCard({ name, factor }: { name: string; factor: ScoreFactor }) {
  return (
    <div className="card">
      <p className="card-title">{FACTOR_LABEL[name] ?? name}</p>
      {factor.observed ? (
        <div className="kpi" style={{ fontSize: 22 }}>
          {Math.round((factor.value ?? 0) * 100)}%
        </div>
      ) : (
        <div className="kpi text-ink3" style={{ fontSize: 16 }}>unobserved</div>
      )}
      <p className="kpi-note">{factor.measures}</p>
      {factor.inputs.length > 0 && (
        <ul className="gap-list">
          {factor.inputs.map((input) => (
            <li key={input}><span className="gap-why mono"
              style={{ fontSize: 12 }}>{input}</span></li>
          ))}
        </ul>
      )}
      {/* Beside every factor, always. The limits are the point of the panel. */}
      <p className="text-ink3" style={{ fontSize: 12, marginTop: 8 }}>
        <strong>Cannot see:</strong> {factor.cannot_see}
      </p>
    </div>
  )
}
