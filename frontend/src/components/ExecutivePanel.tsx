import type { Accuracy, CrosshairView, RunRow, SupplierRegister,
              Summary } from '../api/types'

/**
 * Is the programme working — not what should we work on.
 *
 * WHAT MAKES THIS A PROJECTION RATHER THAN A RESKIN. `App.tsx` warned that a
 * Management view with fewer columns is not an executive view, and it was
 * right: the temptation is to show the same ranked findings in a bigger font.
 * This projects a different question off the same graph. Management asks which
 * finding to work; this asks whether the last ten runs moved, whether the
 * predictions have been any good, what the product still cannot see, and where
 * the supply chain has no diversity.
 *
 * COVERAGE LEADS. On every other screen "what we could not establish" is a
 * caveat below the result. Here it is the top item, because an executive's
 * decision is usually about where to spend next, and the honest answer to that
 * is almost always "on the part we cannot currently see" rather than on the
 * ranked list somebody is already working.
 *
 * NO TRAFFIC LIGHT, NO POSTURE SCORE, NO TREND ARROW ON ONE RUN. A single
 * number summarising an estate is the artefact this product exists not to
 * produce, and an arrow drawn between two runs a day apart is noise given the
 * authority of a direction.
 */

export function ExecutivePanel({ runs, accuracy, crosshair, suppliers, summary }: {
  runs: RunRow[]
  accuracy: Accuracy | null
  crosshair: CrosshairView | null
  suppliers: SupplierRegister | null
  summary: Summary | null
}) {
  const series = [...runs].reverse()
  const gaps = Object.entries(crosshair?.coverage_gaps ?? {})
  const topConcentration = suppliers?.concentrations?.[0] ?? null

  return (
    <section className="stack">
      <h2 className="section">Executive</h2>

      {/* Deliberately first. */}
      <div className="banner banner-warn">
        <strong>What this product still cannot see.</strong>{' '}
        {gaps.length === 0 && !summary?.assets_matched_nothing ? (
          <>Nothing is currently recorded as unassessable — which is itself
          worth checking, because a clean coverage report on a partially
          instrumented estate looks identical to a clean one on a complete
          estate.</>
        ) : (
          <>These are limits of our coverage, not findings about the estate, and
          they bound every other number on this page.</>
        )}
        <ul className="gap-list">
          {gaps.map(([gap, count]) => (
            <li key={gap}>
              <span className="gap-count">{count}</span>
              <span className="gap-why">{gap}</span>
            </li>
          ))}
          {summary && summary.assets_matched_nothing > 0 && (
            <li>
              <span className="gap-count">{summary.assets_matched_nothing}</span>
              <span className="gap-why">
                assets corresponded to nothing in the catalogue — not the same
                as being unaffected
              </span>
            </li>
          )}
          {suppliers && suppliers.never_assessed > 0 && (
            <li>
              <span className="gap-count">{suppliers.never_assessed}</span>
              <span className="gap-why">declared suppliers never assessed</span>
            </li>
          )}
        </ul>
      </div>

      <div className="grid grid-4">
        <div className="card">
          <p className="card-title">Runs on record</p>
          <div className="kpi">{runs.length}</div>
          <p className="kpi-note">
            {runs.length < 2
              ? 'a trend needs a series; one run is a reading'
              : `oldest ${String(series[0]?.scanned_at ?? '').slice(0, 10)}`}
          </p>
        </div>
        <div className="card">
          <p className="card-title">Determinations</p>
          <div className="kpi">{summary?.determinations ?? '—'}</div>
          <p className="kpi-note">
            {summary
              ? `${summary.worklist} still need a version checked`
              : 'no scan on record'}
          </p>
        </div>
        <div className="card">
          <p className="card-title">Forecast accuracy</p>
          <div className="kpi" style={{ fontSize: 20 }}>
            {accuracy?.publishable
              ? accuracy.brier?.toFixed(3)
              : <span className="text-ink3">not published</span>}
          </div>
          <p className="kpi-note">
            {accuracy
              ? `${accuracy.resolved} of ${accuracy.minimum_to_publish} forecasts resolved`
              : 'no forecast record'}
          </p>
        </div>
        <div className="card">
          <p className="card-title">Supply-chain concentration</p>
          <div className="kpi" style={{ fontSize: 20 }}>
            {topConcentration
              ? topConcentration.provider
              : <span className="text-ink3">
                  {suppliers?.concentration_refused ? 'not reportable' : 'none'}
                </span>}
          </div>
          <p className="kpi-note">
            {topConcentration
              ? `${topConcentration.count} suppliers share it (${topConcentration.kind})`
              : suppliers?.concentration_refused
                ? 'register too small to support a conclusion'
                : 'no provider is shared by enough suppliers'}
          </p>
        </div>
      </div>

      {/* ── the trend ───────────────────────────────────────────────────── */}
      <div>
        <h3 style={{ fontSize: 14, fontWeight: 650, margin: '0 0 8px' }}>
          Across runs
        </h3>
        {series.length < 2 ? (
          <p className="text-ink2" style={{ fontSize: 13 }}>
            One run is a reading, not a trend. Nothing is drawn until there are
            two — a line through a single point invites a direction to be read
            off it.
          </p>
        ) : (
          <div className="table-card">
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 80 }}>Run</th>
                    <th style={{ width: 180 }}>When</th>
                    <th className="num" style={{ width: 110 }}>Findings</th>
                    <th className="num" style={{ width: 130 }}>Unmatched</th>
                    <th style={{ width: 150 }}>Catalogue</th>
                    <th>Who ran it</th>
                  </tr>
                </thead>
                <tbody>
                  {[...runs].map((r) => (
                    <tr key={r.id}>
                      <td className="mono">{r.id}</td>
                      <td className="text-ink2">
                        {String(r.scanned_at).slice(0, 19).replace('T', ' ')}
                      </td>
                      <td className="num">{r.summary?.findings ?? '—'}</td>
                      {/* Beside the finding count, always. "0 findings" and
                          "0 findings and 380 assets we could not join" are
                          different sentences. */}
                      <td className="num">{r.assets_unmatched}</td>
                      <td className="mono text-ink2">
                        {r.catalog_version}
                        {r.catalog_age_days !== null && (
                          <span className="text-ink3"> · {r.catalog_age_days}d</span>
                        )}
                      </td>
                      <td className="text-ink2">{r.actor}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
        <p className="text-ink3" style={{ fontSize: 12, marginTop: 8 }}>
          The catalogue version is shown per run because a result computed
          against a stale corpus is a different claim from the same result
          computed today, and nothing in the counts says which you are reading.
        </p>
      </div>
    </section>
  )
}
