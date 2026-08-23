import { useEffect, useState } from 'react'
import { ApiError, crosshair as fetchCrosshair,
         dnsRuns as fetchDnsRuns, findings as fetchFindings,
         intel as fetchIntel, reconciliationGuide,
         summary as fetchSummary } from './api/client'
import type { CrosshairView, DnsRun, Finding, IntelStatus,
              ReconciliationOutcome,
              Summary } from './api/types'
import { CoveragePanel } from './components/CoveragePanel'
import { CrosshairPanel } from './components/CrosshairPanel'
import { TepsBar } from './components/TepsBar'

/**
 * The SKOPOS console.
 *
 * ONE SCREEN, DELIBERATELY. The SRS specifies Executive, Management and
 * Operations projections of one graph. Shipping three half-built views would
 * make the product look broader and be worse; this is the Management view — the
 * prioritised backlog with its evidence — because it is the one that has an
 * engine behind it today. The other two arrive when they have something to
 * project.
 *
 * WHAT THIS SCREEN REFUSES TO DO. It never shows a finding count without also
 * showing what was not assessed, and it never shows a TEPS without its
 * decomposition being one click away. Those two rules are the difference between
 * a console and a dashboard.
 */

const RECON_TONE: Record<ReconciliationOutcome, string> = {
  unexplained_exposure: 'banner-crit',
  discovery_blind_spot: 'banner-warn',
  confirmed: 'banner-info',
  agreed_not_exposed: 'banner-ok',
  inconclusive: 'banner',
}

const RECON_LABEL: Record<ReconciliationOutcome, string> = {
  unexplained_exposure: 'Unexplained exposure',
  discovery_blind_spot: 'Discovery blind spot',
  confirmed: 'Confirmed by both methods',
  agreed_not_exposed: 'Agreed not exposed',
  inconclusive: 'Inconclusive',
}

function Kpi({ title, value, note, tone }: {
  title: string; value: string | number; note?: string; tone?: string
}) {
  return (
    <div className="card">
      <h3 className="card-title">{title}</h3>
      <div className={`kpi ${tone ?? ''}`}>{value}</div>
      {note && <div className="kpi-note">{note}</div>}
    </div>
  )
}

function FindingRow({ finding, open, onToggle }: {
  finding: Finding; open: boolean; onToggle: () => void
}) {
  const f = finding
  return (
    <>
      <tr className="row-button" onClick={onToggle}>
        <td>
          <strong>{f.teps}</strong>{' '}
          <span className={`pill sev-${f.band}`}>{f.band}</span>
        </td>
        <td className="mono">{f.cve}</td>
        <td>
          {f.asset}
          <div className="text-ink3" style={{ fontSize: 12 }}>
            {f.product}{f.version ? ` ${f.version}` : ''}
          </div>
        </td>
        <td>{f.owner ?? <span className="text-ink3">unassigned</span>}</td>
        <td>
          {f.known_ransomware && (
            <span className="pill sev-critical">ransomware</span>
          )}
        </td>
        <td>
          {/* Confidence is visually distinct from severity (FR-UI-003): a
              high-severity, low-confidence finding must never look confirmed. */}
          <span className={`pill ${f.match_confidence === 'confirmed'
            ? 'sev-low' : 'sev-medium'}`}>
            {f.match_confidence}
          </span>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6} style={{ background: 'var(--panel2)' }}>
            <div className="stack">
              <div>
                <h3 className="card-title">Why this score</h3>
                <TepsBar factors={f.factors} />
              </div>

              {f.flags.length > 0 && (
                <div className="flags">
                  {f.flags.map((flag) => (
                    <span className="flag" key={flag}>{flag}</span>
                  ))}
                </div>
              )}

              <div>
                <h3 className="card-title">Evidence</h3>
                <ul className="text-ink2" style={{ margin: 0, paddingLeft: 18, fontSize: 12 }}>
                  {f.evidence.map((line, i) => <li key={i}>{line}</li>)}
                </ul>
              </div>

              {f.cloud && (
                <div>
                  <h3 className="card-title">Cloud context — from OverWatch</h3>
                  <div className="text-ink2" style={{ fontSize: 12 }}>
                    <span className="mono">{f.cloud.kind}</span>
                    {f.cloud.account && ` · account ${f.cloud.account}`}
                    {f.cloud.region && ` · ${f.cloud.region}`}
                    {' · cloud model says '}
                    <strong>{f.cloud.internal_reachability.replace('_', ' ')}</strong>
                    {f.cloud.exposed_ports.length > 0 &&
                      ` · ports ${f.cloud.exposed_ports.join(', ')}`}
                    {f.cloud.fronted_by.length > 0 &&
                      ` · fronted by ${f.cloud.fronted_by.join(', ')}`}
                  </div>
                </div>
              )}

              <div>
                <h3 className="card-title">Required action — CISA</h3>
                <div className="text-ink2" style={{ fontSize: 12 }}>
                  {f.required_action}
                  {f.due_date && <> Due <strong>{f.due_date}</strong>.</>}
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

export function App() {
  const [intel, setIntel] = useState<IntelStatus | null>(null)
  const [summary, setSummary] = useState<Summary | null>(null)
  const [rows, setRows] = useState<Finding[]>([])
  const [guide, setGuide] = useState<Record<string, string>>({})
  const [openRow, setOpenRow] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [theme, setTheme] = useState<'light' | 'dark'>('light')
  const [dnsRun, setDnsRun] = useState<DnsRun | null>(null)
  const [crosshair, setCrosshair] = useState<CrosshairView | null>(null)

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  useEffect(() => {
    fetchIntel().then(setIntel).catch((e) =>
      setError(e instanceof ApiError ? e.message : String(e)))
    reconciliationGuide().then(setGuide).catch(() => { /* guidance is optional */ })
    // A 404 here means no scan has been run, which is a state and not a failure.
    fetchSummary().then(setSummary).catch(() => setSummary(null))
    fetchFindings(200).then((page) => setRows(page.findings)).catch(() => setRows([]))
    // The newest sweep, for the coverage panel. Absent is a state, not an error:
    // no sweep having run is not an estate with no DNS.
    fetchDnsRuns()
      .then((page) => setDnsRun(page.runs[0] ?? null))
      .catch(() => setDnsRun(null))
    // Absent is a state, not an error: no scan on record is not an estate with
    // nothing in the crosshair.
    fetchCrosshair().then(setCrosshair).catch(() => setCrosshair(null))
  }, [])

  const unexplained = summary?.reconciliation?.unexplained_exposure ?? 0
  const blindSpots = summary?.reconciliation?.discovery_blind_spot ?? 0

  return (
    <div className="shell">
      <header className="topbar">
        <div className="wordmark">
          {/* The logo carries the product name and the strapline already, so
              the text beside it would be a second copy of both. It stays as
              the accessible name and is hidden visually — a decorative image
              with no text alternative leaves a screen reader with nothing. */}
          <img
            src="/skopos-logo.png"
            alt="SKOPOS — External Threat Landscape Management"
            className="brandmark"
            width={220}
            height={123}
          />
        </div>
        <div className="topbar-spacer" />
        {intel && (
          <div className="text-ink2" style={{ fontSize: 12, textAlign: 'right' }}>
            Catalogue <strong>{intel.catalog_version}</strong>
            <div className="text-ink3">
              {intel.entries.toLocaleString()} exploited ·{' '}
              {intel.age_days === null ? 'age unknown'
                : intel.age_days === 0 ? 'released today'
                : `${intel.age_days} day${intel.age_days === 1 ? '' : 's'} old`}
            </div>
          </div>
        )}
        <button className="btn" onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}>
          {theme === 'light' ? 'Dark' : 'Light'}
        </button>
      </header>

      <main className="main stack">
        {error && <div className="banner banner-crit" role="alert">{error}</div>}

        <CrosshairPanel view={crosshair} />

        <CoveragePanel run={dnsRun} />

        {!summary && !error && (
          <div className="banner banner-info">
            <strong>No scan has been run yet.</strong>{' '}
            POST <span className="mono">/api/v1/scan</span> with an inventory path,
            and optionally an OverWatch graph export for internal cloud context.
          </div>
        )}

        {summary && (
          <>
            <div className="grid grid-4">
              <Kpi title="Findings" value={summary.findings}
                   note={`across ${summary.assets_affected} asset(s)`} />
              <Kpi title="Ransomware-linked" value={summary.ransomware_linked}
                   tone="text-crit"
                   note="used in known ransomware campaigns" />
              <Kpi title="Determinations" value={summary.determinations}
                   tone={summary.determinations > 0 ? 'text-low' : undefined}
                   note={`${summary.worklist} still need a version checked`} />
              <Kpi title="Unexplained exposures" value={unexplained}
                   tone={unexplained > 0 ? 'text-crit' : 'text-low'}
                   note="reachable, but the cloud model says otherwise" />
            </div>

            {/* THE FINDING NEITHER TOOL PRODUCES ALONE, given the prominence it
                earns rather than buried in a filter. */}
            {unexplained > 0 && (
              <div className={`banner ${RECON_TONE.unexplained_exposure}`}>
                <strong>
                  {RECON_LABEL.unexplained_exposure} — {unexplained}
                </strong>{' '}
                {guide.unexplained_exposure ??
                  'SKOPOS reached these from the internet and OverWatch’s cloud ' +
                  'model says they should not be reachable.'}
              </div>
            )}
            {blindSpots > 0 && (
              <div className={`banner ${RECON_TONE.discovery_blind_spot}`}>
                <strong>
                  {RECON_LABEL.discovery_blind_spot} — {blindSpots}
                </strong>{' '}
                {guide.discovery_blind_spot}
              </div>
            )}

            {/* The honesty counters. A console that shows findings without these
                reads as a complete picture when it may be a partial one. */}
            {(summary.assets_matched_nothing > 0 ||
              summary.cloud_resources_unmappable > 0) && (
              <div className="banner banner-warn">
                <strong>Not everything was assessed.</strong>{' '}
                {summary.assets_matched_nothing > 0 && (
                  <>{summary.assets_matched_nothing} asset(s) corresponded to nothing
                  in the catalogue — which is not the same as being unaffected, since
                  a product named differently here than by CISA will not match. </>
                )}
                {summary.cloud_resources_unmappable > 0 && (
                  <>{summary.cloud_resources_unmappable} cloud resource(s) that
                  OverWatch considers internet-reachable carry no externally-visible
                  identity, so they could not be correlated.</>
                )}
              </div>
            )}
          </>
        )}

        <div>
          <h2 className="section">
            Prioritised findings
            {rows.length > 0 && <span className="text-ink3"> — {rows.length} shown</span>}
          </h2>
          <div className="table-card">
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 130 }}>TEPS</th>
                    <th style={{ width: 150 }}>CVE</th>
                    <th>Asset</th>
                    <th style={{ width: 160 }}>Owner</th>
                    <th style={{ width: 120 }}>Flag</th>
                    <th style={{ width: 120 }}>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((f) => {
                    const key = `${f.asset}:${f.cve}`
                    return (
                      <FindingRow key={key} finding={f} open={openRow === key}
                                  onToggle={() => setOpenRow(openRow === key ? null : key)} />
                    )
                  })}
                  {rows.length === 0 && (
                    <tr>
                      <td colSpan={6} className="empty">
                        No findings to show. Run a scan to populate this view.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
          {rows.length > 0 && (
            <p className="text-ink3" style={{ fontSize: 12, marginTop: 12 }}>
              Every row expands into the factor decomposition behind its score.
              A <span className="pill sev-medium">possible</span> confidence means
              the product name corresponded but no version was compared against a
              published affected range — somebody has to check.
            </p>
          )}
        </div>
      </main>
    </div>
  )
}
