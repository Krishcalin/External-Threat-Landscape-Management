import { useEffect, useState } from 'react'
import { accuracy as fetchAccuracy, alerts as fetchAlerts,
         ApiError, certIn as fetchCertIn, ciiRegister as fetchCii,
         controls as fetchControls, crosshair as fetchCrosshair,
         latency as fetchLatency,
         dnsRuns as fetchDnsRuns, findings as fetchFindings,
         intel as fetchIntel, reconciliationGuide,
         changes as fetchChanges, runs as fetchRuns,
         supplierRegister as fetchSuppliers,
         summary as fetchSummary, tenancy as fetchTenancy } from './api/client'
import type { Accuracy, AlertsView, CertInStatus, CiiRegister, ControlMapping,
              CrosshairView, DnsRun, Finding, IntelStatus, LatencyReport,
              ReconciliationOutcome,
              ChangesView, RunRow, Session, SupplierRegister,
              Summary, Tenancy } from './api/types'
import { logout } from './api/auth'
import { AccountPanel } from './components/AccountPanel'
import { AccuracyPanel } from './components/AccuracyPanel'
import { BrandPanel } from './components/BrandPanel'
import { ExecutivePanel } from './components/ExecutivePanel'
import { GraphPanel } from './components/GraphPanel'
import { LookupPanel } from './components/LookupPanel'
import { OperationsPanel } from './components/OperationsPanel'
import { SupplierPanel } from './components/SupplierPanel'
import { AlertsPanel } from './components/AlertsPanel'
import { CompliancePanel } from './components/CompliancePanel'
import { CoveragePanel } from './components/CoveragePanel'
import { CrosshairPanel } from './components/CrosshairPanel'
import { SystemPanel } from './components/SystemPanel'
import { TepsBar } from './components/TepsBar'

/**
 * The SKOPOS console.
 *
 * SIX SECTIONS, ON THE CONDITION THIS FILE ORIGINALLY SET. It shipped as one
 * screen with a note saying the other views would arrive "when they have
 * something to project", because shipping half-built views makes a product look
 * broader and be worse. They now have engines: compliance, forecast accuracy,
 * the alert decision and the tenancy posture were all built and reachable only
 * by curl. Worklist stays the default because it is what somebody opens the
 * console to do.
 *
 * The Executive and Operations projections in the SRS are still absent, and for
 * the original reason — nothing has been built that would project differently
 * for those audiences, and a re-skinned Management view with fewer columns is
 * not an executive view.
 *
 * WHAT THIS SCREEN REFUSES TO DO. It never shows a finding count without also
 * showing what was not assessed, and it never shows a TEPS without its
 * decomposition being one click away. Those two rules are the difference between
 * a console and a dashboard.
 */

type Section = 'worklist' | 'operations' | 'executive' | 'crosshair'
  | 'graph' | 'lookup' | 'brand' | 'suppliers' | 'compliance'
  | 'accuracy' | 'alerts' | 'system' | 'account'

/** Worklist first because it is what somebody opens the console to do; System
 *  last because it answers a question asked once per deployment. */
const SECTIONS: { id: Section; label: string }[] = [
  { id: 'worklist', label: 'Worklist' },
  // The three SRS projections of one graph, adjacent so it is obvious they are
  // the same data asked three questions rather than three products.
  { id: 'operations', label: 'Operations' },
  { id: 'executive', label: 'Executive' },
  { id: 'crosshair', label: 'Crosshair' },
  { id: 'graph', label: 'Graph' },
  // Adjacent to Suppliers: both ask what the outside world can see about
  // somebody else, and both are passive because they structurally must be.
  { id: 'lookup', label: 'Lookup' },
  { id: 'brand', label: 'Brand' },
  { id: 'suppliers', label: 'Suppliers' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'accuracy', label: 'Accuracy' },
  { id: 'system', label: 'This instance' },
  // Beside "This instance" because both answer questions about the deployment
  // rather than about the estate, and last because neither is why anybody
  // opened the console.
  { id: 'account', label: 'Account' },
]

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

export function App({ session = null }: { session?: Session | null }) {
  const [intel, setIntel] = useState<IntelStatus | null>(null)
  const [summary, setSummary] = useState<Summary | null>(null)
  const [rows, setRows] = useState<Finding[]>([])
  const [guide, setGuide] = useState<Record<string, string>>({})
  const [openRow, setOpenRow] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [theme, setTheme] = useState<'light' | 'dark'>('light')
  const [dnsRun, setDnsRun] = useState<DnsRun | null>(null)
  const [crosshair, setCrosshair] = useState<CrosshairView | null>(null)
  const [latency, setLatency] = useState<LatencyReport | null>(null)
  const [section, setSection] = useState<Section>('worklist')
  const [cii, setCii] = useState<CiiRegister | null>(null)
  const [certin, setCertin] = useState<CertInStatus | null>(null)
  const [controls, setControls] = useState<ControlMapping | null>(null)
  const [accuracy, setAccuracy] = useState<Accuracy | null>(null)
  const [alerts, setAlerts] = useState<AlertsView | null>(null)
  const [tenancy, setTenancy] = useState<Tenancy | null>(null)
  const [supplierRegister, setSupplierRegister] = useState<SupplierRegister | null>(null)
  const [runs, setRuns] = useState<RunRow[]>([])
  const [changes, setChanges] = useState<ChangesView | null>(null)

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
    // 503 when no artefact index is vendored. The base rate simply does not
    // render then — an absent measurement must not become a blank number.
    fetchLatency().then(setLatency).catch(() => setLatency(null))

    // Every one of these is fetched up front rather than on tab activation.
    // The payloads are small, and a section that loads only when opened cannot
    // put a count on its own tab — which is how somebody would miss an alert
    // they never clicked through to.
    //
    // Each failure sets null rather than surfacing an error: a section that
    // could not load says so in its own words, and a page-level error banner
    // for one absent panel would suggest the whole console is broken.
    fetchCii().then(setCii).catch(() => setCii(null))
    fetchCertIn().then(setCertin).catch(() => setCertin(null))
    fetchControls().then(setControls).catch(() => setControls(null))
    fetchAccuracy().then(setAccuracy).catch(() => setAccuracy(null))
    fetchAlerts().then(setAlerts).catch(() => setAlerts(null))
    fetchTenancy().then(setTenancy).catch(() => setTenancy(null))
    fetchSuppliers().then(setSupplierRegister).catch(() => setSupplierRegister(null))
    fetchRuns().then((page) => setRuns(page.runs)).catch(() => setRuns([]))
    fetchChanges().then(setChanges).catch(() => setChanges(null))
    // The session used to be fetched here too, with a raw `fetch` that returned
    // only a username. It now arrives as a prop from AuthGate, which had
    // already resolved it one round trip earlier — two components asking
    // separately can disagree about who is signed in, and the one drawing the
    // sign-out control must not be the one that is wrong.
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
        {session && (
          <div className="whoami">
            <button
              className="btn"
              onClick={() => setSection('account')}
              title="Your account"
            >
              {session.display_name || session.username}
            </button>
            {/* A server call, not a cleared cookie. Revoking the session is
                what makes the token useless; clearing it locally only makes it
                invisible, and a token that still works somewhere else is not a
                signed-out session. The reload is what discards every panel's
                loaded state, so the next person at this machine starts at the
                login screen with nothing rendered behind it. */}
            <button
              className="btn"
              onClick={() => { void logout().finally(() => location.reload()) }}
            >
              Sign out
            </button>
          </div>
        )}
        <button className="btn" onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}>
          {theme === 'light' ? 'Dark' : 'Light'}
        </button>
      </header>

      <nav className="tabs" role="tablist" aria-label="Console sections">
        {/* Account needs somebody to be signed in. On an open instance — no
            users configured — there is no account to administer, and the tab
            would lead to a panel that can only report 401. */}
        {SECTIONS.filter(({ id }) => id !== 'account' || session).map(({ id, label }) => (
          <button
            key={id}
            role="tab"
            id={`tab-${id}`}
            aria-selected={section === id}
            aria-controls={`panel-${id}`}
            className="tab"
            onClick={() => setSection(id)}
          >
            {label}
            {/* Only where the number is something to act on. A count on every
                tab is decoration, and decoration next to a real count makes the
                real one easier to skip. */}
            {id === 'alerts' && alerts && alerts.alerts.length > 0 && (
              <span className="tab-count">{alerts.alerts.length}</span>
            )}
          </button>
        ))}
      </nav>

      <main className="main stack" role="tabpanel"
            id={`panel-${section}`} aria-labelledby={`tab-${section}`}>
        {error && <div className="banner banner-crit" role="alert">{error}</div>}

        {section === 'operations' && (
          <OperationsPanel findings={rows} changes={changes} />
        )}

        {section === 'executive' && (
          <ExecutivePanel runs={runs} accuracy={accuracy} crosshair={crosshair}
                          suppliers={supplierRegister} summary={summary} />
        )}

        {section === 'graph' && <GraphPanel />}

        {section === 'lookup' && (
          <LookupPanel actor={session?.username ?? 'console'} />
        )}

        {section === 'brand' && (
          <BrandPanel actor={session?.username ?? 'console'} />
        )}

        {section === 'suppliers' && (
          <SupplierPanel register={supplierRegister} />
        )}

        {section === 'crosshair' && (
          <CrosshairPanel view={crosshair} latency={latency} />
        )}

        {section === 'compliance' && (
          <CompliancePanel cii={cii} certin={certin} controls={controls} />
        )}

        {section === 'accuracy' && <AccuracyPanel accuracy={accuracy} />}

        {section === 'account' && session && <AccountPanel session={session} />}

        {section === 'alerts' && <AlertsPanel view={alerts} />}

        {section === 'system' && <SystemPanel tenancy={tenancy} intel={intel} />}

        {section === 'worklist' && <>
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
        </>}
      </main>
    </div>
  )
}
