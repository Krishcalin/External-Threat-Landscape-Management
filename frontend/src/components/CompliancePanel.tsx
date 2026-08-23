import type { CertInStatus, CiiRegister, ControlMapping } from '../api/types'

/**
 * The India compliance pack: CERT-In, NCIIPC/CII, and the control mapping.
 *
 * THE REFUSALS ARE THE CONTENT, NOT THE FOOTNOTES. Every screen in this
 * category, in every product, is built to make an organisation feel covered.
 * This one exists to say what it cannot tell you, and if that lives in a
 * tooltip it may as well not exist — somebody preparing for an assessment reads
 * the headline number and stops.
 *
 * So: seven of eight CERT-In categories render as NOT OBSERVABLE in the same
 * table as the one that is; the CII register leads with "SKOPOS does not
 * designate"; and every control shows what it does NOT do beside what it
 * contributes, with no coverage percentage anywhere.
 *
 * THERE IS NO BUTTON THAT FILES ANYTHING. No "start the six-hour clock", no
 * "generate notification". Both exist as API routes that require a named human
 * declaring an incident in their own words, and a console button would be the
 * exact path core/cert_in.py refuses to provide.
 */

export function CompliancePanel({ cii, certin, controls }: {
  cii: CiiRegister | null
  certin: CertInStatus | null
  controls: ControlMapping | null
}) {
  if (!cii && !certin && !controls) {
    return (
      <section className="stack">
        <div className="empty">The compliance pack could not be loaded.</div>
      </section>
    )
  }

  return (
    <section className="stack">
      {certin && <CertIn status={certin} />}
      {cii && <Cii register={cii} />}
      {controls && <Controls mapping={controls} />}
    </section>
  )
}

/* ── CERT-In ───────────────────────────────────────────────────────────────
 * The six-hour clock, and why nothing here starts one. */
function CertIn({ status }: { status: CertInStatus }) {
  const observable = status.categories.filter((c) => c.skopos_can_observe)

  return (
    <div>
      <h2 className="section">CERT-In reporting</h2>

      <div className="banner banner-warn">
        <strong>No finding here starts a six-hour clock.</strong>{' '}
        {status.why_not_automatic}
      </div>

      <div className="grid grid-4" style={{ marginTop: 16 }}>
        <div className="card">
          <p className="card-title">Reporting window</p>
          <div className="kpi">{status.window_hours}h</div>
          <p className="kpi-note">from becoming aware, not from a scan result</p>
        </div>
        <div className="card">
          <p className="card-title">Observable from outside</p>
          <div className={observable.length ? 'kpi text-med' : 'kpi'}>
            {observable.length} of {status.categories.length}
          </div>
          <p className="kpi-note">
            Annexure I categories this product could contribute evidence toward
          </p>
        </div>
        <div className="card" style={{ gridColumn: 'span 2' }}>
          <p className="card-title">Directive</p>
          <div style={{ fontSize: 13, fontWeight: 600 }}>{status.directive}</div>
          <p className="kpi-note">
            The text of the directive is the authority, not this screen.
            References checked {status.reviewed_on}.
          </p>
        </div>
      </div>

      <div className="table-card" style={{ marginTop: 16 }}>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th style={{ width: 300 }}>Reportable category</th>
                <th style={{ width: 150 }}>SKOPOS</th>
                <th>Why</th>
              </tr>
            </thead>
            <tbody>
              {status.categories.map((c) => (
                <tr key={c.category}>
                  <td style={{ textTransform: 'capitalize' }}>{c.label}</td>
                  <td>
                    {/* Colour is never the only carrier — the pill says it. */}
                    <span className={`pill ${c.skopos_can_observe
                      ? 'sev-informational' : 'sev-medium'}`}>
                      {c.skopos_can_observe ? 'can contribute' : 'cannot observe'}
                    </span>
                  </td>
                  <td className="text-ink2">{c.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <p className="text-ink3" style={{ fontSize: 12, marginTop: 12 }}>
        {status.summary}
      </p>
    </div>
  )
}

/* ── CII register ─────────────────────────────────────────────────────────── */
function Cii({ register }: { register: CiiRegister }) {
  return (
    <div>
      <h2 className="section">Critical Information Infrastructure</h2>

      <div className="banner banner-info">
        <strong>SKOPOS does not designate anything.</strong>{' '}
        {register.skopos_does_not_designate}
      </div>

      <p className="text-ink2" style={{ fontSize: 13, marginTop: 12 }}>
        {register.headline}
      </p>

      {register.entries.length > 0 && (
        <div className="table-card" style={{ marginTop: 12 }}>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Asset</th>
                  <th style={{ width: 200 }}>Sector</th>
                  <th style={{ width: 190 }}>Basis</th>
                  <th style={{ width: 110 }}>Findings</th>
                  <th style={{ width: 150 }}>First seen by us</th>
                </tr>
              </thead>
              <tbody>
                {register.entries.map((e) => (
                  <tr key={e.asset}>
                    <td className="mono">{e.asset}</td>
                    <td>{e.sector_label}</td>
                    <td>
                      <span className={`pill ${e.basis === 'gazette_notification'
                        ? 'sev-informational' : 'sev-medium'}`}>
                        {e.basis === 'gazette_notification'
                          ? 'gazette-notified' : 'organisation-assessed'}
                      </span>
                      {e.gazette_reference && (
                        <div className="mono text-ink3" style={{ marginTop: 4 }}>
                          {e.gazette_reference}
                        </div>
                      )}
                      <div className="text-ink3" style={{ fontSize: 11, marginTop: 4 }}>
                        {e.basis_meaning}
                      </div>
                    </td>
                    <td>
                      {e.determinations} determined
                      <div className="text-ink3" style={{ fontSize: 11 }}>
                        {e.worklist} still need a version checked
                      </div>
                    </td>
                    {/* The field name carries the caveat: this is OUR first
                        sighting, never a claim about when exposure began. */}
                    <td className="text-ink2">
                      {e.first_observed_by_skopos ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {register.undeclared_assets.length > 0 && (
        <div className="banner banner-warn" style={{ marginTop: 12 }}>
          <strong>
            {register.undeclared_assets.length} externally visible asset(s) carry
            no designation.
          </strong>{' '}
          This is a question for you, not a finding — the answer may legitimately
          be that they are out of scope and always were.
          <ul className="gap-list" style={{ marginTop: 8 }}>
            {register.undeclared_assets.slice(0, 12).map((a) => (
              <li key={a}><span className="mono">{a}</span></li>
            ))}
          </ul>
          {register.undeclared_assets.length > 12 && (
            <span className="text-ink3">
              and {register.undeclared_assets.length - 12} more
            </span>
          )}
        </div>
      )}

      {register.note && (
        <p className="text-ink3" style={{ fontSize: 12, marginTop: 12 }}>
          {register.note}
        </p>
      )}

      <p className="text-ink3" style={{ fontSize: 12, marginTop: 8 }}>
        {register.authority}. References checked {register.reviewed_on}.
      </p>
    </div>
  )
}

/* ── controls ─────────────────────────────────────────────────────────────── */
function Controls({ mapping }: { mapping: ControlMapping }) {
  return (
    <div>
      <h2 className="section">
        Control mapping
        <span className="text-ink3"> — {mapping.frameworks.join(' · ')}</span>
      </h2>

      {/* NO COVERAGE PERCENTAGE, anywhere on this screen. A percentage would be
          summed and shown to a board, and the board would be receiving a number
          no external scanner has the basis to produce. */}
      <div className="banner banner-info">
        <strong>Supporting a control is not satisfying it.</strong>{' '}
        {mapping.disclaimer}
      </div>

      <div className="grid grid-2" style={{ marginTop: 16 }}>
        {mapping.controls.map((c) => (
          <div className="card" key={`${c.framework}-${c.id}`}>
            <p className="card-title">{c.framework}</p>
            <div style={{ fontSize: 14, fontWeight: 650, marginBottom: 8 }}>
              <span className="mono" style={{ fontSize: 13 }}>{c.id}</span>{' '}
              {c.title}
            </div>

            <p style={{ fontSize: 13, margin: '0 0 10px' }}>
              <span className="pill sev-low">contributes</span>{' '}
              <span className="text-ink2">{c.contributes}</span>
            </p>

            {/* Given equal weight to `contributes`, on purpose. */}
            <p style={{ fontSize: 13, margin: '0 0 10px' }}>
              <span className="pill sev-medium">does not</span>{' '}
              <span className="text-ink2">{c.does_not}</span>
            </p>

            <div className="legend">
              <span className="text-ink3">evidence from</span>
              {c.evidence_from.map((e) => (
                <span key={e} className="chip mono">{e}</span>
              ))}
            </div>
          </div>
        ))}
      </div>

      <p className="text-ink3" style={{ fontSize: 12, marginTop: 12 }}>
        Control titles are quoted verbatim from the published standards.
        References checked {mapping.reviewed_on}.
      </p>
    </div>
  )
}
