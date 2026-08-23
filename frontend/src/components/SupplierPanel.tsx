import type { SupplierRegister } from '../api/types'

/**
 * Third parties, assessed from outside without touching them.
 *
 * WHY THERE IS NO VULNERABILITY COLUMN. Every other product in this category
 * shows one, and this one structurally cannot. A supplier's estate belongs to
 * somebody else; the customer cannot prove ownership of it; the gate refuses
 * every active operation against an unverified asset. No active probe means no
 * fingerprint, no fingerprint means no product name, no product name means no
 * CVE join. A supplier CVE count here would be invented, so the panel says that
 * out loud rather than leaving a suspicious gap where competitors have a number.
 *
 * WHAT LEADS, AND WHY IT IS NOT SPF. Measured against 8 real domains before
 * this screen was designed: SPF 8/8 and DMARC 8/8. Publishing them is now
 * universal, so a column of "yes" would be the first thing a reader sees and
 * the moment they learn the panel is decorative. What separates suppliers is
 * how far they took it — enforcement 7/8, CAA 3/8, MTA-STS 1/8 — so those lead
 * and presence is context.
 *
 * THREE STATES PER SIGNAL, NEVER TWO. Present, absent, and UNOBSERVED. Merging
 * the third into the second renders this product's coverage gap as the
 * supplier's neglect, which is the commonest lie in third-party risk tooling
 * and the one this panel is most at risk of telling.
 */

const SIGNAL_LABEL: Record<string, string> = {
  dmarc_enforced: 'DMARC enforced',
  mta_sts: 'MTA-STS',
  caa: 'CAA',
  cert_expiring: 'Cert expiring',
  registry_lock: 'Registry lock',
  spf: 'SPF',
  dmarc: 'DMARC',
}

export function SupplierPanel({ register }: { register: SupplierRegister | null }) {
  if (!register) {
    return (
      <section className="stack">
        <h2 className="section">Suppliers</h2>
        <div className="empty">The register could not be loaded.</div>
      </section>
    )
  }

  const ranked = register.ranking_signals
  const context = ['spf', 'dmarc'].filter((s) => !ranked.includes(s))

  return (
    <section className="stack">
      <h2 className="section">
        Suppliers
        <span className="text-ink3"> — {register.suppliers.length} declared</span>
      </h2>

      {/* Said plainly, where a competitor would put a vulnerability count. */}
      <div className="banner banner-info">
        <strong>No supplier vulnerabilities are reported here, and none can be.</strong>{' '}
        {register.no_cve_join}
      </div>

      <p className="lede">{register.headline}</p>

      {register.never_assessed > 0 && (
        <div className="banner banner-warn">
          <strong>
            {register.never_assessed} of {register.suppliers.length} have never
            been assessed.
          </strong>{' '}
          Every signal for them reads as <em>unobserved</em>, which is the truth —
          reporting them as absent would be this product&rsquo;s inaction
          rendered as the supplier&rsquo;s neglect. Assess with{' '}
          <span className="mono">POST /api/v1/suppliers/assess</span>.
        </div>
      )}

      {/* ── concentration ───────────────────────────────────────────────── */}
      <div>
        <h3 style={{ fontSize: 14, fontWeight: 650, margin: '0 0 8px' }}>
          Concentration
        </h3>

        {register.concentration_refused ? (
          <div className="banner banner-warn">
            <strong>No concentration is reported.</strong>{' '}
            {register.concentration_refused}
          </div>
        ) : register.concentrations.length === 0 ? (
          <p className="text-ink2" style={{ fontSize: 13 }}>
            No provider is shared by enough of the register to report.
          </p>
        ) : (
          <>
            <div className="banner banner-info">
              <strong>What a concentration is, and is not.</strong>{' '}
              {register.concentration_meaning}
            </div>
            <div className="table-card" style={{ marginTop: 12 }}>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: 90 }}>Kind</th>
                      <th style={{ width: 240 }}>Provider</th>
                      <th style={{ width: 110 }} className="num">Suppliers</th>
                      <th style={{ width: 110 }} className="num">Critical</th>
                      <th>Who</th>
                    </tr>
                  </thead>
                  <tbody>
                    {register.concentrations.map((c) => (
                      <tr key={`${c.kind}-${c.provider}`}>
                        <td><span className="chip">{c.kind}</span></td>
                        <td className="mono">{c.provider}</td>
                        <td className="num">
                          {c.count}
                          {c.share_of_register !== null && (
                            <div className="text-ink3" style={{ fontSize: 11 }}>
                              {(c.share_of_register * 100).toFixed(0)}% of register
                            </div>
                          )}
                        </td>
                        <td className="num">
                          {c.critical_suppliers > 0
                            ? <span className="pill sev-critical">
                                {c.critical_suppliers}
                              </span>
                            : <span className="text-ink3">0</span>}
                        </td>
                        <td className="text-ink2" style={{ fontSize: 12 }}>
                          {c.suppliers.slice(0, 6).join(', ')}
                          {c.suppliers.length > 6 &&
                            ` and ${c.suppliers.length - 6} more`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </div>

      {/* ── posture ─────────────────────────────────────────────────────── */}
      <div>
        <h3 style={{ fontSize: 14, fontWeight: 650, margin: '0 0 8px' }}>
          Published posture
        </h3>
        <p className="text-ink3" style={{ fontSize: 12, marginTop: 0 }}>
          {register.discrimination}
        </p>

        <div className="table-card">
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Supplier</th>
                  <th style={{ width: 110 }}>Tier</th>
                  {/* The discriminating signals lead. */}
                  {ranked.map((s) => (
                    <th key={s} style={{ width: 120 }}>{SIGNAL_LABEL[s] ?? s}</th>
                  ))}
                  {context.map((s) => (
                    <th key={s} style={{ width: 90 }} className="text-ink3">
                      {SIGNAL_LABEL[s] ?? s}
                    </th>
                  ))}
                  <th style={{ width: 220 }}>Depends on</th>
                </tr>
              </thead>
              <tbody>
                {register.suppliers.map((p) => (
                  <tr key={p.domain}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{p.supplier}</div>
                      <div className="mono text-ink3">{p.domain}</div>
                    </td>
                    <td>
                      <span className={`pill ${p.tier === 'critical'
                        ? 'sev-critical' : p.tier === 'important'
                          ? 'sev-medium' : 'sev-informational'}`}>
                        {p.tier}
                      </span>
                    </td>
                    {[...ranked, ...context].map((s) => (
                      <SignalCell key={s} signal={s} posture={p} />
                    ))}
                    <td className="text-ink2" style={{ fontSize: 12 }}>
                      {Object.entries(p.providers).map(([kind, provider]) => (
                        <div key={kind}>
                          <span className="text-ink3">{kind}: </span>
                          <span className="mono">{provider}</span>
                        </div>
                      ))}
                      {Object.keys(p.providers).length === 0 && (
                        <span className="text-ink3">not observed</span>
                      )}
                    </td>
                  </tr>
                ))}
                {register.suppliers.length === 0 && (
                  <tr>
                    <td colSpan={4 + ranked.length + context.length} className="empty">
                      No suppliers declared. An empty register is not a supply
                      chain with no third parties — it is one nobody has
                      written down.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <p className="text-ink3" style={{ fontSize: 12 }}>
        Posture measures published configuration, which correlates with how an
        organisation runs things and is <strong>not</strong> a measurement of
        their security. A supplier with perfect DMARC can be breached tomorrow.
        What it is good for is being comparable across a whole register at no
        cost to the supplier.
      </p>
    </section>
  )
}

/** Three states, never two. `?` is ours; `—` is theirs. */
function SignalCell({ signal, posture }: {
  signal: string
  posture: { present: string[]; absent: string[]; unobserved: string[] }
}) {
  if (posture.present.includes(signal)) {
    return <td><span className="pill sev-low">yes</span></td>
  }
  if (posture.absent.includes(signal)) {
    return <td><span className="pill sev-medium">no</span></td>
  }
  return (
    <td>
      <span className="chip" title="we did not observe this — not a claim about them">
        unobserved
      </span>
    </td>
  )
}
