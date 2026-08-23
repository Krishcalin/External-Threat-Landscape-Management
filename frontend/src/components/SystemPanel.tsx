import type { IntelStatus, Tenancy } from '../api/types'

/**
 * What this instance is actually running.
 *
 * WHY TENANCY IS ON A SCREEN AT ALL. A deployment can have a perfectly correct
 * multi-tenant schema and no tenancy whatsoever — that is exactly the state this
 * product was in until migration 006, because the application connected as a
 * superuser and PostgreSQL row-level security does not apply to such a role.
 * Nothing in any query result says which one you have. So it is reported, in
 * words, where an operator will see it.
 *
 * THE ISOLATION CLAIM IS RENDERED IN FULL. "Row-level security" in a feature
 * list reads as a stronger claim than a session-variable implementation
 * supports: it stops one tenant's rows reaching another THROUGH A BUG, and it
 * is not isolation against a compromised application. Somebody choosing this
 * product for a regulated workload needs the second sentence as much as the
 * first, so it is not abbreviated.
 *
 * CORPUS AGE SITS HERE TOO, because a result computed against a stale catalogue
 * is a different claim from the same result computed today, and nothing in the
 * numbers says which you are holding.
 */

export function SystemPanel({ tenancy, intel }: {
  tenancy: Tenancy | null
  intel: IntelStatus | null
}) {
  const enforced = tenancy?.enforcement.startsWith('enforced') ?? false
  const unbound = tenancy !== null && !tenancy.bound_org

  return (
    <section className="stack">
      <h2 className="section">This instance</h2>

      {tenancy && (
        <>
          <div className={`banner ${enforced ? 'banner-ok' : 'banner-crit'}`}>
            <strong>
              {enforced
                ? 'Row-level security is enforced.'
                : 'Row-level security is NOT enforced.'}
            </strong>{' '}
            {tenancy.enforcement}
          </div>

          {unbound && (
            <div className="banner banner-crit">
              <strong>This connection is bound to no organisation.</strong>{' '}
              Every query will return nothing rather than everything, which is
              the correct direction to fail — but it means this console is
              showing you an empty estate, not a clean one.
            </div>
          )}

          <div className="grid grid-2">
            <div className="card">
              <p className="card-title">Organisation</p>
              <div className="kpi" style={{ fontSize: 22 }}>{tenancy.org}</div>
              <p className="kpi-note">
                connection bound to{' '}
                <span className="mono">{tenancy.bound_org ?? 'nothing'}</span>
              </p>
            </div>

            <div className="card">
              <p className="card-title">What that isolation is worth</p>
              {/* Not abbreviated, not a tooltip. The second half of this
                  sentence is the half somebody needs before choosing this
                  product for a regulated workload. */}
              <p className="text-ink2" style={{ fontSize: 13, margin: 0 }}>
                {tenancy.isolation_meaning}
              </p>
            </div>
          </div>
        </>
      )}

      {intel && (
        <div className="grid grid-4">
          <div className="card">
            <p className="card-title">Catalogue</p>
            <div className="kpi" style={{ fontSize: 22 }}>{intel.catalog_version}</div>
            <p className="kpi-note">
              {intel.age_days === null ? 'age unknown'
                : intel.age_days === 0 ? 'released today'
                : `${intel.age_days} day${intel.age_days === 1 ? '' : 's'} old`}
            </p>
          </div>
          <div className="card">
            <p className="card-title">Exploited vulnerabilities</p>
            <div className="kpi">{intel.entries.toLocaleString()}</div>
            <p className="kpi-note">{intel.ransomware_linked} ransomware-linked</p>
          </div>
          <div className="card">
            <p className="card-title">Version-determinable</p>
            <div className="kpi">
              {intel.determinable_share === null || intel.determinable_share === undefined
                ? '—'
                : `${(intel.determinable_share * 100).toFixed(1)}%`}
            </div>
            {/* The number that decides whether a finding can ever be more than
                a worklist entry. Stated on every run, and here. */}
            <p className="kpi-note">
              the rest can only ever be worklist entries, however they are
              presented
            </p>
          </div>
          <div className="card">
            <p className="card-title">EPSS scope</p>
            <div className="kpi" style={{ fontSize: 20 }}>{intel.epss_scope}</div>
            <p className="kpi-note">
              EPSS is a forecast of exploitation; KEV membership is an
              observation of it
            </p>
          </div>
        </div>
      )}

      <div className="card">
        <p className="card-title">Sharing findings</p>
        <p className="text-ink2" style={{ fontSize: 13, marginTop: 0 }}>
          A STIX 2.1 bundle is available at{' '}
          <span className="mono">/api/v1/export/stix</span>, and a TAXII 2.1
          server at <span className="mono">/taxii2/</span> when{' '}
          <span className="mono">SKOPOS_API_TOKEN</span> is set. Both carry the
          worklist/determination distinction as an explicit confidence and a
          note object inside the bundle — a caveat that stays behind in this
          console is not a caveat.
        </p>
        {/* Deliberately not a download button. The bundle names your unpatched
            systems; handing it out from an unauthenticated console would make
            the token on the TAXII route pointless. */}
        <p className="text-ink3" style={{ fontSize: 12, marginBottom: 0 }}>
          There is no download button here on purpose: the bundle names your
          unpatched systems, and serving it from an unauthenticated console
          would make the token on the TAXII route meaningless.
        </p>
      </div>
    </section>
  )
}
