import type { Accuracy, AlertsView, CertInStatus, CiiRegister,
              ControlMapping, CrosshairView, DnsRunsPage, FindingsPage,
              ChangesView, IntelStatus, LatencyReport, RunsPage, Summary,
              BreachReport, ExposureGraph, LookalikeReport,
              LookupResult, SourceCatalogue,
              SupplierRegister, Tenancy } from './types'

/** Relative paths only: the built bundle carries no origin, so it can be served
 *  by the API itself in a deployment and proxied in development. */
export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    headers: { Accept: 'application/json' },
  })
  if (!response.ok) {
    let detail = response.statusText
    try {
      detail = (await response.json()).detail ?? detail
    } catch {
      /* a non-JSON error body is still an error; keep the status text */
    }
    throw new ApiError(response.status, detail)
  }
  return response.json() as Promise<T>
}

export const intel = () => get<IntelStatus>('/intel')
export const summary = () => get<Summary>('/summary')
export const findings = (limit = 100) => get<FindingsPage>(`/findings?limit=${limit}`)
export const reconciliationGuide = () =>
  get<Record<string, string>>('/reconciliation')

export const dnsRuns = () => get<DnsRunsPage>('/dns/runs?limit=20')
export const changeMeaning = () => get<Record<string, string>>('/dns/change-meaning')
export const takeoverMeaning = () => get<Record<string, string>>('/takeover/meaning')

/** Deliberately absent: a `takeover()` fetch.
 *
 *  The route requires a bearer token and is not registered at all without one,
 *  because a ranked list of dangling subdomains with evidence attached is
 *  finished reconnaissance against the customer. Shipping a client call that
 *  401s from an unauthenticated SPA would imply the console is the place to
 *  read it; it is not, until there is a session to carry the token. */

export const crosshair = () => get<CrosshairView>('/crosshair?limit=200')

/** The class table, fetched once — not one request per row.
 *
 *  There is deliberately no `latencyFor(cve)` here. A per-row number on the
 *  findings table would be read as a countdown for that asset, and the module
 *  behind it measures a population, not an estate. The per-CVE route exists for
 *  an operator asking about one CVE on purpose. */
export const latency = () => get<LatencyReport>('/latency')

/* ── compliance ───────────────────────────────────────────────────────────── */
export const ciiRegister = () => get<CiiRegister>('/compliance/cii')
export const certIn = () => get<CertInStatus>('/compliance/cert-in')
export const controls = () => get<ControlMapping>('/compliance/controls')

/* ── accuracy, alerts, tenancy ────────────────────────────────────────────── */
export const accuracy = () => get<Accuracy>('/accuracy')
export const alerts = () => get<AlertsView>('/alerts')
export const tenancy = () => get<Tenancy>('/tenancy')

/** Deliberately absent: a `certInDraft()` call.
 *
 *  The draft endpoint is a POST that takes a Declaration — a named person
 *  stating they became aware of an incident, in their own words. A console
 *  button that produced a regulator-facing document from a finding would be
 *  exactly the path `core/cert_in.py` refuses to provide. Whoever files makes
 *  that determination first, and they do it deliberately. */

/* ── suppliers ─────────────────────────────────────────────────────────────
 * Read-only from the console. Declaring a supplier and assessing one are both
 * POSTs somebody makes on purpose — assessment performs outbound lookups
 * against a third party, and that is not something a page refresh should do. */
export const supplierRegister = () => get<SupplierRegister>('/suppliers')

/* ── the projections ──────────────────────────────────────────────────────── */
export const runs = () => get<RunsPage>('/runs?limit=20')
export const changes = () => get<ChangesView>('/changes')

/* ── the lookup ────────────────────────────────────────────────────────────
 * A POST because it performs outbound lookups against somebody else's estate,
 * and every permit names an actor. Passive throughout — see `passive_only` in
 * the response, which is rendered rather than assumed. */
export async function lookupTarget(target: string, actor: string) {
  const response = await fetch('/api/v1/lookup', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ target, actor }),
  })
  if (!response.ok) {
    let detail: unknown = response.statusText
    try { detail = (await response.json()).detail } catch { /* keep status */ }
    const message = typeof detail === 'string'
      ? detail
      : (detail as { error?: string })?.error ?? response.statusText
    throw new ApiError(response.status, message)
  }
  return response.json() as Promise<LookupResult>
}

export const lookupSources = () => get<SourceCatalogue>('/lookup/sources')

/* ── brand and identity exposure ───────────────────────────────────────────
 * Both POST: each performs outbound lookups, and every permit names an actor. */
async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    let detail: unknown = response.statusText
    try { detail = (await response.json()).detail } catch { /* keep status */ }
    const message = typeof detail === 'string'
      ? detail
      : (detail as { error?: string })?.error ?? response.statusText
    throw new ApiError(response.status, message)
  }
  return response.json() as Promise<T>
}

export const brandLookalikes = (terms: string[], owned: string[], declaredBy: string) =>
  post<LookalikeReport>('/brand/lookalikes',
    { terms, owned, declared_by: declaredBy })

export const accountBreaches = (address: string, actor: string) =>
  post<BreachReport>('/identity/breaches', { address, actor })

export const secretsScanning = () =>
  get<{ supported: boolean; reason: string; integration: string;
        what_skopos_does_contribute: string }>('/identity/secrets-scanning')

/** The exposure graph. Read-only: it draws what the last scan already computed
 *  and triggers no collection of its own. */
export const exposureGraph = () => get<ExposureGraph>('/graph?limit=300')
