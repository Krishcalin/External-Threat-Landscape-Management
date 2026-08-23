import type { CrosshairView, DnsRunsPage, FindingsPage, IntelStatus,
              Summary } from './types'

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
