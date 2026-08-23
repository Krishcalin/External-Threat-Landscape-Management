/** The auth calls, and the one thing the console must never hold.
 *
 *  THE SESSION TOKEN NEVER TOUCHES JAVASCRIPT. It arrives as an HttpOnly
 *  cookie, so this file has no token to store and no place to put it. That is
 *  deliberate: a token in localStorage is readable by any script that reaches
 *  the page, and "we sanitise everything" has never once been true forever.
 *
 *  So every call here sends `credentials: 'include'` and the browser attaches
 *  the cookie. There is no `getToken()`, and there is nothing to log out of
 *  locally — logout is a server call that revokes the session, because a
 *  cleared client is not a revoked session.
 */
import type { AuthStatus, PendingLogin, Enrolment, EnrolConfirmed,
              Session } from './types'

export class AuthError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

async function call<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    let detail = response.statusText
    try {
      detail = (await response.json()).detail ?? detail
    } catch {
      /* a non-JSON error body is still an error */
    }
    throw new AuthError(response.status, String(detail))
  }
  return response.json() as Promise<T>
}

/** Public on purpose: somebody needs to know they are on an OPEN instance
 *  before they type anything into it. */
export const authStatus = () => call<AuthStatus>('/auth/status')

export const session = () => call<Session>('/auth/session')

/** Step one. Never returns a session — a password alone is not enough. */
export const login = (username: string, password: string) =>
  call<PendingLogin>('/auth/login', { username, password })

/** Step two. The cookie is set by the server; nothing is returned to store. */
export const verify = (pending: string, code: string) =>
  call<Session>('/auth/verify', { pending, code })

export const beginEnrolment = (pending: string) =>
  call<Enrolment>('/auth/enrol', { pending, code: '' })

export const confirmEnrolment = (pending: string, code: string) =>
  call<EnrolConfirmed>('/auth/enrol/confirm', { pending, code })

export const logout = () => call<{ revoked: boolean }>('/auth/logout', {})
