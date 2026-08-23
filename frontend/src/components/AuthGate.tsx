import { useEffect, useState } from 'react'
import { authStatus, session as fetchSession } from '../api/auth'
import type { AuthStatus, Session } from '../api/types'
import { Login } from '../routes/Login'

/**
 * What the browser sees before the console does.
 *
 * THREE STATES, AND THE MIDDLE ONE IS THE ONE THAT MATTERS.
 *
 *   authenticated  — render the console
 *   enforced, no session — render the login page
 *   NOT ENFORCED — render the console with a banner saying it is OPEN
 *
 * The third exists because a fresh deployment has no users and locking it would
 * leave nobody able to make one. What it must never do is look identical to a
 * protected instance, so the banner is loud, permanent and not dismissible. An
 * open console that does not say so is the failure this whole workstream exists
 * to end.
 */
export function AuthGate({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<AuthStatus | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [checked, setChecked] = useState(false)

  useEffect(() => {
    // Both, always. The session tells us who; the status tells us whether the
    // absence of a session actually matters.
    Promise.all([
      authStatus().then(setStatus).catch(() => setStatus(null)),
      fetchSession().then(setSession).catch(() => setSession(null)),
    ]).finally(() => setChecked(true))
  }, [])

  // Deliberately blank rather than a spinner: this resolves in one round trip,
  // and a flash of a login form before a valid session resolves reads as having
  // been logged out.
  if (!checked) return <div className="login-shell" />

  if (!session && status?.enforced) {
    return <Login onAuthenticated={setSession} />
  }

  return (
    <>
      {status && !status.enforced && (
        <div className="banner banner-crit open-banner" role="alert">
          <strong>This console is not protected.</strong> {status.state}
        </div>
      )}
      {children}
    </>
  )
}
