import { useEffect, useState } from 'react'
import { authStatus, session as fetchSession } from '../api/auth'
import type { AuthStatus, Session } from '../api/types'
import { Login } from '../routes/Login'
import { FirstPasswordChange } from './FirstPasswordChange'

/**
 * What the browser sees before the console does.
 *
 * FOUR STATES, AND THE MIDDLE TWO ARE THE ONES THAT MATTER.
 *
 *   authenticated  — render the console
 *   enforced, no session — render the login page
 *   authenticated but STILL ON AN ISSUED PASSWORD — render only the change form
 *   NOT ENFORCED — render the console with a banner saying it is OPEN
 *
 * The third exists because an account an administrator created starts with a
 * credential the administrator has seen. Until it is changed, it is not yet the
 * user's own account, and the console must not open. The server enforces this
 * independently in `api/auth_routes.py`; this only saves the user from watching
 * every panel fail with a 403 it cannot explain.
 *
 * The fourth exists because a fresh deployment has no users and locking it
 * would leave nobody able to make one. What it must never do is look identical
 * to a protected instance, so the banner is loud, permanent and not
 * dismissible. An open console that does not say so is the failure this whole
 * workstream exists to end.
 */
export function AuthGate({
  children,
}: {
  /** A function rather than a node, so the console below receives the session
   *  it needs to draw the Accounts section and the sign-out control. Passing it
   *  down beats re-fetching: two components asking `/auth/session` separately
   *  can disagree about who is signed in. */
  children: (session: Session | null) => React.ReactNode
}) {
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

  if (session?.must_change_password) {
    return (
      <FirstPasswordChange
        session={session}
        onChanged={() => setSession({ ...session, must_change_password: false })}
      />
    )
  }

  return (
    <>
      {status && !status.enforced && (
        <div className="banner banner-crit open-banner" role="alert">
          <strong>This console is not protected.</strong> {status.state}
        </div>
      )}
      {children(session)}
    </>
  )
}
