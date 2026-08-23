import { useState } from 'react'
import { changePassword } from '../api/account'
import { AuthError, logout } from '../api/auth'
import type { Session } from '../api/types'

/**
 * The screen an account sees on its first sign-in, before anything else.
 *
 * WHY IT IS A WHOLE SCREEN RATHER THAN A PROMPT
 * ----------------------------------------------
 * The account is still using a password an administrator chose and has seen, so
 * it is not yet this person's own account. The server refuses every other API
 * path for such a session; if the console rendered its usual layout, every
 * panel behind this would fail with a 403 the user cannot act on, and the
 * screen would read as broken rather than as a step.
 *
 * There is a sign-out button, and it matters: somebody who reaches this screen
 * unexpectedly — on a shared machine, or having been handed a credential they
 * did not ask for — needs a way out that is not "choose a password".
 */
export function FirstPasswordChange({
  session, onChanged,
}: { session: Session; onChanged: () => void }) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const mismatch = confirm.length > 0 && next !== confirm

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    setError(null)
    if (next !== confirm) {
      setError('The two new passwords do not match.')
      return
    }
    setBusy(true)
    try {
      await changePassword(current, next)
      onChanged()
    } catch (exc) {
      setError(exc instanceof AuthError ? exc.message : String(exc))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-form-side">
          <div className="login-form-wrap">
            <h1 className="login-title">Choose your password</h1>
            <p className="login-sub">
              Signed in as <strong>{session.username}</strong>. This account is
              still using the password an administrator issued, so it cannot be
              used until you replace it — they have seen that one, and you have
              not chosen it.
            </p>

            <form onSubmit={submit}>
              <label className="login-label" htmlFor="fpc-current">
                The password you were given
              </label>
              <input
                id="fpc-current" type="password" className="login-input"
                value={current} required autoFocus
                autoComplete="current-password"
                onChange={(e) => setCurrent(e.target.value)}
              />

              <label className="login-label" htmlFor="fpc-new">
                Your new password
              </label>
              <input
                id="fpc-new" type="password" className="login-input"
                value={next} required minLength={12}
                autoComplete="new-password"
                onChange={(e) => setNext(e.target.value)}
              />

              <label className="login-label" htmlFor="fpc-confirm">
                Your new password again
              </label>
              <input
                id="fpc-confirm" type="password" className="login-input"
                value={confirm} required autoComplete="new-password"
                aria-invalid={mismatch}
                onChange={(e) => setConfirm(e.target.value)}
              />

              <p className="login-notice">
                At least 12 characters. Once it is set, the administrator who
                created this account can no longer sign in as you.
              </p>

              {mismatch && (
                <div className="banner banner-warn">
                  The two new passwords do not match.
                </div>
              )}
              {error && (
                <div className="banner banner-crit" role="alert">{error}</div>
              )}

              <button className="login-btn" type="submit" disabled={busy}>
                {busy ? 'Setting…' : 'Set password and continue'}
              </button>
            </form>

            <button
              className="enrol-alt"
              onClick={() => { void logout().finally(() => location.reload()) }}
            >
              Sign out instead
            </button>
          </div>
        </div>

        <div className="login-brand-side">
          <img
            src="/skopos-logo.png"
            alt="SKOPOS — External Threat Landscape Management"
            className="login-logo"
          />
        </div>
      </div>
    </div>
  )
}
