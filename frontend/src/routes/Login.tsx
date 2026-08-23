import { useState } from 'react'
import { AuthError, beginEnrolment, confirmEnrolment, login, verify }
  from '../api/auth'
import type { Enrolment, Session } from '../api/types'

/**
 * The landing page. Form on the left, brand on the right.
 *
 * WHY THE BRAND IS ON SCREEN AT ALL, AND WHY IT MOVES FIRST ON A PHONE.
 * A bare username box with no branding above it is exactly what a phishing page
 * looks like. On a narrow viewport the two columns collapse to one and the
 * brand takes `order: -1`, so the product identifies itself BEFORE it asks for
 * a credential rather than after.
 *
 * WHY THE PASSWORD AND THE CODE ARE ON SEPARATE STEPS. One form taking both
 * cannot tell a user whose password is wrong from one whose phone clock has
 * drifted, so it says "login failed" to both and the second user never works
 * out what to fix. It also means the server consults a TOTP secret for callers
 * who have not proven a password.
 *
 * WHAT THIS SCREEN WILL NOT TELL YOU. Whether a username exists. The server
 * returns one message for a wrong password, an unknown user and a disabled
 * account, and this renders it verbatim rather than helpfully interpreting it —
 * a form that distinguishes them enumerates usernames for whoever is
 * credential-stuffing.
 *
 * ENROLMENT OFFERS THREE WAYS IN, NONE REDUNDANT. The QR for a second device
 * with a camera; the URI as a LINK, so on the phone itself it opens the
 * authenticator directly with nothing to scan; and the typed key for when the
 * camera will not focus or the screen is being shared. Nothing is active until
 * a working code comes back, so a failed scan cannot lock anybody out.
 */

type Step = 'password' | 'code' | 'enrol' | 'recovery'

export function Login({ onAuthenticated }: { onAuthenticated: (s: Session) => void }) {
  const [step, setStep] = useState<Step>('password')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [pending, setPending] = useState('')
  const [enrolment, setEnrolment] = useState<Enrolment | null>(null)
  const [recovery, setRecovery] = useState<string[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const fail = (e: unknown) =>
    setError(e instanceof AuthError ? e.message : String(e))

  async function submitPassword(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true); setError('')
    try {
      const result = await login(username, password)
      setPending(result.pending)
      if (result.enrolled) {
        setStep('code')
      } else {
        // No second factor yet: send them to set one up rather than to a code
        // field they have no way to fill.
        setEnrolment(await beginEnrolment(result.pending))
        setStep('enrol')
      }
    } catch (e) { fail(e) } finally { setBusy(false) }
  }

  async function submitCode(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true); setError('')
    try {
      onAuthenticated(await verify(pending, code))
    } catch (e) { fail(e); setCode('') } finally { setBusy(false) }
  }

  async function submitEnrolment(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true); setError('')
    try {
      const done = await confirmEnrolment(pending, code)
      setRecovery(done.recovery_codes)
      setCode('')
      setStep('recovery')
    } catch (e) { fail(e); setCode('') } finally { setBusy(false) }
  }

  return (
    <div className="login-page">
      <div className="login-form-side">
        <div className="login-form-wrap">
          {error && (
            <div className="banner banner-crit" role="alert"
                 style={{ marginBottom: 16 }}>
              {error}
            </div>
          )}

          {step === 'password' && (
            <>
              <h1 className="login-title">Sign in</h1>
              <p className="login-sub">
                A password alone will not sign you in. A second factor is
                required.
              </p>
              <form onSubmit={submitPassword} className="login-card">
                <label className="login-label" htmlFor="u">Username</label>
                <input id="u" className="login-input" value={username} autoFocus
                       autoComplete="username"
                       onChange={(e) => setUsername(e.target.value)} required />
                <label className="login-label" htmlFor="p">Password</label>
                <input id="p" className="login-input" type="password"
                       value={password} autoComplete="current-password"
                       onChange={(e) => setPassword(e.target.value)} required />
                <button className="btn btn-primary login-btn" disabled={busy}>
                  {busy ? 'Checking…' : 'Continue'}
                </button>
              </form>
            </>
          )}

          {step === 'code' && (
            <>
              <h1 className="login-title">Authentication code</h1>
              <p className="login-sub">
                Six digits from your authenticator. A recovery code works here
                too, if the phone is gone.
              </p>
              <form onSubmit={submitCode} className="login-card">
                <label className="login-label" htmlFor="c">Code</label>
                <input id="c" className="login-input" value={code} autoFocus
                       inputMode="numeric" autoComplete="one-time-code"
                       maxLength={11}
                       onChange={(e) => setCode(e.target.value)} required />
                <button className="btn btn-primary login-btn" disabled={busy}>
                  {busy ? 'Verifying…' : 'Sign in'}
                </button>
              </form>
              <p className="login-notice">
                Codes are single-use even inside the 30 seconds they stay on
                screen. If you have just used one, wait for the next.
              </p>
            </>
          )}

          {step === 'enrol' && enrolment && (
            <>
              <h1 className="login-title">Set up your second factor</h1>
              <p className="login-sub">
                Scan with Microsoft Authenticator, Google Authenticator, Authy
                or 1Password.
              </p>

              {/* Rendered server-side as SVG by a stdlib encoder verified
                  against ISO/IEC 18004's worked example — no client library,
                  and the secret passes through one less piece of code. */}
              {enrolment.qr_svg && (
                <div className="qr-frame"
                     dangerouslySetInnerHTML={{ __html: enrolment.qr_svg }} />
              )}

              <div className="enrol-alt">
                {/* A LINK: on the phone itself this opens the authenticator
                    directly, with nothing to scan. */}
                <a className="btn" href={enrolment.uri}>
                  Open in authenticator app
                </a>
                <details className="enrol-key">
                  <summary>Or enter the key by hand</summary>
                  <code className="mono secret-key">{enrolment.formatted}</code>
                </details>
              </div>

              <form onSubmit={submitEnrolment} className="login-card">
                <label className="login-label" htmlFor="e">
                  Now type back the code it shows
                </label>
                <input id="e" className="login-input" value={code} autoFocus
                       inputMode="numeric" autoComplete="one-time-code"
                       maxLength={11}
                       onChange={(e) => setCode(e.target.value)} required />
                <button className="btn btn-primary login-btn" disabled={busy}>
                  {busy ? 'Confirming…' : 'Confirm'}
                </button>
              </form>
              <p className="login-notice">{enrolment.note}</p>
            </>
          )}

          {step === 'recovery' && (
            <>
              <h1 className="login-title">Save your recovery codes</h1>
              <div className="banner banner-warn" style={{ marginBottom: 14 }}>
                <strong>Shown once, and never again.</strong> They are stored
                only as hashes, so nobody — including whoever runs this
                instance — can recover them for you.
              </div>
              <ul className="recovery-list">
                {recovery.map((c) => <li key={c} className="mono">{c}</li>)}
              </ul>
              <p className="login-sub" style={{ marginTop: 14 }}>
                Keep them somewhere that is <strong>not</strong> the phone you
                just enrolled. That phone being lost is the thing these exist to
                survive.
              </p>
              <button className="btn btn-primary login-btn"
                      onClick={() => setStep('code')}>
                I have saved them — sign in
              </button>
            </>
          )}
        </div>
      </div>

      <div className="login-brand-side">
        <img src="/skopos-logo.png"
             alt="SKOPOS — External Threat Landscape Management"
             className="login-logo" />
      </div>
    </div>
  )
}
