import { useState } from 'react'
import { AuthError, beginEnrolment, confirmEnrolment, login, verify }
  from '../api/auth'
import type { Enrolment, Session } from '../api/types'

/**
 * The landing page. Three steps, never one form.
 *
 * WHY THE PASSWORD AND THE CODE ARE ON SEPARATE SCREENS. One form taking both
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
 * ENROLMENT CANNOT LOCK YOU OUT. The secret is issued but nothing is active
 * until a working code is typed back, so a failed scan or a mistyped key simply
 * does not enrol. The recovery codes are shown once, and the copy says where
 * NOT to keep them — the phone that was just enrolled is the thing they exist
 * to survive.
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
    <div className="login-shell">
      <div className="login-card">
        <img src="/skopos-logo.png" alt="SKOPOS" className="brandmark"
             style={{ height: 56, marginBottom: 20 }} />

        {error && (
          <div className="banner banner-crit" role="alert"
               style={{ marginBottom: 16 }}>
            {error}
          </div>
        )}

        {step === 'password' && (
          <form onSubmit={submitPassword} className="stack">
            <h1 className="login-title">Sign in</h1>
            <label className="field">
              <span>Username</span>
              <input value={username} autoFocus autoComplete="username"
                     onChange={(e) => setUsername(e.target.value)} required />
            </label>
            <label className="field">
              <span>Password</span>
              <input type="password" value={password}
                     autoComplete="current-password"
                     onChange={(e) => setPassword(e.target.value)} required />
            </label>
            <button className="btn btn-primary" disabled={busy} type="submit">
              {busy ? 'Checking…' : 'Continue'}
            </button>
            <p className="text-ink3" style={{ fontSize: 12 }}>
              A password alone will not sign you in. A second factor is required.
            </p>
          </form>
        )}

        {step === 'code' && (
          <form onSubmit={submitCode} className="stack">
            <h1 className="login-title">Authentication code</h1>
            <label className="field">
              <span>Six digits from your authenticator</span>
              <input value={code} autoFocus inputMode="numeric"
                     autoComplete="one-time-code" maxLength={11}
                     onChange={(e) => setCode(e.target.value)} required />
            </label>
            <button className="btn btn-primary" disabled={busy} type="submit">
              {busy ? 'Verifying…' : 'Sign in'}
            </button>
            <p className="text-ink3" style={{ fontSize: 12 }}>
              A recovery code works here too, if the phone is gone. Codes are
              single-use even inside the 30 seconds they stay on screen — if you
              have just used one, wait for the next.
            </p>
          </form>
        )}

        {step === 'enrol' && enrolment && (
          <form onSubmit={submitEnrolment} className="stack">
            <h1 className="login-title">Set up your second factor</h1>
            <p className="text-ink2" style={{ fontSize: 13 }}>
              Scan this with Microsoft Authenticator, Google Authenticator,
              Authy or 1Password — or enter the key by hand.
            </p>

            {/* The URI is a LINK, so on a phone this opens the authenticator
                directly with nothing to scan. The key below covers the case
                where the camera is unavailable or the screen is being shared. */}
            <a className="btn" href={enrolment.uri}>Open in authenticator app</a>

            <div className="secret-box">
              <span className="text-ink3" style={{ fontSize: 11 }}>SETUP KEY</span>
              <code className="mono secret-key">{enrolment.formatted}</code>
            </div>

            <label className="field">
              <span>Now type back the code it shows</span>
              <input value={code} autoFocus inputMode="numeric"
                     autoComplete="one-time-code" maxLength={11}
                     onChange={(e) => setCode(e.target.value)} required />
            </label>
            <button className="btn btn-primary" disabled={busy} type="submit">
              {busy ? 'Confirming…' : 'Confirm'}
            </button>
            <p className="text-ink3" style={{ fontSize: 12 }}>{enrolment.note}</p>
          </form>
        )}

        {step === 'recovery' && (
          <div className="stack">
            <h1 className="login-title">Save your recovery codes</h1>
            <div className="banner banner-warn">
              <strong>Shown once, and never again.</strong> They are stored only
              as hashes, so nobody — including whoever runs this instance — can
              recover them for you.
            </div>
            <ul className="recovery-list">
              {recovery.map((c) => <li key={c} className="mono">{c}</li>)}
            </ul>
            <p className="text-ink2" style={{ fontSize: 13 }}>
              Keep them somewhere that is <strong>not</strong> the phone you just
              enrolled. That phone being lost is the thing these exist to
              survive.
            </p>
            <button className="btn btn-primary" onClick={() => setStep('code')}>
              I have saved them — sign in
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
