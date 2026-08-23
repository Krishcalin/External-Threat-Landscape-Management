import { useEffect, useState } from 'react'
import { AuthError } from '../api/auth'
import {
  changePassword, createUser, listUsers, resetPassword, resetSecondFactor,
  setDisabled, setRole,
} from '../api/account'
import type { AccountCreated, AccountList, Session } from '../api/types'

/**
 * Your own account, and — for an administrator — everybody else's.
 *
 * TWO SECTIONS, IN THAT ORDER, ON PURPOSE. Every user has the first; only an
 * administrator sees the second. Putting the user list first would make the
 * commonest thing anybody comes here to do — change their own password — the
 * thing they have to scroll past a table to reach.
 *
 * WHAT AN ADMINISTRATOR CAN DO HERE, SAID ON THE SCREEN
 * ------------------------------------------------------
 * Resetting a password and resetting a second factor are, together, a takeover:
 * do both and you can sign in as that person. The screen says so — in the
 * confirmation before each action and again beside the issued password —
 * because the power is real, is not preventable while an administrator can do
 * both, and is written to the audit chain either way.
 *
 * An administrator still cannot CHOOSE a password (it is generated), cannot
 * read anybody's authenticator secret, and cannot disable themselves or the
 * last administrator.
 */
export function AccountPanel({ session }: { session: Session }) {
  return (
    <div className="stack">
      <YourAccount session={session} />
      {session.is_admin && <Users session={session} />}
      {!session.is_admin && (
        <div className="card">
          <div className="card-title">Other accounts</div>
          <p className="lede">
            Creating and disabling accounts is limited to administrators on this
            instance. Ask one of them.
          </p>
          <p className="text-ink2">
            Being an administrator confers no authority over any estate — it
            does not permit scanning a host, which stays gated on verified
            ownership for everybody.
          </p>
        </div>
      )}
    </div>
  )
}

/* ── your own account ──────────────────────────────────────────────────── */

function YourAccount({ session }: { session: Session }) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<string | null>(null)

  const mismatch = confirm.length > 0 && next !== confirm

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    setError(null)
    setDone(null)
    if (next !== confirm) {
      // Caught here rather than at the server: the server never receives the
      // confirmation field, so it cannot check this and should not pretend to.
      setError('The two new passwords do not match.')
      return
    }
    setBusy(true)
    try {
      const result = await changePassword(current, next)
      setDone(result.note)
      setCurrent('')
      setNext('')
      setConfirm('')
    } catch (exc) {
      setError(exc instanceof AuthError ? exc.message : String(exc))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card">
      <div className="card-title">Your account</div>

      <div className="grid grid-4" style={{ marginBottom: 16 }}>
        <Fact label="Signed in as" value={session.username} mono />
        <Fact label="Display name" value={session.display_name} />
        <Fact label="Organisation" value={session.org_id} mono />
        <Fact
          label="Role"
          value={session.is_admin ? 'Administrator' : 'User'}
        />
      </div>

      <h3 className="lookup-h3">Change your password</h3>
      <p className="text-ink2" style={{ marginTop: 0 }}>
        Your current password is required. A session proves who signed in, not
        who is holding the browser now — without it, a stolen session could set
        a new password and lock you out of your own account.
      </p>

      <form onSubmit={submit} className="stack" style={{ maxWidth: 420 }}>
        <label className="field">
          <span>Current password</span>
          <input
            type="password" className="login-input" value={current}
            autoComplete="current-password" required
            onChange={(e) => setCurrent(e.target.value)}
          />
        </label>
        <label className="field">
          <span>New password</span>
          <input
            type="password" className="login-input" value={next}
            autoComplete="new-password" required minLength={12}
            onChange={(e) => setNext(e.target.value)}
          />
        </label>
        <label className="field">
          <span>New password again</span>
          <input
            type="password" className="login-input" value={confirm}
            autoComplete="new-password" required
            aria-invalid={mismatch}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </label>
        <p className="text-ink3" style={{ margin: 0, fontSize: 12 }}>
          At least 12 characters. Every other session you have open will be
          signed out; this one stays.
        </p>
        {mismatch && (
          <div className="banner banner-warn">
            The two new passwords do not match.
          </div>
        )}
        {error && <div className="banner banner-crit" role="alert">{error}</div>}
        {done && <div className="banner banner-ok" role="status">{done}</div>}
        <div>
          <button className="btn btn-primary" type="submit" disabled={busy}>
            {busy ? 'Changing…' : 'Change password'}
          </button>
        </div>
      </form>
    </div>
  )
}

/* ── administering other accounts ──────────────────────────────────────── */

/** What the one-time-password card is currently showing, from either source. */
type Issued = { who: string; password: string; steps: string[]; note?: string }

function Users({ session }: { session: Session }) {
  const [data, setData] = useState<AccountList | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [note, setNote] = useState<string | null>(null)
  const [issued, setIssued] = useState<Issued | null>(null)

  async function refresh() {
    try {
      setData(await listUsers())
      setError(null)
    } catch (exc) {
      setError(exc instanceof AuthError ? exc.message : String(exc))
    }
  }

  useEffect(() => {
    void refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  /** Every mutating action funnels through here so that a refusal is shown
   *  rather than swallowed, and the table is always re-read afterwards. A
   *  button that silently does nothing is worse than one that errors. */
  async function act(what: () => Promise<{ note: string }>) {
    setError(null)
    setNote(null)
    try {
      setNote((await what()).note)
    } catch (exc) {
      setError(exc instanceof AuthError ? exc.message : String(exc))
    }
    await refresh()
  }

  /** A reset returns a password, so it cannot go through `act()` — that shows a
   *  note and discards the body. */
  async function issueReset(username: string) {
    setError(null)
    setNote(null)
    try {
      const result = await resetPassword(username)
      setIssued({
        who: result.username, password: result.initial_password,
        steps: result.next_steps, note: result.note,
      })
    } catch (exc) {
      setError(exc instanceof AuthError ? exc.message : String(exc))
    }
    await refresh()
  }

  return (
    <>
      <NewAccount
        onCreated={(result) => {
          setIssued({
            who: result.created, password: result.initial_password,
            steps: result.next_steps,
          })
          void refresh()
        }}
      />

      {issued && (
        <OneTimePassword {...issued} onDismiss={() => setIssued(null)} />
      )}

      <div className="card">
        <div className="card-title">
          Accounts in {data?.org_id ?? session.org_id}
        </div>

        {error && <div className="banner banner-crit" role="alert">{error}</div>}
        {note && <div className="banner banner-info" role="status">{note}</div>}

        {data && (
          <div className="grid grid-4" style={{ marginBottom: 16 }}>
            <Fact label="Accounts" value={String(data.summary.total)} />
            <Fact label="Administrators"
                  value={String(data.summary.administrators)} />
            <Fact label="Disabled" value={String(data.summary.disabled)} />
            {/* Surfaced because it appears in no total: an account created and
                never used is either a colleague who never received their
                credential, or an account nobody needed. */}
            <Fact label="Never signed in"
                  value={String(data.summary.never_signed_in)} />
          </div>
        )}

        {data === null && !error && <div className="empty">Loading…</div>}

        {data && data.users.length > 0 && (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Account</th>
                  <th>Role</th>
                  <th>Second factor</th>
                  <th>Last signed in</th>
                  <th>State</th>
                  <th aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {data.users.map((user) => (
                  <tr key={user.username}>
                    <td>
                      <span className="mono">{user.username}</span>
                      {user.is_you && <span className="pill">you</span>}
                      <div className="text-ink3" style={{ fontSize: 12 }}>
                        {user.display_name}
                        {user.created_by && ` · created by ${user.created_by}`}
                      </div>
                    </td>
                    <td>{user.is_admin ? 'Administrator' : 'User'}</td>
                    <td>
                      {user.second_factor === 'enrolled' ? (
                        'Enrolled'
                      ) : (
                        <span className="text-med">Not enrolled</span>
                      )}
                    </td>
                    <td>{user.last_login_at
                      ? new Date(user.last_login_at).toLocaleDateString()
                      : <span className="text-med">Never</span>}</td>
                    <td>
                      {user.disabled ? (
                        <span className="text-crit">Disabled</span>
                      ) : user.must_change_password ? (
                        <span className="text-med">Password not yet changed</span>
                      ) : (
                        'Active'
                      )}
                    </td>
                    <td>
                      <RowActions
                        user={user}
                        onDisable={(d) =>
                          act(() => setDisabled(user.username, d))}
                        onRole={(a) => act(() => setRole(user.username, a))}
                        onResetFactor={() =>
                          act(() => resetSecondFactor(user.username))}
                        onResetPassword={() =>
                          void issueReset(user.username)}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <p className="text-ink3" style={{ fontSize: 12 }}>
          A reset issues a generated password, never one you choose — an
          administrator picking passwords produces a house pattern, and a house
          pattern means every account here shares a guessable prefix. Resetting
          a password and a second factor together lets you sign in as that
          person; that is not preventable while you can do both, so both are
          written to the audit log instead.
        </p>
      </div>
    </>
  )
}

function RowActions({
  user, onDisable, onRole, onResetFactor, onResetPassword,
}: {
  user: AccountList['users'][number]
  onDisable: (disabled: boolean) => void
  onRole: (isAdmin: boolean) => void
  onResetFactor: () => void
  onResetPassword: () => void
}) {
  // Your own row offers nothing. Disabling yourself locks you out instantly and
  // demoting yourself may leave the instance with no administrator; the server
  // refuses both, and offering a button whose only outcome is a refusal is
  // worse than not offering it.
  if (user.is_you) {
    return <span className="text-ink3" style={{ fontSize: 12 }}>—</span>
  }
  return (
    <div className="chip-wrap">
      <button className="btn" onClick={() => onDisable(!user.disabled)}>
        {user.disabled ? 'Restore' : 'Disable'}
      </button>
      <button className="btn" onClick={() => onRole(!user.is_admin)}>
        {user.is_admin ? 'Remove admin' : 'Make admin'}
      </button>
      <button
        className="btn"
        onClick={() => {
          if (window.confirm(
            `Issue ${user.username} a new one-time password?\n\n` +
            'Their current password stops working and their sessions end. ' +
            'You will see the new one, so until they change it you could ' +
            'sign in as them if you also reset their second factor. Both ' +
            'actions are recorded in the audit log.',
          )) onResetPassword()
        }}
      >
        Reset password
      </button>
      {user.second_factor === 'enrolled' && (
        <button
          className="btn"
          onClick={() => {
            // The one action here that weakens an account, so it is the one
            // that asks. Everything else is reversible or restrictive.
            if (window.confirm(
              `Clear ${user.username}'s authenticator?\n\n` +
              'Their recovery codes are voided and their sessions ended. They ' +
              'will enrol a new authenticator at next sign-in. Confirm you ' +
              'are speaking to the right person first.',
            )) onResetFactor()
          }}
        >
          Reset second factor
        </button>
      )}
    </div>
  )
}

function NewAccount({ onCreated }: { onCreated: (r: AccountCreated) => void }) {
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [isAdmin, setIsAdmin] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      onCreated(await createUser(username.trim(), displayName.trim(), isAdmin))
      setUsername('')
      setDisplayName('')
      setIsAdmin(false)
    } catch (exc) {
      setError(exc instanceof AuthError ? exc.message : String(exc))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card">
      <div className="card-title">Create an account</div>
      <p className="lede" style={{ marginTop: 0 }}>
        A one-time password is generated and shown once. Give it to the person
        directly; they must change it before the account can do anything, and
        they then enrol their own authenticator.
      </p>
      <form onSubmit={submit} className="stack" style={{ maxWidth: 420 }}>
        <label className="field">
          <span>Username</span>
          <input
            className="login-input" value={username} required
            autoComplete="off" spellCheck={false}
            placeholder="a.patel"
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>
        <label className="field">
          <span>Display name <span className="text-ink3">(optional)</span></span>
          <input
            className="login-input" value={displayName} autoComplete="off"
            placeholder="Anita Patel"
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </label>
        <label className="field" style={{ flexDirection: 'row', gap: 8,
                                          alignItems: 'flex-start' }}>
          <input
            type="checkbox" checked={isAdmin}
            onChange={(e) => setIsAdmin(e.target.checked)}
          />
          <span>
            Can administer accounts
            <div className="text-ink3" style={{ fontSize: 12 }}>
              Lets them create and disable accounts. Grants no authority over
              any estate — scanning stays gated on verified ownership. Worth
              having a second one: an instance with a single administrator has
              no recovery path if that person leaves.
            </div>
          </span>
        </label>
        {error && <div className="banner banner-crit" role="alert">{error}</div>}
        <div>
          <button className="btn btn-primary" type="submit" disabled={busy}>
            {busy ? 'Creating…' : 'Create account'}
          </button>
        </div>
      </form>
    </div>
  )
}

/** Shown after a creation OR a reset — both issue a password exactly once, and
 *  a second component for the second case would be a second place to forget the
 *  warning. */
function OneTimePassword({
  who, password, steps, note, onDismiss,
}: {
  who: string
  password: string
  steps: string[]
  note?: string
  onDismiss: () => void
}) {
  return (
    <div className="card">
      <div className="card-title">Password for {who} — shown once</div>
      <div className="banner banner-warn">
        <strong>This is the only time this password is displayed.</strong> It is
        not stored in readable form and no endpoint will repeat it. If it is
        lost before {who} receives it, reset it again.
      </div>
      <div className="secret-box">
        <span className="secret-key mono">{password}</span>
      </div>
      <ol className="gap-list">
        {steps.map((step) => <li key={step}>{step}</li>)}
      </ol>
      {/* Rendered, not tucked into a tooltip. It is the sentence that says what
          an administrator can actually do with what is on this screen. */}
      {note && <p className="gap-why">{note}</p>}
      <button className="btn" onClick={onDismiss}>
        I have given it to them
      </button>
    </div>
  )
}

function Fact({ label, value, mono }: {
  label: string; value: string; mono?: boolean
}) {
  return (
    <div>
      <p className="fact-label">{label}</p>
      <div className={mono ? 'fact-value mono' : 'fact-value'}>{value}</div>
    </div>
  )
}
