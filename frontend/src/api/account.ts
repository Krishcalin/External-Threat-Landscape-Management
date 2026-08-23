/** Account administration calls.
 *
 *  Same discipline as `auth.ts`: the session travels as an HttpOnly cookie, so
 *  every call sends `credentials: 'include'` and there is no token in this file
 *  to hold or to leak.
 *
 *  ONE THING WORTH SAYING ABOUT `createUser` AND `resetPassword`. Both return a
 *  password the server will never repeat. Nothing here writes it to storage and
 *  the panel that renders it does not persist it either — if it is lost before
 *  the person receives it, the repair is another `resetPassword`, not a lookup.
 *  A credential that can be retrieved later is a credential sitting in a
 *  database.
 */
import { AuthError } from './auth'
import type { AccountCreated, AccountList, PasswordChanged,
              PasswordReset } from './types'

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

export const listUsers = () => call<AccountList>('/account/users')

export const createUser = (
  username: string,
  display_name: string,
  is_admin: boolean,
) => call<AccountCreated>('/account/users', { username, display_name, is_admin })

/** Requires the current password even though a session already exists: that
 *  proves who logged in, not who is holding the cookie now. */
export const changePassword = (
  current_password: string,
  new_password: string,
) => call<PasswordChanged>('/account/password', {
  current_password, new_password,
})

export const setDisabled = (username: string, disabled: boolean) =>
  call<{ username: string; disabled: boolean; note: string }>(
    `/account/users/${encodeURIComponent(username)}/disabled`, { disabled })

export const setRole = (username: string, is_admin: boolean) =>
  call<{ username: string; is_admin: boolean; note: string }>(
    `/account/users/${encodeURIComponent(username)}/role`, { is_admin })

export const resetSecondFactor = (username: string) =>
  call<{ username: string; second_factor: string; note: string }>(
    `/account/users/${encodeURIComponent(username)}/second-factor/reset`, {})

/** For somebody who has forgotten their password. Returns a one-time password
 *  shown once — the same contract as creation, and the same warning: an
 *  administrator who resets this AND the second factor can sign in as them. */
export const resetPassword = (username: string) =>
  call<PasswordReset>(
    `/account/users/${encodeURIComponent(username)}/password/reset`, {})
