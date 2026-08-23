"""The HTTP half of authentication, and the middleware that binds the org.

`core/authn.py` owns cryptography, `core/auth_store.py` owns storage, and this
owns HTTP. Kept in its own module because `api/app.py` is already long and
because the middleware here changes the behaviour of every other route in it.

WHEN AUTHENTICATION IS ENFORCED
--------------------------------
As soon as a user exists. Not on a flag, and not never.

The alternatives are both worse. Enforcing unconditionally locks out every
existing deployment on upgrade, with no user to log in as and no way to make
one. Enforcing only on an explicit flag means a deployment that forgets it runs
open forever, silently, which is the state this whole workstream exists to end.

So: an empty user table means the console is open AND SAYS SO, on `/health` and
across the top of every page. Bootstrap one administrator and it locks. That
fails toward closed the moment somebody configures it, and never leaves a
deployment quietly unprotected while believing otherwise.

WHY THE MIDDLEWARE BINDS THE ORG RATHER THAN A DEPENDENCY DOING IT
-------------------------------------------------------------------
A FastAPI dependency binds only for routes that declare it, so a route added by
somebody who has not heard of tenancy would serve `SKOPOS_ORG_ID` — the exact
failure mode P5 recorded. Middleware wraps everything, including routes that do
not know it exists.

Verified rather than assumed: a ContextVar set in async middleware IS visible
inside a sync route, because Starlette runs those through `anyio.to_thread`,
which copies the context. Had it not propagated, every request would have
silently served the wrong tenant.
"""
from __future__ import annotations

import os
from typing import Any, Callable, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core import authn, tenancy
from core.auth_store import (BOOTSTRAP_PASSWORD_ENV, BOOTSTRAP_USER_ENV,
                             LoginFailed, SecondFactorRequired, bootstrap,
                             open_auth_store, open_pending)
from core.store import StoreUnavailable

#: Reachable without a session. Everything else requires one once a user exists.
#:
#: `/api/v1/health` is open on purpose: a load balancer probes it, and a probe
#: that needs a credential is a probe that reports the service down whenever the
#: credential is wrong.
PUBLIC_PREFIXES = ("/api/v1/health", "/api/v1/auth/", "/assets/", "/taxii2/")
PUBLIC_EXACT = ("/", "/favicon.png", "/skopos-logo.png", "/api/docs",
                "/api/openapi.json")


class _LoginBody(BaseModel):
    username: str
    password: str


class _VerifyBody(BaseModel):
    pending: str
    code: str


class _EnrolBody(BaseModel):
    code: str


def _store():
    try:
        return open_auth_store()
    except StoreUnavailable:
        return None


def auth_status() -> Dict[str, Any]:
    """Whether authentication is enforced, and if not, why not.

    Reported rather than inferred. A console that is open and does not say so is
    indistinguishable from one that is protected.
    """
    store = _store()
    if store is None:
        return {"enforced": False, "users": None,
                "state": "no database reachable, so no authentication is "
                         "possible and none is enforced"}
    try:
        count = store.user_count()
    except Exception as exc:                                   # noqa: BLE001
        return {"enforced": False, "users": None,
                "state": f"the user table could not be read: {exc}"}
    if count == 0:
        return {
            "enforced": False, "users": 0,
            "state": (
                f"NO USERS EXIST, so this console is OPEN to anyone who can "
                f"reach it. Set {BOOTSTRAP_USER_ENV} and "
                f"{BOOTSTRAP_PASSWORD_ENV} and restart to create the first "
                f"administrator; authentication enforces itself the moment one "
                f"exists."),
        }
    return {"enforced": True, "users": count,
            "state": f"{count} user(s) configured; a session is required"}


def _is_public(path: str) -> bool:
    if path in PUBLIC_EXACT:
        return True
    if any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES):
        return True
    # The console is a single-page app: any non-API path serves the shell, and
    # the shell itself is what renders the login form. Gating it would leave a
    # user with a 401 body and no way to authenticate.
    return not path.startswith("/api/")


def register(app: FastAPI) -> bool:
    """Add the auth routes and the org-binding middleware."""

    @app.middleware("http")
    async def bind_org_and_enforce(request: Request, call_next):
        store = _store()
        session: Optional[Dict[str, Any]] = None
        if store is not None:
            token = (request.cookies.get(authn.SESSION_COOKIE)
                     or authn.split_cookie(request.headers.get("cookie", "")))
            if token:
                try:
                    session = store.resolve_session(token)
                except StoreUnavailable:
                    session = None

        if session is None and not _is_public(request.url.path):
            status = auth_status()
            if status["enforced"]:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "a session is required",
                             "login": "/api/v1/auth/login"})

        org = session["org_id"] if session else tenancy.current_org()
        # Bound for EVERY route, including ones written by somebody who has
        # never heard of tenancy. That is the point of doing it here.
        with tenancy.using(org):
            request.state.session = session
            return await call_next(request)

    @app.get("/api/v1/auth/status", tags=["auth"])
    def status() -> Dict[str, Any]:
        """Whether this console is protected. Deliberately public — a user
        needs to know they are on an open instance before they type anything
        into it."""
        return auth_status()

    @app.post("/api/v1/auth/login", tags=["auth"])
    def login(body: _LoginBody) -> Dict[str, Any]:
        """Step one. Never returns a session — a password alone is not enough."""
        store = _store()
        if store is None:
            raise HTTPException(status_code=503,
                                detail="no database reachable")
        try:
            store.start_login(body.username, body.password)
        except SecondFactorRequired as required:
            return {"pending": required.pending, "enrolled": required.enrolled,
                    "next": "/api/v1/auth/verify" if required.enrolled
                            else "/api/v1/auth/enrol"}
        except LoginFailed as failed:
            # One message for a wrong password, a wrong username and a disabled
            # account. A form that distinguishes them enumerates usernames.
            raise HTTPException(status_code=401, detail=str(failed))
        raise HTTPException(status_code=500,
                            detail="login did not demand a second factor")

    @app.post("/api/v1/auth/verify", tags=["auth"])
    def verify(body: _VerifyBody, response: Response,
               request: Request) -> Dict[str, Any]:
        """Step two. Issues the session cookie."""
        store = _store()
        if store is None:
            raise HTTPException(status_code=503, detail="no database reachable")
        try:
            session = store.complete_login(
                body.pending, body.code,
                user_agent=request.headers.get("user-agent", ""))
        except LoginFailed as failed:
            raise HTTPException(status_code=401, detail=str(failed))

        response.set_cookie(
            authn.SESSION_COOKIE, session["token"],
            httponly=True,                 # a cross-site script cannot read it
            samesite="lax",
            # Only over TLS when the request arrived over TLS. Setting it
            # unconditionally breaks a local http deployment, and not setting it
            # in production sends the session in clear.
            secure=request.url.scheme == "https",
            max_age=authn.SESSION_TTL_SECONDS, path="/")
        return {"username": session["username"], "org_id": session["org_id"],
                "display_name": session["display_name"],
                "expires_at": session["expires_at"]}

    @app.get("/api/v1/auth/session", tags=["auth"])
    def whoami(request: Request) -> Dict[str, Any]:
        session = getattr(request.state, "session", None)
        if session is None:
            raise HTTPException(status_code=401, detail="no session")
        return {"username": session["username"], "org_id": session["org_id"],
                "display_name": session["display_name"],
                "expires_at": session["expires_at"]}

    @app.post("/api/v1/auth/logout", tags=["auth"])
    def logout(request: Request, response: Response) -> Dict[str, Any]:
        store = _store()
        token = request.cookies.get(authn.SESSION_COOKIE, "")
        revoked = bool(store and token and store.revoke_session(token))
        response.delete_cookie(authn.SESSION_COOKIE, path="/")
        # The cookie is cleared either way: a session the server has already
        # forgotten should not leave a token sitting in the browser.
        return {"revoked": revoked}

    @app.post("/api/v1/auth/enrol", tags=["auth"])
    def enrol(body: _VerifyBody) -> Dict[str, Any]:
        """Issue a TOTP secret against a pending login.

        Reached only with a valid pending token, so a caller must already have
        proven the password. `code` is unused here and required by the shared
        body model; enrolment is confirmed by the next call.
        """
        store = _store()
        if store is None:
            raise HTTPException(status_code=503, detail="no database reachable")
        user_id = open_pending(body.pending)
        if user_id is None:
            raise HTTPException(status_code=401,
                                detail="this login attempt has expired; start again")
        enrolment = store.begin_enrolment(user_id)
        return {
            "secret": enrolment["secret"],
            "formatted": enrolment["formatted"],
            "uri": enrolment["uri"],
            "note": ("Nothing is enrolled until you type back a working code. "
                     "A failed scan cannot lock you out."),
        }

    @app.post("/api/v1/auth/enrol/confirm", tags=["auth"])
    def enrol_confirm(body: _VerifyBody) -> Dict[str, Any]:
        """Activate the second factor and return recovery codes, once."""
        store = _store()
        if store is None:
            raise HTTPException(status_code=503, detail="no database reachable")
        user_id = open_pending(body.pending)
        if user_id is None:
            raise HTTPException(status_code=401,
                                detail="this login attempt has expired; start again")
        try:
            codes = store.confirm_enrolment(user_id, body.code)
        except LoginFailed as failed:
            raise HTTPException(status_code=401, detail=str(failed))
        return {
            "recovery_codes": codes,
            "note": ("Shown once and never again — they are stored only as "
                     "hashes. Keep them somewhere that is not the phone you "
                     "just enrolled, because that is the thing they exist to "
                     "survive."),
            "next": "/api/v1/auth/verify",
        }

    return True


def bootstrap_from_env() -> Optional[str]:
    """Create the first administrator, once, if the environment names one."""
    store = _store()
    if store is None:
        return None
    try:
        return bootstrap(store)
    except Exception:                                          # noqa: BLE001
        # A failed bootstrap must not stop the service: the console still needs
        # to come up and report that it is unauthenticated.
        return None


__all__ = ["register", "auth_status", "bootstrap_from_env", "PUBLIC_PREFIXES",
           "PUBLIC_EXACT"]
