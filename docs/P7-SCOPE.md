# P7 — Ask anything, and the console that fronts it

The product owner's direction, recorded as given:

> Input an IP (/24) or a domain and see what the public sources say about it —
> risks, ratings, threats, vulnerabilities, probability, and the threat actors
> that have targeted it and are targeting it now. The same for email addresses,
> exposed AWS keys and tokens, password-harvesting sites, and brand reputation.
> A traffic-analysis graph and an attack-path view, full page, dramatic. And an
> `index.html` landing page with two-factor auth, as OverWatch has.

| Workstream | What it is |
|---|---|
| [W1](#w1--authentication-and-the-tenancy-last-mile) | Landing page, TOTP two-factor, sessions — and the org binding that finishes tenancy |
| [W2](#w2--ask-anything-passive-lookup) | Type an IP/CIDR or domain, get what the public record says |
| [W3](#w3--identity-and-brand-exposure) | Breach corpora, exposed keys and tokens, lookalike domains |
| [W4](#w4--the-graph) | Attack path, full page |

---

## Three things in the direction that the measurements already answered

Raised once, here, so the build can proceed against the honest version of each
rather than discovering the collision at demo time.

### 1. "Threat actors who have targeted this and are targeting now"

P3 built this and closed it with a measurement: the ATT&CK corpus carries **0 CVE
references** in `external_references`, only 5 of 191 groups mention a CVE in
prose, and resolving technique → group implicates a **median of 57 groups per
CVE, 139 at the extreme**. An attribution naming 57 groups is not attribution,
and `core/crosshair.py` exists precisely because the honest answer was
convergence rather than actors. `CrosshairPanel` renders the refusal on screen.

**But the direction is not asking for the same thing, and part of it is real.**
Two distinct claims hide in one sentence:

| Claim | Verdict |
|---|---|
| "Groups known to use this CVE are targeting you" | **Refused.** Inference, measured, 57-group median. |
| "This IP/domain appears in an abuse feed, a blocklist, a paste, or a breach corpus TODAY" | **Supportable.** An observation about the asset with a named source and a date. |

W2 and W3 build the second. Nothing in P7 revives the first, and a screen that
implied it would undo the one piece of intellectual honesty this product is
best known for internally.

### 2. "Risks, rating, probability"

This product refuses a single composite grade, for the same reason it refuses a
compliance coverage percentage: the number gets screenshotted, shown to a board,
and its inputs never travel with it. TEPS exists and is **always decomposed into
its four factors on the same screen**.

**The honest version, which is what W2 will build:** an asset-level score with
the same contract as TEPS — a number that expands into the observations behind
it in one interaction, and refuses to render at all when it has too few inputs
to mean anything. A letter grade in the style of Bitsight or SecurityScorecard
is not that, and is not being built.

Probability is already handled and already refuses: `core/latency.py` answers
only for the one reference class in four that has enough resolved samples, and
`core/backtest.py` publishes no accuracy figure below 30 resolved forecasts.

### 3. "Traffic analysis graph"

**Cannot be built as stated, and no amount of effort changes that.** SKOPOS is an
outside-in product. It has never seen a packet of the customer's traffic, has no
flow logs, no agent, no tap. A traffic graph would be drawn from nothing.

What is real and is what W4 will build:

- **The exposure graph** — asset → observed service → CVE → evidence — which is
  the data the product actually holds, and which nothing currently visualises.
- **Attack path from the outside in** — internet-reachable entry, what it runs,
  what that corresponds to, and where OverWatch's cloud model disagrees. The
  `unexplained_exposure` reconciliation is already the most interesting edge in
  the product and appears today only as a counter.

If genuine traffic analysis is wanted, it belongs in OverWatch, which has flow
logs. Building a fake one here would be the M8 mistake with a nicer animation.

---

## W1 — authentication, and the tenancy last mile

**Why this is first.** Everything else in P7 exposes more, to more people. The
console is unauthenticated today, which is why there is no STIX download button
on it and why the takeover route and the TAXII server are gated behind a bearer
token instead. Adding "type any domain and see its exposure" to an anonymous
console would be building a reconnaissance service open to whoever reaches the
port.

It also closes a gap flagged in P5 and left open: tenancy enforces perfectly at
the database and **nothing resolves an org per request** — `tenancy.using()`
exists and nothing calls it, so every request falls back to `SKOPOS_ORG_ID`. A
session that carries a user carries their org, and that is the missing link. The
enforcement floor was built first on purpose; this is the part that sits on it.

**Design, following OverWatch's split** (`aws_totp.py` / `cnapp_authn.py` /
`cnapp_authn_api.py`), which separates cryptography from storage from HTTP:

- `core/totp.py` — RFC 6238, stdlib only, verified against **the RFC's own
  published test vectors** rather than against itself. SHA-1 because that is
  what every mainstream authenticator assumes, and the break is collision
  resistance, which HMAC does not rely on.
- `core/authn.py` — password hashing, session tokens, recovery codes.
- `core/auth_store.py` + `db/008` — users, sessions, enrolments; org-scoped and
  under the same RLS as everything else.
- Routes and an `AuthGate` in the console.

**No default credential.** Not `admin/admin`, and not an auto-generated one
printed to stdout — container logs are aggregated, shipped and retained. The
first administrator comes from `SKOPOS_BOOTSTRAP_USER` /
`SKOPOS_BOOTSTRAP_PASSWORD`, applied once against an empty user table and
ignored thereafter.

**Two-factor is not optional for a console that will hold this data.** Recovery
codes exist because a wiped phone otherwise means an administrator can never log
in again, and for the first administrator there is no administrator to ask.

### W1a — the accounts the login implied (added after P7 closed)

W1 shipped a login and no way to use it: no second account could be created, no
password could be changed, and nothing in the console called the logout endpoint
that existed. The gap was reported from a screenshot of the running instance,
which is the correct way to find it and a late one.

**A role column was the first thing needed, not the last.** Migration 008 made
every user equal, which is fine while the only user is the bootstrap
administrator and stops being fine the moment a second exists — without a role,
any authenticated user could create another, so one compromised low-privilege
session escalates to permanent access by making itself a friend. `is_admin` is
one boolean rather than a permissions matrix, because a product with two verbs
that invents a matrix has built machinery nobody can audit.

**Three things an administrator deliberately cannot do**, each because the
alternative is worse than the missing feature:

| Refused | Why |
|---|---|
| Disable themselves, or the last administrator | There is no recovery path from an instance with none — the state `008` already records as unrecoverable, reachable by one misclick |
| Create an account in another organisation | The org is read from the session and cannot be passed. As a parameter it would defeat migration 006's boundary through the front door |
| Anything at all to an estate | `is_admin` appears nowhere in the authorisation path; a test asserts `gate.py` never mentions it |

**And one thing this got wrong first.** The original design had no password reset
at all, reasoning that an administrator who cannot set a password cannot sign in
as you. That was true, and it cost more than it bought: a forgotten password
meant a permanently dead account, and because `008` makes usernames globally
unique, a permanently burned username with it. A product whose answer to "I
forgot my password" is "your account is gone" gets worked around by people
sharing credentials, which is a worse security outcome than a bounded
administrator power.

So the reset exists, and the claim was corrected everywhere it appeared rather
than left standing. **An administrator who resets both a password and a second
factor can sign in as that user.** That is true of every system where one person
can do both. What is bounded is the rest: the password is generated rather than
chosen, the account is locked to the change form until its owner replaces it,
and **both halves are written to the hash-chained audit log** — the takeover is
reconstructable even though it is not preventable.

**Auditing account actions surfaced a real privilege bug in `core/store.py`.**
`append_audit` took `LOCK TABLE audit_log IN EXCLUSIVE MODE`, which was fine
while the only caller was the CLI connecting as the table owner. The API
connects as `skopos_app`, which holds INSERT and SELECT on that table and
deliberately nothing else — an application able to UPDATE or DELETE its own
tamper-evident log is not one. PostgreSQL requires UPDATE, DELETE, TRUNCATE or
MAINTAIN for every lock mode above ROW EXCLUSIVE, so the first audited route
failed with `InsufficientPrivilege`. Granting those privileges would have fixed
the symptom by deleting the property; a transaction-scoped advisory lock needs no
table privilege, serialises identically, and both callers take the same key.

**A password change requires the current password**, even though the session
already passed both factors at login. Those prove who signed in; they do not
prove who is holding the cookie now. Without the rule a stolen session becomes a
permanent takeover — the thief sets a new password, the owner is locked out, and
the second factor never comes up again. It also revokes every *other* session
and reports how many, because somebody who sees "3 other sessions" when they
expected none has just learned something.

**An account an administrator created is not yet that person's account.** It
starts on a credential the administrator chose and has seen, so
`must_change_password` gates it: the session can reach the change form, logout
and nothing else. Enforced in the middleware rather than a dependency, for the
same reason the org binding is — a dependency binds only for routes that declare
it, and the next route added by somebody who has not heard of this would serve a
locked session.

**One bug the tests caught before a user did.** `reset_second_factor` set
`totp_last_counter` to NULL against a `NOT NULL DEFAULT -1` column, so clearing
an enrolment would have raised `NotNullViolation` — the recovery path for a lost
authenticator, failing exactly when somebody needed it. -1 is the column's
sentinel for "nothing accepted yet"; 0 would be a counter.

Verified end-to-end against the running container rather than in unit tests
alone: **48 checks** driving the real HTTP API with real cookies, including that
a disabled account's live session dies on the next request rather than at
expiry, that a locked account really can reach nothing but its own password
form, and that no issued password appears anywhere in the audit log. The
privilege bug above was invisible to every unit test and failed on the first
live call — which is the argument for the probe existing at all.

---

## W2 — ask anything (passive lookup)

**The collision to resolve first.** `scope check tata.com` today refuses *every*
operation, passive ones included, because nothing is scoped. The direction wants
a box you type any domain into. Those are not reconcilable by loosening scope —
loosening it would widen what the ACTIVE collectors may touch, which is the one
thing the gate exists to prevent.

**The resolution, which the architecture already contains.** W1 of P6 established
that a third party can be assessed **passively and only passively**, because
ownership cannot be proven and every active operation fails closed. An ad-hoc
lookup is that same path without the register: passive operations only, an actor
recorded, an audit entry written, and no route by which it can escalate.

So `POST /api/v1/lookup` takes a domain, a hostname or a CIDR and returns what
the public record says. What it must never do is become a way to reach an
unverified asset actively, and the test for that is the same one W1 of P6 has.

**Sources, and their real constraints.** `collect/registry.py` already models a
source with its terms, its review date and whether it is on by default — the
machinery exists. What is new is that several of these need keys and have terms
that a customer, not this product, must accept:

| Source | Reality |
|---|---|
| Shodan | API key, paid tiers. Terms restrict redistribution. |
| Have I Been Pwned | API key, paid, per-request rate limit. |
| VirusTotal | API key; free tier is 4 req/min and non-commercial. |
| CT logs, RDAP, WHOIS, DNS | Already integrated, no key, already used. |

Anything requiring a key is **off until the operator supplies one**, and its
absence is reported as *unobserved* rather than as a clean result — the same
three-state discipline the supplier posture already enforces. A lookup that
silently skipped Shodan because no key was set would report an empty result that
reads as "nothing exposed".

---

## W3 — identity and brand exposure

- **Email address in a breach corpus** — HIBP-shaped. An observation with a
  source and a date. It is not a statement that the account is compromised now.
- **Exposed keys and tokens** — note the overlap: a separate Secrets Scanner
  already exists in this portfolio. This should ingest or defer to it rather
  than growing a second regex corpus that drifts out of step.
- **Lookalike / password-harvesting domains** — **the strongest fit in P7.**
  SKOPOS already reads certificate transparency. A phishing site needs a
  certificate, and getting one puts it in a public log. Detecting registrable
  lookalikes of a customer's brand from CT is a genuinely novel output built on
  a collector that already exists.
- **Brand reputation** — needs a definition before it needs code. "Reputation"
  as an unsourced number is the rating problem again. As *"these 4 domains
  issued certificates impersonating your name last week"*, it is concrete.

---

## W4 — the graph

Full page, and the drama should come from the data being real rather than from
the animation. Nodes are assets, services, vulnerabilities and evidence; edges
are the joins the product already computes. The reconciliation outcomes —
especially `unexplained_exposure`, reachable from outside while the cloud model
says otherwise — are the edges worth making unmissable, and today they are a
number in a banner.

Coverage gaps must be drawable too. A graph that renders only what was observed
makes an uninstrumented estate look clean, which is the failure the Crosshair
panel already refuses in table form.

---

## What would make this plan wrong

- If the keyed sources (Shodan, HIBP, VirusTotal) turn out not to be licensable
  for this use, W2 degrades to what CT/RDAP/WHOIS/DNS already provide — still
  useful, considerably less than the direction describes. **Establish the
  licensing before building the panels.**
- If lookalike detection produces mostly false positives on real brand names, it
  needs a threshold below which it declines, exactly as concentration analysis
  does. Measure against a real brand before shipping the screen.
- If the graph needs data the product does not hold, the graph is wrong, not the
  data.
