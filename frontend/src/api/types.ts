/** Shapes served by `api/app.py`. Kept in step by hand for now; the OpenAPI
 *  schema at /api/openapi.json is the authority if they ever disagree. */

export type Band = 'critical' | 'high' | 'medium' | 'low' | 'informational'

/** FR-M2-010's three-value confidence. `confirmed` is reserved for a version
 *  actually compared against a published affected range — a product-name
 *  correspondence is `possible` however strongly the names agree. */
export type MatchConfidence = 'confirmed' | 'probable' | 'possible'

/** The outside-in / inside-out matrix. The middle two are the reason the
 *  OverWatch integration exists. */
export type ReconciliationOutcome =
  | 'confirmed'
  | 'unexplained_exposure'
  | 'discovery_blind_spot'
  | 'agreed_not_exposed'
  | 'inconclusive'

export interface IntelStatus {
  catalog_version: string
  released: string | null
  retrieved: string | null
  /** Days since CISA released this catalogue. Shown beside every result: a
   *  figure computed against a stale corpus is a different claim from the same
   *  figure computed today, and nothing in the numbers says which. */
  age_days: number | null
  entries: number
  epss_scope: string
  ransomware_linked: number
  /** Whether the corpus carries CNA affected ranges at all. */
  affected_ranges?: boolean
  /** The share of the catalogue whose versions can actually be compared —
   *  measured over the full corpus, not a sample. Everything outside it can
   *  only ever be a worklist entry, however it is presented. */
  determinable_share?: number | null
}

export interface Factors {
  exposure: number
  exploitability: number
  adversary_interest: number
  business_criticality: number
}

export interface CloudContext {
  resource_id: string
  kind: string
  account: string | null
  region: string | null
  internal_reachability: 'reachable' | 'not_reachable' | 'unknown'
  exposed_ports: number[]
  fronted_by: string[]
}

export interface Finding {
  asset: string
  product: string
  version: string | null
  owner: string | null
  environment: string | null
  cve: string
  vulnerability: string
  known_ransomware: boolean
  due_date: string | null
  epss: number | null
  required_action: string
  teps: number
  band: Band
  /** Each factor's weighted share. FR-M10-002: no black-box number anywhere. */
  factors: Factors
  factor_values: Factors & { mitigation: number }
  /** Why this score should be read with caution. Never hidden. */
  flags: string[]
  model_version: string
  basis: 'product_match' | 'version_range'
  match_confidence: MatchConfidence
  name_confidence: 'strong' | 'partial'
  evidence: string[]
  cloud: CloudContext | null
  reconciliation: ReconciliationOutcome | null
}

export interface Summary {
  scanned_at: string
  findings: number
  assets_affected: number
  bands: Partial<Record<Band, number>>
  ransomware_linked: number
  /** A version was compared against a published affected range. */
  determinations: number
  /** Everything else — somebody has to check the version. */
  worklist: number
  reconciliation: Partial<Record<ReconciliationOutcome, number>>
  /** The two honesty counters. A console showing findings without these reads
   *  as a complete picture when it may be a partial one. */
  assets_matched_nothing: number
  cloud_resources_unmappable: number
  catalogue: IntelStatus
}

export interface FindingsPage {
  total: number
  returned: number
  findings: Finding[]
}

/** One DNS sweep and what it could NOT see.
 *
 *  The three gap counters are separate on purpose. A resolver outage
 *  (`unobserved`), a resolver disagreement (`quorum_failed`) and an operator's
 *  exclusion (`refused`) are different facts with different remedies, and an
 *  aggregate "health" number would hide which one you are looking at. */
export interface DnsRun {
  id: number
  started_at: string
  actor: string
  resolvers: string[]
  /** Counted per (name, rrtype) PAIR. Per-name counting would let a name with
   *  five of six record types failed report as fully observed. */
  attempted: number
  observed: number
  quorum_failed: number
  unobserved: number
  refused: number
  degraded: boolean
}

export interface DnsRunsPage {
  total: number
  runs: DnsRun[]
}

/** Deliberately has no `vulnerable` member, and never will. The only
 *  experiment that would establish one is registering the resource, which the
 *  gate refuses before scope or ownership are even consulted. */
export type TakeoverVerdict =
  | 'registrable_domain_unregistered'
  | 'provider_guarded'
  | 'internal_dangling'
  | 'no_claim_signal_found'
  | 'inconclusive'

export interface TakeoverFinding {
  name: string
  verdict: TakeoverVerdict
  corroboration: string
  target: string
  target_rcode: string
  resolvers_agreeing: number
  reasons: string[]
  first_seen: string
  last_seen: string
}

/** One finding and the independent signals that put it in the crosshair. */
export interface AimedEntry {
  asset: string
  cve: string
  product: string
  owner: string | null
  teps: number
  tier: 'converged' | 'elevated' | 'present'
  signals: string[]
  /** What could NOT be established. A gap in OUR coverage, not evidence of
   *  safety — and it is what holds an entry out of the top tier. */
  unknown: string[]
}

export interface CrosshairView {
  headline: string
  total_findings: number
  tiers: Record<string, AimedEntry[]>
  coverage_gaps: Record<string, number>
  signal_meaning: Record<string, string>
  tier_meaning: Record<string, string>
  /** Rendered, never tucked into a tooltip: a screen called Crosshair invites
   *  exactly the reading this product has to refuse. */
  not_targeting: string
}

/** Weaponisation latency: what happened to comparable past vulnerabilities.
 *
 *  Class-level, never per-asset. `median` is the middle of a REFERENCE CLASS,
 *  and attaching it to a row would read as "this asset has 8 days" — which is
 *  a forecast about one estate, not a base rate over a population. */
export interface LatencyClass {
  reference_class: string
  ransomware: boolean
  weaponised: boolean
  samples: number
  usable: boolean
  p25: number | null
  median: number | null
  p75: number | null
  spread_days: number | null
  note: string
}

export interface LatencyReport {
  classes: Record<string, LatencyClass>
  usable_classes: number
  total_classes: number
  observations: number
  excluded: Record<string, number>
  window_since: string
  not_a_forecast: string
  artefact_coverage: number | null
  coverage_meaning: string | null
}

/* ── compliance ───────────────────────────────────────────────────────────
 * Every one of these carries a REFUSAL as a first-class field rather than a
 * footnote, because the refusals are what the panels are mostly for. */

export interface CiiEntry {
  asset: string
  sector_label: string
  basis: string
  basis_meaning: string
  gazette_reference: string | null
  declared_by: string | null
  declared_on: string | null
  findings: number
  determinations: number
  worklist: number
  first_observed_by_skopos: string | null
  externally_reachable: boolean | null
  note: string | null
}

export interface CiiRegister {
  authority: string
  cii_definition: string
  reviewed_on: string
  headline: string
  entries: CiiEntry[]
  undeclared_assets: string[]
  sectors: Record<string, string>
  /** SKOPOS does not and cannot determine CII status. Rendered, not hidden. */
  skopos_does_not_designate: string
  note?: string
}

export interface CertInCategory {
  category: string
  label: string
  skopos_can_observe: boolean
  note: string
}

export interface CertInStatus {
  directive: string
  reviewed_on: string
  window_hours: number
  /** Why no finding starts a six-hour countdown. */
  why_not_automatic: string
  categories: CertInCategory[]
  summary: string
}

export interface Control {
  framework: string
  id: string
  title: string
  contributes: string
  /** The half that makes the mapping honest. Never collapsed into a tooltip. */
  does_not: string
  evidence_from: string[]
}

export interface ControlMapping {
  reviewed_on: string
  disclaimer: string
  controls: Control[]
  frameworks: string[]
}

/* ── accuracy ─────────────────────────────────────────────────────────────── */
export interface CalibrationBucket {
  band: string
  forecast: number
  observed: number | null
  n: number
}

export interface Accuracy {
  model_version: string
  issued: number
  resolved: number
  /** False until enough forecasts resolve. No figure is shown before then. */
  publishable: boolean
  minimum_to_publish: number
  brier: number | null
  climatology_brier: number | null
  uninformative_brier: number
  base_rate: number | null
  skill_vs_climatology: number | null
  outcomes: Record<string, number>
  calibration: CalibrationBucket[]
  /** Structurally unmeasurable on a KEV-only corpus. Says so in words. */
  lead_time: string
  headline: string
}

/* ── alerts ───────────────────────────────────────────────────────────────── */
export interface AlertRow {
  trigger: string
  subject: string
  body: string
  detail: Record<string, unknown>
  at: string
}

export interface AlertsView {
  previous_run: number | null
  is_baseline: boolean
  alerts: AlertRow[]
  suppressed_below_band: number
  suppressed_by_cap: number
  minimum_band: string
  note: string
  /** Always false from this route: it decides, it does not deliver. */
  delivered: boolean
  delivery: string
  triggers_off_by_default: string[]
}

/* ── tenancy ──────────────────────────────────────────────────────────────── */
export interface Tenancy {
  org: string
  /** States its own limit: a defence against a bug, not against a compromise. */
  isolation_meaning: string
  /** Whether RLS actually applies, or the app is connected as a superuser. */
  enforcement: string
  bound_org: string | null
}

/* ── suppliers ─────────────────────────────────────────────────────────────
 * There is no vulnerability field here, and there cannot be. A supplier's
 * estate is somebody else's; the gate refuses every active operation against
 * an unverified asset, so there is no fingerprint, no product name, and no CVE
 * join. A supplier CVE count would be a fabrication. */

export interface SupplierPosture {
  supplier: string
  domain: string
  tier: string
  tier_meaning: string
  dependency: string | null
  present: string[]
  absent: string[]
  /** Kept apart from `absent` on purpose: our coverage gap is not their gap. */
  unobserved: string[]
  providers: Record<string, string>
  notes: string[]
  signal_meaning: Record<string, { means: string; does_not_mean: string }>
}

export interface ConcentrationRow {
  kind: string
  provider: string
  suppliers: string[]
  count: number
  critical_suppliers: number
  share_of_register: number | null
}

export interface SupplierRegister {
  headline: string
  suppliers: SupplierPosture[]
  concentrations: ConcentrationRow[]
  /** A correlation in availability and blast radius — not a shared vuln. */
  concentration_meaning: string
  /** Present when the register is too small to support a conclusion. */
  concentration_refused: string | null
  minimum_register: number
  no_cve_join: string
  assessed: number
  never_assessed: number
  discrimination: string
  /** Presence-of-SPF and presence-of-DMARC are excluded: measured 8/8. */
  ranking_signals: string[]
}

/* ── the projections ──────────────────────────────────────────────────────── */
export interface RunRow {
  id: number
  scanned_at: string
  actor: string
  catalog_version: string
  catalog_age_days: number | null
  assets_read: number
  assets_unmatched: number
  summary: Record<string, number>
}

export interface RunsPage { runs: RunRow[] }

export interface ChangesView {
  previous_run: number | null
  is_baseline: boolean
  headline: string
  new: number
  resolved: number
  changed_band: number
  carried: number
}

/* ── authentication ────────────────────────────────────────────────────────
 * No token type appears here, because the console never holds one: the session
 * arrives as an HttpOnly cookie the browser attaches and JavaScript cannot
 * read. */

export interface AuthStatus {
  enforced: boolean
  users: number | null
  /** Rendered verbatim when `enforced` is false. An open console that does not
   *  say so is indistinguishable from a protected one. */
  state: string
}

export interface Session {
  username: string
  org_id: string
  display_name: string
  expires_at: string
  /** Whether to draw the Accounts section. NOT the control — every account
   *  route re-checks this server-side, because hiding a button is not the same
   *  as refusing a request. */
  is_admin: boolean
  /** Still using the password an administrator issued. While true the session
   *  can reach the password form and nothing else. */
  must_change_password: boolean
}

export interface AccountUser {
  username: string
  display_name: string
  is_admin: boolean
  disabled: boolean
  second_factor: 'enrolled' | 'not enrolled'
  must_change_password: boolean
  created_at: string | null
  created_by: string | null
  last_login_at: string | null
  is_you: boolean
}

export interface AccountSummary {
  total: number
  administrators: number
  disabled: number
  awaiting_second_factor: number
  /** Either a colleague who never received their credential, or an account
   *  nobody needed. Both want attention; neither shows up in a total. */
  never_signed_in: number
}

export interface AccountList {
  org_id: string
  users: AccountUser[]
  summary: AccountSummary
}

/** The response to a creation. `initial_password` is present exactly once and
 *  is not retrievable afterwards — there is no endpoint that will repeat it. */
export interface AccountCreated {
  created: string
  display_name: string
  is_admin: boolean
  initial_password: string
  shown_once: boolean
  next_steps: string[]
}

export interface PasswordChanged {
  changed: boolean
  other_sessions_revoked: number
  note: string
}

/** A one-time password issued to somebody who forgot theirs. `note` states the
 *  takeover path plainly and is rendered, not swallowed. */
export interface PasswordReset {
  username: string
  initial_password: string
  shown_once: boolean
  next_steps: string[]
  note: string
}

export interface PendingLogin {
  pending: string
  /** False means send them to enrolment, not to a code field they cannot
   *  fill. */
  enrolled: boolean
  next: string
}

export interface Enrolment {
  secret: string
  formatted: string
  uri: string
  /** Rendered server-side by a stdlib encoder. Empty if rendering failed — the
   *  key and the link both still work, so a QR failure must not block
   *  enrolment. */
  qr_svg: string
  note: string
}

export interface EnrolConfirmed {
  recovery_codes: string[]
  note: string
  next: string
}

/* ── the lookup ────────────────────────────────────────────────────────────
 * Note what is NOT here: no grade, no letter, no single verdict field. The
 * score arrives with its decomposition attached or it does not arrive. */

export interface ScoreFactor {
  value: number | null
  observed: boolean
  inputs: string[]
  measures: string
  /** Rendered beside every factor. The limits are the point. */
  cannot_see: string
}

export interface LookupScore {
  value: number | null
  publishable: boolean
  minimum_factors: number
  factors: Record<string, ScoreFactor>
  /** Present when too few factors were observed to publish anything. */
  refusal: string | null
  not_a_grade: string
  unobserved: string[]
}

export interface KeyedSource {
  source: string
  /** False means no key. NOT the same as answering and finding nothing. */
  available: boolean
  answered: boolean
  observations: Record<string, unknown>[]
  detail: string
  verified_live: boolean
  caveat: string | null
}

export interface UnavailableSource {
  source: string
  why: string
  cost: string
  terms: string
}

export interface LookupResult {
  target: { raw: string; kind: string; value: string; addresses: string[] }
  headline: string
  score: LookupScore
  names: string[]
  reverse_dns: Record<string, string>
  registration: Record<string, unknown>
  posture: SupplierPosture | null
  unavailable_sources: UnavailableSource[]
  keyed_sources: KeyedSource[]
  passive_only: string
  coverage: { attempted: number; observed: number; refused: unknown[] }
}

export interface SourceCatalogue {
  sources: {
    name: string
    operation: string
    terms: string
    configured: boolean
    default_on: boolean
    credential_env: string | null
    note: string
  }[]
  terms_reviewed_on: string
  note: string
}

/* ── brand imitation ───────────────────────────────────────────────────────
 * `searched` is the most important field here. Zero candidates from a
 * successful search and zero because no source could be asked are different
 * answers, and zero is what a customer hopes to see. */

export interface LookalikeCandidate {
  name: string
  /** The domain somebody REGISTERED — what a customer actually answers about. */
  registration: string
  term: string
  signals: string[]
  signal_meaning: Record<string, string>
  strength: number
  first_seen: string | null
  /** On every row, because a row is what gets copied into a takedown request. */
  not_a_verdict: string
}

export interface LookalikeReport {
  headline: string
  /** False means NOTHING was asked. Never render this as "none found". */
  searched: boolean
  examined: number
  candidates: LookalikeCandidate[]
  minimum_signals: number
  unavailable_sources: { source: string; why: string; cost: string }[]
  signal_meaning: Record<string, string>
  never_a_verdict: string
  terms: string[]
  owned: string[]
}

export interface BreachReport {
  address: string
  source: string
  available: boolean
  answered: boolean
  observations: Record<string, unknown>[]
  detail: string
  verified_live: boolean
  caveat: string | null
  what_this_does_not_say: string
}

/* ── the exposure graph ────────────────────────────────────────────────────
 * No traffic, no flows, no throughput: this product has never seen a packet of
 * the customer's traffic. `unexplained_state` has THREE values — a missing
 * cloud model is `undrawable`, not `absent`. */

export interface GraphNode {
  id: string
  kind: 'asset' | 'product' | 'vulnerability' | 'gap'
  label: string
  detail: string
  band: string
  count: number
}

export interface GraphEdge {
  source: string
  target: string
  kind: string
  detail: string
  meaning: string
}

export interface ExposureGraph {
  headline: string
  nodes: GraphNode[]
  /** Pre-sorted by weight server-side, so the unexplained edge draws last. */
  edges: GraphEdge[]
  gaps: Record<string, number>
  node_meaning: Record<string, string>
  edge_meaning: Record<string, string>
  cloud_model: boolean | null
  unexplained_state: 'present' | 'absent' | 'undrawable'
  unexplained_note: string
  not_a_traffic_graph: string
  sparse_is_not_safe: string
  findings_drawn: number
  truncated: boolean
  beyond_catalogue: { advisories: number; note: string }
}

/* ── the rule catalogue and the refusal register (P8 W1, W8) ───────────── */

export interface CatalogueRule {
  id: string
  title: string
  category: string
  /** Never a number. A number invites summation, and a sum of forty rules is
   *  the scalar the catalogue exists to avoid. */
  severity: 'act' | 'check' | 'context' | 'coverage'
  detects: string
  /** What firing does NOT establish. Required, never empty, and rendered with
   *  the same weight as `detects`. */
  limits: string
  emitted_by: string
  evidence: string[]
  needs: string | null
}

export interface RuleCatalogue {
  rules: CatalogueRule[]
  count: number
  by_category: Record<string, CatalogueRule[]>
  severities: Record<string, string>
  note: string
}

export interface Refusal {
  id: string
  title: string
  ground: 'measured' | 'governance' | 'capability' | 'authority' | 'honesty'
  /** What a competitor sells here — named so the reader knows it was
   *  considered rather than overlooked. */
  sold_elsewhere: string
  because: string
  recorded_in: string
}

export interface RefusalRegister {
  refusals: Refusal[]
  count: number
  by_ground: Record<string, number>
  /** The OTHER kind: absent because unbuilt, not because declined. Never
   *  merged with the refusals. */
  gaps: string[]
  note: string
  document: string
}


/* ── landscape seeds ───────────────────────────────────────────────────────
 * The four inputs a landscape can start from. They are NOT equivalent: only a
 * domain expands, and the capability text is served by the API rather than
 * written in the console so the promise and the code enforcing it cannot
 * drift apart. */
export interface SeedCapabilities {
  runs: string[]
  expands_to_new_assets?: boolean
  produces?: string
  requires?: string[]
  limits: string
}

export interface SeedKindInfo {
  kind: string
  label: string
  example: string
  expands: boolean
  capabilities: SeedCapabilities
}

export interface SeedKindCatalogue {
  kinds: SeedKindInfo[]
  passive_only: string
  why_not_individual: string
  why_org_is_only_a_question: string
}

export interface Seed {
  kind: string
  value: string
  /** What was typed, minus anything personal. For an email this is the domain
   *  with the mailbox already discarded — never stored, not merely hidden. */
  as_entered: string
  note: string
  expands: boolean
  capabilities: SeedCapabilities
}

export interface SeedPlan {
  seeds: Seed[]
  refused: { input: string; why: string }[]
  summary: {
    seeds: number
    by_kind: Record<string, number>
    expanding_seeds: number
    notes: string[]
    passive_only: string
  }
}

/** One editable line in the console form. Local state only. */
export interface SeedRow {
  id: number
  kind: string
  value: string
}
