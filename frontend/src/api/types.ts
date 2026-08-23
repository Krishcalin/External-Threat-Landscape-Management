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
