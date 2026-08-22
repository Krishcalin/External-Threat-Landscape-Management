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
