import { useEffect, useState } from 'react'
import { ruleCatalogue, refusalRegister } from '../api/client'
import type { CatalogueRule, RefusalRegister, RuleCatalogue } from '../api/types'

/**
 * What this product checks, and what it refuses to claim.
 *
 * TWO HALVES, AND THE SECOND IS NOT AN APPENDIX. A competitor publishes 40+
 * named risk rules and collapses them into a single 0–99 score. This screen
 * publishes the rules and refuses the collapse — so it has to do the second
 * half too, or it is just a shorter version of the same thing.
 *
 * THE FIELD THAT MAKES IT DIFFERENT is `limits`. Every rule states what firing
 * does NOT establish, and it is rendered at the same weight as what firing
 * means. A catalogue where the caveats are smaller than the claims has already
 * decided which one it wants read.
 *
 * NO COUNTS OF FIRINGS HERE. This is a description of the software, served
 * from a public endpoint that names no asset — which is the whole reason
 * somebody can read it before installing anything.
 */
export function RulesPanel() {
  const [rules, setRules] = useState<RuleCatalogue | null>(null)
  const [refusals, setRefusals] = useState<RefusalRegister | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    ruleCatalogue().then(setRules).catch((e) => setError(String(e)))
    refusalRegister().then(setRefusals).catch(() => setRefusals(null))
  }, [])

  if (error) {
    return <div className="banner banner-crit" role="alert">{error}</div>
  }
  if (!rules) return <div className="empty">Loading…</div>

  return (
    <div className="stack">
      <div className="card">
        <p className="card-title">What SKOPOS checks</p>
        <div className="kpi">{rules.count}</div>
        <p className="kpi-note">
          named rules, each carrying its own evidence and its own limits
        </p>
        <p className="lede">{rules.note}</p>
        <div className="chip-wrap">
          {Object.entries(rules.severities).map(([name, meaning]) => (
            <span key={name} className={`pill sev-${name}`} title={meaning}>
              {name}
            </span>
          ))}
        </div>
        <dl className="sev-key">
          {Object.entries(rules.severities).map(([name, meaning]) => (
            <div key={name}>
              <dt>{name}</dt>
              <dd>{meaning}</dd>
            </div>
          ))}
        </dl>
      </div>

      {Object.entries(rules.by_category).map(([category, items]) => (
        <div className="card" key={category}>
          <p className="card-title">
            {category} <span className="text-ink3">· {items.length}</span>
          </p>
          <div className="rule-list">
            {items.map((rule) => <RuleRow key={rule.id} rule={rule} />)}
          </div>
        </div>
      ))}

      {refusals && <Refusals register={refusals} />}
    </div>
  )
}

function RuleRow({ rule }: { rule: CatalogueRule }) {
  return (
    <div className="rule">
      <div className="rule-head">
        <span className={`pill sev-${rule.severity}`}>{rule.severity}</span>
        <strong>{rule.title}</strong>
        <code className="mono rule-id">{rule.id}</code>
      </div>
      <p className="rule-detects">{rule.detects}</p>
      {/* Same weight as the claim above it, deliberately. A catalogue whose
          caveats are smaller than its claims has decided which gets read. */}
      <p className="rule-limits">
        <span className="rule-limits-label">Does not mean</span>
        {rule.limits}
      </p>
      <div className="rule-foot">
        <code className="mono">{rule.emitted_by}</code>
        {rule.evidence.length > 0 && (
          <span className="text-ink3">
            evidence: {rule.evidence.join(', ')}
          </span>
        )}
      </div>
    </div>
  )
}

function Refusals({ register }: { register: RefusalRegister }) {
  return (
    <>
      <div className="card">
        <p className="card-title">What SKOPOS refuses to tell you</p>
        <div className="kpi">{register.count}</div>
        <p className="kpi-note">
          capabilities a competitor sells, absent here for a recorded reason
        </p>
        <p className="lede">{register.note}</p>
        <div className="rule-list">
          {register.refusals.map((refusal) => (
            <div className="rule" key={refusal.id}>
              <div className="rule-head">
                <span className="pill">{refusal.ground}</span>
                <strong>{refusal.title}</strong>
              </div>
              <p className="rule-detects">
                <span className="rule-limits-label">Sold elsewhere</span>
                {refusal.sold_elsewhere}
              </p>
              {/* The field that makes the entry worth reading: most of these
                  carry the number that produced them. */}
              <p className="rule-limits">
                <span className="rule-limits-label">Because</span>
                {refusal.because}
              </p>
              <div className="rule-foot">
                <code className="mono">{refusal.recorded_in}</code>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <p className="card-title">Gaps, which are a different thing</p>
        <p className="lede">
          Absent because they have not been built, not because they were
          declined. Listed separately and never merged — presenting a gap as a
          principled refusal is exactly the dishonesty the register above exists
          to avoid.
        </p>
        <ul className="gap-list">
          {register.gaps.map((gap) => <li key={gap}>{gap}</li>)}
        </ul>
      </div>
    </>
  )
}
