import type { Factors } from '../api/types'

/**
 * The TEPS decomposition, rendered as a contribution bar.
 *
 * FR-M10-002 and FR-UI-001: every score expands into its factors in one
 * interaction and no black-box number is permitted anywhere in the product.
 * This component IS that requirement — it is not decoration.
 *
 * The segments are weighted contributions, not raw factor values, because the
 * question a reader is asking is "what is driving this number", and a factor of
 * 1.0 carrying a 0.20 weight drives less than a factor of 0.8 carrying 0.30.
 *
 * Colour is never the only carrier: the legend names every segment and states
 * its contribution numerically, so the bar is readable in greyscale, in print,
 * and by somebody who cannot distinguish the hues.
 */

const LABELS: Record<keyof Factors, string> = {
  exposure: 'Exposure',
  exploitability: 'Exploitability',
  adversary_interest: 'Adversary interest',
  business_criticality: 'Business criticality',
}

const ORDER: (keyof Factors)[] = [
  'exposure', 'exploitability', 'adversary_interest', 'business_criticality',
]

export function TepsBar({ factors, showLegend = true }: {
  factors: Factors
  showLegend?: boolean
}) {
  const total = ORDER.reduce((sum, key) => sum + (factors[key] ?? 0), 0)
  // A zero total would divide by zero and render an invisible bar that looks
  // like a rendering fault rather than a score of nothing.
  const scale = total > 0 ? 100 / total : 0

  return (
    <div>
      <div
        className="teps-bar"
        role="img"
        aria-label={ORDER.map((k) => `${LABELS[k]} ${(factors[k] ?? 0).toFixed(3)}`).join(', ')}
      >
        {ORDER.map((key) => {
          const value = factors[key] ?? 0
          if (value <= 0) return null
          return (
            <div
              key={key}
              className={`teps-seg teps-seg-${key}`}
              style={{ width: `${value * scale}%` }}
              title={`${LABELS[key]}: ${value.toFixed(3)}`}
            />
          )
        })}
      </div>
      {showLegend && (
        <div className="legend">
          {ORDER.map((key) => (
            <span className="legend-item" key={key}>
              <span className={`swatch teps-seg-${key}`} aria-hidden="true" />
              {LABELS[key]} <strong>{(factors[key] ?? 0).toFixed(3)}</strong>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
