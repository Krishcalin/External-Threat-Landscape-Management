import { useEffect, useMemo, useState } from 'react'
import { exposureGraph } from '../api/client'
import type { ExposureGraph, GraphEdge, GraphNode } from '../api/types'

/**
 * The exposure graph, full page.
 *
 * A LAYERED LAYOUT, NOT A FORCE-DIRECTED ONE. A physics simulation looks
 * impressive in a screenshot and is hard to read on the second viewing: nodes
 * land somewhere different every load, so nobody builds a memory of where
 * anything is. This data is inherently layered — an asset runs a product, a
 * product corresponds to a vulnerability — so it is drawn in three columns, in
 * a stable order, and the same estate looks the same tomorrow.
 *
 * The drama should come from the data being real, not from the animation.
 *
 * WHAT IS DRAWN THAT MOST GRAPHS OMIT. Coverage gaps. A picture of only what
 * was observed makes an uninstrumented estate look clean — a sparse graph reads
 * as a small attack surface when it may be a small amount of instrumentation.
 * So `never probed` and `version not compared` are nodes with counts, not a
 * footnote, and they sit in the same visual field as the findings.
 *
 * THE RED EDGE. `unexplained_exposure` — reachable from the internet while the
 * cloud model says otherwise — is the one finding neither product makes alone,
 * so it is drawn last, heaviest and in the critical colour. When no cloud model
 * has been ingested it is UNDRAWABLE rather than absent, and the banner says
 * which, because a missing input rendered as a clean result is the failure this
 * codebase keeps catching in itself.
 */

const COLUMN = { asset: 0, product: 1, vulnerability: 2, gap: 3 } as const
const COL_X = [90, 380, 690, 980]
const ROW_H = 30
const TOP = 46

const EDGE_STYLE: Record<string, { stroke: string; width: number; dash?: string }> = {
  runs: { stroke: 'var(--line)', width: 1.5 },
  corresponds: { stroke: 'var(--med)', width: 1.5, dash: '4 3' },
  determined: { stroke: 'var(--crit)', width: 2 },
  retired: { stroke: 'var(--ink3)', width: 1, dash: '2 4' },
  unexplained_exposure: { stroke: 'var(--crit)', width: 3 },
  limits: { stroke: 'var(--ink3)', width: 1, dash: '2 4' },
}

const BAND_FILL: Record<string, string> = {
  critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)',
  low: 'var(--low)', informational: 'var(--info)',
}

export function GraphPanel() {
  const [graph, setGraph] = useState<ExposureGraph | null>(null)
  const [error, setError] = useState('')
  const [focus, setFocus] = useState<string | null>(null)

  useEffect(() => {
    exposureGraph()
      .then(setGraph)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
  }, [])

  const placed = useMemo(() => {
    if (!graph) return { positions: {} as Record<string, { x: number; y: number }>, height: 0 }
    const byColumn: Record<number, GraphNode[]> = { 0: [], 1: [], 2: [], 3: [] }
    for (const node of graph.nodes) {
      byColumn[COLUMN[node.kind as keyof typeof COLUMN] ?? 3].push(node)
    }
    const positions: Record<string, { x: number; y: number }> = {}
    let tallest = 0
    for (const [col, nodes] of Object.entries(byColumn)) {
      // Stable order: by band, then label. The same estate draws the same way
      // tomorrow, which is what makes a graph learnable.
      nodes.sort((a, b) => (b.band ?? '').localeCompare(a.band ?? '')
        || a.label.localeCompare(b.label))
      nodes.forEach((n, i) => {
        positions[n.id] = { x: COL_X[Number(col)], y: TOP + i * ROW_H }
      })
      tallest = Math.max(tallest, nodes.length)
    }
    return { positions, height: TOP + tallest * ROW_H + 30 }
  }, [graph])

  if (error) {
    return (
      <section className="stack">
        <h2 className="section">Exposure graph</h2>
        <div className="banner banner-crit" role="alert">{error}</div>
      </section>
    )
  }
  if (!graph) {
    return (
      <section className="stack">
        <h2 className="section">Exposure graph</h2>
        <div className="empty">Loading…</div>
      </section>
    )
  }

  const undrawable = graph.unexplained_state === 'undrawable'
  const connected = (id: string) =>
    graph.edges.some((e) => (e.source === id && e.target === focus)
      || (e.target === id && e.source === focus)) || id === focus

  return (
    <section className="stack">
      <h2 className="section">
        Exposure graph
        <span className="text-ink3"> — {graph.findings_drawn} finding(s)</span>
      </h2>

      <p className="lede">{graph.headline}</p>

      {/* The refusal, stated before the picture rather than under it. */}
      <div className="banner banner-info">
        <strong>This is not a traffic graph.</strong> {graph.not_a_traffic_graph}
      </div>

      <div className={`banner ${undrawable ? 'banner-warn' : 'banner-info'}`}>
        <strong>
          {undrawable
            ? 'The unexplained-exposure edge could not be drawn.'
            : graph.unexplained_state === 'present'
              ? 'Reachable while the cloud model says otherwise.'
              : 'A cloud model was ingested and disagrees with nothing.'}
        </strong>{' '}
        {graph.unexplained_note}
      </div>

      {/* Gaps above the picture, for the same reason the Crosshair puts them
          above the table: they bound everything below. */}
      {Object.keys(graph.gaps).length > 0 && (
        <div className="banner banner-warn">
          <strong>What could not be established.</strong>{' '}
          {graph.sparse_is_not_safe}
          <ul className="gap-list">
            {Object.entries(graph.gaps).map(([gap, count]) => (
              <li key={gap}>
                <span className="gap-count">{count}</span>
                <span className="gap-why">{gap}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="graph-legend">
        {Object.entries(EDGE_STYLE).filter(([k]) => k !== 'limits').map(([kind, style]) => (
          <span key={kind} className="legend-item">
            <svg width="26" height="8" aria-hidden="true">
              <line x1="0" y1="4" x2="26" y2="4" stroke={style.stroke}
                    strokeWidth={style.width} strokeDasharray={style.dash} />
            </svg>
            {kind.replace(/_/g, ' ')}
          </span>
        ))}
        <span className="text-ink3" style={{ fontSize: 11 }}>
          click a node to isolate what touches it
        </span>
      </div>

      <div className="graph-frame">
        <svg viewBox={`0 0 1180 ${placed.height}`} className="graph-svg"
             role="img" aria-label="Exposure graph: assets, products and vulnerabilities">
          {['Assets', 'Products', 'Exploited vulnerabilities', 'Coverage gaps']
            .map((title, i) => (
              <text key={title} x={COL_X[i]} y={24} className="graph-col-title">
                {title}
              </text>
            ))}

          {/* Edges first so nodes sit on top. Sorted by weight server-side, so
              the unexplained edge is drawn last and reads as heaviest. */}
          {graph.edges.map((e: GraphEdge, i) => {
            const a = placed.positions[e.source]
            const b = placed.positions[e.target]
            if (!a || !b) return null
            const style = EDGE_STYLE[e.kind] ?? EDGE_STYLE.runs
            const dim = focus && !(e.source === focus || e.target === focus)
            return (
              <path key={i}
                    d={`M ${a.x + 150} ${a.y} C ${a.x + 230} ${a.y}, ${b.x - 80} ${b.y}, ${b.x} ${b.y}`}
                    fill="none" stroke={style.stroke} strokeWidth={style.width}
                    strokeDasharray={style.dash} opacity={dim ? 0.08 : 0.75} />
            )
          })}

          {graph.nodes.map((n: GraphNode) => {
            const at = placed.positions[n.id]
            if (!at) return null
            const dim = focus !== null && !connected(n.id)
            const isGap = n.kind === 'gap'
            return (
              <g key={n.id} opacity={dim ? 0.15 : 1}
                 onClick={() => setFocus(focus === n.id ? null : n.id)}
                 className="graph-node">
                <rect x={at.x} y={at.y - 11} width={150} height={22} rx={5}
                      className={isGap ? 'graph-gap-box' : 'graph-node-box'} />
                {!isGap && (
                  <circle cx={at.x + 9} cy={at.y} r={4}
                          fill={BAND_FILL[n.band] ?? 'var(--ink3)'} />
                )}
                <text x={at.x + (isGap ? 8 : 19)} y={at.y + 4}
                      className={isGap ? 'graph-gap-label' : 'graph-label'}>
                  {n.label.length > 21 ? n.label.slice(0, 20) + '…' : n.label}
                </text>
                <title>
                  {`${n.label}\n${n.detail}`}
                  {n.count ? `\n${n.count} finding(s)` : ''}
                </title>
              </g>
            )
          })}
        </svg>
      </div>

      {graph.truncated && (
        <p className="text-ink3" style={{ fontSize: 12 }}>
          The graph is capped at {graph.findings_drawn} findings and more exist.
          A capped picture that does not say so reads as a complete one.
        </p>
      )}

      {/* Advisories are held apart on purpose, and the reason is worth reading
          rather than being a silent absence. */}
      <div className="card">
        <p className="card-title">Beyond the exploited catalogue</p>
        <p className="text-ink2" style={{ fontSize: 13, margin: 0 }}>
          {graph.beyond_catalogue.note}
        </p>
      </div>
    </section>
  )
}
