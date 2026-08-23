// Renders every panel against the LIVE API, in Node, and fails if one throws.
//
// WHY THIS EXISTS ALONGSIDE tsc. A type-check proves shapes agree with the
// declarations; it does not prove the page executes. A `.map` over a field the
// API returns as null type-checks perfectly and throws on a live page, and the
// production build succeeds either way.
//
// Run it against a running stack:  npm run render-check
import { renderToString } from 'react-dom/server'
import { AccuracyPanel } from '../src/components/AccuracyPanel'
import { AlertsPanel } from '../src/components/AlertsPanel'
import { CompliancePanel } from '../src/components/CompliancePanel'
import { CoveragePanel } from '../src/components/CoveragePanel'
import { CrosshairPanel } from '../src/components/CrosshairPanel'
import { SystemPanel } from '../src/components/SystemPanel'

const BASE = 'http://127.0.0.1:8100/api/v1'
// A failed fetch must NOT become `null` here. `null` is a legitimate state
// every panel renders — "no scan on record" — so swallowing a 503 makes a
// broken endpoint look like a healthy empty one, and the check reports success.
// That happened: a first run against a still-warming container reported every
// panel "ok" while two of them had rendered their empty states.
let fetchFailures = 0
const get = async (p: string) => {
  const r = await fetch(`${BASE}${p}`)
  if (!r.ok) {
    fetchFailures++
    console.log(`  FETCH ${p} -> HTTP ${r.status}`)
    return null
  }
  return await r.json()
}

async function main() {
  const [cii, certin, controls, accuracy, alerts, tenancy, intel, crosshair,
         latency, dns] = await Promise.all([
    get('/compliance/cii'), get('/compliance/cert-in'), get('/compliance/controls'),
    get('/accuracy'), get('/alerts'), get('/tenancy'), get('/intel'),
    get('/crosshair?limit=200'), get('/latency'), get('/dns/runs?limit=20'),
  ])

  const cases: [string, () => JSX.Element][] = [
    ['Compliance', () => <CompliancePanel cii={cii} certin={certin} controls={controls} />],
    ['Compliance (all null)', () => <CompliancePanel cii={null} certin={null} controls={null} />],
    ['Accuracy', () => <AccuracyPanel accuracy={accuracy} />],
    ['Accuracy (null)', () => <AccuracyPanel accuracy={null} />],
    ['Alerts', () => <AlertsPanel view={alerts} />],
    ['Alerts (null)', () => <AlertsPanel view={null} />],
    ['System', () => <SystemPanel tenancy={tenancy} intel={intel} />],
    ['System (null)', () => <SystemPanel tenancy={null} intel={null} />],
    ['Crosshair', () => <CrosshairPanel view={crosshair} latency={latency} />],
    ['Crosshair (null)', () => <CrosshairPanel view={null} latency={null} />],
    ['Coverage', () => <CoveragePanel run={dns?.runs?.[0] ?? null} />],
  ]

  let failed = 0
  for (const [name, render] of cases) {
    try {
      const html = renderToString(render())
      console.log(`  ok    ${name.padEnd(24)} ${html.length.toLocaleString()} chars`)
    } catch (e) {
      failed++
      console.log(`  THROW ${name.padEnd(24)} ${(e as Error).message}`)
    }
  }
  if (fetchFailures) {
    console.log(`  ${fetchFailures} endpoint(s) did not answer; the "ok" rows`
                + ` above may be empty states rather than rendered panels`)
  }
  process.exit(failed || fetchFailures ? 1 : 0)
}
main()
