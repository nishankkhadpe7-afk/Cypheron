import { useEffect, useState } from 'react'
import { getHealth, getHistory, getScan, streamScan } from './api'
import { Analyst, CategoryBars, CheckList, Findings, GradeStamp, History, SeverityCounts } from './components'

const DEMO_URL = 'http://localhost:8081'

export default function App() {
  const [url, setUrl] = useState('')
  const [activeChecks, setActiveChecks] = useState(false)
  const [consent, setConsent] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [checks, setChecks] = useState([])
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')
  const [history, setHistory] = useState([])
  const [backendUp, setBackendUp] = useState(null)

  const refreshHistory = () => getHistory().then(setHistory).catch(() => {})

  useEffect(() => {
    getHealth().then(() => setBackendUp(true)).catch(() => setBackendUp(false))
    refreshHistory()
  }, [])

  const needsConsent = activeChecks && !consent

  async function runScan(e) {
    e?.preventDefault()
    if (!url.trim() || scanning || needsConsent) return
    setScanning(true); setError(''); setReport(null); setChecks([])

    const onEvent = (evt) => {
      if (evt.type === 'start') {
        setChecks(evt.checks.map((name) => ({ name, status: 'pending', findings: [] })))
      } else {
        setChecks((prev) => prev.map((c) => {
          if (c.name !== evt.check) return c
          if (evt.type === 'check_start') return { ...c, status: 'running' }
          if (evt.type === 'check_done') return { ...c, status: 'done', findings: evt.findings }
          if (evt.type === 'check_error') return { ...c, status: 'error' }
          return c
        }))
      }
    }

    try {
      const result = await streamScan({ url: url.trim(), activeChecks, consent }, onEvent)
      setReport(result)
      setBackendUp(true)
      refreshHistory()
    } catch (err) {
      setError(err.message)
    } finally {
      setScanning(false)
    }
  }

  async function openScan(id) {
    try {
      const r = await getScan(id)
      setReport(r); setChecks([]); setError(''); setUrl(r.url)
    } catch (err) { setError(err.message) }
  }

  return (
    <div className="mx-auto max-w-6xl px-4 pb-24 sm:px-8">
      {/* header */}
      <header className="flex items-center justify-between py-6">
        <div className="flex items-center gap-3">
          <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden>
            <rect x="3" y="3" width="26" height="26" rx="3" fill="none" stroke="var(--color-stamp)" strokeWidth="3" />
            <path d="M10 17l4 4 8-9" fill="none" stroke="var(--color-stamp)" strokeWidth="3" />
          </svg>
          <span className="wide text-xl font-bold">Cypheron</span>
        </div>
        <span className="flex items-center gap-2 text-sm text-muted">
          <span className="h-2 w-2 rounded-full" style={{ background: backendUp === null ? 'var(--color-rule)' : backendUp ? 'var(--color-sev-pass)' : 'var(--color-sev-high)' }} />
          {backendUp === null ? 'Connecting…' : backendUp ? 'Scanner online' : 'Scanner offline'}
        </span>
      </header>

      {/* scan form — the hero is the tool itself */}
      <form onSubmit={runScan} className="border-y-2 border-ink py-8">
        <label htmlFor="url" className="wide block text-3xl font-bold sm:text-4xl">Which site should we inspect?</label>
        <div className="mt-5 flex flex-col gap-3 sm:flex-row">
          <input
            id="url"
            type="text"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            placeholder="https://your-site.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="min-w-0 flex-1 rounded-lg border-2 border-ink bg-sheet px-4 py-3 text-lg placeholder:text-muted/70 focus:border-stamp focus:outline-none"
          />
          <button
            type="submit"
            disabled={scanning || !url.trim() || needsConsent}
            className="wide rounded-lg bg-stamp px-7 py-3 text-lg font-bold text-white transition-opacity disabled:opacity-40"
          >
            {scanning ? 'Scanning…' : 'Scan site'}
          </button>
        </div>

        <div className="mt-4 flex flex-col gap-2 text-[15px] sm:flex-row sm:flex-wrap sm:gap-x-8">
          <label className="flex items-center gap-2">
            <input type="checkbox" className="h-4 w-4 accent-[var(--color-stamp)]" checked={activeChecks} onChange={(e) => setActiveChecks(e.target.checked)} />
            Also look for exposed files (.git, .env, backups)
          </label>
          {activeChecks && (
            <label className="flex items-center gap-2">
              <input type="checkbox" className="h-4 w-4 accent-[var(--color-stamp)]" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
              I own this site or have permission to test it
            </label>
          )}
          <button type="button" onClick={() => { setUrl(DEMO_URL); setActiveChecks(true); setConsent(true) }} className="text-left text-stamp underline underline-offset-2 sm:ml-auto">
            Use the local demo site
          </button>
        </div>
        {needsConsent && (
          <p className="mt-3 text-[15px] text-sev-high">Exposed-file checks request extra paths on the server, so confirm you're allowed to test it.</p>
        )}
      </form>

      {error && (
        <div role="alert" className="mt-6 rounded-lg border-2 border-sev-high px-5 py-4 text-[15px]">
          <p className="font-semibold text-sev-high">Scan didn't run</p>
          <p className="mt-1">{error}</p>
        </div>
      )}

      <div className="mt-10 grid gap-12 lg:grid-cols-[18rem_1fr]">
        {/* left rail */}
        <aside className="space-y-10 lg:sticky lg:top-6 lg:self-start">
          {checks.length > 0 && (
            <section>
              <h2 className="wide mb-3 text-lg font-bold">{scanning ? 'Running checks' : 'Checks run'}</h2>
              <CheckList checks={checks} />
            </section>
          )}
          <section>
            <h2 className="wide mb-3 text-lg font-bold">Recent scans</h2>
            <History items={history} onOpen={openScan} currentId={report?.id} />
          </section>
        </aside>

        {/* report */}
        <main className="min-w-0 max-lg:order-first">
          {!report && !scanning && (
            <div className="max-w-[60ch] space-y-4 text-[17px] leading-relaxed text-muted">
              <p>
                Cypheron checks a website the way an inspector checks a building: security headers,
                HTTPS and certificates, cookies, CORS, forms, and what the server gives away about itself.
              </p>
              <p>
                Nothing is attacked. Every check looks at responses an ordinary visitor would get, unless you
                turn on exposed-file checks for a site you control.
              </p>
            </div>
          )}

          {scanning && !report && (
            <p className="text-[17px] text-muted">Inspecting {url}…</p>
          )}

          {report && (
            <div className="space-y-12">
              <GradeStamp report={report} />
              {report.warnings?.map((w) => (
                <p key={w} className="rounded-lg bg-sev-medium/10 px-4 py-3 text-[15px]">{w}</p>
              ))}
              <SeverityCounts counts={report.counts} />
              <section>
                <h2 className="wide mb-4 text-xl font-bold">Analyst summary</h2>
                <Analyst analyst={report.analyst} />
              </section>
              <section>
                <h2 className="wide mb-4 text-xl font-bold">By area</h2>
                <CategoryBars categories={report.categories} />
              </section>
              <section>
                <h2 className="wide mb-1 text-xl font-bold">Findings</h2>
                <p className="mb-4 text-[15px] text-muted">Most severe first. Open a finding to see why it matters and how to fix it.</p>
                <Findings findings={report.findings} />
              </section>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
