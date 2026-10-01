import { useState } from 'react'

export const SEVERITY = {
  critical: { label: 'Critical', color: 'var(--color-sev-critical)' },
  high: { label: 'High', color: 'var(--color-sev-high)' },
  medium: { label: 'Medium', color: 'var(--color-sev-medium)' },
  low: { label: 'Low', color: 'var(--color-sev-low)' },
  info: { label: 'Info', color: 'var(--color-sev-info)' },
  pass: { label: 'Pass', color: 'var(--color-sev-pass)' },
}

const RISK_COLOR = {
  CRITICAL: 'var(--color-sev-critical)', HIGH: 'var(--color-sev-high)',
  MEDIUM: 'var(--color-sev-medium)', LOW: 'var(--color-sev-pass)',
}

/* ------------------------------------------------------------- live checks */
export function CheckList({ checks }) {
  if (!checks.length) return null
  return (
    <ol className="space-y-px">
      {checks.map((c, i) => {
        const issues = c.findings.filter((f) => !['pass', 'info'].includes(f.severity)).length
        return (
          <li key={c.name} className="flex items-baseline gap-3 py-1.5 text-[15px]">
            <span className="narrow w-5 shrink-0 text-right tabular-nums text-muted">{i + 1}</span>
            <span className={c.status === 'pending' ? 'text-muted' : ''}>{c.name}</span>
            <span className="ml-auto shrink-0 text-sm tabular-nums">
              {c.status === 'pending' && <span className="text-muted">waiting</span>}
              {c.status === 'running' && (
                <span className="text-stamp"><span className="running-dot">●</span> checking</span>
              )}
              {c.status === 'error' && <span className="text-sev-high">failed</span>}
              {c.status === 'done' && (issues
                ? <span className="text-sev-high">{issues} {issues === 1 ? 'issue' : 'issues'}</span>
                : <span className="text-sev-pass">clear</span>)}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

/* -------------------------------------------------------------- the stamp */
export function GradeStamp({ report }) {
  const color = RISK_COLOR[report.risk]
  const diff = report.previous_score == null ? null : report.score - report.previous_score
  return (
    <div className="flex flex-wrap items-center gap-x-10 gap-y-6">
      <div
        key={report.id}
        className="stamp grid h-36 w-36 shrink-0 place-items-center rounded-xl border-[6px]"
        style={{ borderColor: color, color }}
        role="img"
        aria-label={`Grade ${report.grade}`}
      >
        <div className="text-center leading-none">
          <div className="wide text-[88px] font-extrabold">{report.grade}</div>
          <div className="wide -mt-1 text-xs font-bold tracking-wide">{report.risk} RISK</div>
        </div>
      </div>
      <div>
        <div className="flex items-baseline gap-2">
          <span className="wide text-6xl font-bold tabular-nums">{report.score}</span>
          <span className="text-xl text-muted">/ 100</span>
        </div>
        {diff !== null && (
          <p className="mt-1 text-[15px]">
            {diff === 0 ? 'Same as the previous scan of this site.' : (
              <>
                <span style={{ color: diff > 0 ? 'var(--color-sev-pass)' : 'var(--color-sev-high)' }} className="font-semibold">
                  {diff > 0 ? '+' : ''}{diff} points
                </span>{' '}since the previous scan ({report.previous_score}).
              </>
            )}
          </p>
        )}
        <p className="mt-1 text-sm text-muted">
          {report.final_url} — {report.findings.length} results in {(report.duration_ms / 1000).toFixed(1)} s
          {report.active_checks ? ', including exposed-file probes' : ''}
        </p>
      </div>
    </div>
  )
}

export function SeverityCounts({ counts }) {
  const order = ['critical', 'high', 'medium', 'low', 'pass']
  return (
    <dl className="grid grid-cols-5 border-y border-rule">
      {order.map((s) => (
        <div key={s} className="border-l border-rule py-3 pl-3 first:border-l-0 first:pl-0">
          <dt className="text-sm text-muted">{s === 'pass' ? 'Passed' : SEVERITY[s].label}</dt>
          <dd className="wide text-3xl font-semibold tabular-nums" style={{ color: counts[s] ? SEVERITY[s].color : 'var(--color-rule)' }}>
            {counts[s]}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function CategoryBars({ categories }) {
  return (
    <ul className="space-y-3">
      {categories.map((c) => (
        <li key={c.key} className="grid grid-cols-[minmax(0,11rem)_1fr_auto] items-center gap-4 text-[15px]">
          <span className="truncate">{c.label}</span>
          <span className="h-2 overflow-hidden rounded-full bg-rule/60" role="meter" aria-valuenow={c.percent} aria-valuemin={0} aria-valuemax={100} aria-label={c.label}>
            <span
              className="block h-full rounded-full"
              style={{ width: `${Math.max(c.percent, 2)}%`, background: c.percent >= 80 ? 'var(--color-sev-pass)' : c.percent >= 50 ? 'var(--color-sev-medium)' : 'var(--color-sev-high)' }}
            />
          </span>
          <span className="w-24 text-right text-sm tabular-nums text-muted">{c.passed} of {c.total} passed</span>
        </li>
      ))}
    </ul>
  )
}

export function Analyst({ analyst }) {
  return (
    <figure className="border-l-4 border-stamp pl-5">
      <blockquote className="max-w-[68ch] text-lg leading-relaxed">{analyst.text}</blockquote>
      <figcaption className="mt-2 text-sm text-muted">
        {analyst.source === 'ai' ? 'Written by the AI security analyst' : 'Rule-based analyst summary (set ANTHROPIC_API_KEY for AI)'}
      </figcaption>
    </figure>
  )
}

/* -------------------------------------------------------------- findings */
function FindingRow({ f }) {
  const [open, setOpen] = useState(false)
  const sev = SEVERITY[f.severity]
  const expandable = f.description || f.evidence
  return (
    <li className="border-b border-rule">
      <button
        type="button"
        onClick={() => expandable && setOpen(!open)}
        aria-expanded={expandable ? open : undefined}
        className={`grid w-full grid-cols-[6rem_1fr_auto] items-baseline gap-4 py-3 text-left ${expandable ? 'cursor-pointer hover:bg-sheet' : 'cursor-default'}`}
      >
        <span className="flex items-center gap-2 text-sm font-semibold" style={{ color: sev.color }}>
          <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: sev.color }} />
          {sev.label}
        </span>
        <span className="text-[16px]">{f.title}</span>
        {expandable && <span className="text-muted" aria-hidden>{open ? '−' : '+'}</span>}
      </button>
      {open && (
        <div className="mb-4 ml-[7rem] max-w-[68ch] space-y-3 text-[15px] leading-relaxed max-sm:ml-0">
          {f.description && <p>{f.description}</p>}
          {f.impact && <p><span className="font-semibold">Why it matters. </span>{f.impact}</p>}
          {f.recommendation && <p><span className="font-semibold">How to fix. </span>{f.recommendation}</p>}
          {f.evidence && (
            <p className="break-all rounded bg-ink/5 px-3 py-2 font-mono text-[13px]">{f.evidence}</p>
          )}
          {f.references?.map((r) => (
            <a key={r} href={r} target="_blank" rel="noreferrer" className="block text-sm text-stamp underline underline-offset-2">{r}</a>
          ))}
        </div>
      )}
    </li>
  )
}

export function Findings({ findings }) {
  const [showPassed, setShowPassed] = useState(false)
  const issues = findings.filter((f) => f.severity !== 'pass')
  const passed = findings.filter((f) => f.severity === 'pass')
  return (
    <div>
      <ul className="border-t border-rule">
        {issues.map((f) => <FindingRow key={f.id} f={f} />)}
        {showPassed && passed.map((f) => <FindingRow key={f.id} f={f} />)}
      </ul>
      {passed.length > 0 && (
        <button type="button" onClick={() => setShowPassed(!showPassed)} className="mt-3 text-sm text-stamp underline underline-offset-2">
          {showPassed ? 'Hide passed checks' : `Show ${passed.length} passed checks`}
        </button>
      )}
    </div>
  )
}

/* --------------------------------------------------------------- history */
export function History({ items, onOpen, currentId }) {
  if (!items.length) return <p className="text-[15px] text-muted">Scans you run appear here.</p>
  return (
    <ul>
      {items.map((s) => (
        <li key={s.id}>
          <button
            type="button"
            onClick={() => onOpen(s.id)}
            className={`grid w-full grid-cols-[2rem_1fr_auto] items-baseline gap-3 border-b border-rule py-2 text-left text-[15px] hover:bg-sheet ${s.id === currentId ? 'font-semibold' : ''}`}
          >
            <span className="wide font-bold" style={{ color: RISK_COLOR[s.risk] }}>{s.grade}</span>
            <span className="truncate">{s.host}</span>
            <span className="text-sm tabular-nums text-muted">
              {new Date(s.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </span>
          </button>
        </li>
      ))}
    </ul>
  )
}
