import { useMemo, useState } from 'react';
import {
  Button,
  Callout,
  Card,
  CodeBlock,
  DownloadButton,
  KVTable,
  Select,
  TextArea,
  TextInput,
} from '@/components/ui';
import { useLocalStorage } from '@/lib/hooks';
import { cvssBase, parseVector, severity } from './CvssCalculator';

/**
 * Structured finding writer. The vector string is the single source of truth for
 * severity: the score is recomputed on every keystroke from the parsed vector, so
 * the severity select can never disagree with the number in the report.
 */

type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

const SEVERITIES: Array<{ value: Severity; label: string }> = [
  { value: 'Critical', label: 'Critical (9.0–10.0)' },
  { value: 'High', label: 'High (7.0–8.9)' },
  { value: 'Medium', label: 'Medium (4.0–6.9)' },
  { value: 'Low', label: 'Low (0.1–3.9)' },
  { value: 'Info', label: 'Informational' },
];

interface Draft {
  title: string;
  severity: Severity;
  vector: string;
  asset: string;
  category: string;
  description: string;
  impact: string;
  steps: string;
  request: string;
  response: string;
  remediation: string;
  references: string;
  affected: string;
}

const EMPTY: Draft = {
  title: 'Reflected XSS in the support ticket search',
  severity: 'High',
  vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
  asset: 'https://support.example.com/search?q= · 203.0.113.10:443',
  category: 'OWASP A03:2021 — Injection (WSTG-INPV-01)',
  description:
    'The `q` parameter is echoed into the results header without output encoding. A crafted link executes script in the victim’s session on the support portal origin.',
  impact:
    'An authenticated support agent can be made to run arbitrary script with their session, which exposes the ticket queue and permits ticket reassignment.',
  steps: [
    '1. Sign in to the support portal as any agent.',
    '2. Request `/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E`.',
    '3. Observe the payload executing in the results header — no encoding applied.',
  ].join('\n'),
  request: 'GET /search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E HTTP/1.1\nHost: support.example.com\nCookie: SESSID=<redacted>',
  response: 'HTTP/1.1 200 OK\nContent-Type: text/html\n\n<h2>Results for <img src=x onerror=alert(document.domain)></h2>',
  remediation:
    'Context-aware HTML-encode the parameter on output. Add a strict Content-Security-Policy without `unsafe-inline`. Treat the reflected value as text, never as markup.',
  references: 'https://owasp.org/www-community/attacks/xss/',
  affected: 'All support agents (approximately 240 accounts) on the EU tenant',
};

export default function FindingWriter() {
  const [draft, setDraft] = useLocalStorage<Draft>('finding-draft', EMPTY);
  const [saved, setSaved] = useState(false);

  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => {
    setDraft((prev) => ({ ...prev, [key]: value }));
    setSaved(false);
  };

  const cvss = useMemo(() => {
    const parsed = parseVector(draft.vector);
    if (!parsed) return null;
    const r = cvssBase(parsed);
    return { score: r.score, band: severity(r.score) };
  }, [draft.vector]);

  const markdown = useMemo(() => renderFinding(draft, cvss), [draft, cvss]);

  return (
    <>
      <Card
        title="Finding"
        action={
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={() => { setDraft(EMPTY); setSaved(false); }}>
              Reset
            </Button>
            <Button size="sm" variant="primary" onClick={() => setSaved(true)}>
              {saved ? 'Draft saved' : 'Draft autosaves'}
            </Button>
          </div>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <TextInput label="Title" value={draft.title} onChange={(v) => set('title', v)} />
          <Select<Severity> label="Severity" value={draft.severity} onChange={(v) => set('severity', v)} options={SEVERITIES} />
          <TextInput
            label="CVSS v3.1 vector"
            value={draft.vector}
            onChange={(v) => set('vector', v)}
            mono
            hint={cvss ? `${cvss.score.toFixed(1)} — ${cvss.band.label}` : 'Unparsable vector — check the metric keys and values'}
          />
          <TextInput label="Asset" value={draft.asset} onChange={(v) => set('asset', v)} mono />
          <TextInput label="Category / reference" value={draft.category} onChange={(v) => set('category', v)} />
          <TextInput label="Affected users / scope" value={draft.affected} onChange={(v) => set('affected', v)} />
        </div>
        <div className="mt-3 grid gap-3">
          <TextArea label="Description" value={draft.description} onChange={(v) => set('description', v)} rows={3} />
          <TextArea label="Impact" value={draft.impact} onChange={(v) => set('impact', v)} rows={3} />
          <TextArea label="Evidence — reproduction steps" value={draft.steps} onChange={(v) => set('steps', v)} rows={4} />
          <div className="grid gap-3 sm:grid-cols-2">
            <TextArea label="Request" value={draft.request} onChange={(v) => set('request', v)} rows={5} />
            <TextArea label="Response" value={draft.response} onChange={(v) => set('response', v)} rows={5} />
          </div>
          <TextArea label="Remediation" value={draft.remediation} onChange={(v) => set('remediation', v)} rows={3} />
          <TextArea label="References" value={draft.references} onChange={(v) => set('references', v)} rows={2} />
        </div>
        {cvss && draft.severity !== 'Info' && severityMismatch(draft.severity, cvss.band.label) && (
          <div className="mt-3">
            <Callout tone="warn" title="Severity and vector disagree">
              The vector computes to <strong>{cvss.score.toFixed(1)} ({cvss.band.label})</strong> but the severity field
              says {draft.severity}. Client triage will pick the lower of the two — align them before submitting.
            </Callout>
          </div>
        )}
      </Card>

      <Card
        title="Report output"
        action={<DownloadButton text={markdown} filename={`${slug(draft.title) || 'finding'}.md`} label="Download .md" />}
      >
        <CodeBlock code={markdown} label="finding.md" maxHeight={420} />
      </Card>

      <Card title="Submission check">
        <KVTable
          rows={[
            ['Severity', `${draft.severity}${cvss ? ` · vector says ${cvss.score.toFixed(1)}` : ''}`],
            ['Reproduction steps', draft.steps.trim().split('\n').filter(Boolean).length ? `${draft.steps.trim().split('\n').filter(Boolean).length} step(s)` : 'MISSING'],
            ['Request/response captured', draft.request.trim() && draft.response.trim() ? 'Yes' : 'MISSING'],
            ['Remediation actionable', draft.remediation.trim().length > 40 ? 'Yes' : 'Too short to action'],
            ['Affected population stated', draft.affected.trim() ? 'Yes' : 'MISSING'],
            ['Draft storage', 'redforge:finding-draft (localStorage)'],
          ]}
        />
        <div className="mt-3">
          <Callout tone="info" title="Draft persistence">
            The form autosaves to this browser only. Nothing leaves the page — no upload, no API call — so a refresh
            during a live test will not lose the write-up.
          </Callout>
        </div>
      </Card>
    </>
  );
}

function severityMismatch(picked: Severity, computed: string): boolean {
  return picked.toLowerCase() !== computed.toLowerCase();
}

function slug(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 60);
}

function renderFinding(d: Draft, cvss: { score: number; band: { label: string } } | null): string {
  const lines = [
    `# ${d.title || 'Untitled finding'}`,
    '',
    '| Field | Value |',
    '| --- | --- |',
    `| Severity | **${d.severity}** |`,
    `| CVSS v3.1 | ${d.vector || '—'}${cvss ? ` (${cvss.score.toFixed(1)})` : ''} |`,
    `| Asset | ${d.asset || '—'} |`,
    `| Category | ${d.category || '—'} |`,
    `| Affected scope | ${d.affected || '—'} |`,
    '',
    '## Description',
    '',
    d.description.trim() || '_Not written yet._',
    '',
    '## Impact',
    '',
    d.impact.trim() || '_Not written yet._',
    '',
    '## Evidence',
    '',
    '### Reproduction',
    '',
    fence(d.steps, 'text'),
    '',
    '### Request',
    '',
    fence(d.request, 'http'),
    '',
    '### Response',
    '',
    fence(d.response, 'http'),
    '',
    '## Remediation',
    '',
    d.remediation.trim() || '_Not written yet._',
    '',
    '## References',
    '',
    ...(d.references.trim()
      ? d.references
          .split('\n')
          .map((r) => r.trim())
          .filter(Boolean)
          .map((r) => `- ${r}`)
      : ['_None supplied._']),
    '',
    '---',
    '',
    '_Base CVSS only. Temporal and environmental metrics were not applied; re-score against the client environment before prioritisation._',
  ];
  return lines.join('\n');
}

function fence(body: string, lang: string): string {
  const trimmed = body.trim();
  if (!trimmed) return '_Not captured._';
  return ['```' + lang, trimmed, '```'].join('\n');
}
