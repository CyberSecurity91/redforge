import { useMemo, useState } from 'react';
import {
  Button,
  Checkbox,
  Callout,
  Card,
  CodeBlock,
  DownloadButton,
  NumberInput,
  OutputField,
  SectionTitle,
  Select,
  TextInput,
} from '@/components/ui';
import { useLocalStorage } from '@/lib/hooks';

/**
 * Attack narrative builder. Rows are the engagement story in time order; the
 * tool validates MITRE technique IDs against a local table, flags rows that
 * cannot be evidenced, attributes elapsed time to phases, and exports a
 * Markdown report plus a mermaid gantt block.
 */

type Phase = 'recon' | 'access' | 'exec' | 'lateral' | 'impact' | 'cleanup';

const PHASES: Array<{ value: Phase; label: string; tint: string }> = [
  { value: 'recon', label: 'Recon', tint: 'var(--info)' },
  { value: 'access', label: 'Access', tint: 'var(--warn)' },
  { value: 'exec', label: 'Execution', tint: 'var(--accent)' },
  { value: 'lateral', label: 'Lateral', tint: '#a855f7' },
  { value: 'impact', label: 'Impact', tint: '#e11d48' },
  { value: 'cleanup', label: 'Cleanup', tint: 'var(--ok)' },
];

/** ~40 real ATT&CK technique IDs, Enterprise matrix, as of v15. */
const TECHNIQUES: Array<[string, string]> = [
  ['T1003', 'OS Credential Dumping'],
  ['T1003.001', 'LSASS Memory'],
  ['T1003.003', 'NTDS'],
  ['T1021.001', 'Remote Services: RDP'],
  ['T1021.002', 'Remote Services: SMB/Windows Admin Shares'],
  ['T1021.004', 'Remote Services: SSH'],
  ['T1046', 'Network Service Discovery'],
  ['T1048', 'Exfiltration Over Alternative Protocol'],
  ['T1053.005', 'Scheduled Task/Job'],
  ['T1059.001', 'PowerShell'],
  ['T1059.003', 'Windows Command Shell'],
  ['T1068', 'Exploitation for Privilege Escalation'],
  ['T1071.001', 'Web Protocols'],
  ['T1078', 'Valid Accounts'],
  ['T1087.002', 'Domain Account Discovery'],
  ['T1090', 'Proxy'],
  ['T1105', 'Ingress Tool Transfer'],
  ['T1110.003', 'Brute Force: Password Spraying'],
  ['T1133', 'External Remote Services'],
  ['T1134', 'Access Token Manipulation'],
  ['T1190', 'Exploit Public-Facing Application'],
  ['T1203', 'Exploitation for Client Execution'],
  ['T1210', 'Exploitation of Remote Services'],
  ['T1486', 'Data Encrypted for Impact'],
  ['T1505.003', 'Web Shell'],
  ['T1543.003', 'Windows Service'],
  ['T1547.001', 'Registry Run Keys'],
  ['T1548.002', 'Bypass User Account Control'],
  ['T1550.002', 'Pass the Hash'],
  ['T1550.003', 'Pass the Ticket'],
  ['T1552.001', 'Credentials In Files'],
  ['T1555.003', 'Credentials from Web Browsers'],
  ['T1558.003', 'Kerberoasting'],
  ['T1562.001', 'Impair Defenses: Disable or Modify Tools'],
  ['T1567.002', 'Exfiltration to Cloud Storage'],
  ['T1569.002', 'Service Execution'],
  ['T1570', 'Lateral Tool Transfer'],
  ['T1583.001', 'Acquire Infrastructure: Domains'],
  ['T1589.002', 'Gather Victim Identity Information: Email Addresses'],
  ['T1595.002', 'Active Scanning: Vulnerability Scanning'],
  ['T1566.001', 'Phishing: Spearphishing Attachment'],
  ['T1598.003', 'Phishing for Information'],
];

interface Row {
  id: string;
  time: string;
  phase: Phase;
  host: string;
  action: string;
  evidence: string;
  technique: string;
}

const SEED: Row[] = [
  { id: 'r1', time: '2026-03-02 09:10', phase: 'recon', host: 'ext', action: 'Subdomain enumeration on example.com', evidence: 'EV-01', technique: 'T1595.002' },
  { id: 'r2', time: '2026-03-02 11:40', phase: 'recon', host: 'ext', action: 'Vulnerable build fingerprinted on VPN portal', evidence: 'EV-02', technique: 'T1595.002' },
  { id: 'r3', time: '2026-03-02 14:05', phase: 'access', host: 'vpn.example.com', action: 'Public-facing application exploited for initial foothold', evidence: 'EV-03', technique: 'T1190' },
  { id: 'r4', time: '2026-03-02 14:22', phase: 'exec', host: 'ws-0142', action: 'PowerShell cradle staged from 10.10.14.7', evidence: 'EV-04', technique: 'T1059.001' },
  { id: 'r5', time: '2026-03-02 15:02', phase: 'lateral', host: 'fs01', action: 'SMB admin share used with recovered local admin hash', evidence: 'EV-05', technique: 'T1021.002' },
  { id: 'r6', time: '2026-03-03 09:31', phase: 'impact', host: 'dc01', action: 'Domain admin access proven by non-destructive read of NTDS metadata', evidence: '', technique: 'T1003.003' },
];

const fmtDur = (ms: number): string => {
  if (!Number.isFinite(ms) || ms <= 0) return '0m';
  const m = Math.round(ms / 60000);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
};

const toMs = (t: string): number | null => {
  const s = t.trim().replace(' ', 'T');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(s)) return null;
  const ms = Date.parse(`${s.length === 16 ? `${s}:00` : s}`);
  return Number.isFinite(ms) ? ms : null;
};

export default function AttackNarrativeTimeline() {
  const [rows, setRows] = useLocalStorage<Row[]>('attack-narrative', SEED);
  const [title, setTitle] = useState('Engagement narrative — example.com');
  const [strictEvidence, setStrictEvidence] = useState(true);
  const [draft, setDraft] = useState<Row>({ id: '', time: '', phase: 'recon', host: '', action: '', evidence: '', technique: '' });

  const table = useMemo(() => new Map(TECHNIQUES.map(([id, name]) => [id, name])), []);

  const parsed = useMemo(() => {
    const withMs = rows.map((r, i) => ({ row: r, i, ms: toMs(r.time) }));
    const sorted = [...withMs].sort((a, b) => (a.ms ?? Number.MAX_SAFE_INTEGER) - (b.ms ?? Number.MAX_SAFE_INTEGER));
    return sorted.map((p, idx) => ({
      ...p,
      order: idx + 1,
      name: table.get(p.row.technique.trim().toUpperCase()) ?? null,
      valid: table.has(p.row.technique.trim().toUpperCase()),
      blanks: !p.row.evidence.trim() || !p.row.host.trim() || !p.row.action.trim() || !p.row.technique.trim(),
    }));
  }, [rows, table]);

  const durations = useMemo(() => {
    const map = new Map<Phase, number>();
    let total = 0;
    for (let i = 0; i < parsed.length; i++) {
      const cur = parsed[i];
      const next = parsed[i + 1];
      const start = cur?.ms;
      const end = next?.ms;
      if (start === null || start === undefined || end === null || end === undefined) continue;
      const delta = Math.max(0, end - start);
      map.set(cur.row.phase, (map.get(cur.row.phase) ?? 0) + delta);
      total += delta;
    }
    return { map, total };
  }, [parsed]);

  const alerts = useMemo(
    () => ({
      noEvidence: parsed.filter((p) => !p.row.evidence.trim()).length,
      badTechnique: parsed.filter((p) => p.row.technique.trim() && !p.valid).length,
      badTime: parsed.filter((p) => p.ms === null).length,
      blanks: parsed.filter((p) => p.blanks).length,
    }),
    [parsed],
  );

  const markdown = useMemo(() => {
    const lines: string[] = [`# ${title}`, '', `**Rows:** ${parsed.length} · **Span:** ${fmtDur(durations.total)} · **Techniques:** ${new Set(parsed.map((p) => p.row.technique)).size}`, '', '## Timeline', '', '| # | Time | Phase | Host | Action | Evidence | ATT&CK |', '| --- | --- | --- | --- | --- | --- | --- |'];
    for (const p of parsed) {
      const t = p.row.technique.trim().toUpperCase();
      const label = p.name ? `${t} — ${p.name}` : t || '—';
      const ev = p.row.evidence.trim() || '**MISSING**';
      lines.push(`| ${p.order} | ${p.row.time || '—'} | ${p.row.phase} | ${p.row.host || '—'} | ${p.row.action.replace(/\|/g, '\\|') || '—'} | ${ev} | ${label} |`);
    }
    lines.push('', '## Phase durations', '', '| Phase | Elapsed |', '| --- | --- |');
    for (const ph of PHASES) lines.push(`| ${ph.label} | ${fmtDur(durations.map.get(ph.value) ?? 0)} |`);
    lines.push(`| **Total** | **${fmtDur(durations.total)}** |`, '', '## Mermaid', '', '```mermaid', mermaidFor(parsed), '```', '');
    if (alerts.noEvidence || alerts.badTechnique) {
      lines.push('## Outstanding gaps', '');
      if (alerts.noEvidence) lines.push(`- ${alerts.noEvidence} row(s) have no evidence reference.`);
      if (alerts.badTechnique) lines.push(`- ${alerts.badTechnique} row(s) carry a technique ID that is not in the ATT&CK table.`);
      lines.push('');
    }
    return lines.join('\n');
  }, [title, parsed, durations, alerts]);

  const mermaid = useMemo(() => mermaidFor(parsed), [parsed]);

  const add = () => {
    const id = `r${Date.now().toString(36)}`;
    setRows([...rows, { ...draft, id, action: draft.action || 'Untitled step' }]);
    setDraft({ id: '', time: '', phase: 'recon', host: '', action: '', evidence: '', technique: '' });
  };

  const remove = (id: string) => setRows(rows.filter((r) => r.id !== id));

  const move = (id: string) => {
    // Reorder against the sorted view so the arrows match what the operator sees.
    const idx = parsed.findIndex((p) => p.row.id === id);
    const prev = parsed[idx - 1];
    if (idx <= 0 || !prev) return;
    const swapped = rows.map((r) => (r.id === id ? { ...r, time: prev.row.time } : r.id === prev.row.id ? { ...r, time: rows.find((x) => x.id === id)?.time ?? '' } : r));
    setRows(swapped);
  };

  const patchDraft = <K extends keyof Row>(k: K, v: Row[K]) => setDraft({ ...draft, [k]: v });

  return (
    <>
      <Card
        title="Narrative settings"
        action={<DownloadButton text={markdown} filename="attack-narrative.md" label="Download .md" />}
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput label="Report title" value={title} onChange={setTitle} />
          <NumberInput label="Rows" value={rows.length} onChange={() => undefined} min={0} hint="Managed in the editor below" />
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <Checkbox checked={strictEvidence} onChange={setStrictEvidence} label="Treat missing evidence as blocking" description="Rows without an evidence ref are marked MISSING in the export." />
          <div className="flex items-end">
            <Callout tone={alerts.noEvidence ? 'warn' : 'ok'} title={alerts.noEvidence ? `${alerts.noEvidence} row(s) without evidence` : 'Every row is evidenced'}>
              {alerts.noEvidence
                ? 'An unevidenced step is a claim, not a finding. Attach a screenshot ref, a log excerpt or a capture ID.'
                : 'All rows carry an evidence reference; the export will not carry unresolved claims.'}
            </Callout>
          </div>
        </div>
      </Card>

      <Card title="Timeline rows">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr className="text-left text-[11px] tracking-wide text-[var(--text-faint)] uppercase">
                <th className="py-1 pr-2 font-medium">#</th>
                <th className="py-1 pr-2 font-medium">Time</th>
                <th className="py-1 pr-2 font-medium">Phase</th>
                <th className="py-1 pr-2 font-medium">Host</th>
                <th className="py-1 pr-2 font-medium">Action</th>
                <th className="py-1 pr-2 font-medium">Evidence</th>
                <th className="py-1 pr-2 font-medium">ATT&CK</th>
                <th className="py-1 font-medium"> </th>
              </tr>
            </thead>
            <tbody>
              {parsed.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-6 text-center text-[12.5px] text-[var(--text-faint)]">
                    No rows yet — add the first step below. Times sort as you type.
                  </td>
                </tr>
              )}
              {parsed.map((p) => {
                const tint = PHASES.find((ph) => ph.value === p.row.phase)?.tint ?? 'var(--text-muted)';
                return (
                  <tr key={p.row.id} className="border-t border-[var(--card-border)] align-top">
                    <td className="py-1 pr-2 text-[var(--text-faint)]">{p.order}</td>
                    <td className="rf-mono py-1 pr-2 whitespace-nowrap text-[var(--text-muted)]">{p.row.time || '—'}</td>
                    <td className="py-1 pr-2">
                      <span className="rounded px-1.5 py-0.5 text-[10.5px] font-medium" style={{ color: tint, border: `1px solid ${tint}` }}>
                        {p.row.phase}
                      </span>
                    </td>
                    <td className="rf-mono py-1 pr-2 text-[var(--text)]">{p.row.host || '—'}</td>
                    <td className="py-1 pr-2 text-[var(--text-muted)]">{p.row.action || '—'}</td>
                    <td className="rf-mono py-1 pr-2" style={{ color: p.row.evidence ? 'var(--text-muted)' : 'var(--warn)' }}>
                      {p.row.evidence || 'MISSING'}
                    </td>
                    <td className="py-1 pr-2">
                      <span className="rf-mono" style={{ color: p.valid ? 'var(--text)' : 'var(--accent)' }}>
                        {p.row.technique || '—'}
                      </span>
                      {p.name && <div className="text-[10.5px] text-[var(--text-faint)]">{p.name}</div>}
                      {!p.valid && p.row.technique && <div className="text-[10.5px] text-[var(--accent)]">unknown ID</div>}
                    </td>
                    <td className="py-1">
                      <div className="flex items-center justify-end gap-1">
                        <button type="button" title="Move up" onClick={() => move(p.row.id)} className="px-1 text-[var(--text-faint)] hover:text-[var(--accent)]">
                          ↑
                        </button>
                        <button type="button" title="Delete row" onClick={() => remove(p.row.id)} className="px-1 text-[var(--text-faint)] hover:text-[var(--accent)]">
                          ×
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Add a row">
        <div className="grid gap-3 sm:grid-cols-3">
          <TextInput label="Time" value={draft.time} onChange={(v) => patchDraft('time', v)} mono placeholder="2026-03-03 10:00" hint="YYYY-MM-DD HH:MM" />
          <Select<Phase> label="Phase" value={draft.phase} onChange={(v) => patchDraft('phase', v)} options={PHASES.map((p) => ({ value: p.value, label: p.label }))} />
          <TextInput label="Host" value={draft.host} onChange={(v) => patchDraft('host', v)} mono placeholder="ws-0142" />
          <TextInput label="Action" value={draft.action} onChange={(v) => patchDraft('action', v)} placeholder="What the operator did" className="sm:col-span-2" />
          <TextInput label="Evidence ref" value={draft.evidence} onChange={(v) => patchDraft('evidence', v)} mono placeholder="EV-07" />
          <TextInput label="ATT&CK technique" value={draft.technique} onChange={(v) => patchDraft('technique', v)} mono placeholder="T1021.002" hint={table.get(draft.technique.trim().toUpperCase()) ?? 'not in the local table'} />
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Button size="sm" variant="outline" onClick={add}>Append row</Button>
          <Button size="sm" variant="ghost" onClick={() => setRows(SEED)}>Reset to the worked example</Button>
          <span className="text-[11.5px] text-[var(--text-faint)]">Saved locally under redforge:attack-narrative</span>
        </div>
      </Card>

      <Card title="Phases and validation">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <SectionTitle>Phase durations</SectionTitle>
            <div className="space-y-1">
              {PHASES.map((ph) => {
                const d = durations.map.get(ph.value) ?? 0;
                const pct = durations.total ? Math.round((d / durations.total) * 100) : 0;
                return (
                  <div key={ph.value} className="flex items-center gap-2 text-[12px]">
                    <span className="w-20 shrink-0 text-[var(--text-muted)]">{ph.label}</span>
                    <div className="h-1.5 flex-1 overflow-hidden rounded bg-[var(--neutral-btn)]">
                      <div className="h-full rounded" style={{ width: `${pct}%`, background: ph.tint }} />
                    </div>
                    <span className="rf-mono w-12 shrink-0 text-right text-[var(--text-faint)]">{fmtDur(d)}</span>
                  </div>
                );
              })}
            </div>
            <div className="mt-2 text-[11.5px] text-[var(--text-faint)]">Total elapsed: {fmtDur(durations.total)}</div>
          </div>
          <div>
            <SectionTitle>Validation</SectionTitle>
            <div className="grid grid-cols-2 gap-2">
              <OutputField label="Rows missing evidence" value={String(alerts.noEvidence)} />
              <OutputField label="Unknown technique IDs" value={String(alerts.badTechnique)} />
              <OutputField label="Unparseable times" value={String(alerts.badTime)} />
              <OutputField label="Incomplete rows" value={String(alerts.blanks)} />
            </div>
            {strictEvidence && alerts.noEvidence > 0 && (
              <div className="mt-3">
                <Callout tone="danger" title="Blocking under the current setting">
                  {alerts.noEvidence} row(s) will export with MISSING in the evidence column. Either evidence them or
                  drop them from the narrative — a claim without a reference is what gets a finding rejected.
                </Callout>
              </div>
            )}
          </div>
        </div>
      </Card>

      <Card title="Export">
        <SectionTitle>Mermaid gantt</SectionTitle>
        <CodeBlock code={mermaid} label="mermaid" maxHeight={260} />
        <div className="mt-4">
          <SectionTitle>Markdown report</SectionTitle>
          <CodeBlock code={markdown} label="attack-narrative.md" maxHeight={320} />
        </div>
      </Card>
    </>
  );
}

function mermaidFor(parsed: Array<{ row: Row; ms: number | null }>): string {
  const lines = ['gantt', '  dateFormat  YYYY-MM-DD HH:mm', '  axisFormat  %d %b %H:%M', '  title Engagement narrative'];
  for (const ph of PHASES) {
    const inPhase = parsed.filter((p) => p.row.phase === ph.value && p.ms !== null);
    if (!inPhase.length) continue;
    lines.push(`  section ${ph.label}`);
    inPhase.forEach((p) => {
      const label = p.row.technique ? `${p.row.technique} ${p.row.host}` : p.row.host || p.row.action.slice(0, 24);
      lines.push(`  ${p.row.action.slice(0, 40).replace(/[:#]/g, ' ')} :${p.row.time.replace(' ', 'T').slice(0, 16)}, 1m`);
      lines.push(`  %% ${label}`);
    });
  }
  return lines.join('\n');
}
