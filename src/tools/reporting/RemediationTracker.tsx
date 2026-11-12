import { useMemo, useState } from 'react';
import { Pencil, Trash2 } from 'lucide-react';
import {
  Button,
  Callout,
  Card,
  DownloadButton,
  IconButton,
  KVTable,
  NumberInput,
  OutputBlock,
  Select,
  TextInput,
} from '@/components/ui';
import { useLocalStorage } from '@/lib/hooks';

/**
 * Findings tracker with a live SLA clock. The due date is never typed in: it is the
 * discovery date plus the severity's SLA, both visible and editable, so the board can be
 * re-baselined when a client changes policy mid-engagement.
 */

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
type Status = 'open' | 'in-progress' | 'fixed' | 'risk-accepted';

interface Finding {
  id: string;
  title: string;
  severity: Severity;
  owner: string;
  discovered: string;
  status: Status;
}

interface TrackRow extends Finding {
  slaDays: number;
  due: string;
  dueMs: number;
  days: number | null;
  overdue: boolean;
}

const DAY = 86_400_000;

const SEVERITIES: Array<{ value: Severity; label: string }> = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Informational' },
];

const STATUSES: Array<{ value: Status; label: string }> = [
  { value: 'open', label: 'Open' },
  { value: 'in-progress', label: 'In progress' },
  { value: 'fixed', label: 'Fixed' },
  { value: 'risk-accepted', label: 'Risk accepted' },
];

const DEFAULT_SLA: Record<Severity, number> = { critical: 3, high: 7, medium: 30, low: 90, info: 180 };
const SEVERITY_FILTER_OPTIONS: Array<{ value: 'all' | Severity; label: string }> = [
  { value: 'all', label: 'All severities' },
  ...SEVERITIES,
];
const STATUS_FILTER_OPTIONS: Array<{ value: 'all' | Status; label: string }> = [
  { value: 'all', label: 'All statuses' },
  ...STATUSES,
];
const SORT_OPTIONS: Array<{ value: 'due' | 'discovered'; label: string }> = [
  { value: 'due', label: 'Due date — soonest first' },
  { value: 'discovered', label: 'Discovered — oldest first' },
];
const COLUMNS = ['ID', 'Finding', 'Severity', 'Owner', 'Discovered', 'SLA', 'Due', 'Status', 'Clock', ''];

const SEED: Finding[] = [
  { id: 'RF-001', title: 'Reflected XSS in the support ticket search', severity: 'high', owner: 'A. Whitfield', discovered: '2026-10-28', status: 'in-progress' },
  { id: 'RF-002', title: 'Anonymous LDAP bind on the legacy directory', severity: 'critical', owner: 'M. Okonkwo', discovered: '2026-11-01', status: 'open' },
  { id: 'RF-003', title: 'Bucket listing on the marketing assets origin', severity: 'medium', owner: 'J. Fairbairn', discovered: '2026-10-05', status: 'fixed' },
  { id: 'RF-004', title: 'TLS 1.0 still offered on the payments gateway', severity: 'low', owner: 'S. Ellery', discovered: '2026-09-18', status: 'risk-accepted' },
];

const SEVERITY_COLOUR: Record<Severity, string> = { critical: 'var(--accent)', high: 'var(--warn)', medium: 'var(--info)', low: 'var(--text-muted)', info: 'var(--text-faint)' };
const STATUS_COLOUR: Record<Status, string> = { open: 'var(--accent)', 'in-progress': 'var(--warn)', fixed: 'var(--ok)', 'risk-accepted': 'var(--info)' };

export default function RemediationTracker() {
  const [rows, setRows] = useLocalStorage<Finding[]>('remediation-rows', SEED);
  const [sla, setSla] = useLocalStorage<Record<Severity, number>>('remediation-sla', DEFAULT_SLA);
  const [asOf, setAsOf] = useState(todayISO());

  const [editingId, setEditingId] = useState<string | null>(null);
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState<Severity>('high');
  const [owner, setOwner] = useState('');
  const [discovered, setDiscovered] = useState(todayISO());
  const [status, setStatus] = useState<Status>('open');

  const [statusFilter, setStatusFilter] = useState<'all' | Status>('all');
  const [severityFilter, setSeverityFilter] = useState<'all' | Severity>('all');
  const [sortBy, setSortBy] = useState<'due' | 'discovered'>('due');

  const asOfMs = useMemo(() => {
    const ms = Date.parse(`${asOf}T00:00:00Z`);
    return Number.isFinite(ms) ? ms : Date.now();
  }, [asOf]);

  const track = useMemo<TrackRow[]>(() => {
    return rows
      .map((f) => {
        const slaDays = Math.max(0, sla[f.severity] ?? 0);
        const start = Date.parse(`${f.discovered}T00:00:00Z`);
        const dueMs = Number.isFinite(start) ? start + slaDays * DAY : null;
        const days = dueMs === null ? null : Math.round((dueMs - asOfMs) / DAY);
        return {
          ...f,
          slaDays,
          due: dueMs === null ? '—' : isoFromMs(dueMs),
          dueMs: dueMs ?? Number.POSITIVE_INFINITY,
          days,
          overdue: days !== null && days < 0 && (f.status === 'open' || f.status === 'in-progress'),
        };
      })
      .sort((a, b) =>
        sortBy === 'due' ? a.dueMs - b.dueMs : a.discovered.localeCompare(b.discovered) || a.id.localeCompare(b.id),
      );
  }, [rows, sla, asOfMs, sortBy]);

  const visible = useMemo(
    () =>
      track.filter(
        (r) =>
          (statusFilter === 'all' || r.status === statusFilter) &&
          (severityFilter === 'all' || r.severity === severityFilter),
      ),
    [track, statusFilter, severityFilter],
  );

  const counts = useMemo(() => {
    const base: Record<Status, number> = { open: 0, 'in-progress': 0, fixed: 0, 'risk-accepted': 0 };
    for (const r of track) base[r.status] += 1;
    return base;
  }, [track]);

  const overdue = track.filter((r) => r.overdue).length;

  const csv = useMemo(() => {
    const header = ['id', 'title', 'severity', 'owner', 'discovered', 'sla_days', 'due', 'status', 'days_remaining'];
    const lines = track.map((r) =>
      [
        r.id, csvCell(r.title), r.severity, csvCell(r.owner), r.discovered, String(r.slaDays), r.due, r.status,
        r.status === 'fixed' || r.status === 'risk-accepted' ? 'closed' : r.days === null ? 'unknown' : String(r.days),
      ].join(','),
    );
    return [header.join(','), ...lines].join('\n');
  }, [track]);

  const resetForm = () => {
    setEditingId(null);
    setTitle('');
    setOwner('');
  };

  const submit = () => {
    const clean = title.trim();
    if (!clean) return;
    const named = owner.trim() || 'unassigned';
    if (editingId) {
      setRows((prev) =>
        prev.map((f) => (f.id === editingId ? { ...f, title: clean, severity, owner: named, discovered, status } : f)),
      );
    } else {
      setRows((prev) => [...prev, { id: nextId(prev), title: clean, severity, owner: named, discovered, status }]);
    }
    resetForm();
  };

  const startEdit = (f: TrackRow) => {
    setEditingId(f.id);
    setTitle(f.title);
    setSeverity(f.severity);
    setOwner(f.owner);
    setDiscovered(f.discovered);
    setStatus(f.status);
  };

  const remove = (id: string) => {
    setRows((prev) => prev.filter((f) => f.id !== id));
    if (editingId === id) setEditingId(null);
  };

  return (
    <>
      <Card
        title={editingId ? `Edit ${editingId}` : 'Add finding'}
        action={editingId ? <Button size="sm" variant="ghost" onClick={resetForm}>Cancel edit</Button> : undefined}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <TextInput label="Title" value={title} onChange={setTitle} placeholder="Unauthenticated API exposes invoice PDFs" />
          <Select<Severity> label="Severity" value={severity} onChange={setSeverity} options={SEVERITIES} hint={`SLA ${sla[severity]} d`} />
          <TextInput label="Owner" value={owner} onChange={setOwner} placeholder="unassigned" />
          <TextInput label="Discovered" value={discovered} onChange={setDiscovered} type="date" mono />
          <Select<Status> label="Status" value={status} onChange={setStatus} options={STATUSES} />
          <div className="flex items-end pb-1">
            <Button variant="primary" size="sm" onClick={submit} disabled={!title.trim()}>
              {editingId ? 'Save changes' : 'Add to tracker'}
            </Button>
          </div>
        </div>
        <div className="mt-3">
          <Callout tone="info" title="Due date is derived">
            Due date = discovered + the severity's SLA days. Change the SLA table below and every open row re-clocks
            immediately — the point of a live table rather than a clause in a policy PDF.
          </Callout>
        </div>
      </Card>

      <Card title="SLA clock">
        <div className="grid gap-3 sm:grid-cols-3">
          {SEVERITIES.map((s) => (
            <NumberInput
              key={s.value}
              label={`${s.label} — days`}
              value={sla[s.value]}
              onChange={(v) => setSla((prev) => ({ ...prev, [s.value]: Math.max(0, v) }))}
              min={0}
              max={365}
            />
          ))}
          <TextInput label="As of" value={asOf} onChange={setAsOf} type="date" mono hint="day counter reference" />
        </div>
        <div className="mt-4">
          <KVTable
            rows={[
              ['Open', String(counts.open)],
              ['In progress', String(counts['in-progress'])],
              ['Fixed', String(counts.fixed)],
              ['Risk accepted', String(counts['risk-accepted'])],
              ['Overdue (open and in progress)', `${overdue} of ${track.length}`],
            ]}
          />
        </div>
      </Card>

      <Card
        title="Tracker"
        action={
          <span className="flex items-center gap-2">
            <Chip label={overdue ? `${overdue} overdue` : 'nothing overdue'} colour={overdue ? 'var(--accent)' : 'var(--ok)'} />
            <DownloadButton text={csv} filename="remediation-tracker.csv" label="Export CSV" />
          </span>
        }
      >
        <div className="grid gap-3 sm:grid-cols-3">
          <Select<'all' | Status> label="Status filter" value={statusFilter} onChange={setStatusFilter} options={STATUS_FILTER_OPTIONS} />
          <Select<'all' | Severity> label="Severity filter" value={severityFilter} onChange={setSeverityFilter} options={SEVERITY_FILTER_OPTIONS} />
          <Select<'due' | 'discovered'> label="Sort" value={sortBy} onChange={setSortBy} options={SORT_OPTIONS} />
        </div>

        <div className="mt-4 overflow-x-auto">
          {visible.length === 0 ? (
            <div className="rounded border border-dashed border-[var(--card-border)] px-3 py-8 text-center text-[12.5px] text-[var(--text-faint)]">
              No findings match these filters. Clear the status or severity filter, or add a row above.
            </div>
          ) : (
            <table className="w-full border-collapse text-[12px]">
              <thead>
                <tr className="text-left text-[11px] tracking-wide text-[var(--text-faint)] uppercase">
                  {COLUMNS.map((c) => (
                    <th key={c} className="py-1 pr-3 font-medium whitespace-nowrap">{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visible.map((r) => (
                  <tr key={r.id} className="border-t border-[var(--card-border)] align-top">
                    <td className="rf-mono py-1.5 pr-3 whitespace-nowrap text-[var(--text-faint)]">{r.id}</td>
                    <td className="py-1.5 pr-3">{r.title}</td>
                    <td className="py-1.5 pr-3 whitespace-nowrap"><Chip label={r.severity} colour={SEVERITY_COLOUR[r.severity]} /></td>
                    <td className="py-1.5 pr-3 whitespace-nowrap text-[var(--text-muted)]">{r.owner}</td>
                    <td className="rf-mono py-1.5 pr-3 whitespace-nowrap text-[var(--text-muted)]">{r.discovered}</td>
                    <td className="rf-mono py-1.5 pr-3 whitespace-nowrap text-[var(--text-muted)]">{r.slaDays}d</td>
                    <td className="rf-mono py-1.5 pr-3 whitespace-nowrap text-[var(--text-muted)]">{r.due}</td>
                    <td className="py-1.5 pr-3 whitespace-nowrap"><Chip label={r.status} colour={STATUS_COLOUR[r.status]} /></td>
                    <td className="rf-mono py-1.5 pr-3 whitespace-nowrap"><Clock row={r} /></td>
                    <td className="py-1.5 whitespace-nowrap">
                      <IconButton title={`Edit ${r.id}`} onClick={() => startEdit(r)}><Pencil size={13} /></IconButton>
                      <IconButton title={`Delete ${r.id}`} onClick={() => remove(r.id)}><Trash2 size={13} /></IconButton>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Card>

      <Card title="CSV export">
        <OutputBlock value={csv} label="remediation-tracker.csv" rows={10} />
        <div className="mt-3">
          <Callout tone="info" title="What the export contains">
            Rows leave in the current sort order but ignore the on-screen filters, so the client receives the whole
            board. Closed rows carry <span className="rf-mono">closed</span> in the clock column rather than a stale
            negative count.
          </Callout>
        </div>
      </Card>
    </>
  );
}

function Clock({ row }: { row: TrackRow }) {
  if (row.status === 'fixed' || row.status === 'risk-accepted' || row.days === null) {
    return <span className="text-[var(--text-faint)]">closed</span>;
  }
  if (row.overdue) {
    return <span style={{ color: 'var(--accent)' }}>{Math.abs(row.days)}d over</span>;
  }
  return <span style={{ color: row.days <= 3 ? 'var(--warn)' : 'var(--text-muted)' }}>{row.days}d left</span>;
}

function Chip({ label, colour }: { label: string; colour: string }) {
  return (
    <span
      className="rounded-full px-2 py-[1px] text-[10.5px] font-medium"
      style={{ backgroundColor: 'var(--neutral-btn)', color: colour }}
    >
      {label}
    </span>
  );
}

function nextId(rows: Finding[]): string {
  const max = rows.reduce((n, r) => {
    const m = /(\d+)$/.exec(r.id);
    return m ? Math.max(n, Number(m[1])) : n;
  }, 0);
  return `RF-${String(max + 1).padStart(3, '0')}`;
}

function todayISO(): string {
  return new Date().toISOString().slice(0, 10);
}

function isoFromMs(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

function csvCell(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}
