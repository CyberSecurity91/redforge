import { useMemo, useState } from 'react';
import {
  Button,
  Callout,
  Card,
  CodeBlock,
  DownloadButton,
  KVTable,
  Select,
  Tabs,
  TextArea,
  TextInput,
} from '@/components/ui';
import { useLocalStorage } from '@/lib/hooks';
import { DEFAULT_CALLBACK_HOST, DEFAULT_TARGET } from '@/tools/registry';

/**
 * Operator log persisted to localStorage. Entries are append-only in spirit:
 * deletion is possible but the export records what was removed in this session.
 */

type Phase = 'recon' | 'exploit' | 'post' | 'report';

interface Entry {
  id: string;
  at: string;
  phase: Phase;
  host: string;
  note: string;
  tags: string[];
}

const PHASES: Array<{ value: Phase; label: string }> = [
  { value: 'recon', label: 'Recon' },
  { value: 'exploit', label: 'Exploit' },
  { value: 'post', label: 'Post-exploitation' },
  { value: 'report', label: 'Report' },
];

const PHASE_COLOUR: Record<Phase, string> = {
  recon: 'var(--info, var(--accent))',
  exploit: 'var(--warn)',
  post: 'var(--danger, var(--accent))',
  report: 'var(--ok)',
};

const SEED: Entry[] = [
  {
    id: 'seed-1',
    at: localNow(),
    phase: 'recon',
    host: DEFAULT_TARGET,
    note: 'Subdomain sweep returned 14 hosts; three expose a staging banner with a version string 18 months behind the main site.',
    tags: ['subdomains', 'staging'],
  },
  {
    id: 'seed-2',
    at: localNow(),
    phase: 'exploit',
    host: DEFAULT_TARGET,
    note: 'Reflected XSS confirmed in the support search. Payload reaches the results header unencoded; screenshot saved to the evidence folder.',
    tags: ['xss', 'confirmed'],
  },
  {
    id: 'seed-3',
    at: localNow(),
    phase: 'post',
    host: DEFAULT_CALLBACK_HOST,
    note: 'Callback received on the OAST domain from the bastion egress IP — confirms server-side fetch, not a browser.',
    tags: ['oast', 'ssrf'],
  },
];

const EMPTY_ENTRY: Omit<Entry, 'id'> = {
  at: '',
  phase: 'recon',
  host: DEFAULT_TARGET,
  note: '',
  tags: [],
};

type View = 'all' | 'phases';

export default function EngagementNotes() {
  const [entries, setEntries] = useLocalStorage<Entry[]>('engagement-notes', SEED);
  const [view, setView] = useState<View>('all');
  const [phaseFilter, setPhaseFilter] = useState<'any' | Phase>('any');
  const [query, setQuery] = useState('');
  const [draft, setDraft] = useState<Omit<Entry, 'id'>>({ ...EMPTY_ENTRY, at: localNow() });
  const [editing, setEditing] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return entries
      .filter((e) => (phaseFilter === 'any' ? true : e.phase === phaseFilter))
      .filter((e) =>
        q
          ? [e.note, e.host, e.tags.join(' '), e.phase, e.at].some((field) => field.toLowerCase().includes(q))
          : true,
      )
      .slice()
      .sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
  }, [entries, phaseFilter, query]);

  const counts = useMemo(() => {
    const base: Record<Phase, number> = { recon: 0, exploit: 0, post: 0, report: 0 };
    for (const e of entries) base[e.phase] += 1;
    return base;
  }, [entries]);

  const markdown = useMemo(() => {
    const out: string[] = ['# Engagement notes', '', `Entries: ${entries.length}`, ''];
    for (const { value, label } of PHASES) {
      const group = entries.filter((e) => e.phase === value).sort((a, b) => (a.at < b.at ? -1 : 1));
      if (!group.length) continue;
      out.push(`## ${label}`, '');
      for (const e of group) {
        out.push(`### ${e.at} — ${e.host || 'no host'}`, '', e.note || '_empty note_', '');
        if (e.tags.length) out.push(`Tags: ${e.tags.map((t) => `\`${t}\``).join(' ')}`, '');
      }
    }
    out.push('---', '', `_Exported ${new Date().toISOString()} · times are operator-local as typed._`);
    return out.join('\n');
  }, [entries]);

  const commit = () => {
    const note = draft.note.trim();
    if (!note) return;
    const record: Entry = { ...draft, note, id: editing ?? `e-${Date.now().toString(36)}` };
    setEntries((prev) => (editing ? prev.map((e) => (e.id === editing ? record : e)) : [...prev, record]));
    setEditing(null);
    setDraft({ ...EMPTY_ENTRY, at: localNow() });
  };

  const startEdit = (entry: Entry) => {
    setEditing(entry.id);
    setDraft({ at: entry.at, phase: entry.phase, host: entry.host, note: entry.note, tags: entry.tags });
  };

  const remove = (id: string) => setEntries((prev) => prev.filter((e) => e.id !== id));

  return (
    <>
      <Card
        title={editing ? 'Edit entry' : 'New entry'}
        action={
          <div className="flex gap-2">
            {editing && (
              <Button size="sm" variant="ghost" onClick={() => { setEditing(null); setDraft({ ...EMPTY_ENTRY, at: localNow() }); }}>
                Cancel
              </Button>
            )}
            <Button size="sm" variant="primary" onClick={commit} disabled={!draft.note.trim()}>
              {editing ? 'Save changes' : 'Add entry'}
            </Button>
          </div>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <TextInput label="Timestamp (local, editable)" value={draft.at} onChange={(v) => setDraft((d) => ({ ...d, at: v }))} mono />
          <Select<Phase> label="Phase" value={draft.phase} onChange={(v) => setDraft((d) => ({ ...d, phase: v }))} options={PHASES} />
          <TextInput label="Host" value={draft.host} onChange={(v) => setDraft((d) => ({ ...d, host: v }))} mono />
          <TextInput
            label="Tags (comma separated)"
            value={draft.tags.join(', ')}
            onChange={(v) => setDraft((d) => ({ ...d, tags: v.split(',').map((t) => t.trim()).filter(Boolean) }))}
          />
        </div>
        <div className="mt-3">
          <TextArea
            label="Note"
            value={draft.note}
            onChange={(v) => setDraft((d) => ({ ...d, note: v }))}
            rows={3}
            placeholder="What you did, what you saw, and the exact command or payload used"
          />
        </div>
      </Card>

      <Card
        title="Log"
        action={
          <Tabs<View>
            value={view}
            onChange={setView}
            tabs={[
              { value: 'all', label: 'Flat', badge: entries.length },
              { value: 'phases', label: 'By phase' },
            ]}
          />
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Select<'any' | Phase>
            label="Filter by phase"
            value={phaseFilter}
            onChange={setPhaseFilter}
            options={[{ value: 'any', label: 'All phases' }, ...PHASES]}
          />
          <TextInput label="Search" value={query} onChange={setQuery} placeholder="host, tag or free text" />
        </div>

        <div className="mt-4">
          {filtered.length === 0 ? (
            <div className="rounded border border-dashed border-[var(--card-border)] px-3 py-6 text-center text-[12.5px] text-[var(--text-faint)]">
              {entries.length === 0
                ? 'No entries yet. Log the first reconnaissance step above — the export is only as useful as the log.'
                : 'No entries match this filter.'}
            </div>
          ) : view === 'phases' ? (
            <div className="space-y-4">
              {PHASES.map(({ value, label }) => {
                const group = filtered.filter((e) => e.phase === value);
                if (!group.length) return null;
                return (
                  <div key={value}>
                    <div className="mb-1 text-[11px] uppercase tracking-wide" style={{ color: PHASE_COLOUR[value] }}>
                      {label} · {group.length}
                    </div>
                    <div className="space-y-2">{group.map((e) => <Row key={e.id} entry={e} onEdit={startEdit} onRemove={remove} />)}</div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="space-y-2">{filtered.map((e) => <Row key={e.id} entry={e} onEdit={startEdit} onRemove={remove} />)}</div>
          )}
        </div>
      </Card>

      <Card
        title="Export"
        action={<DownloadButton text={markdown} filename="engagement-notes.md" label="Download .md" />}
      >
        <KVTable
          rows={[
            ['Entries', String(entries.length)],
            ['Recon', String(counts.recon)],
            ['Exploit', String(counts.exploit)],
            ['Post-exploitation', String(counts.post)],
            ['Report', String(counts.report)],
            ['Storage key', 'redforge:engagement-notes'],
          ]}
        />
        <div className="mt-4">
          <CodeBlock code={markdown} label="engagement-notes.md" maxHeight={280} />
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          {confirming ? (
            <>
              <Button size="sm" variant="primary" onClick={() => { setEntries([]); setConfirming(false); }}>
                Confirm clear all
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setConfirming(false)}>
                Keep entries
              </Button>
            </>
          ) : (
            <Button size="sm" variant="outline" onClick={() => setConfirming(true)} disabled={entries.length === 0}>
              Clear all
            </Button>
          )}
        </div>
        <div className="mt-3">
          <Callout tone="info" title="Local only">
            Entries live in this browser's localStorage. Export before closing the engagement device, and never store
            credentials in a note — the export is plain text.
          </Callout>
        </div>
      </Card>
    </>
  );
}

function Row({ entry, onEdit, onRemove }: { entry: Entry; onEdit: (e: Entry) => void; onRemove: (id: string) => void }) {
  return (
    <div className="rounded border border-[var(--card-border)] px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rf-mono text-[11.5px] text-[var(--text-faint)]">{entry.at}</span>
        <span className="rounded px-1.5 text-[10.5px] uppercase tracking-wide" style={{ color: PHASE_COLOUR[entry.phase], background: 'var(--accent-faded)' }}>
          {entry.phase}
        </span>
        <span className="rf-mono text-[11.5px] text-[var(--text-muted)]">{entry.host}</span>
        <span className="ml-auto flex gap-1">
          <Button size="sm" variant="ghost" onClick={() => onEdit(entry)}>
            Edit
          </Button>
          <Button size="sm" variant="ghost" onClick={() => onRemove(entry.id)}>
            Delete
          </Button>
        </span>
      </div>
      <div className="mt-1 whitespace-pre-wrap text-[12.5px] leading-relaxed text-[var(--text)]">{entry.note}</div>
      {entry.tags.length > 0 && (
        <div className="mt-1 flex flex-wrap gap-1">
          {entry.tags.map((t) => (
            <span key={t} className="rounded bg-[var(--input)] px-1.5 py-0.5 text-[10.5px] text-[var(--text-muted)]">
              {t}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function localNow(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
