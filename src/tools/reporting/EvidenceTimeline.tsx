import { useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, DownloadButton, KVTable, Select, TextArea } from '@/components/ui';
import { DEFAULT_TARGET } from '@/tools/registry';

/**
 * Evidence timeline normaliser. Accepts the four timestamp shapes that turn up in
 * real logs, converts each to UTC using the selected input offset, sorts, and
 * flags duplicates and implausible deltas.
 */

type Parsed = {
  raw: string;
  message: string;
  ms: number;
  iso: string;
  sourceFormat: string;
};

const OFFSETS = [
  { value: '0', label: 'UTC (+00:00)' },
  { value: '60', label: 'UTC+01:00 (CET / BST)' },
  { value: '120', label: 'UTC+02:00 (CEST)' },
  { value: '330', label: 'UTC+05:30 (IST)' },
  { value: '-300', label: 'UTC−05:00 (EST)' },
  { value: '-480', label: 'UTC−08:00 (PST)' },
];

const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

const SAMPLE = [
  '2025-06-02 09:14:02 GET /login 200 10.10.14.7',
  '2025-06-02T09:15:41Z POST /api/v2/tickets 201 10.10.14.7',
  'Jun  2 09:16:10 bastion sshd[2214]: Accepted publickey for tester',
  '1717320000 curl http://example.com/.git/config 200',
  '2025-06-02 09:17:30 GET /admin 403 10.10.14.7',
  '2025-06-02 09:17:30 GET /admin 403 10.10.14.7',
  '2025-06-02 09:12:00 GET /search?q=xss 200 10.10.14.7',
].join('\n');

type Row = Parsed & { deltaMs: number | null; flags: string[] };

export default function EvidenceTimeline() {
  const [raw, setRaw] = useState(SAMPLE);
  const [offset, setOffset] = useState('0');
  const [year, setYear] = useState('2025');

  const analysis = useMemo(() => {
    const offsetMin = Number(offset);
    const lines = raw.split('\n').map((l) => l.trim()).filter(Boolean);
    const parsed: Parsed[] = [];
    const unparsed: string[] = [];

    for (const line of lines) {
      const p = parseLine(line, offsetMin, Number(year) || new Date().getUTCFullYear());
      if (p) parsed.push(p);
      else unparsed.push(line);
    }

    const sorted = [...parsed].sort((a, b) => a.ms - b.ms);
    const rows: Row[] = sorted.map((p, i) => {
      const deltaMs = i === 0 ? null : p.ms - sorted[i - 1].ms;
      const flags: string[] = [];
      if (deltaMs !== null && deltaMs < 0) flags.push('negative delta');
      if (deltaMs === 0) flags.push('duplicate timestamp');
      if (deltaMs !== null && deltaMs > 0 && deltaMs < 1000) flags.push('sub-second burst');
      if (deltaMs !== null && deltaMs > 3_600_000) flags.push('gap > 1h');
      return { ...p, deltaMs, flags };
    });

    const outOfOrder = parsed.filter((p, i) => i > 0 && p.ms < parsed[i - 1].ms).length;
    const dupes = rows.filter((r) => r.flags.includes('duplicate timestamp')).length;
    const spanMs = rows.length ? (rows[rows.length - 1]?.ms ?? 0) - (rows[0]?.ms ?? 0) : 0;

    return { rows, unparsed, outOfOrder, dupes, spanMs, total: parsed.length };
  }, [raw, offset, year]);

  const markdown = useMemo(() => {
    const out = [
      '# Evidence timeline',
      '',
      `Input timezone offset: UTC${formatOffset(Number(offset))} · all times normalised to UTC.`,
      '',
      '| # | UTC timestamp | Δ since previous | Source format | Message | Flags |',
      '| --- | --- | --- | --- | --- | --- |',
      ...analysis.rows.map(
        (r, i) =>
          `| ${i + 1} | ${r.iso} | ${r.deltaMs === null ? '—' : formatDelta(r.deltaMs)} | ${r.sourceFormat} | ${r.message.replace(/\|/g, '\\|')} | ${r.flags.join(', ') || '—'} |`,
      ),
      '',
      `**Events:** ${analysis.total} · **Span:** ${formatDelta(analysis.spanMs)} · **Duplicates:** ${analysis.dupes} · **Out-of-order input lines:** ${analysis.outOfOrder}`,
      '',
    ];
    if (analysis.unparsed.length) {
      out.push('## Unparsed lines', '', '```text', ...analysis.unparsed, '```', '');
    }
    out.push('_Times are normalised, not synchronised: a host clock that was wrong at collection time will still be wrong here._');
    return out.join('\n');
  }, [analysis, offset]);

  const skew = useMemo(() => {
    if (!analysis.rows.length) return null;
    if (analysis.dupes > 0) {
      return 'Duplicate timestamps usually mean two collection sources with different clock offsets, or a log shipper replaying a buffer. Confirm which before quoting either entry as evidence.';
    }
    const smallest = analysis.rows.reduce((acc, r) => (r.deltaMs !== null && r.deltaMs < acc ? r.deltaMs : acc), Number.POSITIVE_INFINITY);
    if (smallest < 1000) {
      return `A ${formatDelta(smallest)} gap between adjacent entries is faster than a human click. Either it is automation, or the two sources are not on the same clock — log the NTP state of both hosts.`;
    }
    if (analysis.outOfOrder > 0) {
      return `${analysis.outOfOrder} input line(s) arrived out of order. The sorted view hides this; keep the original file as collected and cite both.`;
    }
    return null;
  }, [analysis]);

  return (
    <>
      <Card title="Input">
        <div className="grid gap-3 sm:grid-cols-2">
          <Select value={offset} onChange={setOffset} label="Input timezone (offset from UTC)" options={OFFSETS} />
          <Select
            value={year}
            onChange={setYear}
            label="Year for syslog lines (no year in the record)"
            options={['2024', '2025', '2026'].map((y) => ({ value: y, label: y }))}
          />
        </div>
        <div className="mt-3">
          <TextArea
            label="Log lines"
            value={raw}
            onChange={setRaw}
            rows={10}
            placeholder={`2025-06-02 09:14:02 GET /login 200 ${DEFAULT_TARGET}\n2025-06-02T09:15:41Z ...\nJun  2 09:16:10 host sshd[2214]: ...\n1717320000 ...`}
            hint="Accepts YYYY-MM-DD HH:MM:SS, ISO 8601, syslog MMM dd HH:MM:SS and epoch seconds/millis. Text after the timestamp is the message."
          />
        </div>
      </Card>

      <Card
        title="Normalised timeline (UTC)"
        action={<DownloadButton text={markdown} filename="evidence-timeline.md" label="Download .md" />}
      >
        {analysis.rows.length === 0 ? (
          <div className="rounded border border-dashed border-[var(--card-border)] px-3 py-6 text-center text-[12.5px] text-[var(--text-faint)]">
            No timestamps parsed yet — paste a few log lines above, one event per line.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[12px]">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wide text-[var(--text-faint)]">
                  <th className="py-1 pr-3 font-medium">#</th>
                  <th className="py-1 pr-3 font-medium">UTC</th>
                  <th className="py-1 pr-3 font-medium">Δ</th>
                  <th className="py-1 pr-3 font-medium">Format</th>
                  <th className="py-1 pr-3 font-medium">Message</th>
                  <th className="py-1 font-medium">Flags</th>
                </tr>
              </thead>
              <tbody>
                {analysis.rows.map((r, i) => (
                  <tr key={`${r.ms}-${i}`} className="border-t border-[var(--card-border)] align-top">
                    <td className="py-1 pr-3 text-[var(--text-faint)]">{i + 1}</td>
                    <td className="rf-mono whitespace-nowrap py-1 pr-3 text-[var(--text)]">{r.iso}</td>
                    <td
                      className="rf-mono whitespace-nowrap py-1 pr-3"
                      style={{ color: r.deltaMs === null ? 'var(--text-faint)' : r.deltaMs < 0 ? 'var(--warn)' : 'var(--text-muted)' }}
                    >
                      {r.deltaMs === null ? '—' : formatDelta(r.deltaMs)}
                    </td>
                    <td className="py-1 pr-3 text-[var(--text-muted)]">{r.sourceFormat}</td>
                    <td className="rf-mono py-1 pr-3 text-[var(--text-muted)]">{r.message || '—'}</td>
                    <td className="py-1">
                      {r.flags.length ? (
                        <span style={{ color: 'var(--warn)' }}>{r.flags.join(', ')}</span>
                      ) : (
                        <span className="text-[var(--text-faint)]">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Summary">
        <KVTable
          rows={[
            ['Events parsed', String(analysis.total)],
            ['Span', analysis.total ? formatDelta(analysis.spanMs) : '—'],
            ['Duplicate timestamps', String(analysis.dupes)],
            ['Out-of-order input lines', String(analysis.outOfOrder)],
            ['Unparsed lines', String(analysis.unparsed.length)],
          ]}
        />
        <div className="mt-3 space-y-3">
          {skew ? (
            <Callout tone="warn" title="Clock skew">
              {skew}
            </Callout>
          ) : (
            <Callout tone="ok" title="No skew indicators">
              Deltas are positive and well separated. Still record the NTP source for each host — a timeline is only as
              good as the clocks behind it.
            </Callout>
          )}
          {analysis.unparsed.length > 0 && (
            <Callout tone="info" title={`${analysis.unparsed.length} line(s) not recognised`}>
              Those lines are carried into the export under "Unparsed lines" rather than dropped, so the evidence set
              stays complete.
            </Callout>
          )}
        </div>
      </Card>

      <Card title="Export preview">
        <CodeBlock code={markdown} label="evidence-timeline.md" maxHeight={300} />
      </Card>
    </>
  );
}

function parseLine(line: string, offsetMin: number, defaultYear: number): Parsed | null {
  // 1. Epoch seconds or millis at the start of the line.
  const epoch = /^(\d{10}|\d{13})\b\s*(.*)$/.exec(line);
  if (epoch) {
    const digits = epoch[1] ?? '';
    const ms = digits.length === 13 ? Number(digits) : Number(digits) * 1000;
    if (Number.isFinite(ms)) {
      return { raw: line, message: (epoch[2] ?? '').trim(), ms, iso: isoUtc(ms), sourceFormat: digits.length === 13 ? 'epoch ms' : 'epoch s' };
    }
  }

  // 2. ISO 8601 with explicit Z or offset.
  const isoTz = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})\s*(.*)$/.exec(line);
  if (isoTz) {
    const ms = Date.parse(`${isoTz[1]}T${isoTz[2]}${isoTz[3]}`);
    if (Number.isFinite(ms)) {
      return { raw: line, message: (isoTz[4] ?? '').trim(), ms, iso: isoUtc(ms), sourceFormat: 'ISO 8601 (tz)' };
    }
  }

  // 3. Naive YYYY-MM-DD HH:MM:SS — interpreted in the selected offset.
  const naive = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?\s*(.*)$/.exec(line);
  if (naive) {
    const ms = Date.parse(`${naive[1]}T${naive[2]}Z`);
    if (Number.isFinite(ms)) {
      const shifted = ms - offsetMin * 60_000;
      return { raw: line, message: (naive[3] ?? '').trim(), ms: shifted, iso: isoUtc(shifted), sourceFormat: 'ISO 8601 (local)' };
    }
  }

  // 4. Syslog: MMM dd HH:MM:SS (day may be space padded).
  const syslog = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s*(.*)$/.exec(line);
  if (syslog) {
    const month = MONTHS[syslog[1] ?? ''];
    if (month !== undefined) {
      const base = Date.UTC(defaultYear, month, Number(syslog[2]), ...hhmmss(syslog[3] ?? ''));
      if (Number.isFinite(base)) {
        const shifted = base - offsetMin * 60_000;
        return { raw: line, message: (syslog[4] ?? '').trim(), ms: shifted, iso: isoUtc(shifted), sourceFormat: 'syslog' };
      }
    }
  }

  return null;
}

function hhmmss(s: string): [number, number, number] {
  const [h, m, sec] = s.split(':').map(Number);
  return [h ?? 0, m ?? 0, sec ?? 0];
}

function isoUtc(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}Z`;
}

function formatDelta(ms: number): string {
  if (ms === 0) return '0s';
  const sign = ms < 0 ? '−' : '+';
  const abs = Math.abs(ms);
  if (abs < 1000) return `${sign}${abs}ms`;
  if (abs < 60_000) return `${sign}${(abs / 1000).toFixed(abs < 10_000 ? 1 : 0)}s`;
  if (abs < 3_600_000) return `${sign}${Math.floor(abs / 60_000)}m${Math.round((abs % 60_000) / 1000)}s`;
  return `${sign}${(abs / 3_600_000).toFixed(1)}h`;
}

function formatOffset(min: number): string {
  const sign = min < 0 ? '−' : '+';
  const abs = Math.abs(min);
  return `${sign}${String(Math.floor(abs / 60)).padStart(2, '0')}:${String(abs % 60).padStart(2, '0')}`;
}
