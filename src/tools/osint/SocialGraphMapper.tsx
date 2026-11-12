import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  CodeBlock,
  DownloadButton,
  KVTable,
  SearchInput,
  Tabs,
  TextArea,
} from '@/components/ui';
import { useLocalStorage } from '@/lib/hooks';

/**
 * Entity relationship mapper for OSINT pivots. Lines are parsed into a directed graph,
 * duplicates and self-loops are called out rather than silently merged, and the three
 * exports let the same graph move into Graphviz, a Mermaid diagram or a spreadsheet.
 */

interface Edge {
  from: string;
  to: string;
  label: string;
  line: number;
}

interface Parsed {
  edges: Edge[];
  uniqueEdges: Edge[];
  nodes: string[];
  degree: Map<string, number>;
  malformed: Array<{ line: number; text: string }>;
  duplicates: Array<{ line: number; text: string; first: number }>;
  selfLoops: number;
  contentLines: number;
}

const SAMPLE = [
  'alex.turner -> northwind.example.com : works at',
  'northwind.example.com -> 203.0.113.10 : resolves to',
  'northwind.example.com -> payroll.example.com : shares certificate',
  '203.0.113.10 -> vpn.example.com : reverse DNS',
  'alex.turner -- owns --> alex.turner@example.com',
  'alex.turner@example.com -> mail.example.com : hosted on',
  '203.0.113.10 -> 203.0.113.10 : stale record',
  'payroll.example.com -> 203.0.113.10 : resolves to',
  'alex.turner -> northwind.example.com : works at',
  'malformed line without an arrow',
  'vpn.example.com ->',
].join('\n');

const ARROW = /^(.*?)\s*->\s*(.*)$/;
const LABELLED = /^(.*?)\s*--\s*(.*?)\s*-->\s*(.*)$/;
const BARE = /^[\w.@:'’\- ]{1,80}$/;
const TAB_OPTIONS: Array<{ value: 'dot' | 'mermaid' | 'csv'; label: string }> = [
  { value: 'dot', label: 'Graphviz DOT' },
  { value: 'mermaid', label: 'Mermaid' },
  { value: 'csv', label: 'Node / edge CSV' },
];

export default function SocialGraphMapper() {
  const [raw, setRaw] = useLocalStorage<string>('social-graph-input', SAMPLE);
  const [filter, setFilter] = useState('');
  const [tab, setTab] = useState<'dot' | 'mermaid' | 'csv'>('dot');

  const parsed = useMemo<Parsed>(() => parse(raw), [raw]);

  const top = useMemo(
    () =>
      parsed.nodes
        .map((n) => ({ node: n, degree: parsed.degree.get(n) ?? 0 }))
        .sort((a, b) => b.degree - a.degree || a.node.localeCompare(b.node))
        .slice(0, 8),
    [parsed],
  );

  const isolated = useMemo(() => parsed.nodes.filter((n) => (parsed.degree.get(n) ?? 0) === 0), [parsed]);

  const visibleEdges = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return parsed.edges;
    return parsed.edges.filter((e) =>
      [e.from, e.to, e.label].some((v) => v.toLowerCase().includes(q)),
    );
  }, [parsed.edges, filter]);

  const dot = useMemo(() => toDot(parsed), [parsed]);
  const mermaid = useMemo(() => toMermaid(parsed), [parsed]);
  const csv = useMemo(() => toCsv(parsed), [parsed]);
  const exportText = tab === 'dot' ? dot : tab === 'mermaid' ? mermaid : csv;
  const exportName = tab === 'dot' ? 'entity-graph.dot' : tab === 'mermaid' ? 'entity-graph.mmd' : 'entity-graph.csv';

  return (
    <>
      <Card title="Graph input">
        <TextArea
          label="Edges"
          value={raw}
          onChange={setRaw}
          rows={10}
          hint="entity -> entity : label · entity -- label --> entity · a bare line declares an isolated node"
        />
        <div className="mt-3">
          <KVTable
            rows={[
              ['Lines with content', String(parsed.contentLines)],
              ['Edges parsed', String(parsed.edges.length)],
              ['Unique edges', String(parsed.uniqueEdges.length)],
              ['Entities', String(parsed.nodes.length)],
              ['Duplicate edges', String(parsed.duplicates.length)],
              ['Self-loops', String(parsed.selfLoops)],
              ['Malformed lines', String(parsed.malformed.length)],
            ]}
          />
        </div>
        {parsed.malformed.length > 0 && (
          <div className="mt-3">
            <Callout tone="danger" title={`${parsed.malformed.length} line(s) could not be parsed`}>
              <ul className="m-0 list-disc pl-4">
                {parsed.malformed.slice(0, 6).map((m) => (
                  <li key={m.line}>
                    line {m.line}: <span className="rf-mono">{m.text || '(empty)'}</span>
                  </li>
                ))}
              </ul>
              {parsed.malformed.length > 6 && <div className="mt-1">…and {parsed.malformed.length - 6} more.</div>}
            </Callout>
          </div>
        )}
      </Card>
      <Card title="Entities by degree">
        {parsed.nodes.length === 0 ? (
          <div className="rounded border border-dashed border-[var(--card-border)] px-3 py-6 text-center text-[12.5px] text-[var(--text-faint)]">
            Nothing parsed yet. Paste at least one edge above.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[12px]">
              <thead>
                <tr className="text-left text-[11px] tracking-wide text-[var(--text-faint)] uppercase">
                  <th className="py-1 pr-3 font-medium">Entity</th>
                  <th className="py-1 pr-3 font-medium">Degree</th>
                  <th className="py-1 font-medium">Role</th>
                </tr>
              </thead>
              <tbody>
                {top.map((t) => (
                  <tr key={t.node} className="border-t border-[var(--card-border)]">
                    <td className="rf-mono py-1.5 pr-3 text-[var(--text)]">{t.node}</td>
                    <td className="rf-mono py-1.5 pr-3 text-[var(--text-muted)]">{t.degree}</td>
                    <td className="py-1.5 text-[var(--text-muted)]">{t.degree >= 4 ? 'hub — pivot here first' : t.degree >= 2 ? 'connector' : 'leaf'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="mt-3">
          <Callout tone={isolated.length ? 'warn' : 'info'} title="Isolated entities">
            {isolated.length
              ? `${isolated.length} declared entit${isolated.length === 1 ? 'y has' : 'ies have'} no edges: ${isolated.join(', ')}. Either the relationship was missed or the line is a typo — a bare line is read as a node declaration.`
              : 'None. Every declared entity has at least one edge, so no relationship line was dropped silently.'}
          </Callout>
        </div>
      </Card>
      <Card title="Edges" action={<span className="rf-mono text-[11px] text-[var(--text-faint)]">{visibleEdges.length} shown</span>}>
        <SearchInput value={filter} onChange={setFilter} placeholder="Filter by entity or label" />
        <div className="mt-3 overflow-x-auto">
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr className="text-left text-[11px] tracking-wide text-[var(--text-faint)] uppercase">
                <th className="py-1 pr-3 font-medium">Line</th>
                <th className="py-1 pr-3 font-medium">From</th>
                <th className="py-1 pr-3 font-medium">Label</th>
                <th className="py-1 pr-3 font-medium">To</th>
                <th className="py-1 font-medium">Flag</th>
              </tr>
            </thead>
            <tbody>
              {visibleEdges.map((e) => {
                const dup = parsed.duplicates.some((d) => d.line === e.line);
                const loop = e.from === e.to;
                return (
                  <tr key={e.line} className="border-t border-[var(--card-border)]">
                    <td className="rf-mono py-1.5 pr-3 text-[var(--text-faint)]">{e.line}</td>
                    <td className="rf-mono py-1.5 pr-3 text-[var(--text)]">{e.from}</td>
                    <td className="py-1.5 pr-3 text-[var(--text-muted)]">{e.label || '—'}</td>
                    <td className="rf-mono py-1.5 pr-3 text-[var(--text)]">{e.to}</td>
                    <td className="py-1.5">{loop && <Chip label="self-loop" colour="var(--accent)" />} {dup && <Chip label="duplicate" colour="var(--warn)" />}</td>
                  </tr>
                );
              })}
              {visibleEdges.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-6 text-center text-[12.5px] text-[var(--text-faint)]">
                    No edge matches “{filter}”.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title="Export" action={<DownloadButton text={exportText} filename={exportName} label="Download current tab" />}>
        <Tabs<'dot' | 'mermaid' | 'csv'> value={tab} onChange={setTab} tabs={TAB_OPTIONS} />
        <div className="mt-3"><CodeBlock code={exportText} label={exportName} maxHeight={320} /></div>
      </Card>
    </>
  );
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

function parse(raw: string): Parsed {
  const edges: Edge[] = [];
  const malformed: Array<{ line: number; text: string }> = [];
  const duplicates: Array<{ line: number; text: string; first: number }> = [];
  const nodeSet = new Set<string>();
  const seen = new Map<string, number>();
  let contentLines = 0;

  raw.split('\n').forEach((text, i) => {
    const line = i + 1;
    const trimmed = text.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    contentLines += 1;

    const labelled = LABELLED.exec(trimmed);
    const plain = labelled ? null : ARROW.exec(trimmed);
    let from = '';
    let to = '';
    let label = '';

    if (labelled) {
      from = (labelled[1] ?? '').trim();
      label = (labelled[2] ?? '').trim();
      to = (labelled[3] ?? '').trim();
    } else if (plain) {
      from = (plain[1] ?? '').trim();
      const rest = (plain[2] ?? '').trim();
      const colon = rest.indexOf(':');
      to = (colon >= 0 ? rest.slice(0, colon) : rest).trim();
      label = colon >= 0 ? rest.slice(colon + 1).trim() : '';
    } else if (BARE.test(trimmed)) {
      nodeSet.add(trimmed);
      return;
    } else {
      malformed.push({ line, text: trimmed });
      return;
    }

    if (!from || !to) {
      malformed.push({ line, text: trimmed });
      return;
    }
    addEdge(from, to, label, line);
  });

  function addEdge(from: string, to: string, label: string, line: number) {
    const e: Edge = { from, to, label, line };
    nodeSet.add(from);
    nodeSet.add(to);
    const key = `${from.toLowerCase()}|${to.toLowerCase()}|${label.toLowerCase()}`;
    const first = seen.get(key);
    if (first !== undefined) duplicates.push({ line, text: `${from} -> ${to}`, first });
    else seen.set(key, line);
    edges.push(e);
  }

  const degree = new Map<string, number>();
  for (const n of nodeSet) degree.set(n, 0);
  for (const e of edges) {
    degree.set(e.from, (degree.get(e.from) ?? 0) + 1);
    degree.set(e.to, (degree.get(e.to) ?? 0) + 1);
  }

  const uniqueKeys = new Set<string>();
  const uniqueEdges = edges.filter((e) => {
    const key = `${e.from.toLowerCase()}|${e.to.toLowerCase()}|${e.label.toLowerCase()}`;
    if (uniqueKeys.has(key)) return false;
    uniqueKeys.add(key);
    return true;
  });

  return {
    edges,
    uniqueEdges,
    nodes: Array.from(nodeSet),
    degree,
    malformed,
    duplicates,
    selfLoops: edges.filter((e) => e.from === e.to).length,
    contentLines,
  };
}

function toDot(p: Parsed): string {
  const q = (s: string) => `"${s.replace(/"/g, '\\"')}"`;
  const lines = ['digraph entities {', '  rankdir=LR;', '  node [shape=box, fontname="Helvetica"];'];
  for (const n of p.nodes) lines.push(`  ${q(n)};`);
  for (const e of p.uniqueEdges) {
    lines.push(e.label ? `  ${q(e.from)} -> ${q(e.to)} [label=${q(e.label)}];` : `  ${q(e.from)} -> ${q(e.to)};`);
  }
  lines.push('}');
  return lines.join('\n');
}

function toMermaid(p: Parsed): string {
  const ids = new Map<string, string>();
  p.nodes.forEach((n, i) => ids.set(n, `n${i}`));
  const esc = (s: string) => s.replace(/"/g, '#quot;');
  const lines = ['flowchart LR'];
  for (const n of p.nodes) lines.push(`  ${ids.get(n)}["${esc(n)}"]`);
  for (const e of p.uniqueEdges) {
    const a = ids.get(e.from);
    const b = ids.get(e.to);
    lines.push(e.label ? `  ${a} -->|"${esc(e.label)}"| ${b}` : `  ${a} --> ${b}`);
  }
  return lines.join('\n');
}

function toCsv(p: Parsed): string {
  const nodes = ['# nodes', 'node,degree', ...p.nodes.map((n) => `${csvCell(n)},${p.degree.get(n) ?? 0}`)];
  const edges = [
    '',
    '# edges',
    'source,label,target,duplicate,self_loop',
    ...p.edges.map((e) => {
      const dup = p.duplicates.some((d) => d.line === e.line) ? 'yes' : 'no';
      return `${csvCell(e.from)},${csvCell(e.label)},${csvCell(e.to)},${dup},${e.from === e.to ? 'yes' : 'no'}`;
    }),
  ];
  return [...nodes, ...edges].join('\n');
}

function csvCell(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}
