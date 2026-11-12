import { useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, KVTable, OutputBlock, Select, Tabs, TextArea, TextInput } from '@/components/ui';

/**
 * URL / percent encoding with the flavours that actually change a server's
 * interpretation: full-URI vs component, double encoding, and the three legacy
 * escape styles (`\uXXXX`, IIS `%uXXXX`, HTML numeric entities).
 */

type Mode = 'encode' | 'decode';
type Flavour = 'component' | 'fulluri' | 'double' | 'unicode' | 'iis' | 'html';

const FLAVOURS: Array<{ value: Flavour; label: string }> = [
  { value: 'component', label: 'Percent (component) — encodeURIComponent' },
  { value: 'fulluri', label: 'Full URI — encodeURI (keeps :/?#[]@)' },
  { value: 'double', label: 'Double encode — %25 for every %' },
  { value: 'unicode', label: 'Unicode escape — \\uXXXX' },
  { value: 'iis', label: 'IIS %uXXXX form' },
  { value: 'html', label: 'HTML numeric entity — &#xNN;' },
];

const FLAVOUR_NOTE: Record<Flavour, string> = {
  component: 'Everything outside A-Z a-z 0-9 - _ . ! ~ * \' ( ) is escaped. Use for a single query value.',
  fulluri:
    'Reserved delimiters survive. A path traversal written with these stays readable to the server and invisible to a naive filter.',
  double:
    'The form that walks past a filter which decodes once and then passes the value on to a second decoder. Check the vulnerability class before relying on it.',
  unicode: 'JavaScript / Java / Python string escape. Renders as one character once the interpreter parses it.',
  iis: 'Legacy IIS/ASP convention. Some WAF rulesets still do not normalise %u002e to a dot.',
  html: 'Entity form for HTML contexts. Numeric entities are decoded by the browser before any script filter sees them.',
};

const RESERVED = new Set(['?', '#', '[', ']', '@', '!', '$', '&', "'", '(', ')', '*', '+', ',', ';', '=', ':', '/']);

const hex2 = (n: number) => n.toString(16).toUpperCase().padStart(2, '0');
const hex4 = (n: number) => n.toString(16).toUpperCase().padStart(4, '0');

function encodeChar(ch: string, flavour: Flavour, keep: Set<string>): string {
  if (keep.has(ch)) return ch;
  const cp = ch.codePointAt(0) ?? 0;
  switch (flavour) {
    case 'component':
      return encodeURIComponent(ch);
    case 'fulluri':
      return RESERVED.has(ch) ? ch : encodeURIComponent(ch);
    case 'double':
      return encodeURIComponent(ch).replace(/%/g, '%25');
    case 'unicode':
      return cp > 0xffff ? `\\u{${cp.toString(16).toUpperCase()}}` : `\\u${hex4(cp)}`;
    case 'iis':
      return `%u${hex4(cp)}`;
    case 'html':
      return `&#x${cp.toString(16).toUpperCase()};`;
  }
}

/** Legacy escape decoders — kept separate because each has its own grammar. */
function decodeLegacy(text: string, flavour: Flavour): string {
  if (flavour === 'unicode')
    return text.replace(/\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})/g, (_, a, b) =>
      String.fromCodePoint(parseInt(a ?? b, 16)),
    );
  if (flavour === 'iis')
    return text.replace(/%u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  if (flavour === 'html')
    return text.replace(/&#x([0-9a-fA-F]+);|&#(\d+);/g, (_, h, d) =>
      String.fromCodePoint(h ? parseInt(h, 16) : parseInt(d, 10)),
    );
  if (flavour === 'double') {
    try {
      return decodeURIComponent(decodeURIComponent(text));
    } catch {
      return decodeURIComponent(text.replace(/%(?![\dA-Fa-f]{2})/g, '%25'));
    }
  }
  if (flavour === 'fulluri') return decodeURI(text);
  return decodeURIComponent(text);
}

export default function UrlEncoder() {
  const [mode, setMode] = useState<Mode>('encode');
  const [flavour, setFlavour] = useState<Flavour>('component');
  const [input, setInput] = useState('');
  const [keep, setKeep] = useState('');

  const keepSet = useMemo(() => new Set(Array.from(keep)), [keep]);

  const result = useMemo(() => {
    if (!input) return { output: '', error: null as string | null };
    try {
      if (mode === 'encode') {
        if (flavour === 'double')
          return { output: input.split('').map((c) => encodeChar(c, 'component', keepSet).replace(/%/g, '%25')).join(''), error: null };
        return { output: Array.from(input).map((c) => encodeChar(c, flavour, keepSet)).join(''), error: null };
      }
      const decoded = decodeLegacy(input, flavour);
      if (decoded.includes('\uFFFD')) throw new Error('Result contains replacement characters — the input is not valid in this flavour');
      return { output: decoded, error: null };
    } catch (e) {
      return { output: '', error: e instanceof Error ? e.message : 'Conversion failed' };
    }
  }, [input, mode, flavour, keepSet]);

  /** Per-character diff for anything non-alphanumeric in the input. */
  const diff = useMemo(() => {
    const rows: Array<{ ch: string; cp: string; enc: string; total: number }> = [];
    const seen = new Map<string, { cp: string; enc: string; total: number }>();
    for (const ch of input) {
      if (/[A-Za-z0-9]/.test(ch)) continue;
      const existing = seen.get(ch);
      if (existing) existing.total += 1;
      else seen.set(ch, { cp: `U+${hex4(ch.codePointAt(0) ?? 0)}`, enc: encodeChar(ch, flavour, keepSet), total: 1 });
    }
    for (const [ch, v] of seen) rows.push({ ch, ...v });
    return rows.sort((a, b) => b.total - a.total || a.ch.codePointAt(0)! - b.ch.codePointAt(0)!);
  }, [input, flavour, keepSet]);

  const stats = useMemo(() => {
    const total = Array.from(input).filter((c) => !/[A-Za-z0-9]/.test(c)).length;
    return { total, distinct: diff.length, expanded: result.output.length - input.length };
  }, [input, diff, result.output]);

  const curlEquivalent = useMemo(() => {
    if (!input.trim()) return '';
    const encoded = mode === 'encode' ? result.output : encodeURIComponent(result.output);
    return `curl -s -o /dev/null -w '%{http_code}' 'http://example.com/search?q=${encoded}'`;
  }, [input, result.output, mode]);

  return (
    <>
      <Card title="Input">
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <Tabs<Mode>
            value={mode}
            onChange={setMode}
            tabs={[
              { value: 'encode', label: 'Encode' },
              { value: 'decode', label: 'Decode' },
            ]}
          />
          <div className="min-w-[300px] flex-1">
            <Select<Flavour> value={flavour} onChange={setFlavour} options={FLAVOURS} />
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-[1fr_220px]">
          <TextArea
            label={mode === 'encode' ? 'Raw text' : 'Encoded text'}
            value={input}
            onChange={setInput}
            rows={5}
            placeholder={mode === 'encode' ? '../../etc/passwd?x=1' : '%2e%2e%2f%2e%2e%2fetc%2fpasswd'}
          />
          <div>
            <TextInput
              label="Characters to keep"
              hint="Never escaped"
              value={keep}
              onChange={setKeep}
              mono
              placeholder=". / ="
            />
            <div className="mt-3 space-y-1 text-[11.5px] text-[var(--text-faint)]">
              <div>
                Non-alphanumeric characters: <span className="rf-mono">{stats.total}</span>
              </div>
              <div>
                Distinct forms: <span className="rf-mono">{stats.distinct}</span>
              </div>
              <div>
                Length change: <span className="rf-mono">{stats.expanded >= 0 ? `+${stats.expanded}` : stats.expanded}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-3">
          <Callout tone="info" title="Flavour note">
            {FLAVOUR_NOTE[flavour]}
          </Callout>
        </div>
      </Card>

      <Card title="Output">
        {result.error ? (
          <Callout tone="danger" title="Conversion failed">
            {result.error}
          </Callout>
        ) : (
          <OutputBlock value={result.output} rows={5} label={mode === 'encode' ? 'Encoded' : 'Decoded'} />
        )}
        <div className="mt-4">
          <CodeBlock code={curlEquivalent || '# Nothing to encode yet'} label="Probe request" maxHeight={120} />
        </div>
      </Card>

      <Card title="Per-character diff">
        {diff.length === 0 ? (
          <p className="m-0 text-[12.5px] text-[var(--text-faint)]">
            {input ? 'The input is entirely alphanumeric — nothing to escape.' : 'Type something above to see each escaped character.'}
          </p>
        ) : (
          <div className="max-h-[340px] overflow-auto rounded border border-[var(--card-border)]">
            <table className="w-full text-[12.5px]">
              <thead className="sticky top-0 bg-[var(--card)]">
                <tr className="text-left text-[var(--text-muted)]">
                  <th className="px-3 py-1.5 font-medium">Char</th>
                  <th className="px-3 py-1.5 font-medium">Code point</th>
                  <th className="px-3 py-1.5 font-medium">Encoded form</th>
                  <th className="px-3 py-1.5 text-right font-medium">Count</th>
                </tr>
              </thead>
              <tbody>
                {diff.map((row) => (
                  <tr key={row.ch} className="border-t border-[var(--card-border)]">
                    <td className="rf-mono px-3 py-1.5 text-[var(--accent)]">{row.ch === ' ' ? '␠ (space)' : row.ch}</td>
                    <td className="rf-mono px-3 py-1.5 text-[var(--text-muted)]">{row.cp}</td>
                    <td className="rf-mono px-3 py-1.5 break-all text-[var(--text)]">{row.enc}</td>
                    <td className="rf-mono px-3 py-1.5 text-right text-[var(--text-muted)]">{row.total}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Cross-flavour reference">
        <p className="mt-0 mb-3 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
          The same byte, five ways. Useful when a filter normalises one form but not the other four.
        </p>
        <KVTable
          rows={[
            ['Percent', '%2E%2E%2F'],
            ['Double encoded', '%252E%252E%252F'],
            ['Unicode escape', '\\u002e\\u002e\\u002f'],
            ['IIS %u form', '%u002e%u002e%u002f'],
            ['HTML entity', '&#x2E;&#x2E;&#x2F;'],
            ['Overlong UTF-8', '%c0%ae%c0%ae%c0%af  (rejected by modern parsers, still seen in old Tomcat/IIS)'],
          ]}
        />
      </Card>
    </>
  );
}
