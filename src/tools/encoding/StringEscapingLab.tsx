import { useMemo, useState } from 'react';
import { Callout, Card, CopyChip, KVTable, OutputBlock, TextArea } from '@/components/ui';
import { utf8 } from '@/lib/bytes';

/* ── Escapers ────────────────────────────────────────────────────────────── */

function cEscape(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0) ?? 0;
    if (ch === '\\') out += '\\\\';
    else if (ch === '"') out += '\\"';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (c < 0x20 || c === 0x7f) out += `\\x${c.toString(16).padStart(2, '0')}`;
    else if (c > 0x7e) out += c > 0xffff ? `\\U${c.toString(16).padStart(8, '0')}` : `\\u${c.toString(16).padStart(4, '0')}`;
    else out += ch;
  }
  return `${out}"`;
}

function jsonEscape(s: string): string {
  return JSON.stringify(s).replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function templateEscape(s: string): string {
  const body = s
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\$\{/g, '\\${')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
  return `\`${body}\``;
}

function xmlEscape(s: string): string {
  return s
    .replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c] ?? c)
    .replace(/[\u0080-\uffff]/g, (c) => `&#x${c.charCodeAt(0).toString(16)};`);
}

function sqlStandard(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}

function sqlMysql(s: string): string {
  const body = s
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/\0/g, '\\0')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
    .replace(/\x1a/g, '\\Z');
  return `'${body}'`;
}

function shellSingle(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function shellDouble(s: string): string {
  const body = s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\$/g, '\\$').replace(/`/g, '\\`');
  return `"${body}"`;
}

function regexEscape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

function yamlDouble(s: string): string {
  const body = s
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
    .replace(/[\u0000-\u001f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
  return `"${body}"`;
}

function unicodeEscapes(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) out += `\\u${s.charCodeAt(i).toString(16).padStart(4, '0')}`;
  return out;
}

function windowsUnicode(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) out += `%u${s.charCodeAt(i).toString(16).toUpperCase().padStart(4, '0')}`;
  return out;
}

/* ── Unescapers ──────────────────────────────────────────────────────────── */

function cUnescape(s: string): string {
  return s.replace(/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[nrtbfv0'"\\])/g, (_m, g: string) => {
    switch (g[0]) {
      case 'n': return '\n';
      case 'r': return '\r';
      case 't': return '\t';
      case 'b': return '\b';
      case 'f': return '\f';
      case 'v': return '\v';
      case '0': return '\0';
      case 'x': return String.fromCharCode(parseInt(g.slice(1), 16));
      case 'u': return String.fromCharCode(parseInt(g.slice(1), 16));
      case 'U': return String.fromCodePoint(parseInt(g.slice(1), 16));
      default: return g;
    }
  });
}

const ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0', copy: '\u00a9', reg: '\u00ae', hellip: '\u2026',
};

function htmlUnescape(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (m, body: string) => {
    if (body[0] === '#') {
      const code = body[1].toLowerCase() === 'x' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : m;
    }
    return ENTITIES[body.toLowerCase()] ?? m;
  });
}

interface Detected {
  form: string;
  value: string;
  note: string;
}

function smartUnescape(raw: string): Detected {
  const s = raw.trim();
  if (!s) return { form: 'empty', value: '', note: 'Nothing to reverse.' };

  if (/^"[\s\S]*"$/.test(s)) {
    try {
      const parsed: unknown = JSON.parse(s);
      if (typeof parsed === 'string') return { form: 'JSON string', value: parsed, note: 'Parsed with JSON.parse — escapes and \\u sequences resolved.' };
    } catch {
      /* fall through: not JSON, probably a C or shell literal */
    }
  }

  if (/%u[0-9a-f]{4}/i.test(s)) {
    const decoded = s.replace(/%u([0-9a-f]{4})/gi, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16)));
    try {
      return { form: 'Windows %u escape', value: decodeURIComponent(decoded), note: 'Non-standard IIS/JavaScript escape, not RFC 3986.' };
    } catch {
      return { form: 'Windows %u escape', value: decoded, note: 'Partially decoded — the remaining percent sequences are not valid UTF-8.' };
    }
  }

  if (/^'[\s\S]*'$/.test(s)) {
    const inner = s.slice(1, -1).replace(/'\\''/g, "'");
    return { form: 'Shell single-quoted', value: inner, note: "Each embedded quote was closed and reopened as '\\''." };
  }

  if (/^"[\s\S]*"$/.test(s)) {
    const inner = s.slice(1, -1);
    return { form: 'C / shell double-quoted', value: cUnescape(inner), note: 'Backslash escapes resolved; $ and ` expansion is not simulated.' };
  }

  if (/&(#x?[0-9a-f]+|[a-z]+);/i.test(s)) {
    return { form: 'HTML / XML entities', value: htmlUnescape(s), note: 'Named entities and numeric code points resolved.' };
  }

  if (/%[0-9a-f]{2}/i.test(s)) {
    try {
      return { form: 'URL percent-encoding', value: decodeURIComponent(s), note: 'Decoded as UTF-8 percent-encoding.' };
    } catch {
      return { form: 'URL percent-encoding', value: s, note: 'Malformed percent sequence — left untouched.' };
    }
  }

  if (/\\[nrtbfv0xuU'"\\]/.test(s)) {
    return { form: 'C-style backslash escapes', value: cUnescape(s), note: 'Interpreted as a C string body without surrounding quotes.' };
  }

  return { form: 'plain text', value: s, note: 'No escaping pattern matched, so the input is returned unchanged.' };
}

export default function StringEscapingLab() {
  const [input, setInput] = useState('He said "hi" — don\'t panic\\n');
  const [pasted, setPasted] = useState('');

  const rows = useMemo(
    () => [
      { label: 'JSON', note: 'RFC 8259, non-ASCII forced to \\u', value: jsonEscape(input) },
      { label: 'JavaScript template', note: 'backtick literal', value: templateEscape(input) },
      { label: 'C string', note: 'double-quoted, \\xNN for controls', value: cEscape(input) },
      { label: 'SQL (standard)', note: 'quote doubling, ANSI', value: sqlStandard(input) },
      { label: 'SQL (MySQL)', note: 'backslash escapes, default mode', value: sqlMysql(input) },
      { label: 'XML / HTML', note: 'entities plus numeric non-ASCII', value: xmlEscape(input) },
      { label: 'Shell single-quoted', note: "POSIX, '\\'' splice", value: shellSingle(input) },
      { label: 'Shell double-quoted', note: '$ and ` neutralised', value: shellDouble(input) },
      { label: 'Regex', note: 'PCRE metacharacters', value: regexEscape(input) },
      { label: 'YAML double-quoted', note: 'flow scalar', value: yamlDouble(input) },
      { label: 'URL', note: 'encodeURIComponent', value: encodeURIComponent(input) },
      { label: 'Unicode \\uXXXX', note: 'UTF-16 code units', value: unicodeEscapes(input) },
      { label: 'Unicode %uXXXX', note: 'IIS / legacy JS', value: windowsUnicode(input) },
    ],
    [input],
  );

  const detected = useMemo(() => smartUnescape(pasted), [pasted]);
  const controls = Array.from(input).filter((c) => c.codePointAt(0)! < 0x20).length;
  const nonAscii = Array.from(input).filter((c) => (c.codePointAt(0) ?? 0) > 0x7e).length;

  return (
    <>
      <Card title="Input">
        <TextArea
          label="Raw string"
          value={input}
          onChange={setInput}
          rows={4}
          mono
          hint="Everything below is derived from this exact string, including control characters."
        />
        <div className="mt-4">
          <KVTable
            rows={[
              ['UTF-16 code units', String(input.length)],
              ['Code points', String(Array.from(input).length)],
              ['UTF-8 bytes', String(utf8(input).length)],
              ['Control characters', String(controls)],
              ['Non-ASCII characters', String(nonAscii)],
            ]}
          />
        </div>
      </Card>

      <Card title="Escaped forms">
        <div className="overflow-hidden rounded border border-[var(--card-border)]">
          {rows.map((r) => (
            <div
              key={r.label}
              className="grid gap-1.5 border-b border-[var(--card-border)] px-3 py-2.5 last:border-b-0 sm:grid-cols-[160px_1fr_auto] sm:items-start sm:gap-3"
            >
              <div className="min-w-0">
                <div className="text-[12.5px] text-[var(--text)]">{r.label}</div>
                <div className="text-[10.5px] leading-snug text-[var(--text-faint)]">{r.note}</div>
              </div>
              <pre className="rf-mono m-0 max-h-[112px] overflow-auto text-[11.5px] leading-relaxed break-all whitespace-pre-wrap text-[var(--text-muted)]">
                {r.value}
              </pre>
              <div className="justify-self-start sm:justify-self-end">
                <CopyChip text={r.value} label="copy" />
              </div>
            </div>
          ))}
        </div>
        <div className="mt-3">
          <Callout tone="warn" title="Delimiters are part of the output">
            Each row includes its own quoting so it can be pasted straight into the target language. A shell
            single-quoted value that itself contains a single quote is spliced as{' '}
            <span className="rf-mono">'…'\''…'</span> — that is three tokens to the shell, one to the program.
          </Callout>
        </div>
      </Card>

      <Card title="Unescape">
        <TextArea
          label="Paste an escaped string"
          value={pasted}
          onChange={setPasted}
          rows={4}
          mono
          placeholder={String.raw`"line one\nline two"  ·  %3Cscript%3E  ·  &#x3c;b&#x3e;`}
          hint="The form is detected from the delimiters and escape syntax, then reversed."
        />
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <span className="rounded border border-[var(--card-border)] px-2 py-0.5 text-[11px] text-[var(--text-muted)]">
            detected: {detected.form}
          </span>
          <span className="text-[11px] text-[var(--text-faint)]">{detected.note}</span>
        </div>
        <div className="mt-3">
          <OutputBlock value={detected.value} rows={5} label="Reversed value" empty="Paste something above to reverse it." />
        </div>
      </Card>

      <Card title="Context traps">
        <div className="space-y-3">
          <Callout tone="danger" title="Quote doubling is not universal">
            Standard SQL doubles the quote, MySQL additionally treats a backslash as an escape by default. Running the
            MySQL form against a server with <span className="rf-mono">NO_BACKSLASH_ESCAPES</span> leaves the backslash
            literal and changes the string.
          </Callout>
          <Callout tone="warn" title="Shell double quotes do not stop command substitution escape sequences">
            <span className="rf-mono">\$</span> and <span className="rf-mono">\`</span> are neutralised above, but a
            literal newline inside double quotes is preserved, not escaped. Use single quotes or ANSI-C{' '}
            <span className="rf-mono">$'…'</span> quoting when the value must stay one shell word.
          </Callout>
          <Callout tone="info" title="YAML has three scalar styles">
            Double-quoted flow scalars accept <span className="rf-mono">\n</span> and{' '}
            <span className="rf-mono">\uXXXX</span>; single-quoted scalars only double an embedded quote; plain scalars
            break on <span className="rf-mono">: </span> and <span className="rf-mono"> #</span>. The row above is the
            only one of the three that is always safe.
          </Callout>
        </div>
      </Card>
    </>
  );
}
