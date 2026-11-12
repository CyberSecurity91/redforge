import { useMemo, useState } from 'react';
import {
  Button,
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  CopyChip,
  KVTable,
  OutputBlock,
  OutputField,
  SectionTitle,
  Tabs,
  TextArea,
} from '@/components/ui';
import { b64Encode } from '@/lib/encoding';

/**
 * MIME quoted-printable, both directions.
 *
 * The encoder is deliberately the *conservative* one: RFC 2045 §6.7 allows a much
 * laxer encoder than it requires of decoders, and the disagreements between mail
 * parsers all live in that gap — so every byte this tool leaves literal is a byte a
 * parser cannot argue about.
 */

const CRLF = '\r\n';
const SOFT_LIMIT = 76;
const HARD_LIMIT = 78;

/** RFC 2045 printable range, minus `=` which is the escape introducer. */
function isLiteral(code: number): boolean {
  if (code === 0x3d) return false; // '='
  if (code === 0x09) return true; // TAB is legal mid-line
  return code >= 0x21 && code <= 0x7e;
}

const hex2 = (b: number) => b.toString(16).toUpperCase().padStart(2, '0');

type EncodeResult = { text: string; warnings: string[] };

/**
 * Encode to quoted-printable with soft breaks. `crlf` selects CRLF (wire format)
 * or LF (what a unix-local .eml ends up with after a naive save).
 */
function encodeQp(input: string, opts: { crlf: boolean; encodeTrailingWs: boolean; dotStuff: boolean }): EncodeResult {
  const eol = opts.crlf ? CRLF : '\n';
  const warnings: string[] = [];
  const lines = input.split(/\r\n|\r|\n/);
  const out: string[] = [];

  lines.forEach((line, li) => {
    let current = '';
    let pending = ''; // whitespace held back so a line-end space can be escaped
    const flush = () => {
      if (pending) {
        current += pending;
        pending = '';
      }
    };

    for (const ch of line) {
      const code = ch.codePointAt(0) ?? 0;
      const bytes = new TextEncoder().encode(ch);
      let piece = '';
      if (isLiteral(code) && bytes.length === 1) {
        piece = ch;
      } else if (code === 0x20) {
        // Space stays literal unless it would land at end of line; hold it back.
        pending += ' ';
        continue;
      } else if (code === 0x09) {
        pending += '\t';
        continue;
      } else {
        piece = Array.from(bytes, (b) => `=${hex2(b)}`).join('');
      }
      flush();
      if (current.length + piece.length > SOFT_LIMIT) {
        out.push(`${current}=`);
        current = '';
      }
      current += piece;
    }

    if (pending) {
      if (opts.encodeTrailingWs) {
        flush();
        current += Array.from(pending, (c) => (c === '\t' ? '=09' : '=20')).join('');
      } else {
        current += pending;
        warnings.push(`Line ${li + 1}: trailing whitespace left literal — MTAs may strip it. Enable “escape trailing whitespace” for wire-safe output.`);
      }
    }
    if (opts.dotStuff && current.startsWith('.')) {
      current = `.${current}`;
      warnings.push(`Line ${li + 1}: dot-stuffed for SMTP transparency.`);
    }
    out.push(current);
  });

  return { text: out.join(eol), warnings };
}

type DecodeIssue = { offset: number; line: number; text: string; severity: 'error' | 'warn' };

type DecodeResult = { text: string; issues: DecodeIssue[]; bytes: number };

/** Decode quoted-printable. Lenient mode repairs what strict mode reports. */
function decodeQp(input: string, lenient: boolean): DecodeResult {
  const issues: DecodeIssue[] = [];
  const bytes: number[] = [];
  const src = input.replace(/\r\n/g, '\n');
  let line = 1;

  for (let i = 0; i < src.length; i += 1) {
    const ch = src[i];
    if (ch === '\n') {
      bytes.push(0x0a);
      line += 1;
      continue;
    }
    if (ch !== '=') {
      bytes.push(...new TextEncoder().encode(ch));
      continue;
    }
    const next = src[i + 1];
    const after = src[i + 2];
    if (next === undefined) {
      issues.push({ offset: i, line, text: 'Stray "=" at end of input', severity: 'error' });
      if (!lenient) bytes.push(0x3d);
      continue;
    }
    if (next === '\n') {
      i += 1; // soft break — the newline itself disappears
      continue;
    }
    if (/[0-9A-Fa-f]/.test(next) && after !== undefined && /[0-9A-Fa-f]/.test(after)) {
      bytes.push(parseInt(next + after, 16));
      i += 2;
      continue;
    }
    const snippet = `=${next}${after ?? ''}`.slice(0, 6);
    issues.push({ offset: i, line, text: `Invalid hex escape ${JSON.stringify(snippet)}`, severity: 'error' });
    if (!lenient) bytes.push(0x3d);
    else bytes.push(0x3d, next.charCodeAt(0));
  }

  let text = '';
  try {
    text = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
  } catch {
    text = '';
  }
  const guard = text.indexOf('\uFFFD');
  if (guard >= 0) issues.push({ offset: guard, line: 1, text: 'Invalid UTF-8 in decoded bytes (replacement char inserted)', severity: 'warn' });
  return { text, issues, bytes: bytes.length };
}

/** Side-by-side byte inspection: offset, raw byte, and what each side calls it. */
function diffBytes(original: string, encoded: string) {
  const a = new TextEncoder().encode(original);
  const b = new TextEncoder().encode(encoded);
  const rows: Array<[string, string, string]> = [];
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const av = a[i];
    const bv = b[i];
    if (av === bv) continue;
    rows.push([
      String(i),
      av === undefined ? '—' : `${hex2(av)} ${String.fromCharCode(av)}`,
      bv === undefined ? '—' : `${hex2(bv)} ${String.fromCharCode(bv)}`,
    ]);
    if (rows.length >= 40) break;
  }
  return { rows, aLen: a.length, bLen: b.length };
}

const SAMPLE = 'Grüße aus dem Labor — the = sign, a tab\there, and a soft hyphen\u00ad inside.';

export default function QuotedPrintableCodec() {
  const [mode, setMode] = useState<'encode' | 'decode'>('encode');
  const [raw, setRaw] = useState(SAMPLE);
  const [crlf, setCrlf] = useState(true);
  const [trailing, setTrailing] = useState(true);
  const [dotStuff, setDotStuff] = useState(false);
  const [lenient, setLenient] = useState(false);

  const encoded = useMemo(
    () => encodeQp(raw, { crlf, encodeTrailingWs: trailing, dotStuff }),
    [raw, crlf, trailing, dotStuff],
  );

  const decoded = useMemo(() => decodeQp(raw, lenient), [raw, lenient]);

  const result = mode === 'encode' ? encoded.text : decoded.text;
  const diff = useMemo(() => (mode === 'encode' ? diffBytes(raw, encoded.text) : null), [mode, raw, encoded.text]);
  const base64 = useMemo(() => b64Encode(new TextEncoder().encode(raw)), [raw]);

  const bodyBytes = new TextEncoder().encode(result).length;
  const longLines = result.split(/\r\n|\n/).filter((l) => l.length > HARD_LIMIT).length;

  return (
    <>
      <Card title="Direction and source">
        <Tabs<'encode' | 'decode'>
          value={mode}
          onChange={setMode}
          tabs={[
            { value: 'encode', label: 'Encode to quoted-printable' },
            { value: 'decode', label: 'Decode from quoted-printable' },
          ]}
        />
        <div className="mt-4">
          <TextArea
            label={mode === 'encode' ? 'Plain text' : 'Quoted-printable body'}
            value={raw}
            onChange={setRaw}
            rows={6}
            mono={mode === 'decode'}
            hint={mode === 'encode' ? `${new TextEncoder().encode(raw).length} UTF-8 bytes in` : 'Paste the encoded body including any soft breaks'}
          />
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          {mode === 'encode' ? (
            <>
              <Checkbox checked={crlf} onChange={setCrlf} label="CRLF line endings" description="Wire format; unset for LF .eml files" />
              <Checkbox checked={trailing} onChange={setTrailing} label="Escape trailing whitespace" description="=20 / =09 at end of line" />
              <Checkbox checked={dotStuff} onChange={setDotStuff} label="Dot-stuff lines" description="SMTP transparency for a leading '.'" />
            </>
          ) : (
            <Checkbox checked={lenient} onChange={setLenient} label="Lenient decode" description="Keep stray '=' and invalid escapes instead of reporting only" />
          )}
        </div>
      </Card>

      <Card
        title={mode === 'encode' ? 'Encoded output' : 'Decoded output'}
        action={<CopyChip text={result} label="Copy" />}
      >
        <OutputBlock
          value={result}
          rows={8}
          label={mode === 'encode' ? 'quoted-printable' : 'text/plain; charset=utf-8'}
          empty={mode === 'encode' ? 'Type something above — an empty body encodes to an empty string.' : 'Paste a quoted-printable body to decode.'}
        />
        <div className="mt-4">
          <KVTable
            rows={[
              ['Body bytes', `${bodyBytes}`],
              ['Soft breaks used', `${(result.match(/=\r?\n/g) ?? []).length}`],
              ['Lines over 78 chars', longLines === 0 ? '0 — within RFC 5322 §2.1.1' : `${longLines} — some MTAs will fold these`],
              ...(mode === 'decode'
                ? ([
                    ['Issues', `${decoded.issues.length}`],
                    ['Decoded bytes', `${decoded.bytes}`],
                  ] as Array<[string, string]>)
                : []),
            ]}
          />
        </div>
        {mode === 'decode' && decoded.issues.length > 0 && (
          <div className="mt-4">
            <SectionTitle>Decoder issues</SectionTitle>
            <div className="overflow-x-auto rounded border border-[var(--card-border)]">
              <table className="w-full text-[12px]">
                <thead>
                  <tr className="bg-[var(--neutral-btn)] text-left text-[var(--text-muted)]">
                    {['line', 'offset', 'severity', 'detail'].map((h) => (
                      <th key={h} className="px-2.5 py-1.5 font-medium whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {decoded.issues.map((it, i) => (
                    <tr key={`${it.offset}-${i}`} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                      <td className="rf-mono px-2.5 py-1.5">{it.line}</td>
                      <td className="rf-mono px-2.5 py-1.5">{it.offset}</td>
                      <td className="px-2.5 py-1.5" style={{ color: it.severity === 'error' ? 'var(--accent)' : 'var(--warn)' }}>
                        {it.severity}
                      </td>
                      <td className="px-2.5 py-1.5">{it.text}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
        {mode === 'encode' && encoded.warnings.length > 0 && (
          <div className="mt-3 text-[11.5px] text-[var(--warn)]">
            {encoded.warnings.slice(0, 3).map((w, i) => (
              <div key={i}>▲ {w}</div>
            ))}
          </div>
        )}
      </Card>

      {mode === 'encode' && (
        <Card title="Byte-level diff">
          {!diff || diff.rows.length === 0 ? (
            <div className="text-[12px] text-[var(--text-faint)]">
              No byte divergence in the first {diff?.aLen ?? 0} bytes — the input was already printable ASCII.
            </div>
          ) : (
            <>
              <div className="mb-3 flex flex-wrap gap-2 text-[11.5px] text-[var(--text-muted)]">
                <span className="rounded border border-[var(--card-border)] px-2 py-0.5">input {diff.aLen} B</span>
                <span className="rounded border border-[var(--card-border)] px-2 py-0.5">encoded {diff.bLen} B</span>
                <span className="rounded border border-[var(--card-border)] px-2 py-0.5">×{(diff.bLen / Math.max(1, diff.aLen)).toFixed(2)} expansion</span>
              </div>
              <div className="overflow-x-auto rounded border border-[var(--card-border)]">
                <table className="w-full text-[12px]">
                  <thead>
                    <tr className="bg-[var(--neutral-btn)] text-left text-[var(--text-muted)]">
                      {['offset', 'input byte', 'encoded byte'].map((h) => (
                        <th key={h} className="px-2.5 py-1.5 font-medium whitespace-nowrap">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {diff.rows.map((r, i) => (
                      <tr key={r[0]} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                        <td className="rf-mono px-2.5 py-1.5">{r[0]}</td>
                        <td className="rf-mono px-2.5 py-1.5">{r[1]}</td>
                        <td className="rf-mono px-2.5 py-1.5">{r[2]}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </Card>
      )}

      <Card title="Headers and alternatives">
        <CodeBlock
          code={`Content-Type: text/plain; charset=utf-8; format=flowed\r
Content-Transfer-Encoding: quoted-printable\r
MIME-Version: 1.0\r
\r
${result.split(/\r?\n/).slice(0, 4).join(CRLF)}`}
          label="MIME block"
          maxHeight={140}
        />
        <div className="mt-3">
          <Callout tone="info" title="format=flowed is not quoted-printable">
            The two are independent. <span className="rf-mono">format=flowed</span> treats a line ending in a single space as
            &ldquo;continue on the next line&rdquo; — which is exactly the trailing space that quoted-printable then escapes
            as <span className="rf-mono">=20</span>, so a flowed body usually carries both. A parser that honours flowed but
            ignores the escape will silently glue paragraphs together.
          </Callout>
        </div>
        <div className="mt-4">
          <OutputField label="Base64 alternative (same bytes)" value={base64} mono />
        </div>
        <div className="mt-3">
          <OutputField label="Command to verify with a real decoder" value={`printf '%s' <encoded> | perl -MMIME::QuotedPrint -0777 -ne 'print decode_qp($_)'`} mono />
        </div>
        <div className="mt-4">
          <Callout tone="warn" title="What MIME parsers disagree about">
            <ul className="list-disc space-y-1 pl-4">
              <li>Stray <span className="rf-mono">=</span> not followed by two hex digits: RFC 2045 says the decoder must
                treat it as literal, several parsers drop the character and the rest of the line.</li>
              <li>A soft break at exactly 76 characters versus 78: encoders may break anywhere ≤76, so a decoder that
                hard-wraps incoming text corrupts already-encoded bodies.</li>
              <li>Trailing whitespace: unescaped spaces are legal on the wire and are stripped by most MTAs, so a body
                that relies on them parses differently at each hop.</li>
              <li>Mixed <span className="rf-mono">\r\n</span> and <span className="rf-mono">\n</span>: the raw newline is
                preserved by strict decoders and normalised by lenient ones.</li>
              <li>Binary payloads carried in quoted-printable (a signature block, an embedded key): decoders that assume
                charset conversion will mangle every byte above 0x7f.</li>
            </ul>
          </Callout>
        </div>
        <div className="mt-4 flex gap-2">
          <Button onClick={() => setRaw(SAMPLE)}>Load sample</Button>
          <Button variant="ghost" onClick={() => setRaw('')}>
            Clear
          </Button>
        </div>
      </Card>
    </>
  );
}
