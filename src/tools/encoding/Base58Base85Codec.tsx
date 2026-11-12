import { useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, CopyChip, KVTable, OutputBlock, Select, Tabs, TextArea } from '@/components/ui';
import { fromHex, toHex } from '@/lib/crypto';
import { utf8, fromUtf8 } from '@/lib/bytes';

const B58_BTC = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_FLICKR = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
const Z85 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#';
const B91 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"';

type Scheme = 'b58btc' | 'b58flickr' | 'a85' | 'z85' | 'b91';
type Bad = Array<[number, string]>;

/* ── Base58: big-integer radix conversion ────────────────────────────────── */

function b58Encode(bytes: Uint8Array, alphabet: string): string {
  if (!bytes.length) return '';
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let num = 0n;
  for (const byte of bytes) num = num * 256n + BigInt(byte);
  let body = '';
  while (num > 0n) { body = alphabet[Number(num % 58n)] + body; num /= 58n; }
  return alphabet[0].repeat(zeros) + body;
}

function b58Decode(input: string, alphabet: string): { bytes: Uint8Array; bad: Bad } {
  const bad: Bad = [];
  let zeros = 0;
  while (zeros < input.length && input[zeros] === alphabet[0]) zeros++;
  let num = 0n;
  for (let i = 0; i < input.length; i++) {
    const idx = alphabet.indexOf(input[i]);
    if (idx < 0) { bad.push([i, input[i]]); continue; }
    num = num * 58n + BigInt(idx);
  }
  const body: number[] = [];
  while (num > 0n) { body.unshift(Number(num % 256n)); num /= 256n; }
  const out = new Uint8Array(zeros + body.length);
  out.set(body, zeros);
  return { bytes: out, bad };
}

/* ── Base85: 4 bytes ↔ 5 characters ──────────────────────────────────────── */

function a85Group(value: number): string {
  let x = value, out = '';
  for (let i = 0; i < 5; i++) { out = String.fromCharCode(33 + (x % 85)) + out; x = Math.floor(x / 85); }
  return out;
}

function a85Encode(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 4) {
    const n = Math.min(4, bytes.length - i);
    const p = [0, 0, 0, 0];
    for (let j = 0; j < n; j++) p[j] = bytes[i + j];
    const value = p[0] * 16777216 + p[1] * 65536 + p[2] * 256 + p[3];
    out += n === 4 && value === 0 ? 'z' : a85Group(value).slice(0, n + 1);
  }
  return out;
}

function a85Decode(input: string): { bytes: Uint8Array; bad: Bad } {
  const bad: Bad = [], out: number[] = [];
  let group: number[] = [];
  const flush = (final: boolean) => {
    const n = group.length;
    if (n < 2) { group = []; return; }
    const padded = [...group];
    while (padded.length < 5) padded.push(84);
    let value = 0;
    for (const d of padded) value = value * 85 + d;
    const quad = [Math.floor(value / 16777216) % 256, Math.floor(value / 65536) % 256, Math.floor(value / 256) % 256, value % 256];
    out.push(...quad.slice(0, final ? n - 1 : 4));
    group = [];
  };
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ch === 'z' && group.length === 0) { out.push(0, 0, 0, 0); continue; }
    const code = ch.charCodeAt(0);
    if (code < 33 || code > 117) { if (ch.trim()) bad.push([i, ch]); continue; }
    group.push(code - 33);
    if (group.length === 5) flush(false);
  }
  flush(true);
  return { bytes: new Uint8Array(out), bad };
}

function z85Encode(bytes: Uint8Array): { out: string; pad: number } {
  const pad = (4 - (bytes.length % 4)) % 4;
  const padded = new Uint8Array(bytes.length + pad);
  padded.set(bytes);
  let out = '';
  for (let i = 0; i < padded.length; i += 4) {
    let v = padded[i] * 16777216 + padded[i + 1] * 65536 + padded[i + 2] * 256 + padded[i + 3];
    let chunk = '';
    for (let j = 0; j < 5; j++) { chunk = Z85[v % 85] + chunk; v = Math.floor(v / 85); }
    out += chunk;
  }
  return { out, pad };
}

function z85Decode(input: string): { bytes: Uint8Array; bad: Bad } {
  const bad: Bad = [], out: number[] = [];
  for (let i = 0; i < input.length; i += 5) {
    const chunk = input.slice(i, i + 5);
    if (chunk.length < 5) { bad.push([i, chunk]); break; }
    let value = 0, broken = false;
    for (let j = 0; j < 5; j++) {
      const idx = Z85.indexOf(chunk[j]);
      if (idx < 0) { bad.push([i + j, chunk[j]]); broken = true; break; }
      value = value * 85 + idx;
    }
    if (broken) continue;
    out.push(Math.floor(value / 16777216) % 256, Math.floor(value / 65536) % 256, Math.floor(value / 256) % 256, value % 256);
  }
  return { bytes: new Uint8Array(out), bad };
}

/* ── basE91 ──────────────────────────────────────────────────────────────── */

function b91Encode(bytes: Uint8Array): string {
  let out = '', b = 0, n = 0;
  for (const byte of bytes) {
    b |= byte << n;
    n += 8;
    if (n > 13) {
      let v = b & 8191;
      if (v > 88) { b >>= 13; n -= 13; } else { v = b & 16383; b >>= 14; n -= 14; }
      out += B91[v % 91] + B91[Math.floor(v / 91)];
    }
  }
  if (n) {
    out += B91[b % 91];
    if (n > 7 || b > 90) out += B91[Math.floor(b / 91)];
  }
  return out;
}

function b91Decode(input: string): { bytes: Uint8Array; bad: Bad } {
  const bad: Bad = [], out: number[] = [];
  let b = 0, n = 0, v = -1;
  for (let i = 0; i < input.length; i++) {
    const d = B91.indexOf(input[i]);
    if (d < 0) { bad.push([i, input[i]]); continue; }
    if (v < 0) { v = d; continue; }
    v += d * 91;
    b |= v << n;
    n += (v & 8191) > 88 ? 13 : 14;
    while (n > 7) { out.push(b & 255); b >>= 8; n -= 8; }
    v = -1;
  }
  if (v >= 0) out.push((b | (v << n)) & 255);
  return { bytes: new Uint8Array(out), bad };
}

function detect(input: string): Scheme | null {
  if (!input) return null;
  const chars = [...input];
  if (chars.every((c) => B58_BTC.includes(c))) return 'b58btc';
  if (chars.every((c) => B58_FLICKR.includes(c))) return 'b58flickr';
  if (input.length % 5 === 0 && chars.every((c) => Z85.includes(c))) return 'z85';
  if (chars.every((c) => c === 'z' || (c >= '!' && c <= 'u'))) return 'a85';
  if (chars.every((c) => B91.includes(c))) return 'b91';
  return null;
}

const SCHEMES: Array<{ value: Scheme; label: string }> = [
  { value: 'b58btc', label: 'Base58 — Bitcoin' },
  { value: 'b58flickr', label: 'Base58 — Flickr' },
  { value: 'a85', label: 'Base85 — ASCII85' },
  { value: 'z85', label: 'Base85 — Z85 (RFC 1924)' },
  { value: 'b91', label: 'Base91' },
];

function encodeWith(scheme: Scheme, bytes: Uint8Array): { out: string; pad: number } {
  if (scheme === 'z85') return z85Encode(bytes);
  if (scheme === 'a85') return { out: a85Encode(bytes), pad: 0 };
  if (scheme === 'b91') return { out: b91Encode(bytes), pad: 0 };
  return { out: b58Encode(bytes, scheme === 'b58btc' ? B58_BTC : B58_FLICKR), pad: 0 };
}

function decodeWith(scheme: Scheme, text: string): { bytes: Uint8Array; bad: Bad } {
  if (scheme === 'z85') return z85Decode(text);
  if (scheme === 'a85') return a85Decode(text);
  if (scheme === 'b91') return b91Decode(text);
  return b58Decode(text, scheme === 'b58btc' ? B58_BTC : B58_FLICKR);
}

interface Outcome { output: string; bad: Bad; bytes: number; chars: number; note: string; roundTrip: string; error: string | null }

export default function Base58Base85Codec() {
  const [input, setInput] = useState('RedForge');
  const [scheme, setScheme] = useState<Scheme>('b58btc');
  const [direction, setDirection] = useState<'encode' | 'decode'>('encode');
  const [hexInput, setHexInput] = useState(false);
  const guess = detect(input.trim());

  const result = useMemo<Outcome>(() => {
    const text = input.trim();
    const blank: Outcome = { output: '', bad: [], bytes: 0, chars: 0, note: '', roundTrip: '', error: null };
    if (!text) return blank;
    try {
      if (direction === 'encode') {
        let bytes: Uint8Array;
        if (hexInput) {
          if (!/^[0-9a-f\s]+$/i.test(text) || text.replace(/\s/g, '').length % 2 !== 0) return { ...blank, error: 'Hex input must be an even number of hexadecimal digits.' };
          bytes = fromHex(text);
        } else bytes = utf8(input);
        const { out, pad } = encodeWith(scheme, bytes);
        const back = decodeWith(scheme, out).bytes;
        const ok = back.length >= bytes.length && [...bytes].every((b, i) => back[i] === b);
        return {
          output: out, bad: [], bytes: bytes.length, chars: out.length,
          note: pad ? `Z85 works in 4-byte blocks — ${pad} zero byte(s) of block padding added.` : '',
          roundTrip: ok ? `✓ decodes back to the original ${bytes.length} byte(s)${pad ? ` (plus ${pad} padding byte(s))` : ''}` : '✗ round trip does not reproduce the input',
          error: null,
        };
      }
      if (scheme === 'z85' && text.length % 5 !== 0) return { ...blank, error: 'Z85 input length must be a multiple of five characters.' };
      const { bytes, bad } = decodeWith(scheme, text);
      const printed = fromUtf8(bytes);
      const printable = /^[\x09\x0a\x0d\x20-\x7e]*$/.test(printed);
      return {
        output: hexInput ? toHex(bytes) : printable ? printed : toHex(bytes),
        bad, bytes: bytes.length, chars: text.length,
        note: !hexInput && !printable ? 'Decoded bytes are not printable UTF-8 — shown as hex.' : '',
        roundTrip: `✓ ${bytes.length} byte(s) recovered from ${text.length} character(s)`,
        error: null,
      };
    } catch (err) {
      return { ...blank, error: err instanceof Error ? err.message : String(err) };
    }
  }, [input, scheme, direction, hexInput]);

  const ratio = result.bytes > 0 ? result.chars / result.bytes : 0;

  return (
    <>
      <Card title="Input">
        <Tabs value={direction} onChange={setDirection} tabs={[{ value: 'encode', label: 'Encode' }, { value: 'decode', label: 'Decode' }]} />
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <Select<Scheme> label="Base encoding" value={scheme} onChange={setScheme} options={SCHEMES} />
          <Select<'text' | 'hex'>
            label={direction === 'encode' ? 'Input bytes' : 'Output bytes'}
            value={hexInput ? 'hex' : 'text'}
            onChange={(v) => setHexInput(v === 'hex')}
            options={[{ value: 'text', label: 'UTF-8 text' }, { value: 'hex', label: 'Hex bytes' }]}
          />
        </div>
        <div className="mt-4">
          <TextArea
            label={direction === 'encode' ? 'Plaintext' : 'Encoded string'}
            value={input}
            onChange={setInput}
            rows={4}
            mono
            hint={guess ? `looks like ${SCHEMES.find((s) => s.value === guess)?.label ?? guess}` : 'no alphabet matched the characters in this string'}
          />
        </div>
        {guess && guess !== scheme && (
          <div className="mt-3 flex items-center justify-between gap-3 rounded border border-[var(--card-border)] px-3 py-2">
            <span className="text-[12px] text-[var(--text-muted)]">
              Auto-detect suggests <span className="rf-mono">{SCHEMES.find((s) => s.value === guess)?.label}</span>.
            </span>
            <button type="button" className="text-[12px] font-medium" style={{ color: 'var(--accent)' }} onClick={() => setScheme(guess)}>use it</button>
          </div>
        )}
      </Card>

      <Card title={direction === 'encode' ? 'Encoded output' : 'Decoded output'}>
        {result.error ? (
          <Callout tone="danger" title="Cannot convert">{result.error}</Callout>
        ) : (
          <>
            <OutputBlock value={result.output} rows={6} label={SCHEMES.find((s) => s.value === scheme)?.label} />
            {result.bad.length > 0 && (
              <div className="mt-3">
                <Callout tone="warn" title={`${result.bad.length} invalid character(s) skipped`}>
                  <div className="flex flex-wrap gap-1.5">
                    {result.bad.slice(0, 24).map(([at, ch], i) => (
                      <span key={i} className="rf-mono rounded border border-[var(--card-border)] px-1.5 py-0.5 text-[11px]">offset {at}: {JSON.stringify(ch)}</span>
                    ))}
                  </div>
                </Callout>
              </div>
            )}
            {result.note && <p className="mt-3 mb-0 text-[11.5px] text-[var(--text-faint)]">{result.note}</p>}
            <p className="mt-2 mb-0 text-[11.5px]" style={{ color: result.roundTrip.startsWith('✓') ? 'var(--ok)' : 'var(--warn)' }}>{result.roundTrip}</p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <CopyChip text={result.output} label="copy output" />
              <span className="text-[11px] text-[var(--text-faint)]">{result.bytes} bytes · {result.chars} chars · {result.bytes ? ratio.toFixed(3) : '—'} chars/byte</span>
            </div>
          </>
        )}
      </Card>

      <Card title="Byte accounting and alphabets">
        <KVTable
          rows={[
            [direction === 'encode' ? 'Input bytes' : 'Recovered bytes', String(result.bytes)],
            [direction === 'encode' ? 'Output characters' : 'Input characters', String(result.chars)],
            ['Characters per byte', result.bytes ? ratio.toFixed(3) : '—'],
            ['Overhead vs raw', result.bytes ? `${((ratio - 1) * 100).toFixed(1)}%` : '—'],
            ['Invalid characters', String(result.bad.length)],
          ]}
        />
        <div className="mt-4">
          <CodeBlock
            label="Alphabets in use"
            code={[`base58btc    ${B58_BTC}`, `base58flickr ${B58_FLICKR}`, `z85          ${Z85}`, `base91       ${B91}`].join('\n')}
          />
        </div>
        <div className="mt-3">
          <Callout tone="info" title="Density versus survivability">
            Base58 costs about 1.37 characters per byte, ASCII85 and Z85 exactly 1.25, basE91 about 1.23. The denser
            alphabets are harder to read aloud and easier for shell, SQL and CSV layers to mangle, which is why Base58
            survives in wallet addresses despite the size penalty. ASCII85 also collapses four zero bytes into a single{' '}
            <span className="rf-mono">z</span>, so its ratio improves on sparse binary.
          </Callout>
        </div>
      </Card>
    </>
  );
}
