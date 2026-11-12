import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  CodeBlock,
  CopyChip,
  KVTable,
  Select,
  Slider,
  Tabs,
  TextArea,
  TextInput,
} from '@/components/ui';
import { b64Decode } from '@/lib/encoding';

type InputFormat = 'hex' | 'base64' | 'plain';
type Mode = 'single' | 'repeating-known' | 'repeating-unknown' | 'key-calc';

const FREQ: Record<string, number> = {
  ' ': 12.7, e: 12.7, t: 9.1, a: 8.2, o: 7.5, i: 7.0, n: 6.7, s: 6.3, h: 6.1, r: 6.0,
  d: 4.3, l: 4.0, c: 2.8, u: 2.8, m: 2.4, w: 2.4, f: 2.2, g: 2.0, y: 2.0, p: 1.9,
  b: 1.5, v: 1.0, k: 0.8, j: 0.15, x: 0.15, q: 0.1, z: 0.07,
};

function scoreEnglish(bytes: Uint8Array): number {
  let score = 0;
  for (const b of bytes) {
    const ch = String.fromCharCode(b).toLowerCase();
    if (FREQ[ch]) score += FREQ[ch];
    else if (b >= 32 && b < 127) score += 0.2;
    else if (b === 9 || b === 10 || b === 13) score += 0.5;
    else score -= 12;
  }
  return score;
}

function preview(bytes: Uint8Array, max = 64): string {
  return Array.from(bytes.slice(0, max), (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '·')).join('');
}

function xorRepeat(bytes: Uint8Array, key: Uint8Array): Uint8Array {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i += 1) out[i] = bytes[i] ^ key[i % key.length];
  return out;
}

function parseInput(value: string, format: InputFormat): Uint8Array {
  if (format === 'hex') {
    const clean = value.replace(/[^0-9a-fA-F]/g, '');
    const out = new Uint8Array(Math.floor(clean.length / 2));
    for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  if (format === 'base64') return b64Decode(value.trim());
  return new TextEncoder().encode(value);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function asciiOf(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
}

/** Hamming distance between two byte arrays — the classic keysize oracle. */
function hamming(a: Uint8Array, b: Uint8Array): number {
  let d = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    let x = a[i] ^ b[i];
    while (x) {
      d += x & 1;
      x >>= 1;
    }
  }
  return d;
}

/** Index of coincidence over printable characters, normalised 0..1. */
function indexOfCoincidence(bytes: Uint8Array): number {
  const counts = new Array<number>(256).fill(0);
  for (const b of bytes) counts[b] += 1;
  const n = bytes.length;
  if (n < 2) return 0;
  let sum = 0;
  for (const c of counts) sum += c * (c - 1);
  return sum / (n * (n - 1));
}

export default function XorCracker() {
  const [mode, setMode] = useState<Mode>('single');
  const [format, setFormat] = useState<InputFormat>('hex');
  const [input, setInput] = useState(
    '1d0f0a1b1c43545c1a0b1d0f0a1b1c43350d1a1b0c5c1a0b1d0f0a1b1c43',
  );
  const [knownKey, setKnownKey] = useState('redforge');
  const [maxKeyLen, setMaxKeyLen] = useState(16);
  const [calcInput, setCalcInput] = useState('41 42 43');
  const [calcKey, setCalcKey] = useState('0f');

  const bytes = useMemo(() => {
    try {
      return { data: parseInput(input, format), error: '' };
    } catch (e) {
      return { data: new Uint8Array(), error: (e as Error).message || 'Cannot decode input.' };
    }
  }, [input, format]);

  const singleByte = useMemo(() => {
    if (mode !== 'single' || bytes.data.length === 0) return [];
    const results: Array<{ key: number; score: number; text: string }> = [];
    for (let k = 0; k < 256; k += 1) {
      const out = new Uint8Array(bytes.data.length);
      for (let i = 0; i < out.length; i += 1) out[i] = bytes.data[i] ^ k;
      results.push({ key: k, score: scoreEnglish(out), text: preview(out, 72) });
    }
    return results.sort((a, b) => b.score - a.score).slice(0, 10);
  }, [mode, bytes.data]);

  const knownResult = useMemo(() => {
    if (mode !== 'repeating-known' || !knownKey) return new Uint8Array();
    return xorRepeat(bytes.data, new TextEncoder().encode(knownKey));
  }, [mode, bytes.data, knownKey]);

  const unknown = useMemo(() => {
    if (mode !== 'repeating-unknown' || bytes.data.length < 8) return null;
    const data = bytes.data;
    const candidates: Array<{ len: number; distance: number; ic: number }> = [];
    for (let len = 1; len <= Math.min(maxKeyLen, Math.floor(data.length / 2)); len += 1) {
      let dist = 0;
      let blocks = 0;
      for (let i = 0; i + 2 * len <= data.length && blocks < 8; i += len, blocks += 1) {
        dist += hamming(data.slice(i, i + len), data.slice(i + len, i + 2 * len)) / len;
      }
      const normalised = blocks ? dist / blocks : Infinity;
      // Index of coincidence on the transposed column at this length.
      let ic = 0;
      for (let col = 0; col < len; col += 1) {
        const values: number[] = [];
        for (let i = col; i < data.length; i += len) values.push(data[i]);
        ic += indexOfCoincidence(Uint8Array.from(values));
      }
      candidates.push({ len, distance: normalised, ic: ic / len });
    }
    const bestLen = [...candidates].sort((a, b) => a.distance - b.distance)[0]?.len ?? 1;
    const key = new Uint8Array(bestLen);
    for (let col = 0; col < bestLen; col += 1) {
      const column: number[] = [];
      for (let i = col; i < data.length; i += bestLen) column.push(data[i]);
      let best = 0;
      let bestScore = -Infinity;
      for (let k = 0; k < 256; k += 1) {
        const decoded = Uint8Array.from(column, (b) => b ^ k);
        const s = scoreEnglish(decoded);
        if (s > bestScore) {
          bestScore = s;
          best = k;
        }
      }
      key[col] = best;
    }
    return { candidates: candidates.slice(0, 6), key, plaintext: xorRepeat(data, key), bestLen };
  }, [mode, bytes.data, maxKeyLen]);

  const calc = useMemo(() => {
    const toBytes = (value: string) => {
      const clean = value.replace(/0x/gi, '').replace(/[^0-9a-fA-F\s,]/g, '').replace(/[\s,]+/g, '');
      if (clean.length % 2 !== 0) return null;
      const out = new Uint8Array(clean.length / 2);
      for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
      return out;
    };
    const a = toBytes(calcInput);
    const k = toBytes(calcKey);
    if (!a || !k || k.length === 0) return null;
    return xorRepeat(a, k);
  }, [calcInput, calcKey]);

  const keyHex = unknown ? bytesToHex(unknown.key) : '';
  const keyAscii = unknown ? asciiOf(unknown.key) : '';

  return (
    <>
      <Card title="Mode">
        <Tabs
          value={mode}
          onChange={setMode}
          tabs={[
            { value: 'single', label: 'Single-byte brute' },
            { value: 'repeating-known', label: 'Repeating key (known)' },
            { value: 'repeating-unknown', label: 'Repeating key (unknown)' },
            { value: 'key-calc', label: 'Hex / XOR calculator' },
          ]}
        />
        {mode !== 'key-calc' && (
          <>
            <div className="mt-4 grid gap-4 sm:grid-cols-3">
              <Select
                label="Input format"
                value={format}
                onChange={setFormat}
                options={[
                  { value: 'hex', label: 'Hex' },
                  { value: 'base64', label: 'Base64' },
                  { value: 'plain', label: 'Plain text' },
                ]}
              />
              {mode === 'repeating-known' && (
                <TextInput label="Key" value={knownKey} onChange={setKnownKey} mono />
              )}
              {mode === 'repeating-unknown' && (
                <div className="sm:col-span-2">
                  <Slider
                    label="Max key length"
                    value={maxKeyLen}
                    onChange={setMaxKeyLen}
                    min={2}
                    max={40}
                    format={(v) => `${v} bytes`}
                  />
                </div>
              )}
            </div>
            <div className="mt-4">
              <TextArea value={input} onChange={setInput} rows={6} label="Ciphertext" hint={`${bytes.data.length} bytes`} />
            </div>
            {bytes.error && <div className="mt-2 text-[11.5px] text-[var(--warn,#eab308)]">{bytes.error}</div>}
          </>
        )}
      </Card>

      {mode === 'single' && (
        <Card title="Top 10 keys" action={<CopyChip text={singleByte[0]?.text ?? ''} label="Copy best" />}>
          {singleByte.length === 0 ? (
            <div className="text-[12px] text-[var(--text-faint)]">Paste ciphertext to brute-force it.</div>
          ) : (
            <KVTable
              rows={singleByte.map((r) => [
                <span key={r.key} className="rf-mono">
                  {r.key.toString(16).padStart(2, '0')} · '{r.key >= 32 && r.key < 127 ? String.fromCharCode(r.key) : '.'}'
                </span>,
                <span key={`${r.key}-t`} className="rf-mono break-all">
                  {r.score.toFixed(1).padStart(7)} {r.text}
                </span>,
              ])}
            />
          )}
          <div className="mt-3">
            <Callout tone="info" title="Scoring">
              English letter frequency with a penalty for non-printable bytes. A clear winner usually scores more
              than twice the runner-up; a flat distribution means the payload is probably already compressed or
              encrypted twice.
            </Callout>
          </div>
        </Card>
      )}

      {mode === 'repeating-known' && (
        <Card title="Result" action={<CopyChip text={preview(knownResult, 512)} label="Copy plaintext" />}>
          <CodeBlock code={knownResult.length ? new TextDecoder('utf-8', { fatal: false }).decode(knownResult) : '—'} maxHeight={260} />
        </Card>
      )}

      {mode === 'repeating-unknown' && (
        <Card title="Recovered key" action={<CopyChip text={unknown ? asciiOf(unknown.key) : ''} label="Copy key" />}>
          {!unknown ? (
            <div className="text-[12px] text-[var(--text-faint)]">Need at least 8 bytes of ciphertext.</div>
          ) : (
            <>
              <KVTable
                rows={[
                  ['Best key length', `${unknown.bestLen} bytes`],
                  ['Key hex', <span key="kh" className="rf-mono break-all">{keyHex}</span>],
                  ['Key ASCII', <span key="ka" className="rf-mono">{keyAscii}</span>],
                  ['Plaintext', <span key="pt" className="rf-mono break-all">{preview(unknown.plaintext, 160)}</span>],
                ]}
              />
              <div className="mt-4">
                <CodeBlock code={new TextDecoder('utf-8', { fatal: false }).decode(unknown.plaintext)} maxHeight={240} />
              </div>
              <div className="mt-4">
                <span className="text-[12px] font-medium text-[var(--text-muted)]">Key-length candidates</span>
                <div className="mt-2">
                  <KVTable
                    rows={unknown.candidates.map((c) => [
                      `${c.len} bytes`,
                      `normalised Hamming ${c.distance.toFixed(2)} · IoC ${c.ic.toFixed(4)}`,
                    ])}
                  />
                </div>
              </div>
            </>
          )}
        </Card>
      )}

      {mode === 'key-calc' && (
        <Card title="XOR calculator">
          <div className="grid gap-4 sm:grid-cols-2">
            <TextInput label="Data (hex)" value={calcInput} onChange={setCalcInput} mono placeholder="41 42 43" />
            <TextInput label="Key (hex)" value={calcKey} onChange={setCalcKey} mono placeholder="0f" />
          </div>
          <div className="mt-4">
            <CodeBlock code={calc ? `${bytesToHex(calc)}\n${asciiOf(calc)}` : '—'} label="hex / ascii" maxHeight={120} />
          </div>
          <div className="mt-3">
            <Callout tone="info" title="Repeating key">
              The key repeats over the data, so a 1-byte key XORs every byte and a 4-byte key cycles every four.
            </Callout>
          </div>
        </Card>
      )}
    </>
  );
}
