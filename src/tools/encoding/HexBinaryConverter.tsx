import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  KVTable,
  OutputBlock,
  Select,
  TextArea,
} from '@/components/ui';
import { hexdump, utf8, fromUtf8, formatBytes } from '@/lib/bytes';

/**
 * Hex / binary / decimal / ASCII converter with a hexdump view. Detection is
 * heuristic and always shown as a verdict, never silently trusted — an operator
 * pasting `01001000` wants to know it is being read as binary, not hex.
 */

type Kind = 'hex' | 'binary' | 'decimal' | 'ascii';
type Sep = '0x' | 'space' | 'colon' | 'backslash' | 'none';

const SEPARATORS: Array<{ value: Sep; label: string }> = [
  { value: '0x', label: '0x prefix — 0xDE 0xAD 0xBE 0xEF' },
  { value: 'space', label: 'Space — DE AD BE EF' },
  { value: 'colon', label: 'Colon — DE:AD:BE:EF' },
  { value: 'backslash', label: 'C escape — \\xDE\\xAD\\xBE\\xEF' },
  { value: 'none', label: 'Contiguous — DEADBEEF' },
];

const SAMPLE = '48656c6c6f2c204f5045502e';

function detect(input: string): { kind: Kind; confidence: string } {
  const t = input.trim().replace(/^0x/i, '');
  if (!t) return { kind: 'ascii', confidence: 'empty input' };
  const compact = t.replace(/[\s,:]/g, '').replace(/\\x|0x/gi, '');
  if (/^[01]+$/.test(compact) && compact.length >= 8) return { kind: 'binary', confidence: 'all bits, length ≥ 8' };
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0 && /[a-fA-F]/.test(compact))
    return { kind: 'hex', confidence: 'even-length, contains a-f' };
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0 && compact.length % 4 === 0)
    return { kind: 'hex', confidence: 'even-length digits only — could be hex or decimal; read as hex' };
  if (/^[\d\s,]+$/.test(t) && t.split(/[\s,]+/).every((v) => Number(v) <= 255))
    return { kind: 'decimal', confidence: 'space/comma separated numbers ≤ 255' };
  if (/^[0-9a-fA-F\s,:\\x]+$/.test(t)) return { kind: 'hex', confidence: 'only hex characters present' };
  return { kind: 'ascii', confidence: 'contains non-numeric characters' };
}

function parseToBytes(input: string, kind: Kind): Uint8Array {
  const t = input.trim();
  if (!t) return new Uint8Array();
  if (kind === 'ascii') return utf8(t);
  if (kind === 'binary') {
    const bits = t.replace(/[\s,_]/g, '').replace(/^0b/i, '');
    if (!/^[01]+$/.test(bits)) throw new Error('Binary input may only contain 0 and 1');
    const padded = bits.padStart(Math.ceil(bits.length / 8) * 8, '0');
    const out: number[] = [];
    for (let i = 0; i < padded.length; i += 8) out.push(parseInt(padded.slice(i, i + 8), 2));
    return new Uint8Array(out);
  }
  const tokens = t
    .replace(/\\x|0x|\\|:/gi, ' ')
    .split(/[\s,]+/)
    .filter(Boolean);
  if (kind === 'decimal') {
    const nums = tokens.map((v) => Number(v));
    if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255))
      throw new Error('Decimal bytes must be integers between 0 and 255');
    return new Uint8Array(nums);
  }
  const out: number[] = [];
  for (const tok of tokens) {
    if (tok.length % 2) throw new Error(`Hex token "${tok}" has an odd number of digits`);
    for (let i = 0; i < tok.length; i += 2) {
      const n = parseInt(tok.slice(i, i + 2), 16);
      if (Number.isNaN(n)) throw new Error(`"${tok.slice(i, i + 2)}" is not a hex byte`);
      out.push(n);
    }
  }
  return new Uint8Array(out);
}

export default function HexBinaryConverter() {
  const [input, setInput] = useState(SAMPLE);
  const [from, setFrom] = useState<Kind>('hex');
  const [manual, setManual] = useState(false);
  const [sep, setSep] = useState<Sep>('space');
  const [upper, setUpper] = useState(false);
  const [width, setWidth] = useState(16);
  const [groupBits, setGroupBits] = useState(true);

  const detected = useMemo(() => detect(input), [input]);
  const effective = manual ? from : detected.kind;

  const parsed = useMemo(() => {
    try {
      return { bytes: parseToBytes(input, effective), error: null as string | null };
    } catch (e) {
      return { bytes: new Uint8Array(), error: e instanceof Error ? e.message : 'Parse failed' };
    }
  }, [input, effective]);

  const { bytes, error } = parsed;

  const hexOut = useMemo(() => {
    const parts = Array.from(bytes, (b) => b.toString(16).padStart(2, '0'));
    if (upper) parts.forEach((_, i) => (parts[i] = parts[i].toUpperCase()));
    switch (sep) {
      case '0x':
        return parts.map((p) => `0x${p}`).join(' ');
      case 'colon':
        return parts.join(':');
      case 'backslash':
        return parts.map((p) => `\\x${p}`).join('');
      case 'none':
        return parts.join('');
      default:
        return parts.join(' ');
    }
  }, [bytes, sep, upper]);

  const binaryOut = useMemo(() => {
    const bits = Array.from(bytes, (b) => b.toString(2).padStart(8, '0'));
    if (!groupBits) return bits.join(' ');
    const out: string[] = [];
    for (let i = 0; i < bits.length; i += 4) out.push(bits.slice(i, i + 4).join(' '));
    return out.join('   ');
  }, [bytes, groupBits]);

  const decimalOut = useMemo(() => Array.from(bytes).join(' '), [bytes]);
  const asciiOut = useMemo(() => fromUtf8(bytes), [bytes]);
  const asciiSafe = useMemo(() => Array.from(bytes, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join(''), [bytes]);

  const dump = useMemo(() => {
    if (!bytes.length) return '';
    return hexdump(bytes, width);
  }, [bytes, width]);

  const stats = useMemo(() => {
    const printable = Array.from(bytes).filter((b) => b >= 32 && b < 127).length;
    return {
      length: bytes.length,
      formatted: formatBytes(bytes.length),
      printable,
      ratio: bytes.length ? Math.round((printable / bytes.length) * 100) : 0,
    };
  }, [bytes]);

  return (
    <>
      <Card title="Input">
        <div className="mb-4 grid gap-3 sm:grid-cols-[1fr_200px_190px]">
          <Select<Kind>
            value={effective}
            onChange={(v) => {
              setFrom(v);
              setManual(true);
            }}
            label="Read input as"
            hint={manual ? 'Manual override' : `Auto-detected: ${detected.confidence}`}
            options={[
              { value: 'hex', label: 'Hex' },
              { value: 'binary', label: 'Binary' },
              { value: 'decimal', label: 'Decimal bytes' },
              { value: 'ascii', label: 'ASCII / UTF-8' },
            ]}
          />
          <Select<Sep> value={sep} onChange={setSep} label="Hex separator" options={SEPARATORS} />
          <Select<string>
            value={String(width)}
            onChange={(v) => setWidth(Number(v))}
            label="Line wrap"
            options={[
              { value: '8', label: '8 bytes' },
              { value: '16', label: '16 bytes (hexdump -C)' },
              { value: '32', label: '32 bytes' },
            ]}
          />
        </div>

        <TextArea
          label="Input"
          value={input}
          onChange={setInput}
          rows={5}
          placeholder="48656c6c6f — or 01001000 01101001 — or 72 101 108 108 111 — or Hello"
        />

        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          <Checkbox
            checked={!manual}
            onChange={(v) => setManual(!v)}
            label="Auto-detect input format"
            description={`Currently reading as ${effective}`}
          />
          <Checkbox checked={upper} onChange={setUpper} label="Uppercase hex" />
          <Checkbox checked={groupBits} onChange={setGroupBits} label="Group binary in 4-bit nibbles" />
        </div>

        <div className="mt-3">
          <KVTable
            rows={[
              ['Detected format', `${detected.kind} (${detected.confidence})`],
              ['Byte length', `${stats.length} · ${stats.formatted}`],
              ['Printable ratio', `${stats.ratio}% — ${stats.printable}/${stats.length} in 0x20-0x7e`],
            ]}
          />
        </div>
      </Card>

      <Card title="Output">
        {error ? (
          <Callout tone="danger" title="Cannot parse">
            {error}
          </Callout>
        ) : (
          <div className="space-y-4">
            <OutputBlock value={hexOut} rows={3} label="Hex" empty="Empty input" />
            <OutputBlock value={binaryOut} rows={4} label="Binary (8-bit groups)" empty="Empty input" />
            <div className="grid gap-4 sm:grid-cols-2">
              <OutputBlock value={decimalOut} rows={3} label="Decimal bytes" empty="Empty input" />
              <OutputBlock value={asciiOut} rows={3} label="ASCII / UTF-8 text" empty="Empty input" />
            </div>
          </div>
        )}
      </Card>

      <Card title="Hexdump">
        {dump ? (
          <>
            <CodeBlock code={dump} label={`hexdump -C · width ${width}`} maxHeight={300} />
            <div className="mt-3">
              <KVTable
                rows={[
                  ['ASCII gutter', asciiSafe.slice(0, 96) || '—'],
                  ['Null bytes', String(Array.from(bytes).filter((b) => b === 0).length)],
                  ['High bytes (≥ 0x80)', String(Array.from(bytes).filter((b) => b >= 0x80).length)],
                  ['First 4 bytes', Array.from(bytes.slice(0, 4), (b) => b.toString(16).padStart(2, '0')).join(' ') || '—'],
                ]}
              />
            </div>
          </>
        ) : (
          <p className="m-0 text-[12.5px] text-[var(--text-faint)]">Enter bytes above to see the dump.</p>
        )}
      </Card>

      <Card title="Reading the dump">
        <Callout tone="info" title="What the gutter tells you">
          A run of dots in the ASCII gutter at the start of a file is either a container header (PNG, gzip, ELF) or an
          encrypted blob. Check the first four bytes against the magic table before guessing: <span className="rf-mono">89 50 4E 47</span> is
          PNG, <span className="rf-mono">1F 8B</span> is gzip, <span className="rf-mono">7F 45 4C 46</span> is ELF,
          <span className="rf-mono">4D 5A</span> is a Windows PE.
        </Callout>
      </Card>
    </>
  );
}
