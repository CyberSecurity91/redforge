import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  CodeBlock,
  CopyChip,
  KVTable,
  NumberInput,
  OutputBlock,
  Select,
  Tabs,
  TextArea,
  TextInput,
} from '@/components/ui';
import { atbash, caesar, rot13 } from '@/lib/encoding';

type Cipher = 'caesar' | 'atbash' | 'vigenere' | 'beaufort' | 'autokey' | 'railfence' | 'columnar';
type Direction = 'encrypt' | 'decrypt';

const CIPHERS: Array<{ value: Cipher; label: string }> = [
  { value: 'caesar', label: 'Caesar / ROT-N' },
  { value: 'atbash', label: 'Atbash' },
  { value: 'vigenere', label: 'Vigenère' },
  { value: 'beaufort', label: 'Beaufort' },
  { value: 'autokey', label: 'Autokey (Vigenère variant)' },
  { value: 'railfence', label: 'Rail fence' },
  { value: 'columnar', label: 'Columnar transposition' },
];

const mod = (n: number, m: number) => ((n % m) + m) % m;
const letterIdx = (ch: string) => ch.toLowerCase().charCodeAt(0) - 97;
const isLetter = (ch: string) => /[a-zA-Z]/.test(ch);
const shiftLetter = (ch: string, shift: number) => {
  const base = ch >= 'a' && ch <= 'z' ? 97 : 65;
  return String.fromCharCode(base + mod(ch.charCodeAt(0) - base + shift, 26));
};

function vigenere(text: string, key: string, dir: Direction, variant: 'vig' | 'beaufort' | 'autokey'): string {
  const cleanKey = key.replace(/[^a-zA-Z]/g, '').toLowerCase() || 'a';
  let out = '';
  let k = 0;
  const stream = [...cleanKey];
  for (const ch of text) {
    if (!isLetter(ch)) {
      out += ch;
      continue;
    }
    const keystream = stream[k % stream.length] ?? 'a';
    const kv = letterIdx(keystream);
    const pv = letterIdx(ch);
    let res: number;
    if (variant === 'beaufort') res = mod(kv - pv, 26);
    else if (variant === 'autokey') res = dir === 'encrypt' ? mod(pv + kv, 26) : mod(pv - kv, 26);
    else res = dir === 'encrypt' ? mod(pv + kv, 26) : mod(pv - kv, 26);
    const plain = res;
    out += ch >= 'A' && ch <= 'Z' ? String.fromCharCode(65 + plain) : String.fromCharCode(97 + plain);
    if (variant === 'autokey' && dir === 'encrypt') stream.push(ch.toLowerCase());
    k += 1;
  }
  return out;
}

function railFence(text: string, rails: number, dir: Direction): string {
  if (rails < 2) return text;
  const pattern: number[] = [];
  let r = 0;
  let down = true;
  for (let i = 0; i < text.length; i += 1) {
    pattern.push(r);
    if (r === 0) down = true;
    else if (r === rails - 1) down = false;
    r += down ? 1 : -1;
  }
  if (dir === 'encrypt') {
    const rows: string[] = Array.from({ length: rails }, () => '');
    [...text].forEach((ch, i) => {
      rows[pattern[i]] += ch;
    });
    return rows.join('');
  }
  const counts = new Array<number>(rails).fill(0);
  pattern.forEach((p) => (counts[p] += 1));
  const rows: string[] = [];
  let pos = 0;
  for (let i = 0; i < rails; i += 1) {
    rows.push(text.slice(pos, pos + counts[i]));
    pos += counts[i];
  }
  const idx = new Array<number>(rails).fill(0);
  let out = '';
  pattern.forEach((p) => {
    out += rows[p][idx[p]++];
  });
  return out;
}

function columnar(text: string, key: string, dir: Direction): string {
  const cleanKey = key.replace(/[^a-zA-Z0-9]/g, '');
  if (!cleanKey) return text;
  const cols = cleanKey.length;
  const order = Array.from(cleanKey)
    .map((ch, i) => ({ ch, i }))
    .sort((a, b) => a.ch.localeCompare(b.ch) || a.i - b.i)
    .map((x) => x.i);

  if (dir === 'encrypt') {
    const rows = Math.ceil(text.length / cols);
    const grid: string[][] = Array.from({ length: rows }, () => new Array<string>(cols).fill(''));
    [...text].forEach((ch, i) => {
      grid[Math.floor(i / cols)][i % cols] = ch;
    });
    return order.map((c) => grid.map((row) => row[c] ?? '').join('')).join('');
  }

  const rows = Math.ceil(text.length / cols);
  const grid: string[][] = Array.from({ length: rows }, () => new Array<string>(cols).fill(''));
  let pos = 0;
  for (const c of order) {
    for (let r = 0; r < rows; r += 1) {
      if (pos < text.length) grid[r][c] = text[pos++];
    }
  }
  return grid.map((row) => row.join('')).join('');
}

export default function ClassicalCiphers() {
  const [cipher, setCipher] = useState<Cipher>('caesar');
  const [direction, setDirection] = useState<Direction>('decrypt');
  const [text, setText] = useState('Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj');
  const [shift, setShift] = useState(3);
  const [key, setKey] = useState('LEMON');
  const [rails, setRails] = useState(3);

  const output = useMemo(() => {
    if (!text) return '';
    switch (cipher) {
      case 'caesar':
        return caesar(text, direction === 'encrypt' ? shift : -shift);
      case 'atbash':
        return atbash(text);
      case 'vigenere':
        return vigenere(text, key, direction, 'vig');
      case 'beaufort':
        return vigenere(text, key, 'encrypt', 'beaufort');
      case 'autokey':
        return vigenere(text, key, direction, 'autokey');
      case 'railfence':
        return railFence(text, rails, direction);
      case 'columnar':
        return columnar(text, key, direction);
      default:
        return '';
    }
  }, [cipher, direction, text, shift, key, rails]);

  const allShifts = useMemo(() => {
    if (cipher !== 'caesar') return [];
    return Array.from({ length: 26 }, (_, i) => ({
      shift: i,
      text: caesar(text, -i),
    }));
  }, [cipher, text]);

  const notes = useMemo(() => {
    switch (cipher) {
      case 'caesar':
        return 'Brute-force all 26 shifts; the readable row is the answer. ROT13 is shift 13, ' + rot13('(this line is ROT13)');
      case 'atbash':
        return 'A↔Z mirror. Self-inverse: applying it twice returns the plaintext.';
      case 'vigenere':
        return 'Key repeats over letters only; punctuation is skipped and the key index does not advance.';
      case 'beaufort':
        return 'Beaufort is reciprocal: encryption and decryption use the same operation (K − P).';
      case 'autokey':
        return 'Key stream is the keyword followed by the plaintext itself, so the period effectively disappears after a few characters.';
      case 'railfence':
        return 'Transposition only — letter frequencies are preserved, which is how you tell it apart from a substitution.';
      case 'columnar':
        return 'Column order is the alphabetical rank of each key character; duplicate letters break ties left to right.';
      default:
        return '';
    }
  }, [cipher]);

  return (
    <>
      <Card title="Cipher">
        <div className="grid gap-4 sm:grid-cols-3">
          <Select label="Cipher" value={cipher} onChange={setCipher} options={CIPHERS} />
          <NumberInput label="Caesar shift" value={shift} onChange={(v) => setShift(mod(v, 26))} min={0} max={25} />
          <NumberInput label="Rails" value={rails} onChange={setRails} min={2} max={12} />
          <TextInput
            label="Key"
            value={key}
            onChange={setKey}
            mono
            disabled={cipher === 'caesar' || cipher === 'atbash'}
            hint="Vigenère / Beaufort / Autokey / Columnar"
          />
        </div>
        <div className="mt-4">
          <Tabs
            value={direction}
            onChange={setDirection}
            tabs={[
              { value: 'encrypt', label: 'Encrypt' },
              { value: 'decrypt', label: 'Decrypt' },
            ]}
          />
        </div>
        <div className="mt-4">
          <TextArea label="Input" value={text} onChange={setText} rows={5} />
        </div>
      </Card>

      <Card title="Output" action={<CopyChip text={output} label="Copy output" />}>
        <OutputBlock value={output} rows={6} label="Result" empty="Enter text above." />
        <div className="mt-4">
          <Callout tone="info" title="How it works">
            {notes}
          </Callout>
        </div>
      </Card>

      {cipher === 'caesar' && (
        <Card title="All 26 shifts" action={<CopyChip text={allShifts.map((s) => s.text).join('\n')} label="Copy all" />}>
          {text ? (
            <KVTable
              rows={allShifts.map((s) => [
                <span key={s.shift} className="rf-mono">
                  ROT{String(s.shift).padStart(2, '0')}
                </span>,
                <span key={`${s.shift}-t`} className="rf-mono break-all">
                  {s.text.slice(0, 120)}
                </span>,
              ])}
            />
          ) : (
            <div className="text-[12px] text-[var(--text-faint)]">Enter text to list every shift.</div>
          )}
        </Card>
      )}

      {cipher === 'railfence' && (
        <Card title="Rail pattern">
          <CodeBlock
            code={Array.from({ length: rails }, (_, r) =>
              [...text]
                .map((_, i) => {
                  const cycle = 2 * rails - 2;
                  const pos = i % cycle;
                  const row = pos < rails ? pos : cycle - pos;
                  return row === r ? '█' : '·';
                })
                .join('')
                .slice(0, 80),
            ).join('\n')}
            label={`Rail fence, ${rails} rails (first 80 chars)`}
            maxHeight={160}
          />
        </Card>
      )}
    </>
  );
}
