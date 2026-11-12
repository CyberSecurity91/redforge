import { useMemo, useState } from 'react';
import { Callout, Card, Checkbox, CodeBlock, KVTable, OutputBlock, Select, TextArea } from '@/components/ui';

/**
 * Confusable-character transliteration for filter and IDN testing. The map is
 * a curated subset of the Unicode confusables.txt families that survive common
 * fonts; every entry is checked visually, not just by code point.
 */

/** Latin base char → [Cyrillic lookalikes, Greek lookalikes] (first entry is the primary swap). */
const CONFUSABLES: Record<string, [string[], string[]]> = {
  a: [['а', 'ӓ', 'ɑ'], ['α', 'ά']],
  b: [['ь', 'в', 'Ь'], ['β', 'ϐ']],
  c: [['с', 'ϲ'], ['ϲ']],
  d: [['ԁ', 'ⅾ'], ['δ']],
  e: [['е', 'ё', 'є'], ['ε', 'έ']],
  f: [['ƒ'], ['ϝ']],
  g: [['ɡ', 'ց'], ['γ']],
  h: [['һ', 'հ'], ['η', 'һ']],
  i: [['і', 'ї', 'ӏ'], ['ι', 'ί']],
  j: [['ј', 'ϳ'], ['ϳ']],
  k: [['к', 'κ'], ['κ']],
  l: [['ӏ', 'ⅼ', 'ӆ'], ['ι']],
  m: [['м', 'ṃ'], ['μ']],
  n: [['п', 'ո'], ['η']],
  o: [['о', 'ө', 'σ'], ['ο', 'ό']],
  p: [['р', 'ρ'], ['ρ', 'ϱ']],
  q: [['ԛ', 'զ'], ['ϙ']],
  r: [['г', 'ᴦ'], ['ρ']],
  s: [['ѕ', 'ꜱ'], ['ϲ']],
  t: [['т', 'τ'], ['τ']],
  u: [['и', 'υ', 'ս'], ['υ', 'ύ']],
  v: [['ν', 'ѵ'], ['ν']],
  w: [['ԝ', 'ѡ'], ['ω']],
  x: [['х', 'ӽ'], ['χ']],
  y: [['у', 'ү', 'ყ'], ['γ', 'ψ']],
  z: [['z', 'ƶ'], ['ζ']],
};

const ZERO_WIDTH: Array<[string, string]> = [
  ['U+200B zero width space', '\u200b'],
  ['U+200C ZWNJ', '\u200c'],
  ['U+200D ZWJ', '\u200d'],
  ['U+2060 word joiner', '\u2060'],
  ['U+FEFF zero width no-break', '\ufeff'],
];

const COMBINING: Array<[string, string]> = [
  ['U+0300 grave', '\u0300'],
  ['U+0301 acute', '\u0301'],
  ['U+0302 circumflex', '\u0302'],
  ['U+0303 tilde', '\u0303'],
  ['U+0308 diaeresis', '\u0308'],
  ['U+0335 short stroke', '\u0335'],
  ['U+0337 short solidus', '\u0337'],
  ['U+0489 Cyrillic millions', '\u0489'],
];

type Mode = 'confusable' | 'fullwidth' | 'zerowidth' | 'combining' | 'mixed';

const SCRIPT_TESTS: Array<[string, RegExp]> = [
  ['Latin', /\p{Script=Latin}/u],
  ['Cyrillic', /\p{Script=Cyrillic}/u],
  ['Greek', /\p{Script=Greek}/u],
  ['Armenian', /\p{Script=Armenian}/u],
  ['Georgian', /\p{Script=Georgian}/u],
  ['Hebrew', /\p{Script=Hebrew}/u],
  ['Arabic', /\p{Script=Arabic}/u],
  ['Han', /\p{Script=Han}/u],
  ['Hangul', /\p{Script=Hangul}/u],
  ['Hiragana', /\p{Script=Hiragana}/u],
  ['Katakana', /\p{Script=Katakana}/u],
];

const SAMPLE = 'paypal.com/login';

function fullwidth(ch: string): string {
  const cp = ch.codePointAt(0) ?? 0;
  if (cp === 0x20) return '\u3000';
  if (cp >= 0x21 && cp <= 0x7e) return String.fromCodePoint(cp + 0xfee0);
  return ch;
}

export default function HomoglyphObfuscator() {
  const [input, setInput] = useState(SAMPLE);
  const [mode, setMode] = useState<Mode>('confusable');
  const [family, setFamily] = useState<'cyrillic' | 'greek'>('cyrillic');
  const [every, setEvery] = useState(2);
  const [zwIndex, setZwIndex] = useState('0');
  const [combiningIndex, setCombiningIndex] = useState('0');
  const [rtl, setRtl] = useState(false);

  const mapping = useMemo(() => {
    const rows: Array<{ index: number; from: string; to: string; cp: string; note: string }> = [];
    let out = '';
    const chars = Array.from(input);
    chars.forEach((ch, i) => {
      let replacement = ch;
      let note = 'unchanged';
      const lower = ch.toLowerCase();
      const entry = CONFUSABLES[lower];
      if (mode === 'confusable' && entry) {
        const pool = family === 'cyrillic' ? entry[0] : entry[1];
        if (pool?.length) {
          const isUpper = ch !== lower;
          replacement = isUpper ? pool[0].toUpperCase() : pool[0];
          note = `${family} confusable`;
        }
      } else if (mode === 'fullwidth') {
        replacement = fullwidth(ch);
        note = replacement !== ch ? 'fullwidth form' : 'no fullwidth form';
      }
      out += replacement;
      if (i % every === 0 && mode === 'confusable' && replacement !== ch) {
        rows.push({
          index: i,
          from: ch,
          to: replacement,
          cp: `U+${(replacement.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`,
          note,
        });
      } else if (mode === 'fullwidth' && replacement !== ch) {
        rows.push({
          index: i,
          from: ch,
          to: replacement,
          cp: `U+${(replacement.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`,
          note,
        });
      }
    });

    if (mode === 'zerowidth') {
      const zw = ZERO_WIDTH[Number(zwIndex)]?.[1] ?? '\u200b';
      out = Array.from(input).join(zw) + zw;
      rows.push({ index: 0, from: '—', to: `[${zw}]`, cp: `U+${zw.codePointAt(0)!.toString(16).toUpperCase()}`, note: 'inserted between every character' });
    }
    if (mode === 'combining') {
      const cm = COMBINING[Number(combiningIndex)]?.[1] ?? '\u0301';
      out = Array.from(input, (c) => c + cm).join('');
      rows.push({ index: 0, from: '—', to: `after each char`, cp: `U+${cm.codePointAt(0)!.toString(16).toUpperCase()}`, note: 'combining overlay' });
    }
    if (rtl) out = `\u202e${out}\u202c`;
    return { out, rows };
  }, [input, mode, family, every, zwIndex, combiningIndex, rtl]);

  const detection = useMemo(() => {
    const counts = new Map<string, number>();
    for (const ch of mapping.out) {
      for (const [name, re] of SCRIPT_TESTS) {
        if (re.test(ch)) {
          counts.set(name, (counts.get(name) ?? 0) + 1);
          break;
        }
      }
    }
    const hidden = Array.from(mapping.out).filter((c) =>
      /[\u200b-\u200f\u2060\ufeff\u202a-\u202e\u0300-\u036f]/.test(c),
    ).length;
    return { counts: Array.from(counts.entries()), hidden, mixed: counts.size > 1 };
  }, [mapping.out]);

  const normalised = useMemo(() => {
    try {
      return mapping.out
        .normalize('NFKC')
        .replace(/[\u200b-\u200f\u2060\ufeff\u202a-\u202e]/g, '')
        .replace(/[\u0300-\u036f]/g, '');
    } catch {
      return mapping.out;
    }
  }, [mapping.out]);

  const confusableTable = useMemo(
    () =>
      Object.entries(CONFUSABLES).map(([base, [cyr, grk]]) => ({
        base,
        cyr: cyr.slice(0, 3).join(' '),
        grk: grk.slice(0, 3).join(' '),
      })),
    [],
  );

  const note = mode === 'confusable'
    ? 'Confusables survive NFKC normalisation for the Cyrillic set — that is what makes them useful and what makes them a phishing tell in mail headers.'
    : mode === 'fullwidth'
      ? 'Fullwidth forms collapse back to ASCII under NFKC. Any sanitiser that normalises will strip this in one step.'
      : mode === 'zerowidth'
        ? 'Zero-width characters are removed by NFKC and by most trim functions; they defeat exact-match filters, not NFD/NFC-aware ones.'
        : mode === 'combining'
          ? 'Combining marks are stripped by NFKC. They break equality checks and string length counters in naive parsers.'
          : 'RTL override reorders glyph output without changing the underlying byte order — the classic "exe.txt" trick.';

  return (
    <>
      <Card title="Input and mode">
        <TextArea label="Text" value={input} onChange={setInput} rows={3} placeholder="paypal.com/login" />
        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          <Select<Mode>
            value={mode}
            onChange={setMode}
            label="Obfuscation"
            options={[
              { value: 'confusable', label: 'Confusable lookalikes (Cyrillic/Greek)' },
              { value: 'fullwidth', label: 'Fullwidth forms' },
              { value: 'zerowidth', label: 'Zero-width insertion' },
              { value: 'combining', label: 'Combining-mark overlay' },
              { value: 'mixed', label: 'Mixed-script detector only' },
            ]}
          />
          {mode === 'confusable' && (
            <>
              <Select<'cyrillic' | 'greek'>
                value={family}
                onChange={setFamily}
                label="Script family"
                options={[
                  { value: 'cyrillic', label: 'Cyrillic' },
                  { value: 'greek', label: 'Greek' },
                ]}
              />
              <Select<string>
                value={String(every)}
                onChange={(v) => setEvery(Number(v))}
                label="Swap cadence"
                options={[
                  { value: '1', label: 'Every character' },
                  { value: '2', label: 'Every 2nd' },
                  { value: '3', label: 'Every 3rd' },
                  { value: '99', label: 'First only' },
                ]}
              />
            </>
          )}
          {mode === 'zerowidth' && (
            <Select<string>
              value={zwIndex}
              onChange={setZwIndex}
              label="Zero-width character"
              options={ZERO_WIDTH.map(([label], i) => ({ value: String(i), label }))}
            />
          )}
          {mode === 'combining' && (
            <Select<string>
              value={combiningIndex}
              onChange={setCombiningIndex}
              label="Combining mark"
              options={COMBINING.map(([label], i) => ({ value: String(i), label }))}
            />
          )}
        </div>
        <div className="mt-3">
          <Checkbox
            checked={rtl}
            onChange={setRtl}
            label="Wrap in U+202E RTL override"
            description="Reverses glyph order without touching bytes"
          />
        </div>
        <div className="mt-3">
          <Callout tone="info" title="What this does to a sanitiser">
            {note}
          </Callout>
        </div>
      </Card>

      <Card title="Obfuscated output">
        <OutputBlock value={mapping.out} rows={3} label="Result" empty="Enter text above" />
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <div>
            <OutputBlock value={normalised} rows={3} label="NFKC-normalised (what a sanitiser sees)" />
          </div>
          <div>
            <KVTable
              rows={[
                ['Visible length', String(Array.from(mapping.out).length)],
                ['Hidden characters', String(detection.hidden)],
                ['Mixed script', detection.mixed ? 'yes' : 'no'],
                ['Scripts present', detection.counts.map(([s, n]) => `${s}×${n}`).join(', ') || 'none'],
              ]}
            />
          </div>
        </div>
      </Card>

      <Card title="Per-character mapping">
        {mapping.rows.length === 0 ? (
          <p className="m-0 text-[12.5px] text-[var(--text-faint)]">
            No substitutions for this mode and cadence — try a different mode or widen the cadence.
          </p>
        ) : (
          <div className="max-h-[300px] overflow-auto rounded border border-[var(--card-border)]">
            <table className="w-full text-[12.5px]">
              <thead className="sticky top-0 bg-[var(--card)] text-left text-[var(--text-muted)]">
                <tr>
                  <th className="px-3 py-1.5 font-medium">#</th>
                  <th className="px-3 py-1.5 font-medium">Original</th>
                  <th className="px-3 py-1.5 font-medium">Replacement</th>
                  <th className="px-3 py-1.5 font-medium">Code point</th>
                  <th className="px-3 py-1.5 font-medium">Note</th>
                </tr>
              </thead>
              <tbody>
                {mapping.rows.map((r, i) => (
                  <tr key={`${r.index}-${i}`} className="border-t border-[var(--card-border)]">
                    <td className="rf-mono px-3 py-1 text-[var(--text-faint)]">{r.index}</td>
                    <td className="rf-mono px-3 py-1 text-[var(--text)]">{r.from}</td>
                    <td className="rf-mono px-3 py-1 text-[var(--accent)]">{r.to}</td>
                    <td className="rf-mono px-3 py-1 text-[var(--text-muted)]">{r.cp}</td>
                    <td className="px-3 py-1 text-[var(--text-muted)]">{r.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Confusable reference">
        <p className="mt-0 mb-3 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
          26 Latin bases with their Cyrillic and Greek lookalikes. Copy the pair you need into a ticket, not the whole
          table — a full alphabet of swaps is a noisy tell in itself.
        </p>
        <div className="max-h-[280px] overflow-auto rounded border border-[var(--card-border)]">
          <table className="w-full text-[12.5px]">
            <thead className="sticky top-0 bg-[var(--card)] text-left text-[var(--text-muted)]">
              <tr>
                <th className="px-3 py-1.5 font-medium">Latin</th>
                <th className="px-3 py-1.5 font-medium">Cyrillic</th>
                <th className="px-3 py-1.5 font-medium">Greek</th>
              </tr>
            </thead>
            <tbody>
              {confusableTable.map((r) => (
                <tr key={r.base} className="border-t border-[var(--card-border)]">
                  <td className="rf-mono px-3 py-1 text-[var(--text)]">{r.base}</td>
                  <td className="rf-mono px-3 py-1 text-[var(--accent)]">{r.cyr}</td>
                  <td className="rf-mono px-3 py-1 text-[var(--info)]">{r.grk}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4">
          <CodeBlock
            code={'python3 -c "import unicodedata,sys;s=sys.argv[1];print(unicodedata.normalize(\'NFKC\',s));print([hex(ord(c)) for c in s if ord(c)>127])" "PАYPAL"'}
            label="Detect confusables in a pasted string"
            maxHeight={100}
          />
        </div>
      </Card>
    </>
  );
}
