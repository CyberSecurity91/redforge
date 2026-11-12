import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CopyChip,
  DownloadButton,
  KVTable,
  NumberInput,
  OutputBlock,
  SectionTitle,
  Select,
  Tabs,
  TextInput,
} from '@/components/ui';
import { seeded } from '@/lib/rng';

type Mode = 'policy' | 'passphrase' | 'seeded';

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?';
const AMBIGUOUS = 'Il1O0o';

const WORDS = [
  'carbon', 'orbit', 'lantern', 'harbour', 'velvet', 'granite', 'cobalt', 'ember',
  'quartz', 'tundra', 'marlin', 'spindle', 'thicket', 'rafter', 'cinder', 'vellum',
  'anvil', 'gantry', 'kestrel', 'prism', 'sable', 'tallow', 'walnut', 'zephyr',
  'basalt', 'cordial', 'dovetail', 'ferrous', 'galleon', 'hollows', 'ingot', 'juniper',
];

const CHAR_SETS = [
  { id: 'lower', label: 'lowercase (a-z)', chars: LOWER },
  { id: 'upper', label: 'uppercase (A-Z)', chars: UPPER },
  { id: 'digits', label: 'digits (0-9)', chars: DIGITS },
  { id: 'symbols', label: 'symbols (!@#$)', chars: SYMBOLS },
];

function shuffleWith<T>(items: T[], next: () => number): T[] {
  const out = [...items];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(next() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

export default function CredentialGenerator() {
  const [mode, setMode] = useState<Mode>('policy');
  const [length, setLength] = useState(14);
  const [words, setWords] = useState(4);
  const [count, setCount] = useState(12);
  const [sets, setSets] = useState<string[]>(['lower', 'upper', 'digits', 'symbols']);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(true);
  const [needDigit, setNeedDigit] = useState(true);
  const [needSymbol, setNeedSymbol] = useState(true);
  const [separator, setSeparator] = useState<'-' | '.' | '_'>('-');
  const [caseStyle, setCaseStyle] = useState<'lower' | 'title' | 'upper'>('title');
  const [seed, setSeed] = useState('engagement-2024');
  const [targetLength, setTargetLength] = useState(12);
  const [minClasses, setMinClasses] = useState(3);

  const pool = useMemo(() => {
    const base = CHAR_SETS.filter((s) => sets.includes(s.id))
      .map((s) => s.chars)
      .join('');
    return excludeAmbiguous ? [...base].filter((c) => !AMBIGUOUS.includes(c)).join('') : base;
  }, [sets, excludeAmbiguous]);

  const candidates = useMemo(() => {
    if (!seed.trim()) return [];
    const next = seeded(seed.trim());
    const out: string[] = [];

    if (mode === 'passphrase') {
      for (let i = 0; i < count; i++) {
        const picked: string[] = [];
        const bag = [...WORDS];
        for (let w = 0; w < Math.max(2, Math.min(words, 8)); w++) {
          const idx = Math.floor(next() * bag.length);
          picked.push(bag.splice(idx, 1)[0]);
        }
        const styled = picked.map((w) => (caseStyle === 'upper' ? w.toUpperCase() : caseStyle === 'title' ? w[0].toUpperCase() + w.slice(1) : w));
        let phrase = styled.join(separator);
        if (sets.includes('digits')) phrase += separator + String(1 + Math.floor(next() * 97)).padStart(2, '0');
        if (sets.includes('symbols')) phrase += SYMBOLS[Math.floor(next() * SYMBOLS.length)];
        out.push(phrase);
      }
      return out;
    }

    if (!pool) return [];
    const minLength = Math.max(6, length);
    for (let i = 0; i < count; i++) {
      const chars: string[] = [];
      for (let c = 0; c < minLength; c++) chars.push(pool[Math.floor(next() * pool.length)]);
      // Force policy shape: one member of each mandatory class, then shuffle so the
      // position of the mandatory character is not predictable.
      if (needDigit && !chars.some((c) => DIGITS.includes(c)) && pool) chars[0] = DIGITS[Math.floor(next() * DIGITS.length)];
      if (needSymbol && !chars.some((c) => SYMBOLS.includes(c))) chars[1] = SYMBOLS[Math.floor(next() * SYMBOLS.length)];
      out.push(shuffleWith(chars, next).join(''));
    }
    return out;
  }, [mode, seed, count, length, words, pool, separator, caseStyle, needDigit, needSymbol, sets]);

  const policyRegex = useMemo(() => {
    const parts: string[] = [`(?=.*[a-z])`];
    if (sets.includes('upper')) parts.push('(?=.*[A-Z])');
    if (needDigit) parts.push('(?=.*\\d)');
    if (needSymbol) parts.push('(?=.*[^A-Za-z0-9])');
    const allowed = sets.includes('symbols') ? 'A-Za-z0-9!@#$%^&*()\\-_=+\\[\\]{};:,.?' : sets.includes('upper') ? 'A-Za-z0-9' : 'a-z0-9';
    return `^${parts.join('')}[${allowed}]{${targetLength},}$`;
  }, [sets, needDigit, needSymbol, targetLength]);

  const compliant = useMemo(() => {
    try {
      const re = new RegExp(policyRegex);
      return candidates.filter((c) => re.test(c)).length;
    } catch {
      return 0;
    }
  }, [candidates, policyRegex]);

  const toggleSet = (id: string, on: boolean) =>
    setSets((prev) => (on ? [...new Set([...prev, id])] : prev.filter((x) => x !== id)));

  return (
    <>
      <Card title="Mode">
        <Tabs
          value={mode}
          onChange={setMode}
          tabs={[
            { value: 'policy', label: 'policy-compliant' },
            { value: 'passphrase', label: 'memorable passphrase' },
            { value: 'seeded', label: 'seeded candidate list' },
          ]}
        />
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <TextInput label="Seed" value={seed} onChange={setSeed} mono placeholder="engagement-2024" hint="Same seed → same list, every time" />
          <div className="grid grid-cols-2 gap-3">
            <NumberInput label="Count" value={count} onChange={setCount} min={1} max={200} />
            {mode === 'passphrase' ? (
              <NumberInput label="Words" value={words} onChange={setWords} min={2} max={8} />
            ) : (
              <NumberInput label="Length" value={length} onChange={setLength} min={6} max={64} />
            )}
          </div>
        </div>
      </Card>

      <Card title={mode === 'passphrase' ? 'Word style' : 'Character policy'}>
        {mode === 'passphrase' ? (
          <div className="grid gap-4 sm:grid-cols-2">
            <Select
              label="Case"
              value={caseStyle}
              onChange={setCaseStyle}
              options={[
                { value: 'lower', label: 'all lower' },
                { value: 'title', label: 'Title Case' },
                { value: 'upper', label: 'ALL UPPER' },
              ]}
            />
            <Select
              label="Separator"
              value={separator}
              onChange={setSeparator}
              options={[
                { value: '-', label: 'hyphen' },
                { value: '.', label: 'dot' },
                { value: '_', label: 'underscore' },
              ]}
            />
            <div className="sm:col-span-2 grid gap-2 sm:grid-cols-2">
              <Checkbox checked={sets.includes('digits')} onChange={(v) => toggleSet('digits', v)} label="Append a 2-digit number" description="Satisfies most 'must contain a digit' rules" />
              <Checkbox checked={sets.includes('symbols')} onChange={(v) => toggleSet('symbols', v)} label="Append a symbol" description="Satisfies most symbol requirements" />
            </div>
          </div>
        ) : (
          <>
            <div className="grid gap-2 sm:grid-cols-2">
              {CHAR_SETS.map((s) => (
                <Checkbox key={s.id} checked={sets.includes(s.id)} onChange={(v) => toggleSet(s.id, v)} label={s.label} />
              ))}
              <Checkbox checked={excludeAmbiguous} onChange={setExcludeAmbiguous} label="Exclude ambiguous characters" description="Removes I l 1 O 0 o" />
              <Checkbox checked={needDigit} onChange={setNeedDigit} label="Must contain a digit" />
              <Checkbox checked={needSymbol} onChange={setNeedSymbol} label="Must contain a symbol" />
            </div>
            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <NumberInput label="Policy minimum length" value={targetLength} onChange={setTargetLength} min={6} max={40} hint="Only used for the regex preview" />
              <NumberInput label="Policy minimum classes" value={minClasses} onChange={setMinClasses} min={1} max={4} />
            </div>
          </>
        )}
      </Card>

      <Card
        title="Candidates"
        action={<DownloadButton text={candidates.join('\n')} filename={`candidates-${seed || 'seed'}.txt`} label="Download" />}
      >
        {candidates.length === 0 ? (
          <Callout tone="info" title="No candidates yet">
            Set a seed and pick at least one character class. Generation is deterministic — the same inputs always give
            the same list, so a retest can be reproduced exactly.
          </Callout>
        ) : (
          <>
            <div className="mb-3 flex flex-wrap items-center gap-3 text-[11.5px] text-[var(--text-muted)]">
              <span>
                <span className="rf-mono text-[var(--text)]">{candidates.length}</span> generated
              </span>
              <span>
                <span style={{ color: compliant === candidates.length ? 'var(--ok)' : 'var(--warn)' }} className="rf-mono">
                  {compliant}
                </span>{' '}
                match the policy regex
              </span>
              <CopyChip text={candidates.join('\n')} label="copy all" />
            </div>
            <OutputBlock value={candidates.join('\n')} rows={12} />
            <div className="mt-4">
              <SectionTitle>Policy preview</SectionTitle>
              <div className="rounded border border-[var(--input-border)] bg-[var(--input)] px-3 py-2">
                <code className="rf-mono text-[11.5px] break-all text-[var(--text)]">{policyRegex}</code>
              </div>
            </div>
          </>
        )}
      </Card>

      <Card title="Why these are policy-shaped">
        <KVTable
          rows={[
            ['Target policy', `${targetLength}+ chars, ${minClasses} classes of ${sets.length || 0} selected`],
            ['Pool size', <span className="rf-mono">{pool.length} characters</span>],
            ['Predictability', mode === 'passphrase' ? 'Word order only — pick 4+ words' : 'Full-length random over the pool'],
            ['Reproducible', <span className="rf-mono">{seed || '—'}</span>],
          ]}
        />
        <div className="mt-4">
          <Callout tone="warn" title="Cracking-strategy note">
            Policy-shaped passwords are a rule, not a random sample: they almost always satisfy a class requirement with
            one character and pad with lowercase. That is exactly what <span className="rf-mono">best64</span> plus a
            digit/symbol rule catches. When you test a policy-shaped list against a captured hash, run dictionary →
            rule → mask in that order; a mask over <span className="rf-mono">?u?l?l?l?l?l?d?d</span> often beats a
            brute-force sweep by orders of magnitude.
          </Callout>
        </div>
      </Card>
    </>
  );
}
