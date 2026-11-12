import { useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, OutputBlock, Select, Tabs, TextArea, TextInput } from '@/components/ui';
import { seeded } from '@/lib/rng';

/**
 * Spoken / written repertoire for a single string: NATO phonetics, leetspeak at
 * three intensities, case mutation, morse, reversal, code points and a vishing
 * read-aloud script. Everything derives from the input — no static fixtures.
 */

type Tab = 'nato' | 'leet' | 'case' | 'morse' | 'codes' | 'script';

const NATO: Record<string, string> = {
  a: 'Alfa', b: 'Bravo', c: 'Charlie', d: 'Delta', e: 'Echo', f: 'Foxtrot', g: 'Golf', h: 'Hotel',
  i: 'India', j: 'Juliett', k: 'Kilo', l: 'Lima', m: 'Mike', n: 'November', o: 'Oscar', p: 'Papa',
  q: 'Quebec', r: 'Romeo', s: 'Sierra', t: 'Tango', u: 'Uniform', v: 'Victor', w: 'Whiskey',
  x: 'X-ray', y: 'Yankee', z: 'Zulu',
  '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three', '4': 'Four', '5': 'Five', '6': 'Six',
  '7': 'Seven', '8': 'Eight', '9': 'Nine', '.': 'Stop', '-': 'Dash', '_': 'Underscore',
  '@': 'At', '/': 'Slash', ':': 'Colon', '?': 'Question mark', '=': 'Equals', '+': 'Plus',
  '#': 'Hash', '&': 'Ampersand', '%': 'Percent', '!': 'Exclamation', ',': 'Comma',
};

const MORSE: Record<string, string> = {
  a: '.-', b: '-...', c: '-.-.', d: '-..', e: '.', f: '..-.', g: '--.', h: '....', i: '..',
  j: '.---', k: '-.-', l: '.-..', m: '--', n: '-.', o: '---', p: '.--.', q: '--.-', r: '.-.',
  s: '...', t: '-', u: '..-', v: '...-', w: '.--', x: '-..-', y: '-.--', z: '--..',
  '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....',
  '6': '-....', '7': '--...', '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--',
  '?': '..--..', '/': '-..-.', '-': '-....-', ':': '---...', "'": '.----.', '@': '.--.-.',
};

const LEET_LIGHT: Record<string, string> = { a: '4', e: '3', i: '1', o: '0', s: '5', t: '7' };
const LEET_HEAVY: Record<string, string> = {
  a: '@', b: '8', c: '(', d: '|)', e: '3', f: 'ph', g: '9', h: '#', i: '!', j: '_|',
  k: '|<', l: '1', m: '|v|', n: '|\\|', o: '0', p: '|*', q: '0_', r: '|2', s: '$', t: '7',
  u: '|_|', v: '\\/', w: '\\/\\/', x: '><', y: '`/', z: '2',
};

const SEPARATORS: Array<{ value: string; label: string }> = [
  { value: ' ', label: 'Space' },
  { value: '-', label: 'Hyphen' },
  { value: '.', label: 'Dot' },
  { value: '_ ', label: 'Underscore + space' },
  { value: '', label: 'None' },
];

type CaseMode = 'alternating' | 'random' | 'upper' | 'lower' | 'first' | 'inverted';

const SAMPLE = 'Session4Alpha';

function toMorse(input: string): string {
  return input
    .toLowerCase()
    .split('')
    .map((ch) => (ch === ' ' ? '/' : MORSE[ch] ?? ''))
    .filter((v, i, arr) => v !== '' || arr[i - 1] !== '')
    .join(' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function caseMutate(input: string, mode: CaseMode, seed: string): string {
  const chars = Array.from(input);
  switch (mode) {
    case 'alternating':
      return chars.map((c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase())).join('');
    case 'random': {
      const rng = seeded(seed || input);
      return chars.map((c) => (rng() > 0.5 ? c.toUpperCase() : c.toLowerCase())).join('');
    }
    case 'upper':
      return input.toUpperCase();
    case 'lower':
      return input.toLowerCase();
    case 'first':
      return input.replace(/\b\w/g, (c) => c.toUpperCase()).replace(/[A-Z]/g, (c, i) => (i === 0 ? c : c.toLowerCase()));
    case 'inverted':
      return chars.map((c) => (c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase())).join('');
  }
}

export default function TextRepertoire() {
  const [input, setInput] = useState(SAMPLE);
  const [tab, setTab] = useState<Tab>('nato');
  const [sep, setSep] = useState('-');
  const [leetLevel, setLeetLevel] = useState<'light' | 'medium' | 'heavy'>('light');
  const [caseMode, setCaseMode] = useState<CaseMode>('alternating');
  const [seed, setSeed] = useState('1');
  const [phone, setPhone] = useState('+44 20 7946 0000');

  const clean = input.trim();

  const natoOut = useMemo(() => {
    if (!clean) return '';
    return Array.from(clean)
      .map((ch) => NATO[ch.toLowerCase()] ?? ch)
      .join(sep);
  }, [clean, sep]);

  const leetOut = useMemo(() => {
    if (!clean) return '';
    return Array.from(clean)
      .map((ch) => {
        const lower = ch.toLowerCase();
        if (leetLevel === 'light') return LEET_LIGHT[lower] ?? ch;
        if (leetLevel === 'medium') return (LEET_LIGHT[lower] && Math.random() > 0.4 ? LEET_LIGHT[lower] : LEET_HEAVY[lower]) ?? ch;
        return LEET_HEAVY[lower] ?? ch;
      })
      .join('');
  }, [clean, leetLevel]);

  const caseOut = useMemo(() => (clean ? caseMutate(clean, caseMode, seed) : ''), [clean, caseMode, seed]);

  const morseOut = useMemo(() => (clean ? toMorse(clean) : ''), [clean]);

  const codesOut = useMemo(() => {
    if (!clean) return '';
    return Array.from(clean)
      .map((ch) => {
        const cp = ch.codePointAt(0) ?? 0;
        return `${ch === ' ' ? '␠' : ch}  U+${cp.toString(16).toUpperCase().padStart(4, '0')}  ${cp}  ${cp.toString(2).padStart(8, '0')}`;
      })
      .join('\n');
  }, [clean]);

  const spelledOut = useMemo(() => {
    if (!clean) return '';
    return Array.from(clean).map((ch) => (ch === ' ' ? '[space]' : ch)).join(sep || ' ');
  }, [clean, sep]);

  const script = useMemo(() => {
    if (!clean) return '';
    const spoken = Array.from(clean)
      .map((ch) => {
        if (ch === ' ') return 'space';
        const word = NATO[ch.toLowerCase()];
        return word ?? ch;
      })
      .join('-');
    return [
      `## Vishing read-aloud script`,
      ``,
      `**Goal**: get the target to read back or confirm the identifier "${clean}".`,
      ``,
      `Operator: "Thanks — I'm calling from IT service desk. I've got a reference here for your`,
      `account. Can I just confirm I'm speaking with the right contact? The reference reads"`,
      ``,
      `    ${spoken}`,
      ``,
      `Target repeats it. Confirm each group; do not rush the last three characters.`,
      ``,
      `Operator: "That's ${spoken.split('-').slice(0, 3).join('-')}... perfect. And the last`,
      `three would be ${spoken.split('-').slice(-3).join('-')}?"`,
      ``,
      `## If the target hesitates`,
      `- "No problem — I can read it again. ${spoken.split('-').slice(0, 6).join('-')}..."`,
      `- Offer to email it to the address already on file instead of reading it out.`,
      `- Ask them to confirm the last two groups only; partial readback still confirms custody.`,
      ``,
      `## Do not`,
      `- Ask for a password, PIN or full card number in the same call.`,
      `- Read the string backwards or ask them to — it destroys the coupling you want to measure.`,
      `- Exceed the agreed call budget (see RoE).`,
      ``,
      `Helpline to quote if challenged: ${phone || 'N/A'}`,
    ].join('\n');
  }, [clean, phone]);

  const active = useMemo(() => {
    switch (tab) {
      case 'nato': return natoOut;
      case 'leet': return leetOut;
      case 'case': return caseOut;
      case 'morse': return morseOut;
      case 'codes': return codesOut;
      case 'script': return script;
    }
  }, [tab, natoOut, leetOut, caseOut, morseOut, codesOut, script]);

  return (
    <>
      <Card title="Input">
        <div className="grid gap-4 sm:grid-cols-[1fr_200px_220px]">
          <TextArea label="Text" value={input} onChange={setInput} rows={3} placeholder="Session4Alpha" />
          <Select<string> value={sep} onChange={setSep} label="Separator" options={SEPARATORS} />
          <TextInput label="Helpline to quote" value={phone} onChange={setPhone} mono hint="Used in the vishing script" />
        </div>
        <div className="mt-3">
          <Callout tone="info" title="Why spell a token out">
            A token read aloud is a token the target owns: if they repeat it back, you have confirmed they identified with
            it. Group lengths of 3–4 read more naturally than 8 and stop the target pattern-matching the whole string.
          </Callout>
        </div>
      </Card>

      <Card
        title="Repertoire"
        action={
          <Tabs<Tab>
            value={tab}
            onChange={setTab}
            tabs={[
              { value: 'nato', label: 'NATO' },
              { value: 'leet', label: 'Leet' },
              { value: 'case', label: 'Case' },
              { value: 'morse', label: 'Morse' },
              { value: 'codes', label: 'Codes' },
              { value: 'script', label: 'Vishing' },
            ]}
          />
        }
      >
        {tab === 'leet' && (
          <div className="mb-3">
            <Select<'light' | 'medium' | 'heavy'>
              value={leetLevel}
              onChange={setLeetLevel}
              label="Intensity"
              hint="Heavy forms include multi-character glyphs like |\\| and ><"
              options={[
                { value: 'light', label: 'Light — a/e/i/o/s/t only' },
                { value: 'medium', label: 'Medium — mixed, partially predictable' },
                { value: 'heavy', label: 'Heavy — full glyph substitution' },
              ]}
            />
          </div>
        )}
        {tab === 'case' && (
          <div className="mb-3 grid gap-3 sm:grid-cols-2">
            <Select<CaseMode>
              value={caseMode}
              onChange={setCaseMode}
              label="Mutation"
              options={[
                { value: 'alternating', label: 'Alternating (aLtErNaTiNg)' },
                { value: 'random', label: 'Random (seeded)' },
                { value: 'upper', label: 'All caps' },
                { value: 'lower', label: 'All lower' },
                { value: 'first', label: 'First letter capitals' },
                { value: 'inverted', label: 'Inverted from input' },
              ]}
            />
            <TextInput
              label="Seed"
              value={seed}
              onChange={setSeed}
              mono
              hint="Same seed + same text = same output, so a ticket can be replayed"
            />
          </div>
        )}

        {clean ? (
          tab === 'script' ? (
            <CodeBlock code={script} label="read-aloud.md" maxHeight={420} />
          ) : (
            <OutputBlock
              value={active}
              rows={tab === 'codes' ? 12 : 5}
              label={tab === 'nato' ? 'NATO spelling' : tab === 'morse' ? 'Morse code' : tab === 'codes' ? 'Code points' : 'Output'}
            />
          )
        ) : (
          <p className="m-0 text-[12.5px] text-[var(--text-faint)]">Enter some text above to build the repertoire.</p>
        )}
      </Card>

      <Card title="All forms at a glance">
        <div className="space-y-3">
          <OutputBlock value={natoOut} rows={2} label="NATO" empty="—" />
          <OutputBlock value={leetOut} rows={2} label="Leetspeak" empty="—" />
          <OutputBlock value={caseOut} rows={2} label="Case mutation" empty="—" />
          <OutputBlock value={morseOut} rows={2} label="Morse" empty="—" />
          <OutputBlock value={spelledOut} rows={2} label="Spelled out for vishing" empty="—" />
        </div>
        <div className="mt-4">
          <Callout tone="warn" title="Morse is not a security control">
            Morse is included because operators read identifiers over poor-quality voice links, not because it conceals
            anything. Anyone with the transcription can reverse it in seconds.
          </Callout>
        </div>
      </Card>
    </>
  );
}
