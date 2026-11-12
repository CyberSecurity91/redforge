import { useMemo, useState } from 'react';
import {
  Button,
  Callout,
  Card,
  CopyChip,
  KVTable,
  OutputField,
  SectionTitle,
  Tabs,
  TextArea,
} from '@/components/ui';

/**
 * Unicode normalisation lab. Four forms of the same string, the characters that
 * vary between them, and the ones that survive NFKC untouched — the latter is the
 * half that matters when a filter normalises and an app does not (or vice versa).
 */

type Form = 'NFC' | 'NFD' | 'NFKC' | 'NFKD';
const FORMS: Form[] = ['NFC', 'NFD', 'NFKC', 'NFKD'];

const PRESETS: Array<{ label: string; hint: string; text: string }> = [
  { label: 'Fullwidth ASCII', hint: 'ｐａｓｓｗｏｒｄ → password under NFKC', text: 'ｐａｓｓｗｏｒｄ１２３' },
  { label: 'Circled letters', hint: 'ⒶⒹⓂⒾⓃ folds to ADM I N', text: 'ⒶⒹⓂⒾⓃ' },
  { label: 'Zero-width joiners', hint: 'U+200D between each letter', text: 'a\u200Db\u200Dc\u200Dd' },
  { label: 'RTL override', hint: 'U+202E flips what the terminal shows', text: 'invoice\u202Etxt.exe' },
  { label: 'LTR override', hint: 'U+202D inside an RTL run', text: '\u202Dsecret\u202C' },
  { label: 'Combining stack', hint: 'U+0336 strike + U+0301 acute', text: 'e\u0301\u0336a\u0308' },
  { label: 'Same string, two bytes', hint: 'é composed vs decomposed', text: 'caf\u00e9 vs cafe\u0301' },
  { label: 'Ligature + fraction', hint: 'ﬁ and ½ under NFKC', text: '\ufb01ne \u00bd \u2160' },
];

/** Small script-class lookup — enough to label a codepoint, not a full UCD dump. */
function scriptOf(cp: number): string {
  if (cp < 0x20) return 'C0 control';
  if (cp === 0x7f) return 'DEL';
  if (cp < 0x80) return 'Basic Latin';
  if (cp >= 0x80 && cp <= 0x9f) return 'C1 control';
  if (cp < 0x250) return 'Latin ext / IPA';
  if (cp >= 0x300 && cp <= 0x36f) return 'Combining diacritic';
  if (cp >= 0x370 && cp <= 0x3ff) return 'Greek';
  if (cp >= 0x400 && cp <= 0x4ff) return 'Cyrillic';
  if (cp >= 0x590 && cp <= 0x5ff) return 'Hebrew';
  if (cp >= 0x600 && cp <= 0x6ff) return 'Arabic';
  if (cp >= 0xff01 && cp <= 0xff60) return 'Half/fullwidth forms';
  if (cp >= 0xff61 && cp <= 0xff9f) return 'Halfwidth katakana';
  if (cp >= 0x2460 && cp <= 0x24ff) return 'Enclosed alphanumeric';
  if (cp >= 0x2000 && cp <= 0x200f) return 'General punctuation / bidi';
  if (cp >= 0x202a && cp <= 0x202e) return 'Bidi control';
  if (cp >= 0x2066 && cp <= 0x2069) return 'Bidi isolate';
  if (cp >= 0xfb00 && cp <= 0xfb06) return 'Latin ligature';
  if (cp >= 0x2150 && cp <= 0x218f) return 'Number form';
  if (cp >= 0x1f300 && cp <= 0x1faff) return 'Emoji';
  if (cp >= 0x4e00 && cp <= 0x9fff) return 'CJK unified';
  return 'Other';
}

/** East-Asian width, approximated from the ranges a payload usually touches. */
function widthOf(cp: number): 'narrow' | 'wide' | 'zero' {
  if (cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0xfeff) return 'zero';
  if (cp === 0x202a || cp === 0x202b || cp === 0x202c || cp === 0x202d || cp === 0x202e) return 'zero';
  if (cp >= 0x2066 && cp <= 0x2069) return 'zero';
  if (cp >= 0x0300 && cp <= 0x036f) return 'zero';
  if (cp >= 0x1100 && cp <= 0x115f) return 'wide';
  if (cp >= 0x2e80 && cp <= 0xa4cf) return 'wide';
  if (cp >= 0xac00 && cp <= 0xd7a3) return 'wide';
  if (cp >= 0xf900 && cp <= 0xfaff) return 'wide';
  if (cp >= 0xff01 && cp <= 0xff60) return 'wide';
  if (cp >= 0x1f300 && cp <= 0x1faff) return 'wide';
  return 'narrow';
}

/** Name approximation: printable ASCII gets its literal, everything else its block. */
function describe(cp: number): string {
  if (cp === 0x20) return 'SPACE';
  if (cp >= 0x21 && cp <= 0x7e) return `LATIN ${JSON.stringify(String.fromCharCode(cp))}`;
  if (cp === 0x09) return 'CHARACTER TABULATION';
  if (cp === 0x0a) return 'LINE FEED';
  if (cp === 0x0d) return 'CARRIAGE RETURN';
  if (cp === 0xad) return 'SOFT HYPHEN';
  const script = scriptOf(cp);
  return `${script.toUpperCase()} ${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

const escapeOf = (s: string) =>
  Array.from(s, (ch) => {
    const cp = ch.codePointAt(0) ?? 0;
    return cp > 0xffff
      ? `\\u{${cp.toString(16).toUpperCase()}}`
      : `\\u${cp.toString(16).toUpperCase().padStart(4, '0')}`;
  }).join('');

const utf8Len = (s: string) => new TextEncoder().encode(s).length;

const visible = (s: string) =>
  Array.from(s, (ch) => {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) || widthOf(cp) === 'zero') {
      return `\u2423(${cp.toString(16).toUpperCase().padStart(4, '0')})`;
    }
    return ch;
  }).join('');

type CharRow = { index: number; char: string; cp: number; name: string; script: string; width: string; survives: boolean };

export default function UnicodeNormalisationLab() {
  const [text, setText] = useState('ｐａｓｓｗｏｒｄ\u200Dadmin');
  const [form, setForm] = useState<Form>('NFKC');

  const forms = useMemo(() => {
    const out = {} as Record<Form, string>;
    for (const f of FORMS) {
      try {
        out[f] = text.normalize(f);
      } catch {
        out[f] = text;
      }
    }
    return out;
  }, [text]);

  const rows = useMemo<CharRow[]>(() => {
    const folded = forms.NFKC;
    return Array.from(text).map((ch, index) => {
      const cp = ch.codePointAt(0) ?? 0;
      return {
        index,
        char: ch,
        cp,
        name: describe(cp),
        script: scriptOf(cp),
        width: widthOf(cp),
        survives: folded.includes(ch),
      };
    });
  }, [text, forms.NFKC]);

  const distinct = useMemo(() => new Set(FORMS.map((f) => forms[f])).size, [forms]);
  const lengths = useMemo(
    () => FORMS.map((f) => ({ form: f, bytes: utf8Len(forms[f]), chars: Array.from(forms[f]).length })),
    [forms],
  );
  const survivals = rows.filter((r) => r.survives && r.cp > 0x7f);
  const changed = rows.filter((r) => !r.survives);

  return (
    <>
      <Card title="Input">
        <TextArea
          label="Text"
          value={text}
          onChange={setText}
          rows={3}
          mono
          hint={`${Array.from(text).length} code points, ${utf8Len(text)} UTF-8 bytes`}
        />
        <div className="mt-3 flex flex-wrap gap-1.5">
          {PRESETS.map((p) => (
            <button
              key={p.label}
              type="button"
              title={p.hint}
              onClick={() => setText(p.text)}
              className="rounded border border-[var(--card-border)] bg-[var(--neutral-btn)] px-2 py-1 text-[11.5px] text-[var(--text-muted)] hover:border-[var(--accent)]"
            >
              {p.label}
            </button>
          ))}
        </div>
        <div className="mt-3 flex gap-2">
          <Button variant="ghost" onClick={() => setText('')}>
            Clear
          </Button>
        </div>
      </Card>

      <Card
        title="Four forms"
        action={
          <span className="text-[11.5px] text-[var(--text-muted)]">
            {distinct === 1 ? 'all four forms identical' : `${distinct} distinct strings`}
          </span>
        }
      >
        {!text ? (
          <div className="text-[12px] text-[var(--text-faint)]">Type or pick a preset — every form of an empty string is empty.</div>
        ) : (
          <>
            <div className="grid gap-3 sm:grid-cols-2">
              {FORMS.map((f) => (
                <div key={f} className="rounded border border-[var(--card-border)] p-2.5">
                  <div className="mb-1 flex items-center justify-between">
                    <span className="text-[11.5px] font-medium text-[var(--text)]">{f}</span>
                    <CopyChip text={forms[f]} label="Copy" />
                  </div>
                  <div className="rf-mono break-all text-[12px] text-[var(--text-muted)]">{visible(forms[f]) || '—'}</div>
                  <div className="mt-1 text-[10.5px] text-[var(--text-faint)]">
                    {utf8Len(forms[f])} bytes · {Array.from(forms[f]).length} code points
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-4">
              <Tabs<Form>
                value={form}
                onChange={setForm}
                tabs={FORMS.map((f) => ({ value: f, label: f, badge: Array.from(forms[f]).length }))}
              />
            </div>
            <div className="mt-3">
              <OutputField label={`${form} escaped`} value={escapeOf(forms[form])} mono />
            </div>
          </>
        )}
      </Card>

      <Card title="Per character">
        {rows.length === 0 ? (
          <div className="text-[12px] text-[var(--text-faint)]">No characters to decompose.</div>
        ) : (
          <>
            <div className="overflow-x-auto rounded border border-[var(--card-border)]">
              <table className="w-full text-[12px]">
                <thead>
                  <tr className="bg-[var(--neutral-btn)] text-left text-[var(--text-muted)]">
                    {['#', 'char', 'codepoint', 'name', 'script', 'width', 'survives NFKC', 'escape'].map((h) => (
                      <th key={h} className="px-2.5 py-1.5 font-medium whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r, i) => (
                    <tr key={`${r.index}-${r.cp}`} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                      <td className="rf-mono px-2.5 py-1.5">{r.index}</td>
                      <td className="rf-mono px-2.5 py-1.5">{r.cp < 0x20 || widthOf(r.cp) === 'zero' ? '·' : r.char}</td>
                      <td className="rf-mono px-2.5 py-1.5">U+{r.cp.toString(16).toUpperCase().padStart(4, '0')}</td>
                      <td className="px-2.5 py-1.5">{r.name}</td>
                      <td className="px-2.5 py-1.5 text-[var(--text-muted)]">{r.script}</td>
                      <td className="px-2.5 py-1.5">{r.width}</td>
                      <td
                        className="px-2.5 py-1.5"
                        style={{ color: r.survives ? 'var(--text-muted)' : 'var(--accent)' }}
                      >
                        {r.survives ? 'yes' : 'folded'}
                      </td>
                      <td className="rf-mono px-2.5 py-1.5">{escapeOf(r.char)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-3">
              <KVTable
                rows={[
                  ['Folded by NFKC', changed.length ? changed.map((r) => `U+${r.cp.toString(16).toUpperCase()}`).join(' ') : 'none'],
                  ['Non-ASCII survivors', survivals.length ? survivals.map((r) => `U+${r.cp.toString(16).toUpperCase()}`).join(' ') : 'none'],
                ]}
              />
            </div>
          </>
        )}
      </Card>

      <Card title="Same string, different bytes">
        <SectionTitle right={<span className="text-[11.5px] text-[var(--text-muted)]">UTF-8 length per form</span>}>
          Byte length
        </SectionTitle>
        <div className="overflow-x-auto rounded border border-[var(--card-border)]">
          <table className="w-full text-[12px]">
            <thead>
              <tr className="bg-[var(--neutral-btn)] text-left text-[var(--text-muted)]">
                {['form', 'code points', 'UTF-8 bytes', 'per code point', 'escaped'].map((h) => (
                  <th key={h} className="px-2.5 py-1.5 font-medium whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {lengths.map((l, i) => (
                <tr key={l.form} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                  <td className="rf-mono px-2.5 py-1.5">{l.form}</td>
                  <td className="rf-mono px-2.5 py-1.5">{l.chars}</td>
                  <td className="rf-mono px-2.5 py-1.5">{l.bytes}</td>
                  <td className="rf-mono px-2.5 py-1.5">{(l.bytes / Math.max(1, l.chars)).toFixed(2)}</td>
                  <td className="rf-mono px-2.5 py-1.5 break-all">{escapeOf(forms[l.form]).slice(0, 72) || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4">
          <Callout tone="warn" title="Why the survivor list is the interesting one">
            NFKC is where most filters meet Unicode: a WAF, a username blocklist or a length check may normalise while the
            application underneath compares raw bytes. Characters that survive NFKC are the ones that pass through both
            layers unchanged — a combining mark, a zero-width joiner or a bidi control can therefore change what a human
            reads without changing what a regex sees. Length checks are the same story: the four forms above differ by{' '}
            {lengths[0].bytes === lengths[1].bytes ? 'zero' : Math.max(...lengths.map((l) => l.bytes)) - Math.min(...lengths.map((l) => l.bytes))}{' '}
            bytes for identical text.
          </Callout>
        </div>
        <div className="mt-3">
          <OutputField label="Escaped original (\uXXXX, copyable into a payload)" value={escapeOf(text)} mono />
        </div>
      </Card>
    </>
  );
}
