import { useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, KVTable, SectionTitle, TextArea, TextInput } from '@/components/ui';
import { DEFAULT_TARGET } from '@/tools/registry';

type Status = 'ok' | 'warn' | 'missing';
type Row = { name: string; status: Status; value: string; note: string };

const SAMPLE = `HTTP/2 200
server: nginx/1.24.0
x-powered-by: Express
strict-transport-security: max-age=86400
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
referrer-policy: no-referrer-when-downgrade
access-control-allow-origin: *
access-control-allow-credentials: true
set-cookie: session=abc123; Path=/`;

const STATUS_STYLE: Record<Status, { label: string; color: string }> = {
  ok: { label: 'OK', color: 'var(--ok)' },
  warn: { label: 'WARN', color: 'var(--warn)' },
  missing: { label: 'MISSING', color: 'var(--accent)' },
};

function parseHeaders(raw: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const line of raw.split(/\r?\n/)) {
    const m = /^([a-z0-9-]+)\s*:\s*(.*)$/i.exec(line.trim());
    if (!m) continue;
    const key = m[1].toLowerCase();
    map.set(key, map.has(key) ? `${map.get(key)}, ${m[2].trim()}` : m[2].trim());
  }
  return map;
}

function grade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  if (score >= 50) return 'E';
  return 'F';
}

function audit(h: Map<string, string>): { rows: Row[]; score: number; cookies: string[] } {
  const rows: Row[] = [];
  const g = (k: string) => h.get(k) ?? '';
  let earned = 0;
  let possible = 0;
  const add = (name: string, max: number, status: Status, value: string, note: string) => {
    rows.push({ name, status, value, note });
    possible += max;
    if (status === 'ok') earned += max;
    else if (status === 'warn') earned += max / 2;
  };

  const hsts = g('strict-transport-security');
  const maxAge = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? 0);
  add(
    'Strict-Transport-Security',
    14,
    !hsts ? 'missing' : maxAge >= 31536000 ? 'ok' : 'warn',
    hsts,
    !hsts ? 'No HSTS — SSL-strip and protocol downgrade remain possible' : maxAge >= 31536000 ? 'max-age ≥ 1 year; add includeSubDomains; preload' : 'max-age too short — use 31536000 and includeSubDomains',
  );

  const csp = g('content-security-policy');
  add('Content-Security-Policy', 16, !csp ? 'missing' : /unsafe-inline|unsafe-eval|\*/.test(csp) ? 'warn' : 'ok', csp, !csp ? 'Reflected and stored XSS are unmitigated at the header layer' : 'Review with the CSP analyser for bypass gadgets');

  const xcto = g('x-content-type-options');
  add('X-Content-Type-Options', 8, /nosniff/i.test(xcto) ? 'ok' : 'missing', xcto, 'nosniff stops MIME sniffing turning a text upload into script');

  const xfo = g('x-frame-options');
  const fa = /frame-ancestors[^;]*/.exec(csp)?.[0] ?? '';
  add('X-Frame-Options / frame-ancestors', 10, fa ? 'ok' : /deny|sameorigin/i.test(xfo) ? 'ok' : 'missing', xfo || fa, 'Clickjacking protection — prefer frame-ancestors with XFO as fallback');

  const rp = g('referrer-policy');
  add('Referrer-Policy', 8, !rp ? 'missing' : /no-referrer|strict-origin/i.test(rp) ? 'ok' : 'warn', rp, 'Leaks tokens in query strings to third parties when permissive');

  const pp = g('permissions-policy');
  add('Permissions-Policy', 6, pp ? 'ok' : 'missing', pp, 'Restrict camera, microphone, geolocation and FLoC');

  const coop = ['cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy'].filter((k) => h.has(k));
  add('COOP / COEP / CORP', 9, coop.length === 3 ? 'ok' : coop.length ? 'warn' : 'missing', coop.map((k) => `${k}: ${g(k)}`).join(' | '), 'Cross-origin isolation stops window.opener and Spectre-style leaks');

  const acao = g('access-control-allow-origin');
  const acac = /true/i.test(g('access-control-allow-credentials'));
  add(
    'CORS policy',
    12,
    !acao ? 'ok' : acao === '*' && acac ? 'missing' : acao === '*' ? 'warn' : 'ok',
    acao ? `ACAO: ${acao}${acac ? ' + credentials' : ''}` : 'no CORS headers',
    acao === '*' ? 'Wildcard ACAO with credentials reads any authenticated response' : 'Echo-back origins are the common CORS bypass — check the reflected Origin',
  );

  const disclosure = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator'].filter((k) => h.has(k));
  add('Version disclosure', 8, disclosure.length ? 'warn' : 'ok', disclosure.map((k) => `${k}: ${g(k)}`).join(' | ') || 'none', 'Server banners pick the exploit kit; remove or genericise');

  const cookies = (h.get('set-cookie') ?? '').split(/, (?=[^ ;]+=)/);
  const cookieIssues = cookies.filter((c) => c && c.includes('=') && !(/secure/i.test(c) && /httponly/i.test(c) && /samesite/i.test(c)));
  add(
    'Cookie flags',
    9,
    cookies.length === 0 ? 'ok' : cookieIssues.length ? 'missing' : 'ok',
    cookies.join(' | ') || 'no Set-Cookie',
    cookies.length === 0 ? 'No session cookie on this response' : cookieIssues.length ? `${cookieIssues.length} cookie(s) missing Secure, HttpOnly or SameSite` : 'Secure, HttpOnly and SameSite set',
  );
  const score = Math.round((earned / possible) * 100);
  return { rows, score, cookies };
}

export default function SecurityHeaderAuditor() {
  const [raw, setRaw] = useState('');
  const [host, setHost] = useState(DEFAULT_TARGET);
  const headers = useMemo(() => parseHeaders(raw), [raw]);
  const result = useMemo(() => (headers.size > 2 ? audit(headers) : null), [headers]);

  return (
    <>
      <Card title="Response headers">
        <TextArea
          label="Paste full response headers"
          value={raw}
          onChange={setRaw}
          rows={9}
          placeholder={SAMPLE}
          hint="Include the status line if you copy from DevTools; it is ignored. One header per line."
          action={
            <button type="button" onClick={() => setRaw(SAMPLE)} className="rounded px-2 py-0.5 text-[11.5px] text-[var(--text-faint)] hover:text-[var(--accent)]">
              Load sample
            </button>
          }
        />
        <div className="mt-4 sm:max-w-sm">
          <TextInput label="Host" value={host} onChange={setHost} mono hint="Used in the capture command" />
        </div>
      </Card>

      {!result ? (
        <Card title="Score">
          <Callout tone="info" title="Paste headers to score">At least three headers are needed for a meaningful result.</Callout>
        </Card>
      ) : (
        <>
          <Card title="Score">
            <div className="flex flex-wrap items-center gap-8">
              <div>
                <div className="rf-mono text-[34px] leading-none" style={{ color: result.score >= 70 ? 'var(--ok)' : result.score >= 50 ? 'var(--warn)' : 'var(--accent)' }}>
                  {result.score}
                  <span className="text-[16px] text-[var(--text-faint)]">/100</span>
                </div>
                <div className="mt-1 text-[11.5px] text-[var(--text-faint)]">weighted score</div>
              </div>
              <div>
                <div className="text-[30px] leading-none text-[var(--text)]">{grade(result.score)}</div>
                <div className="mt-1 text-[11.5px] text-[var(--text-faint)]">grade</div>
              </div>
              <div className="min-w-[240px] flex-1">
                <Callout tone={result.score >= 70 ? 'ok' : result.score >= 50 ? 'warn' : 'danger'}>
                  {result.rows.filter((r) => r.status === 'missing').length} missing,{' '}
                  {result.rows.filter((r) => r.status === 'warn').length} weak, {result.rows.filter((r) => r.status === 'ok').length} good.
                </Callout>
              </div>
            </div>
          </Card>

          <Card title="Checklist">
            <div className="overflow-x-auto rounded border border-[var(--card-border)]">
              <table className="w-full text-[12.5px]">
                <thead>
                  <tr className="bg-[var(--neutral-btn)] text-[11.5px] tracking-wide text-[var(--text-muted)] uppercase">
                    <th className="px-3 py-2 text-left font-medium">Header</th>
                    <th className="px-3 py-2 text-left font-medium">Status</th>
                    <th className="px-3 py-2 text-left font-medium">Value</th>
                    <th className="px-3 py-2 text-left font-medium">Note</th>
                  </tr>
                </thead>
                <tbody>
                  {result.rows.map((r) => (
                    <tr key={r.name} className="border-t border-[var(--card-border)]">
                      <td className="px-3 py-1.5 align-top text-[var(--text)]">{r.name}</td>
                      <td className="px-3 py-1.5 align-top">
                        <span className="rf-mono text-[10.5px] font-semibold" style={{ color: STATUS_STYLE[r.status].color }}>
                          {STATUS_STYLE[r.status].label}
                        </span>
                      </td>
                      <td className="rf-mono max-w-[260px] px-3 py-1.5 align-top break-all text-[var(--text-muted)]">{r.value || '—'}</td>
                      <td className="px-3 py-1.5 align-top text-[11.5px] text-[var(--text-faint)]">{r.note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <Card title="Capture command">
            <CodeBlock
              code={`curl -sS -D - -o /dev/null -H 'User-Agent: Mozilla/5.0' 'https://${host}/'`}
              label="curl -sI equivalent"
            />
            <div className="mt-4">
              <SectionTitle>Header count</SectionTitle>
              <KVTable
                rows={[
                  ['Parsed headers', String(headers.size)],
                  ['Cookies seen', result.cookies.length ? `${result.cookies.length}` : 'none'],
                  ['Duplicate handling', 'Repeated headers are joined with ", "'],
                ]}
              />
            </div>
          </Card>
        </>
      )}
    </>
  );
}
