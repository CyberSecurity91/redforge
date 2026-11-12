import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Callout, Card, DownloadButton, KVTable, OutputBlock, SectionTitle, TextArea } from '@/components/ui';

type Sev = 'high' | 'medium' | 'low';

interface Issue {
  sev: Sev;
  text: string;
}

interface Cookie {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  partitioned: boolean;
  priority?: string;
  sameSite?: string;
  domain?: string;
  path?: string;
  maxAge?: number;
  expires?: string;
  lifetimeDays: number | null;
  session: boolean;
  issues: Issue[];
}

const SEV_STYLE: Record<Sev, { label: string; color: string; weight: number }> = {
  high: { label: 'HIGH', color: 'var(--accent)', weight: 18 },
  medium: { label: 'MED', color: 'var(--warn)', weight: 7 },
  low: { label: 'LOW', color: 'var(--info)', weight: 2 },
};

const SAMPLE = `Set-Cookie: sessionid=8f2c1a9e4b7d; Path=/; Domain=.example.com; HttpOnly
Set-Cookie: __Host-csrf=6b1f0d; Path=/; Secure; SameSite=Strict; Max-Age=3600
Set-Cookie: remember=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc; Path=/; Expires=Wed, 09 Jun 2027 10:18:14 GMT
Set-Cookie: theme=dark; Path=/; SameSite=None`;

const SENSITIVE = /sess|auth|token|jwt|sid|remember|login|csrf|xsrf|bearer/i;

function analyseCookie(rawLine: string, now: number): Cookie | null {
  const line = rawLine.replace(/^\s*set-cookie:\s*/i, '').trim();
  if (!line || line.startsWith('#')) return null;
  const semi = line.indexOf(';');
  const head = semi === -1 ? line : line.slice(0, semi);
  const eq = head.indexOf('=');
  if (eq <= 0) return null;

  const name = head.slice(0, eq).trim();
  const value = head.slice(eq + 1).trim();
  const attrs = new Map<string, string | true>();
  for (const seg of (semi === -1 ? '' : line.slice(semi + 1)).split(';')) {
    const part = seg.trim();
    if (!part) continue;
    const i = part.indexOf('=');
    if (i === -1) attrs.set(part.toLowerCase(), true);
    else attrs.set(part.slice(0, i).trim().toLowerCase(), part.slice(i + 1).trim());
  }

  const flag = (k: string) => attrs.has(k);
  const str = (k: string) => (typeof attrs.get(k) === 'string' ? (attrs.get(k) as string) : undefined);

  const maxAgeRaw = str('max-age');
  const maxAge = maxAgeRaw !== undefined && /^-?\d+$/.test(maxAgeRaw) ? Number(maxAgeRaw) : undefined;
  const expires = str('expires');
  const expiresMs = expires ? Date.parse(expires) : NaN;

  let lifetimeDays: number | null = null;
  if (maxAge !== undefined) lifetimeDays = maxAge / 86400;
  else if (!Number.isNaN(expiresMs)) lifetimeDays = (expiresMs - now) / 86_400_000;

  const sameSite = str('samesite')?.toLowerCase();
  const cookie: Cookie = {
    name,
    value,
    secure: flag('secure'),
    httpOnly: flag('httponly'),
    partitioned: flag('partitioned'),
    priority: str('priority'),
    sameSite,
    domain: str('domain'),
    path: str('path'),
    maxAge,
    expires,
    lifetimeDays,
    session: maxAge === undefined && !expires,
    issues: [],
  };

  const issues: Issue[] = [];
  const sensitive = SENSITIVE.test(name);

  if (!cookie.secure) {
    issues.push({ sev: 'high', text: 'No Secure flag — the cookie will be sent over plain HTTP and is exposed on any TLS downgrade or mixed-content request.' });
  }
  if (!cookie.httpOnly) {
    issues.push({ sev: sensitive ? 'high' : 'medium', text: 'No HttpOnly — document.cookie can read it, so any XSS lifts the value directly.' });
  }
  if (!sameSite) {
    issues.push({ sev: 'medium', text: 'No SameSite — modern browsers assume Lax, but older ones send it on cross-site POST, enabling CSRF.' });
  } else if (sameSite === 'none' && !cookie.secure) {
    issues.push({ sev: 'high', text: 'SameSite=None without Secure is rejected outright by current browsers — the cookie is dropped.' });
  } else if (sameSite === 'none') {
    issues.push({ sev: 'medium', text: 'SameSite=None sends the cookie on every cross-site request — a CSRF token plus Origin check is mandatory.' });
  }
  if (cookie.domain) {
    issues.push({ sev: 'medium', text: `Domain=${cookie.domain} — a host-only cookie would be narrower; every subdomain of this scope can set and read it.` });
  }
  if (name.startsWith('__Host-') && !(cookie.secure && cookie.path === '/' && !cookie.domain)) {
    issues.push({ sev: 'high', text: '__Host- prefix violated — it requires Secure, Path=/ and no Domain attribute, else the browser rejects the cookie.' });
  }
  if (name.startsWith('__Secure-') && !cookie.secure) {
    issues.push({ sev: 'high', text: '__Secure- prefix without Secure — the browser rejects the cookie.' });
  }
  if (maxAge !== undefined && maxAge <= 0) {
    issues.push({ sev: 'high', text: 'Max-Age is zero or negative — the browser deletes the cookie immediately.' });
  }
  if (lifetimeDays !== null && lifetimeDays > 30) {
    issues.push({ sev: 'low', text: `Lifetime ${Math.round(lifetimeDays)} days — a stolen value stays valid long after the browser closes; check for server-side rotation.` });
  }
  if (cookie.session && sensitive) {
    issues.push({ sev: 'low', text: 'Session cookie with no expiry — fine for a login session only if the server also enforces an idle timeout.' });
  }
  if (/^ey[A-Za-z0-9_-]+\./.test(value) || value.length > 500) {
    issues.push({ sev: 'low', text: 'Value looks like a JWT or a long opaque blob — confirm it is signed and revocable server-side, not just encoded.' });
  }

  cookie.issues = issues;
  return cookie;
}

function penalty(c: Cookie): number {
  return c.issues.reduce((s, i) => s + SEV_STYLE[i.sev].weight, 0);
}

function gradeOf(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 78) return 'B';
  if (score >= 64) return 'C';
  if (score >= 48) return 'D';
  return 'F';
}

function fmtLifetime(c: Cookie): string {
  if (c.lifetimeDays === null) return c.expires ?? 'session';
  if (c.lifetimeDays < 0) return 'expired';
  const minutes = c.lifetimeDays * 1440;
  if (minutes < 60) return `${Math.round(minutes)} min`;
  if (c.lifetimeDays < 1) return `${Math.round(minutes / 60)} h`;
  return `${Math.round(c.lifetimeDays)} d`;
}

function Chip({ tone, children }: { tone: Sev | 'ok' | 'muted'; children: ReactNode }) {
  const color = tone === 'ok' ? 'var(--ok)' : tone === 'muted' ? 'var(--text-faint)' : SEV_STYLE[tone].color;
  return (
    <span className="rf-mono rounded px-1.5 py-0.5 text-[10.5px] font-semibold" style={{ color, background: 'var(--neutral-btn)' }}>
      {children}
    </span>
  );
}

export default function CookieSecurityAnalyser() {
  const [raw, setRaw] = useState('');

  const now = useMemo(() => Date.now(), [raw]);
  const cookies = useMemo(
    () =>
      raw
        .split(/\r?\n/)
        .map((l) => analyseCookie(l, now))
        .filter((c): c is Cookie => c !== null),
    [raw, now],
  );

  const total = cookies.reduce((s, c) => s + penalty(c), 0);
  const score = Math.max(0, 100 - Math.min(100, total));
  const grade = gradeOf(score);
  const worst = cookies.reduce<Cookie | null>((w, c) => (!w || penalty(c) > penalty(w) ? c : w), null);
  const insecure = cookies.filter((c) => !c.secure).length;
  const scriptable = cookies.filter((c) => !c.httpOnly).length;

  const findings = useMemo(() => {
    const map = new Map<string, { sev: Sev; text: string; names: string[] }>();
    for (const c of cookies) {
      for (const i of c.issues) {
        const entry = map.get(i.text);
        if (entry) entry.names.push(c.name);
        else map.set(i.text, { sev: i.sev, text: i.text, names: [c.name] });
      }
    }
    const order: Sev[] = ['high', 'medium', 'low'];
    return [...map.values()].sort((a, b) => order.indexOf(a.sev) - order.indexOf(b.sev));
  }, [cookies]);

  const hardened = worst
    ? `Set-Cookie: ${SENSITIVE.test(worst.name) ? `__Host-${worst.name.replace(/^__(Host|Secure)-/, '')}` : worst.name}=${worst.value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=86400`
    : '';

  return (
    <>
      <Card
        title="Set-Cookie headers"
        action={
          cookies.length > 0 ? (
            <DownloadButton text={JSON.stringify(cookies, null, 2)} filename="cookie-audit.json" label="Download JSON" />
          ) : undefined
        }
      >
        <TextArea
          value={raw}
          onChange={setRaw}
          rows={7}
          mono
          label="Paste headers, one per line"
          hint="Accept both a bare cookie string and the full Set-Cookie: prefix"
          placeholder={SAMPLE}
        />
        {cookies.length === 0 ? (
          <div className="mt-4">
            <Callout tone="info" title="Nothing parsed yet">
              Paste the response headers from a proxy. Each line is parsed independently, so a multi-cookie login
              response becomes one row per cookie.
            </Callout>
          </div>
        ) : (
          <div className="mt-5 grid gap-4 sm:grid-cols-3">
            <div className="rounded border border-[var(--card-border)] px-3 py-2.5">
              <div className="text-[11px] uppercase tracking-wide text-[var(--text-faint)]">Overall grade</div>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-[26px] font-semibold leading-none" style={{ color: score >= 78 ? 'var(--ok)' : score >= 48 ? 'var(--warn)' : 'var(--accent)' }}>
                  {grade}
                </span>
                <span className="rf-mono text-[12px] text-[var(--text-muted)]">{score}/100</span>
              </div>
            </div>
            <div className="rounded border border-[var(--card-border)] px-3 py-2.5">
              <div className="text-[11px] uppercase tracking-wide text-[var(--text-faint)]">Cookies parsed</div>
              <div className="rf-mono mt-1 text-[18px] text-[var(--text)]">{cookies.length}</div>
              <div className="mt-0.5 text-[11px] text-[var(--text-faint)]">
                {insecure} without Secure · {scriptable} without HttpOnly
              </div>
            </div>
            <div className="rounded border border-[var(--card-border)] px-3 py-2.5">
              <div className="text-[11px] uppercase tracking-wide text-[var(--text-faint)]">Weakest cookie</div>
              <div className="rf-mono mt-1 truncate text-[13px] text-[var(--text)]">{worst?.name ?? '—'}</div>
              <div className="mt-0.5 text-[11px] text-[var(--text-faint)]">{worst ? `${worst.issues.length} issue(s)` : '—'}</div>
            </div>
          </div>
        )}
      </Card>

      {cookies.length > 0 && (
        <Card title="Per-cookie posture">
          <div className="-mx-2 overflow-x-auto px-2">
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-left text-[var(--text-faint)]">
                  <th className="px-2 py-1.5 font-medium">Cookie</th>
                  <th className="px-2 py-1.5 font-medium">Flags</th>
                  <th className="px-2 py-1.5 font-medium">Lifetime</th>
                  <th className="px-2 py-1.5 font-medium">Scope</th>
                  <th className="px-2 py-1.5 font-medium">Verdict</th>
                </tr>
              </thead>
              <tbody>
                {cookies.map((c, i) => {
                  const highs = c.issues.filter((x) => x.sev === 'high').length;
                  const meds = c.issues.filter((x) => x.sev === 'medium').length;
                  return (
                    <tr key={`${c.name}-${i}`} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                      <td className="rf-mono px-2 py-1.5 align-top break-all text-[11.5px] text-[var(--text)]">{c.name}</td>
                      <td className="px-2 py-1.5 align-top">
                        <span className="flex flex-wrap gap-1">
                          <Chip tone={c.secure ? 'ok' : 'high'}>{c.secure ? 'Secure' : 'no Secure'}</Chip>
                          <Chip tone={c.httpOnly ? 'ok' : 'high'}>{c.httpOnly ? 'HttpOnly' : 'no HttpOnly'}</Chip>
                          <Chip tone={c.sameSite === 'strict' || c.sameSite === 'lax' ? 'ok' : c.sameSite === 'none' ? 'medium' : 'medium'}>
                            {c.sameSite ? `SameSite=${c.sameSite}` : 'SameSite —'}
                          </Chip>
                          {c.partitioned && <Chip tone="ok">Partitioned</Chip>}
                          {c.priority && <Chip tone="muted">Priority={c.priority}</Chip>}
                        </span>
                      </td>
                      <td className="px-2 py-1.5 align-top text-[11.5px] text-[var(--text-muted)]">
                        {fmtLifetime(c)}
                        {c.maxAge !== undefined && (
                          <span className="rf-mono mt-0.5 block text-[10.5px] text-[var(--text-faint)]">Max-Age={c.maxAge}</span>
                        )}
                      </td>
                      <td className="rf-mono px-2 py-1.5 align-top break-all text-[11px] text-[var(--text-faint)]">
                        {c.path ?? '/'}
                        {c.domain ? ` · ${c.domain}` : ' · host-only'}
                      </td>
                      <td className="px-2 py-1.5 align-top">
                        <Chip tone={highs ? 'high' : meds ? 'medium' : 'ok'}>
                          {highs ? 'replace' : meds ? 'harden' : 'acceptable'}
                        </Chip>
                        <div className="mt-1 text-[10.5px] text-[var(--text-faint)]">
                          {highs}H / {meds}M / {c.issues.length - highs - meds}L
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {findings.length > 0 && (
        <Card title="Findings and hardening">
          <div className="space-y-2">
            {findings.map((f) => (
              <div key={f.text} className="flex gap-2.5 rounded border border-[var(--card-border)] px-3 py-2">
                <div className="pt-0.5">
                  <Chip tone={f.sev}>{SEV_STYLE[f.sev].label}</Chip>
                </div>
                <div className="min-w-0">
                  <div className="text-[12.5px] leading-snug text-[var(--text)]">{f.text}</div>
                  <div className="rf-mono mt-1 text-[10.5px] break-all text-[var(--text-faint)]">
                    affected: {[...new Set(f.names)].join(', ')}
                  </div>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-5">
            <SectionTitle>Hardened replacement</SectionTitle>
            <OutputBlock value={hardened} label="Set-Cookie" rows={3} />
          </div>
          <div className="mt-4">
            <KVTable
              rows={[
                ['Rotate on login', 'Issue a fresh session ID on every privilege change; the old value must be invalidated server-side.'],
                ['Prefix by default', 'Use __Host- for session cookies — it forbids Domain and forces Secure + Path=/.'],
                ['CSRF', 'SameSite=Lax stops cross-site POST; SameSite=None needs a synchroniser token and an Origin/Referer check.'],
                ['Subdomain risk', 'A Domain cookie can be set by any subdomain, including one that serves user content.'],
              ]}
            />
          </div>
        </Card>
      )}
    </>
  );
}
