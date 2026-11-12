import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  KVTable,
  SectionTitle,
  TextArea,
  TextInput,
} from '@/components/ui';
import { DEFAULT_TARGET } from '@/tools/registry';

type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info';

type Finding = {
  directive: string;
  severity: Sev;
  title: string;
  detail: string;
};

const SEV_STYLE: Record<Sev, { label: string; color: string; weight: number }> = {
  critical: { label: 'CRIT', color: 'var(--accent)', weight: 30 },
  high: { label: 'HIGH', color: 'var(--accent)', weight: 18 },
  medium: { label: 'MED', color: 'var(--warn)', weight: 10 },
  low: { label: 'LOW', color: 'var(--info)', weight: 4 },
  info: { label: 'INFO', color: 'var(--text-faint)', weight: 0 },
};

const SAMPLE = `content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://*.googleapis.com; img-src * data:; style-src 'self' 'unsafe-inline'; object-src *;
x-xss-protection: 1; mode=block`;

/** Pull only the policy value out of a pasted header block. */
function extractPolicy(raw: string): string {
  const line = raw
    .split(/\r?\n/)
    .find((l) => /content-security-policy(?:-report-only)?\s*:/i.test(l));
  if (!line) return raw.trim().replace(/^(content-security-policy(-report-only)?)\s*:?\s*/i, '');
  return line.replace(/^.*?content-security-policy(-report-only)?\s*:/i, '').trim();
}

function parse(policy: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of policy.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    if (!/^[a-z-]+$/.test(name)) continue;
    out.set(name, tokens.slice(1));
  }
  return out;
}

const CDN_ALLOWLIST = ['cdnjs.cloudflare.com', 'unpkg.com', 'cdn.jsdelivr.net', 'ajax.googleapis.com', 'code.jquery.com', 'stackpath.bootstrapcdn.com'];
const JSONP_HOSTS = ['accounts.google.com', '*.google.com', 'apis.google.com', '*.twitter.com', '*.disqus.com', 'cdn.jsdelivr.net', '*.cloudflare.com'];

function analyse(policy: string): { findings: Finding[]; score: number; grade: string; verdict: string } {
  const dirs = parse(policy);
  const f: Finding[] = [];
  const get = (...names: string[]) => names.map((n) => dirs.get(n) ?? []).find((v) => v.length) ?? [];
  const has = (n: string) => dirs.has(n);

  const script = get('script-src', 'default-src');
  const scriptName = has('script-src') ? 'script-src' : 'default-src';
  const objectSrc = get('object-src');
  const frame = get('frame-ancestors');

  if (script.includes("'unsafe-inline'") && !script.some((t) => t.startsWith("'nonce-") || t.startsWith("'sha"))) {
    f.push({ directive: scriptName, severity: 'critical', title: "'unsafe-inline' without a nonce or hash", detail: 'Any reflected HTML can execute a script tag; the policy provides no XSS mitigation.' });
  } else if (script.includes("'unsafe-inline'")) {
    f.push({ directive: scriptName, severity: 'medium', title: "'unsafe-inline' alongside a nonce", detail: 'Modern browsers ignore unsafe-inline when a nonce is present, but older ones do not — remove it.' });
  }
  if (script.includes("'unsafe-eval'")) {
    f.push({ directive: scriptName, severity: 'high', title: "'unsafe-eval' present", detail: 'eval(), Function() and setTimeout(string) are sinks for DOM-XSS gadgets and some WAF normalisers.' });
  }
  if (script.includes('*')) {
    f.push({ directive: scriptName, severity: 'critical', title: 'Wildcard in script-src', detail: 'Any host can serve script; a single XSS or a takeover of any allow-LISTED CDN gives code execution.' });
  }
  if (script.some((t) => t.startsWith('data:'))) {
    f.push({ directive: scriptName, severity: 'high', title: 'data: URI allowed for script', detail: '<script src=data:text/javascript,…> or an iframe srcdoc chain executes without a host allow-list check.' });
  }
  if (script.some((t) => /^https?:$/.test(t))) {
    f.push({ directive: scriptName, severity: 'high', title: 'Scheme-only source (http: / https:)', detail: 'Equivalent to allowing any host over that scheme.' });
  }
  if (script.includes("'strict-dynamic'")) {
    const hostPart = script.filter((t) => !t.startsWith("'") && t !== '*');
    f.push({
      directive: scriptName,
      severity: hostPart.length ? 'medium' : 'info',
      title: "'strict-dynamic' interaction",
      detail: hostPart.length
        ? `Host allow-list entries (${hostPart.slice(0, 3).join(', ')}) are ignored by CSP3 browsers — only nonced scripts load. Nonce reuse or DOM clobbering of the nonce becomes the path.`
        : 'Host allow-list entries are ignored; the nonce or hash must be unguessable and not reflected.',
    });
  }
  if (!script.length) {
    f.push({ directive: 'script-src', severity: 'critical', title: 'No script-src and no default-src', detail: 'Scripts are unrestricted — the header does nothing for XSS.' });
  }

  if (!objectSrc.length) {
    f.push({ directive: 'object-src', severity: 'high', title: 'object-src missing', detail: 'Legacy plugins (Flash/PDF/Java) can load from any origin; also the first directive to declare when tightening.' });
  } else if (objectSrc.includes('*') || objectSrc.some((t) => t.startsWith('http'))) {
    f.push({ directive: 'object-src', severity: 'medium', title: 'object-src is permissive', detail: 'Set object-src to \'none\'.' });
  }

  if (!has('base-uri')) {
    f.push({ directive: 'base-uri', severity: 'medium', title: 'base-uri missing', detail: 'Injected <base href=//attacker/> rewrites every relative script/link on the page — a classic dangling-markup bypass.' });
  }
  if (!frame.length) {
    f.push({ directive: 'frame-ancestors', severity: 'medium', title: 'frame-ancestors missing', detail: 'Framing protection depends on X-Frame-Options alone; embed chains for clickjacking are open.' });
  } else if (frame.includes('*')) {
    f.push({ directive: 'frame-ancestors', severity: 'medium', title: 'frame-ancestors allows any origin', detail: 'Any site can frame the app — clickjacking and UI redress are back on the table.' });
  }

  if (!has('report-uri') && !has('report-to')) {
    f.push({ directive: 'report-uri', severity: 'low', title: 'No violation reporting', detail: 'Without report-uri/report-to you cannot see blocked injections — a blind spot for tuning.' });
  }
  if (/report-only/i.test(policy)) {
    f.push({ directive: 'Content-Security-Policy-Report-Only', severity: 'info', title: 'Report-only mode', detail: 'Violations are logged, not blocked; the policy is advisory until enforced.' });
  }

  for (const host of CDN_ALLOWLIST) {
    if (script.some((t) => t.includes(host))) {
      f.push({ directive: scriptName, severity: 'high', title: `CDN allow-list entry: ${host}`, detail: 'Any file hosted on this CDN (including user-uploaded content on cdnjs/unpkg/jsDelivr) can be loaded as script. Look for an AngularJS/JSONP gadget hosted on it.' });
    }
  }
  for (const host of JSONP_HOSTS) {
    if (script.some((t) => t.includes(host.replace('*', '')))) {
      f.push({ directive: scriptName, severity: 'critical', title: `JSONP gadget candidate: ${host}`, detail: 'Callback-parameter endpoints on this host return attacker-controlled JavaScript; use callback=? to wrap the response.' });
    }
  }

  const nonce = script.find((t) => t.startsWith("'nonce-"));
  if (nonce) {
    f.push({ directive: scriptName, severity: 'info', title: `Nonce in use (${nonce.length - 9} chars)`, detail: 'Check the nonce rotates per response and is not reused in cached HTML.' });
  }
  const hashes = script.filter((t) => /^'sha(256|384|512)-/.test(t));
  if (hashes.length) {
    f.push({ directive: scriptName, severity: 'info', title: `${hashes.length} hash source(s)`, detail: 'Hashes are safe only if every inline block is hashed and no gadget reuses the same body.' });
  }

  const penalty = f.reduce((n, x) => n + SEV_STYLE[x.severity].weight, 0);
  const score = Math.max(0, 100 - penalty);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  const critical = f.filter((x) => x.severity === 'critical').length;
  const verdict =
    critical > 0
      ? 'Bypassable — at least one critical gap lets an injected script run. Do not treat CSP as a mitigation in the report.'
      : f.some((x) => x.severity === 'high')
        ? 'Partially hardened — policy exists but host allow-lists or unsafe-eval leave realistic gadgets.'
        : f.some((x) => x.severity === 'medium')
          ? 'Mostly sound — remaining gaps are configuration hardening (base-uri, framing, reporting).'
          : 'Strong policy for the directives reviewed.';

  return { findings: f, score, grade, verdict };
}

function SevBadge({ sev }: { sev: Sev }) {
  const s = SEV_STYLE[sev];
  return (
    <span className="rf-mono rounded px-1.5 py-0.5 text-[10.5px] font-semibold" style={{ color: s.color, background: 'var(--neutral-btn)' }}>
      {s.label}
    </span>
  );
}

export default function CspAnalyser() {
  const [raw, setRaw] = useState('');
  const [host, setHost] = useState(DEFAULT_TARGET);

  const policy = useMemo(() => extractPolicy(raw), [raw]);
  const result = useMemo(() => (policy.trim() ? analyse(policy) : null), [policy]);
  const directives = useMemo(() => (policy.trim() ? parse(policy) : null), [policy]);

  return (
    <>
      <Card title="Policy input">
        <TextArea
          label="CSP header or full response headers"
          value={raw}
          onChange={setRaw}
          rows={7}
          placeholder={SAMPLE}
          hint="Paste the CSP header alone or a full header block. CRLF and folded headers are tolerated."
          action={
            <button
              type="button"
              onClick={() => setRaw(SAMPLE)}
              className="rounded px-2 py-0.5 text-[11.5px] text-[var(--text-faint)] hover:text-[var(--accent)]"
            >
              Load sample
            </button>
          }
        />
        <div className="mt-4 sm:max-w-sm">
          <TextInput label="Target host" value={host} onChange={setHost} mono hint="Used in the next-step commands" />
        </div>
      </Card>

      {!result ? (
        <Card title="Result">
          <Callout tone="info" title="No policy parsed">Paste a Content-Security-Policy header to begin.</Callout>
        </Card>
      ) : (
        <>
          <Card title="Score">
            <div className="flex flex-wrap items-center gap-6">
              <div>
                <div className="rf-mono text-[34px] leading-none text-[var(--accent)]">{result.score}</div>
                <div className="mt-1 text-[11.5px] text-[var(--text-faint)]">out of 100</div>
              </div>
              <div>
                <div className="text-[26px] leading-none text-[var(--text)]">{result.grade}</div>
                <div className="mt-1 text-[11.5px] text-[var(--text-faint)]">grade</div>
              </div>
              <div className="min-w-[220px] flex-1">
                <Callout tone={result.score < 50 ? 'danger' : result.score < 75 ? 'warn' : 'ok'}>{result.verdict}</Callout>
              </div>
            </div>
          </Card>

          <Card title="Findings">
            <KVTable
              rows={result.findings.map((x) => [
                <span key={x.title} className="inline-flex items-center gap-2">
                  <SevBadge sev={x.severity} />
                  <span className="rf-mono text-[11.5px] text-[var(--text-faint)]">{x.directive}</span>
                </span>,
                <span key={`${x.title}-d`} className="block">
                  <span className="block text-[var(--text)]">{x.title}</span>
                  <span className="mt-0.5 block font-sans text-[11.5px] text-[var(--text-muted)]">{x.detail}</span>
                </span>,
              ])}
            />
          </Card>

          <Card title="Parsed directives & next steps">
            <SectionTitle>Directives</SectionTitle>
            <KVTable
              rows={directives ? Array.from(directives.entries()).map(([k, v]) => [k, v.join(' ') || '(empty)']) : []}
            />
            <div className="mt-4">
              <SectionTitle>Next step</SectionTitle>
              <ol className="m-0 flex list-decimal flex-col gap-1.5 pl-5 text-[12.5px] text-[var(--text-muted)]">
                <li>
                  Re-fetch with <span className="rf-mono">curl -sI https://{host}/ | grep -i content-security-policy</span> and
                  confirm the header is not only present on the error page.
                </li>
                <li>For every allow-listed host, fetch its <span className="rf-mono">/</span> and look for JSONP callbacks (<span className="rf-mono">?callback=</span>) or an AngularJS bundle with <span className="rf-mono">ng-app</span>.</li>
                <li>If <span className="rf-mono">base-uri</span> is missing, try injecting <span className="rf-mono">{'<base href="//attacker.example/">'}</span> before a relative script tag.</li>
                <li>If <span className="rf-mono">'unsafe-inline'</span> is present with no nonce, confirm with a reflected <span className="rf-mono">{'<script>alert(1)</script>'}</span> payload.</li>
                <li>Record the exact header in the report and state that CSP is a mitigation only after the above pass.</li>
              </ol>
            </div>
          </Card>
        </>
      )}
    </>
  );
}
