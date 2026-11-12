import { useMemo, useState, type ReactNode } from 'react';
import { Callout, Card, KVTable, SectionTitle, TextArea, TextInput } from '@/components/ui';
import { DEFAULT_TARGET } from '@/tools/registry';

type Sev = 'critical' | 'high' | 'medium' | 'info';

const SEV_COLOR: Record<Sev, string> = {
  critical: 'var(--accent)',
  high: 'var(--accent)',
  medium: 'var(--warn)',
  info: 'var(--text-faint)',
};

const SAMPLE = `example.com. 300 IN TXT "v=spf1 ip4:203.0.113.10 ip4:198.51.100.0/24 include:_spf.mailer.example.net ~all"
_dmarc.example.com. 300 IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; adkim=r; aspf=r; pct=100"
google._domainkey.example.com. 300 IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1s3Q7Kk0mJ0h1y9t5v8bQ2xYk4cJm0pQe7wZ1nR2sV5uT8oP3aS6dF9gH2jK4lM6nB8vC0xZ1qW3eR5tY7uI9oP1aS3dF5gH7jK9lM"`;

function chip(text: string, color: string) {
  return (
    <span className="rf-mono rounded px-1.5 py-0.5 text-[10.5px] font-semibold" style={{ color, background: 'var(--neutral-btn)' }}>
      {text}
    </span>
  );
}

/** Strip DNS framing (`name. 300 IN TXT "…"`) down to the record value. */
function recordValue(line: string, marker: string): string | null {
  const at = line.toLowerCase().indexOf(marker);
  if (at < 0) return null;
  const tail = line.slice(at).replace(/\\"/g, '"');
  const quoted = /"([^"]*)"/.exec(tail);
  const raw = quoted ? quoted[1] : tail;
  return raw.replace(/"\s*$/, '').trim() || null;
}

interface Mechanism {
  raw: string;
  qualifier: string;
  name: string;
  value?: string;
  lookup: boolean;
}

function parseSpf(record: string) {
  const tokens = record.split(/\s+/).filter(Boolean).slice(1);
  const mechs: Mechanism[] = [];
  let redirect: string | null = null;
  let exp: string | null = null;
  for (const token of tokens) {
    const m = /^([+\-~?])?(include|ip4|ip6|a|mx|ptr|exists|all)(?::(\S+))?$/i.exec(token);
    if (m) {
      const name = (m[2] ?? '').toLowerCase();
      mechs.push({
        raw: token,
        qualifier: m[1] ?? '+',
        name,
        value: m[3],
        lookup: ['include', 'a', 'mx', 'ptr', 'exists'].includes(name),
      });
      continue;
    }
    const red = /^redirect=(\S+)$/i.exec(token);
    if (red) redirect = red[1] ?? null;
    const ex = /^exp=(\S+)$/i.exec(token);
    if (ex) exp = ex[1] ?? null;
  }
  const all = mechs.find((m) => m.name === 'all');
  const lookups = mechs.filter((m) => m.lookup).length + (redirect ? 1 : 0);
  return { mechs, redirect, exp, all, lookups };
}

function parseTags(record: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of record.split(';')) {
    const [k, ...rest] = part.split('=');
    const key = (k ?? '').trim().toLowerCase();
    if (!key) continue;
    out[key] = rest.join('=').trim();
  }
  return out;
}

/** Rough RSA modulus size from the base64 SubjectPublicKeyInfo blob. */
function keyBits(b64: string): number {
  const der = Math.floor((b64.length * 3) / 4) - (b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0);
  return Math.round(((der - 38) * 8) / 64) * 64;
}

export default function EmailSecurityAuditor() {
  const [domain, setDomain] = useState(DEFAULT_TARGET);
  const [records, setRecords] = useState('');

  const parsed = useMemo(() => {
    const lines = records.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    const spfLine = lines.find((l) => /v=spf1/i.test(l));
    const dmarcLine = lines.find((l) => /v=dmarc1/i.test(l));
    const dkimLines = lines.filter((l) => /v=dkim1|k=rsa|\bp=[a-z0-9+/]{20,}/i.test(l) && /_domainkey|v=dkim1/i.test(l));
    const spf = spfLine ? recordValue(spfLine, 'v=spf1') : null;
    const dmarc = dmarcLine ? recordValue(dmarcLine, 'v=dmarc1') : null;
    const dkim = dkimLines.map((l) => {
      const selector = /([a-z0-9-]+)\._domainkey/i.exec(l)?.[1] ?? 'unknown';
      const tags = parseTags(recordValue(l, 'v=dkim1') ?? '');
      return { selector, tags };
    });
    return { spf, dmarc, dkim };
  }, [records]);

  const analysis = useMemo(() => {
    if (!parsed.spf && !parsed.dmarc && !parsed.dkim.length) return null;
    const spf = parsed.spf ? parseSpf(parsed.spf) : null;
    const dm = parsed.dmarc ? parseTags(parsed.dmarc) : null;
    const p = (dm?.p ?? '').toLowerCase();
    const sp = (dm?.sp ?? '').toLowerCase();
    const pct = dm?.pct ? Math.max(0, Math.min(100, Number(dm.pct))) : 100;

    const findings: Array<{ sev: Sev; title: string; detail: string }> = [];
    const allQ = spf?.all?.qualifier;
    if (!spf) {
      findings.push({ sev: 'critical', title: 'No SPF record', detail: 'Any host may claim the envelope sender; only DMARC alignment could stop delivery, and only if enforced.' });
    } else if (!allQ || allQ === '+') {
      findings.push({ sev: 'critical', title: `SPF ends in ${allQ ?? '(no all)'}`, detail: 'Receivers are told that unlisted senders pass. SPF provides no protection at all in this state.' });
    } else if (allQ === '?') {
      findings.push({ sev: 'high', title: 'SPF ends in ?all', detail: 'Neutral result — receivers apply no reputation penalty. Treat as no SPF.' });
    } else if (allQ === '~') {
      findings.push({ sev: 'medium', title: 'SPF ends in ~all (softfail)', detail: 'Softfail is usually delivered to junk rather than rejected. Phishing still lands.' });
    }
    if (spf && spf.lookups > 10) {
      findings.push({ sev: 'high', title: `${spf.lookups} DNS lookups — RFC 7208 limit is 10`, detail: 'Receivers return permerror, which many evaluate as fail regardless of the sender. Trim includes or flatten them.' });
    }
    if (spf?.mechs.some((m) => m.name === 'ptr')) {
      findings.push({ sev: 'medium', title: 'ptr mechanism present', detail: 'Deprecated in RFC 7208, unreliable, and it consumes a lookup for nothing.' });
    }
    if (spf?.redirect) {
      findings.push({ sev: 'info', title: `redirect=${spf.redirect}`, detail: 'The redirect target replaces the local policy; it counts against the 10-lookup budget and hides the live all-qualifier from this record.' });
    }
    if (!dm) {
      findings.push({ sev: 'critical', title: 'No DMARC record at _dmarc', detail: 'Nothing binds the header From to SPF or DKIM. Direct domain spoofing is possible.' });
    } else {
      if (p === 'none') findings.push({ sev: 'high', title: 'DMARC p=none', detail: 'Reports only; receivers take no action on failure. Spoofed mail still lands.' });
      if (!dm.rua) findings.push({ sev: 'medium', title: 'No rua= reporting address', detail: 'No aggregate reports means no visibility into who is sending as the domain.' });
      if (pct < 100) findings.push({ sev: 'high', title: `pct=${pct}`, detail: `Only ${pct}% of failing mail is actioned; ${100 - pct}% still delivers, so a single message gets through with retries.` });
      if (sp === 'none') findings.push({ sev: 'high', title: 'sp=none under an enforced apex', detail: 'Subdomains are explicitly exempt — spoof mail-as-a-subdomain and alignment passes weakness.' });
      if (dm.adkim === 'r' || dm.aspf === 'r') findings.push({ sev: 'info', title: `Relaxed alignment (adkim=${dm.adkim ?? 'r'}, aspf=${dm.aspf ?? 'r'})`, detail: 'Relaxed mode aligns on the organisational domain, so any sibling subdomain that can send is aligned.' });
    }
    if (!parsed.dkim.length) {
      findings.push({ sev: 'high', title: 'No DKIM key parsed', detail: 'Without a selector, authenticated mail cannot be replayed or checked; DMARC falls back to SPF only.' });
    }
    for (const key of parsed.dkim) {
      if (!key.tags.p) findings.push({ sev: 'medium', title: `Selector ${key.selector} has an empty p=`, detail: 'Empty p= revokes the key; mail signed with it fails DKIM.' });
      else if ((key.tags.k ?? 'rsa') === 'rsa' && keyBits(key.tags.p) < 1024) {
        findings.push({ sev: 'medium', title: `Selector ${key.selector} looks shorter than 1024 bits`, detail: 'Short RSA keys are forgeable at feasible cost; rotate to 2048.' });
      }
      if ((key.tags.k ?? '').toLowerCase() === 'ed25519') findings.push({ sev: 'info', title: `Selector ${key.selector} uses ed25519`, detail: 'Not universally validated by receivers; keep an RSA selector alongside it.' });
    }

    const spfScore = !spf ? 30 : !allQ || allQ === '+' ? 30 : allQ === '?' ? 24 : allQ === '~' ? 14 : 0;
    const dmarcScore = !dm ? 40 : p === 'none' ? 30 : p === 'quarantine' ? 12 : 0;
    const coverage = (dm && !dm.rua ? 5 : 0) + (dm && pct < 100 ? 6 : 0) + (parsed.dkim.length ? 0 : 8) + (spf && spf.lookups > 10 ? 10 : 0);
    const score = Math.min(100, spfScore + dmarcScore + coverage);
    const verdict =
      score >= 60
        ? 'Spoofable — a forged header From reaches the inbox with no receiver-side penalty.'
        : score >= 30
          ? 'Weak — messages may be junked rather than rejected; retries and pct gaps still deliver.'
          : score >= 12
            ? 'Mostly protected — enforcement exists but scope, alignment or coverage leaves a route.'
            : 'Hardened — reject policy with aligned authentication and a usable key.';

    const subdomain =
      !dm
        ? 'Unprotected — no DMARC means no inherited policy for any host under the domain.'
        : sp === 'none'
          ? 'Explicitly unprotected (sp=none) — a spoofed subdomain sender passes policy evaluation.'
          : sp
            ? `sp=${sp} applies to every subdomain that has no record of its own.`
            : `No sp= tag, so subdomains inherit p=${p || '(unset)'} at the organisational domain.`;
    const spfSubdomain = spf
      ? 'SPF is published per name: subdomains without their own TXT record return none, so only DMARC alignment covers them.'
      : 'No SPF at the apex and therefore none inherited — subdomains are envelope-forgeable.';

    const vectors = [
      { vector: 'Display-name spoof (same domain, different From)', live: true, detail: 'Always available; survives any DMARC policy because the address is genuine.' },
      { vector: 'Lookalike / homoglyph domain', live: true, detail: 'Registered attacker domain passes its own authentication; only user education and mail-gateway rules help.' },
      { vector: 'Header From vs envelope From mismatch', live: !dm || p === 'none', detail: 'SPF authenticates the envelope only; without DMARC alignment the visible From is unbound.' },
      { vector: 'Subdomain sender', live: !dm || sp === 'none' || p === 'none', detail: subdomain },
      { vector: 'Relay through a permitted include', live: !!spf?.mechs.some((m) => m.name === 'include'), detail: 'Any tenant of the included provider can send aligned mail with its own payload.' },
      { vector: 'Partial enforcement retry', live: !!dm && pct < 100, detail: `pct=${pct} actions a share of failures; resend until one is sampled out.` },
      { vector: 'Replay of a legitimately signed message', live: parsed.dkim.length > 0, detail: 'DKIM has no recipient binding; a captured message verifies forever for that selector.' },
    ];

    return { spf, dm, p, sp, pct, findings, score, verdict, subdomain, spfSubdomain, vectors };
  }, [parsed]);

  const domainRows: Array<[ReactNode, ReactNode]> = analysis
    ? [
        ['SPF', analysis.spf ? `${analysis.spf.mechs.length} mechanisms · ${analysis.spf.lookups}/10 lookups` : 'absent'],
        ['DMARC', analysis.dm ? `p=${analysis.p || '(unset)'}${analysis.dm.sp ? ` · sp=${analysis.dm.sp}` : ''}${analysis.dm.rua ? ' · rua set' : ' · no rua'}` : 'absent'],
        ['DKIM selectors', parsed.dkim.length ? parsed.dkim.map((k) => k.selector).join(', ') : 'none parsed'],
        ['Subdomain policy', analysis.subdomain],
      ]
    : [];

  return (
    <>
      <Card title="Published records">
        <div className="grid gap-4">
          <TextInput label="Domain under test" value={domain} onChange={setDomain} mono placeholder={DEFAULT_TARGET} hint="Used in the verification commands" />
          <TextArea
            label="SPF, DMARC and DKIM TXT answers"
            value={records}
            onChange={setRecords}
            rows={6}
            placeholder={SAMPLE}
            hint="One record per line, straight from dig or a DNS console. Selector names are read from the _domainkey label."
            action={
              <button
                type="button"
                onClick={() => setRecords(SAMPLE)}
                className="rounded px-2 py-0.5 text-[11.5px] text-[var(--text-faint)] hover:text-[var(--accent)]"
              >
                Load sample
              </button>
            }
          />
        </div>
      </Card>

      {!analysis ? (
        <Card title="Verdict">
          <Callout tone="info" title="No records parsed">Paste at least one SPF, DMARC or DKIM TXT answer to score the domain.</Callout>
        </Card>
      ) : (
        <>
          <Card title="Spoofability">
            <div className="flex flex-wrap items-start gap-6">
              <div>
                <div className="rf-mono text-[34px] leading-none text-[var(--accent)]">{analysis.score}</div>
                <div className="mt-1 text-[11.5px] text-[var(--text-faint)]">risk / 100</div>
              </div>
              <div className="min-w-[240px] flex-1">
                <Callout tone={analysis.score >= 60 ? 'danger' : analysis.score >= 30 ? 'warn' : 'ok'}>{analysis.verdict}</Callout>
              </div>
            </div>
            <div className="mt-4">
              <KVTable rows={domainRows} />
            </div>
            <div className="mt-3 text-[12px] leading-relaxed text-[var(--text-muted)]">{analysis.spfSubdomain}</div>
          </Card>

          <Card title="SPF mechanisms">
            {analysis.spf ? (
              <>
                <KVTable
                  rows={analysis.spf.mechs.map((m) => [
                    <span key={`${m.raw}-k`} className="inline-flex items-center gap-2">
                      {chip(m.qualifier, m.qualifier === '+' ? 'var(--accent)' : m.qualifier === '-' ? 'var(--ok)' : 'var(--warn)')}
                      <span className="rf-mono">{m.name}</span>
                    </span>,
                    <span key={`${m.raw}-v`} className="rf-mono">
                      {m.value ?? '(current domain)'} {m.lookup && <span className="text-[var(--text-faint)]">· costs a lookup</span>}
                    </span>,
                  ])}
                />
                <div className="mt-4">
                  <SectionTitle right={<span className="rf-mono text-[11.5px] text-[var(--text-faint)]">{analysis.spf.lookups}/10</span>}>
                    RFC 7208 lookup budget
                  </SectionTitle>
                  <div className="h-2 w-full overflow-hidden rounded bg-[var(--neutral-btn)]">
                    <div
                      className="h-full rounded"
                      style={{
                        width: `${Math.min(100, (analysis.spf.lookups / 10) * 100)}%`,
                        background: analysis.spf.lookups > 10 ? 'var(--accent)' : analysis.spf.lookups > 7 ? 'var(--warn)' : 'var(--ok)',
                      }}
                    />
                  </div>
                  <p className="mt-2 mb-0 text-[12px] text-[var(--text-muted)]">
                    {analysis.spf.lookups > 10
                      ? 'Over budget: receivers answer permerror, so legitimate mail can fail alongside forged mail.'
                      : `${10 - analysis.spf.lookups} lookups of headroom before permerror. Includes that themselves contain include/redirect chains are counted by the receiver, not by this record.`}
                  </p>
                </div>
              </>
            ) : (
              <Callout tone="danger" title="No SPF">Publish <span className="rf-mono">v=spf1 … -all</span> before touching DMARC enforcement.</Callout>
            )}
          </Card>

          <Card title="DMARC and DKIM">
            {analysis.dm ? (
              <KVTable rows={Object.entries(analysis.dm).map(([k, v]) => [k, v || '(empty)'])} />
            ) : (
              <Callout tone="warn" title="No DMARC tag block">Nothing was parsed from a <span className="rf-mono">v=DMARC1</span> record.</Callout>
            )}
            {parsed.dkim.length > 0 && (
              <div className="mt-4">
                <SectionTitle>DKIM selectors</SectionTitle>
                <KVTable
                  rows={parsed.dkim.map((k) => [
                    k.selector,
                    <span key={k.selector} className="rf-mono">
                      {(k.tags.k ?? 'rsa')} {k.tags.p ? `· ~${keyBits(k.tags.p)} bits` : '· revoked (empty p=)'}
                    </span>,
                  ])}
                />
              </div>
            )}
            <div className="mt-4 flex flex-col gap-2">
              {analysis.findings.map((f) => (
                <div key={f.title} className="flex items-start gap-2 text-[12.5px] leading-relaxed">
                  {chip(f.sev.toUpperCase(), SEV_COLOR[f.sev])}
                  <span>
                    <span className="text-[var(--text)]">{f.title}</span>
                    <span className="text-[var(--text-muted)]"> — {f.detail}</span>
                  </span>
                </div>
              ))}
            </div>
          </Card>

          <Card title="Remaining bypass vectors">
            <KVTable
              rows={analysis.vectors.map((v) => [
                <span key={v.vector} className="inline-flex items-center gap-2">
                  {chip(v.live ? 'LIVE' : 'BLOCKED', v.live ? 'var(--accent)' : 'var(--ok)')}
                  <span className="font-sans text-[12.5px] text-[var(--text)]">{v.vector}</span>
                </span>,
                <span key={`${v.vector}-d`} className="block font-sans text-[12px] text-[var(--text-muted)]">
                  {v.detail}
                </span>,
              ])}
            />
            <div className="mt-4">
              <SectionTitle>Confirm on the wire</SectionTitle>
              <KVTable
                rows={[
                  ['SPF', `dig +short TXT ${domain}`],
                  ['DMARC', `dig +short TXT _dmarc.${domain}`],
                  ['DKIM', `dig +short TXT google._domainkey.${domain}`],
                  ['Envelope test', `swaks --from spoof@${domain} --to test@example.net --server 203.0.113.10`],
                ]}
              />
            </div>
          </Card>
        </>
      )}
    </>
  );
}
