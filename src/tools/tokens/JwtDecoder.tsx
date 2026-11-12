import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  CodeBlock,
  CopyChip,
  KVTable,
  SectionTitle,
  TextArea,
} from '@/components/ui';

type Severity = 'high' | 'medium' | 'low' | 'info';
type Finding = { id: string; severity: Severity; claim: string; detail: string };

const SAMPLE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yMDI0In0.' +
  'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6ImFkbWluIiwic2NvcGUiOiJvcmRlcnM6d3JpdGUiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTczMTUzNjAwMH0.' +
  '3v4nqXxY3s0Q0v5B2m2m2nXq6VfS9k1o0sR2b4t3u1A';

const SEV_COLOR: Record<Severity, string> = {
  high: 'var(--accent)',
  medium: 'var(--warn)',
  low: 'var(--info)',
  info: 'var(--text-faint)',
};

function b64urlToBytes(seg: string): Uint8Array {
  const pad = seg.length % 4 === 0 ? '' : '='.repeat(4 - (seg.length % 4));
  const bin = atob(seg.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToJson(seg: string): { value: Record<string, unknown> | null; error: string | null } {
  try {
    const text = new TextDecoder().decode(b64urlToBytes(seg));
    const value = JSON.parse(text) as unknown;
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return { value: null, error: 'Segment is JSON but not an object' };
    }
    return { value: value as Record<string, unknown>, error: null };
  } catch (e) {
    return { value: null, error: e instanceof Error ? e.message : 'not valid base64url JSON' };
  }
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function pretty(v: unknown): string {
  return JSON.stringify(v, null, 2);
}

const SYMMETRIC = new Set(['HS256', 'HS384', 'HS512']);
const ASYMMETRIC = new Set(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA']);

function analyse(h: Record<string, unknown> | null, p: Record<string, unknown> | null): Finding[] {
  const out: Finding[] = [];
  if (h) {
    const alg = String(h.alg ?? '');
    if (alg.toLowerCase() === 'none') out.push({ id: 'alg-none', severity: 'high', claim: 'alg', detail: 'alg:none — signature verification can be skipped entirely; try re-submitting with the signature segment deleted.' });
    if (SYMMETRIC.has(alg) && typeof h.jwk === 'object' && h.jwk !== null)
      out.push({ id: 'jwk-hs', severity: 'high', claim: 'jwk', detail: 'Embedded jwk alongside an HMAC alg — the server may honour the attacker key (JWK header injection).' });
    if (h.kid !== undefined)
      out.push({ id: 'kid', severity: 'medium', claim: 'kid', detail: `kid present (${JSON.stringify(h.kid)}) — test path traversal (../../dev/null), SQLi and command injection in the key lookup.` });
    if (h.jku !== undefined) out.push({ id: 'jku', severity: 'high', claim: 'jku', detail: 'jku header — point it at a JWKS you host (oast.example.com) to see whether the server fetches it (SSRF + key substitution).' });
    if (h.x5u !== undefined) out.push({ id: 'x5u', severity: 'high', claim: 'x5u', detail: 'x5u header — same class as jku: attacker-supplied certificate chain.' });
    if (typeof h.typ === 'string' && !/jwt/i.test(h.typ)) out.push({ id: 'typ', severity: 'info', claim: 'typ', detail: `Unusual typ ${JSON.stringify(h.typ)} — check whether the parser is type-confused.` });
    if (!alg) out.push({ id: 'no-alg', severity: 'medium', claim: 'alg', detail: 'No alg in header — parser behaviour undefined.' });
  }
  if (p) {
    const now = Math.floor(Date.now() / 1000);
    const exp = typeof p.exp === 'number' ? p.exp : null;
    const iat = typeof p.iat === 'number' ? p.iat : null;
    const nbf = typeof p.nbf === 'number' ? p.nbf : null;
    if (exp === null) out.push({ id: 'no-exp', severity: 'medium', claim: 'exp', detail: 'No exp — token never expires; a leaked copy is permanent access.' });
    else if (exp < now) out.push({ id: 'exp-past', severity: 'low', claim: 'exp', detail: `expired ${new Date(exp * 1000).toISOString()} — reuse to test whether expiry is actually enforced.` });
    else if (exp - now > 60 * 60 * 24 * 7) out.push({ id: 'exp-long', severity: 'medium', claim: 'exp', detail: `Valid for ${Math.round((exp - now) / 86400)} more days — long-lived bearer tokens widen the replay window.` });
    if (iat !== null && iat > now + 300) out.push({ id: 'iat-future', severity: 'low', claim: 'iat', detail: 'iat is in the future — clock skew or a forged token.' });
    if (nbf !== null && nbf > now) out.push({ id: 'nbf', severity: 'info', claim: 'nbf', detail: `nbf in the future (${new Date(nbf * 1000).toISOString()}).` });
    for (const key of ['role', 'roles', 'admin', 'is_admin', 'scope', 'scp', 'tenant', 'tenant_id', 'org', 'permissions', 'groups']) {
      if (key in p) out.push({ id: `priv-${key}`, severity: 'info', claim: key, detail: `Privileged claim ${key} = ${JSON.stringify(p[key])} — the escalation target for a forged payload.` });
    }
    if ('sub' in p && 'iss' in p && typeof p.iss === 'string' && !/^https?:/.test(p.iss))
      out.push({ id: 'iss', severity: 'info', claim: 'iss', detail: `iss is not a URL (${JSON.stringify(p.iss)}) — compare against the discovery document.` });
  }
  return out;
}

export default function JwtDecoder() {
  const [token, setToken] = useState('');

  const parsed = useMemo(() => {
    const raw = token.trim().replace(/^Bearer\s+/i, '');
    if (!raw) return null;
    const parts = raw.split('.');
    const header = parts[0] ? b64urlToJson(parts[0]) : { value: null, error: 'missing segment' };
    const payload = parts[1] ? b64urlToJson(parts[1]) : { value: null, error: 'missing segment' };
    let sig: { hex: string; b64: string; bytes: number } | null = null;
    if (parts[2]) {
      try {
        const b = b64urlToBytes(parts[2]);
        sig = { hex: toHex(b), b64: parts[2], bytes: b.length };
      } catch {
        sig = null;
      }
    }
    const warnings: string[] = [];
    if (parts.length !== 3) warnings.push(`Expected 3 segments, found ${parts.length}.`);
    if (header.error) warnings.push(`Header: ${header.error}`);
    if (payload.error) warnings.push(`Payload: ${payload.error}`);
    const alg = header.value ? String(header.value.alg ?? '') : '';
    if (SYMMETRIC.has(alg) && parts[2])
      warnings.push(`HMAC token (${alg}) — fetch the service public key and test RS→HS confusion by signing with it as the secret.`);
    return { parts, header, payload, sig, alg, warnings, findings: analyse(header.value, payload.value) };
  }, [token]);

  return (
    <>
      <Card title="Token">
        <TextArea
          label="Paste a JWT"
          value={token}
          onChange={setToken}
          rows={5}
          placeholder={SAMPLE}
          hint="Bearer prefix is stripped automatically. Decoding is local — nothing leaves the page."
          action={
            <button type="button" onClick={() => setToken(SAMPLE)} className="rounded px-2 py-0.5 text-[11.5px] text-[var(--text-faint)] hover:text-[var(--accent)]">
              Load sample
            </button>
          }
        />
      </Card>

      {!parsed ? (
        <Card title="Decoded">
          <Callout tone="info" title="Nothing to decode">Paste a token to see the header, claims and signature analysis.</Callout>
        </Card>
      ) : (
        <>
          <Card title="Structure">
            <KVTable
              rows={[
                ['Segments', String(parsed.parts.length)],
                ['Algorithm', parsed.alg || '—'],
                ['Family', SYMMETRIC.has(parsed.alg) ? 'Symmetric (shared secret)' : ASYMMETRIC.has(parsed.alg) ? 'Asymmetric (public key verifies)' : 'Unknown / none'],
                ['Signature bytes', parsed.sig ? `${parsed.sig.bytes} (${parsed.sig.hex.slice(0, 32)}…)` : 'absent'],
                ['Header parsed', parsed.header.value ? 'yes' : 'no'],
                ['Payload parsed', parsed.payload.value ? 'yes' : 'no'],
              ]}
            />
            {parsed.warnings.length > 0 && (
              <div className="mt-4">
                <Callout tone="warn" title="Structural issues">
                  <ul className="m-0 list-disc pl-4">
                    {parsed.warnings.map((w) => (
                      <li key={w}>{w}</li>
                    ))}
                  </ul>
                </Callout>
              </div>
            )}
          </Card>

          <Card title="JSON">
            <div className="grid gap-4 lg:grid-cols-2">
              <div>
                <SectionTitle right={<CopyChip text={parsed.header.value ? pretty(parsed.header.value) : ''} label="header" />}>Header</SectionTitle>
                <CodeBlock code={parsed.header.value ? pretty(parsed.header.value) : `// ${parsed.header.error}`} maxHeight={220} />
              </div>
              <div>
                <SectionTitle right={<CopyChip text={parsed.payload.value ? pretty(parsed.payload.value) : ''} label="payload" />}>Payload</SectionTitle>
                <CodeBlock code={parsed.payload.value ? pretty(parsed.payload.value) : `// ${parsed.payload.error}`} maxHeight={220} />
              </div>
            </div>
            {parsed.sig && (
              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <CodeBlock code={parsed.sig.hex} label="Signature (hex)" maxHeight={120} />
                <CodeBlock code={parsed.sig.b64} label="Signature (base64url, as sent)" maxHeight={120} />
              </div>
            )}
          </Card>

          <Card title="Claims">
            {parsed.payload.value ? (
              <div className="overflow-x-auto rounded border border-[var(--card-border)]">
                <table className="w-full text-[12.5px]">
                  <thead>
                    <tr className="bg-[var(--neutral-btn)] text-[11.5px] tracking-wide text-[var(--text-muted)] uppercase">
                      <th className="px-3 py-2 text-left font-medium">Claim</th>
                      <th className="px-3 py-2 text-left font-medium">Value</th>
                      <th className="px-3 py-2 text-left font-medium">Read</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(parsed.payload.value).map(([k, v]) => {
                      const isTime = ['exp', 'iat', 'nbf', 'auth_time'].includes(k) && typeof v === 'number';
                      return (
                        <tr key={k} className="border-t border-[var(--card-border)]">
                          <td className="rf-mono px-3 py-1.5 align-top text-[var(--text)]">{k}</td>
                          <td className="rf-mono max-w-[280px] px-3 py-1.5 align-top break-all text-[var(--text-muted)]">{typeof v === 'string' ? v : pretty(v)}</td>
                          <td className="px-3 py-1.5 align-top text-[11.5px] text-[var(--text-faint)]">
                            {isTime ? new Date((v as number) * 1000).toISOString() : ''}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <Callout tone="warn" title="Payload unreadable">{parsed.payload.error}</Callout>
            )}
          </Card>

          <Card
            title="Findings"
            action={<span className="rf-mono text-[12px] text-[var(--text-faint)]">{parsed.findings.length}</span>}
          >
            {parsed.findings.length === 0 ? (
              <Callout tone="ok" title="No structural red flags">Nothing in the header or claims matched the known misuse patterns — verification logic still has to be tested separately.</Callout>
            ) : (
              <div className="flex flex-col gap-2.5">
                {parsed.findings.map((f) => (
                  <div key={f.id} className="rounded border border-[var(--card-border)] px-3 py-2">
                    <div className="flex items-baseline gap-2">
                      <span className="rf-mono text-[10.5px] font-semibold" style={{ color: SEV_COLOR[f.severity] }}>
                        {f.severity.toUpperCase()}
                      </span>
                      <span className="rf-mono text-[12px] text-[var(--text)]">{f.claim}</span>
                    </div>
                    <p className="mt-1 mb-0 text-[12px] leading-relaxed text-[var(--text-muted)]">{f.detail}</p>
                  </div>
                ))}
              </div>
            )}
            <div className="mt-4">
              <Callout tone="info" title="Modified-payload workflow">
                Decode the payload, edit the claim you care about, re-encode both segments with base64url (no padding),
                then re-sign with the matching algorithm in the JWT Forger tool — HS* with the recovered secret, RS* only
                with the private key. Keep the original signature to test whether the server verifies it at all.
              </Callout>
            </div>
          </Card>
        </>
      )}
    </>
  );
}
