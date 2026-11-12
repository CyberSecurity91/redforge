import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  CodeBlock,
  KVTable,
  OutputField,
  SectionTitle,
  Select,
  TextArea,
  TextInput,
} from '@/components/ui';
import { DEFAULT_TARGET } from '@/tools/registry';
import { md5Hex, ntlmHash } from '@/lib/crypto';

type Scheme = 'Basic' | 'Bearer' | 'Digest' | 'Negotiate';

const SCHEMES = [
  { value: 'Basic', label: 'Basic — base64(user:pass)' },
  { value: 'Bearer', label: 'Bearer — opaque token passthrough' },
  { value: 'Digest', label: 'Digest — RFC 7616 skeleton' },
  { value: 'Negotiate', label: 'Negotiate / NTLM — type-1 + type-3 skeleton' },
] as const;

function b64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function b64decode(text: string): { value: string; error: string | null } {
  try {
    const bin = atob(text.trim());
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return { value: new TextDecoder().decode(bytes), error: null };
  } catch {
    return { value: '', error: 'not valid base64' };
  }
}

const NTLM_MAGIC = 'TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==';

export default function BasicAuthHeader() {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('hunter2');
  const [scheme, setScheme] = useState<Scheme>('Basic');
  const [host, setHost] = useState(DEFAULT_TARGET);
  const [realm, setRealm] = useState('Restricted');
  const [nonce, setNonce] = useState('dcd98b7102dd2f0e8b11d0f600bfb0c093');
  const [pasted, setPasted] = useState('');

  const creds = `${username}:${password}`;
  const encoded = useMemo(() => b64(creds), [creds]);

  const header = useMemo(() => {
    switch (scheme) {
      case 'Basic':
        return `Authorization: Basic ${encoded}`;
      case 'Bearer':
        return `Authorization: Bearer ${password || '$TOKEN'}`;
      case 'Digest': {
        const ha1 = `${username}:${realm}:${password}`;
        const ha2 = `GET:/`;
        return [
          `Authorization: Digest username="${username}",`,
          `  realm="${realm}",`,
          `  nonce="${nonce}",`,
          `  uri="/",`,
          `  algorithm=MD5,`,
          `  response="<md5(HA1:nonce:nc:cnonce:qop:HA2)>",`,
          `  qop=auth, nc=00000001, cnonce="0a4f113b"`,
          ``,
          `# HA1 = md5("${ha1}")`,
          `# HA2 = md5("${ha2}")`,
          `# response = md5(HA1:nonce:00000001:0a4f113b:auth:HA2)`,
        ].join('\n');
      }
      default:
        return [
          '# type 1 (negotiate message) — embedded NTLMSSP, flags 0xE2088297',
          `Authorization: Negotiate ${NTLM_MAGIC}`,
          '',
          `# type 3 needs the server challenge; NT hash of the password:`,
          `# ntlm = ${ntlmHash(password)}`,
          '# NTLMv2 response = HMAC-MD5(NT, UPPER(user) + domain) ⊕ challenge + blob',
        ].join('\n');
    }
  }, [scheme, encoded, username, password, realm, nonce]);

  const digestResponse = useMemo(() => {
    const ha1 = md5Hex(`${username}:${realm}:${password}`);
    const ha2 = md5Hex('GET:/');
    const response = md5Hex(`${ha1}:${nonce}:00000001:0a4f113b:auth:${ha2}`);
    return { ha1, ha2, response };
  }, [username, password, realm, nonce]);

  const curl = useMemo(
    () =>
      scheme === 'Basic'
        ? `curl -sS -i -u '${creds}' 'https://${host}/'\n# or, header form (URL-encode nothing — base64 handles it)\ncurl -sS -i -H 'Authorization: Basic ${encoded}' 'https://${host}/'`
        : scheme === 'Bearer'
          ? `curl -sS -i -H 'Authorization: Bearer ${password || '$TOKEN'}' 'https://${host}/'`
          : scheme === 'Digest'
            ? `curl -sS -i --digest -u '${creds}' 'https://${host}/'\n# dependency-free alternative: send the precomputed header, then replay on 401\ncurl -sS -i -H "Authorization: Digest username=\\"${username}\\", realm=\\"${realm}\\", nonce=\\"${nonce}\\", uri=\\"/\\", response=\\"${digestResponse.response}\\", qop=auth, nc=00000001, cnonce=\\"0a4f113b\\"" 'https://${host}/'`
            : `curl -sS -i --negotiate -u ':${password}' 'https://${host}/'\ncurl -sS -i 'https://${host}/'   # then replay with -H 'Authorization: Negotiate <type3>'`,
    [scheme, creds, encoded, host, password, username, realm, nonce, digestResponse.response],
  );

  const decoded = useMemo(() => {
    const raw = pasted.trim().replace(/^authorization:\s*/i, '');
    if (!raw) return null;
    if (/^basic\s+/i.test(raw)) return { scheme: 'Basic', ...b64decode(raw.replace(/^basic\s+/i, '')) };
    if (/^bearer\s+/i.test(raw)) return { scheme: 'Bearer', value: raw.replace(/^bearer\s+/i, ''), error: null };
    return { scheme: 'Other', value: raw, error: null };
  }, [pasted]);

  return (
    <>
      <Card title="Credentials">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput label="Username" value={username} onChange={setUsername} mono />
          <TextInput label="Password / token" value={password} onChange={setPassword} mono hint="Used as the bearer token or HTTP password" />
          <Select label="Scheme" value={scheme} onChange={(v) => setScheme(v as Scheme)} options={SCHEMES.map((s) => ({ value: s.value, label: s.label }))} />
          <TextInput label="Host" value={host} onChange={setHost} mono />
          {scheme === 'Digest' && (
            <>
              <TextInput label="Realm" value={realm} onChange={setRealm} mono />
              <TextInput label="Nonce" value={nonce} onChange={setNonce} mono hint="Copy from the WWW-Authenticate challenge" />
            </>
          )}
        </div>
      </Card>

      <Card title="Outputs">
        <div className="flex flex-col gap-4">
          <OutputField label="Authorization header" value={header} />
          <OutputField label="base64(user:pass)" value={encoded} />
          <OutputField label="URL-embedded form" value={scheme === 'Basic' ? `https://${encodeURIComponent(username)}:${encodeURIComponent(password)}@${host}/` : `https://${host}/`} />
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <CodeBlock code={curl} label="curl" maxHeight={160} />
          <CodeBlock
            code={
              scheme === 'Negotiate'
                ? `NT hash      = ${ntlmHash(password)}\nidentity     = UPPER(username) + domain\nNTLMv2       = HMAC-MD5(NT hash, identity) + server challenge + blob`
                : scheme === 'Digest'
                  ? `HA1      = ${digestResponse.ha1}\nHA2      = ${digestResponse.ha2}\nresponse = ${digestResponse.response}`
                  : `md5(user:pass) = ${md5Hex(creds)}`
            }
            label={scheme === 'Digest' ? 'Digest MD5 chain' : scheme === 'Negotiate' ? 'NTLM hash' : 'md5 of credentials'}
            maxHeight={160}
          />
        </div>
      </Card>

      <Card title="Decode an existing header">
        <TextArea
          label="Paste an Authorization header or bare base64"
          value={pasted}
          onChange={setPasted}
          rows={4}
          placeholder="Basic YWRtaW46aHVudGVyMg=="
          hint={`Round-trip check: ${encoded}`}
        />
        {decoded && (
          <div className="mt-4">
            {decoded.error ? (
              <Callout tone="warn" title="Not decodable">{decoded.error} — a Bearer or Digest value is not base64 by design.</Callout>
            ) : (
              <KVTable
                rows={[
                  ['Scheme', decoded.scheme],
                  ['Decoded', decoded.value],
                  ['User', decoded.value.includes(':') ? decoded.value.split(':')[0] : '—'],
                  ['Secret', decoded.value.includes(':') ? decoded.value.slice(decoded.value.indexOf(':') + 1) : '—'],
                ]}
              />
            )}
          </div>
        )}
      </Card>

      <Card title="Notes">
        <div className="flex flex-col gap-3">
          <Callout tone="info" title="Basic is not encryption">
            The credential travels as cleartext base64 — anything that logs headers (proxies, APM, error trackers) has the
            password. Reuse of the header across hosts is the quickest way to catch credentials forwarded to a third party.
          </Callout>
          <Callout tone="warn" title="Negotiate">
            Send the type-1 message first, read the <span className="rf-mono">WWW-Authenticate: Negotiate &lt;base64 challenge&gt;</span>{' '}
            value, and only then build the type-3 blob with the NT hash. A 401 that repeats the challenge means the
            server rejected the domain or the workstation name, not the password.
          </Callout>
          <div>
            <SectionTitle>Facts</SectionTitle>
            <KVTable
              rows={[
                ['Credential bytes', String(new TextEncoder().encode(creds).length)],
                ['Base64 length', String(encoded.length)],
                ['Non-ASCII handling', 'UTF-8 encoded before base64 (RFC 7617 charset="UTF-8")'],
              ]}
            />
          </div>
        </div>
      </Card>
    </>
  );
}
