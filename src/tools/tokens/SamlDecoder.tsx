import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  CodeBlock,
  KVTable,
  SectionTitle,
  Tabs,
  TextArea,
} from '@/components/ui';

type View = 'xml' | 'attributes' | 'findings';

type Parsed = {
  xml: string;
  pretty: string;
  how: string;
  issuer: string;
  destination: string;
  inResponseTo: string;
  nameId: string;
  nameIdFormat: string;
  notOnOrAfter: string;
  notBefore: string;
  attributes: Array<[string, string]>;
  signatureStatus: string;
  signedElement: string;
  findings: Array<{ severity: 'high' | 'medium' | 'low'; title: string; detail: string }>;
};

function b64ToBytes(input: string): Uint8Array {
  const clean = input.replace(/\s+/g, '');
  const pad = clean.length % 4 === 0 ? '' : '='.repeat(4 - (clean.length % 4));
  const bin = atob(clean.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function inflateRaw(bytes: Uint8Array): Promise<string> {
  const ds = new DecompressionStream('deflate-raw');
  const stream = new Blob([bytes as unknown as BlobPart]).stream().pipeThrough(ds);
  const buf = await new Response(stream).arrayBuffer();
  return new TextDecoder().decode(buf);
}

function looksLikeXml(text: string): boolean {
  return /<[\w:-]+[\s>/]/.test(text.slice(0, 400));
}

async function decode(input: string): Promise<{ xml: string; how: string }> {
  const raw = input.trim();
  if (!raw) throw new Error('empty input');
  if (looksLikeXml(raw)) return { xml: raw, how: 'input was already XML' };
  let bytes: Uint8Array;
  try {
    bytes = b64ToBytes(raw);
  } catch {
    throw new Error('input is neither XML nor base64');
  }
  const direct = new TextDecoder().decode(bytes);
  if (looksLikeXml(direct)) return { xml: direct, how: 'base64 → plain XML' };
  try {
    const inflated = await inflateRaw(bytes);
    if (looksLikeXml(inflated)) return { xml: inflated, how: 'base64 → deflate-raw inflate' };
    return { xml: inflated, how: 'base64 → inflate (output does not look like XML)' };
  } catch {
    return { xml: direct, how: 'base64 only — inflate failed, showing raw bytes as text' };
  }
}

function prettyXml(xml: string): string {
  const withBreaks = xml
    .replace(/>\s*</g, '><')
    .replace(/(<\?xml[^>]*\?>)/g, '$1\n')
    .replace(/(<\/[^>]+>)/g, '$1\n')
    .replace(/(<[^/!][^>]*[^/]>)/g, '$1\n');
  let depth = 0;
  const out: string[] = [];
  for (const rawLine of withBreaks.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    if (/^<\//.test(line)) depth = Math.max(0, depth - 1);
    out.push('  '.repeat(depth) + line);
    const opens = /^<[^/!?][^>]*[^/]>$/.test(line) && !/<\/[^>]+>$/.test(line);
    if (opens) depth += 1;
  }
  return out.join('\n');
}

const unescape = (s: string) =>
  s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');

function attr(tag: string, name: string): string {
  const re = new RegExp(`${name}\\s*=\\s*"([^"]*)"`, 'i');
  return unescape(re.exec(tag)?.[1] ?? '');
}

function firstTag(xml: string, name: string): string {
  const re = new RegExp(`<(?:[\\w.-]+:)?${name}\\b[^>]*>([\\s\\S]*?)</(?:[\\w.-]+:)?${name}>`, 'i');
  return unescape(re.exec(xml)?.[1]?.trim() ?? '');
}

function analyse(xml: string, how: string): Parsed {
  const findings: Parsed['findings'] = [];

  const signatures = (xml.match(/<(?:\w+:)?Signature\b/g) ?? []).length;
  const responseStart = xml.search(/<(\w+:)?Response\b/i);
  const assertionStart = xml.search(/<(\w+:)?Assertion\b/i);
  const responseHasSig = /<(?:\w+:)?Response\b[^>]*>[\s\S]*?<(?:\w+:)?Signature\b/i.test(xml);
  const assertionHasSig = /<(?:\w+:)?Assertion\b[^>]*>[\s\S]*?<(?:\w+:)?Signature\b/i.test(xml);

  const sigStatus = signatures === 0 ? 'none' : `${signatures} Signature element(s)`;
  const signedElement =
    signatures === 0
      ? 'unsigned'
      : responseHasSig && assertionStart < responseStart
        ? 'Response (and possibly assertion)'
        : assertionHasSig
          ? 'Assertion'
          : 'Response';

  if (signatures === 0) {
    findings.push({ severity: 'high', title: 'No XML signature', detail: 'The assertion is not signed at all — if the SP accepts it, attribute claims are fully attacker-controlled.' });
  } else if (responseHasSig && !assertionHasSig) {
    findings.push({
      severity: 'high',
      title: 'Signature on Response only — assertion wrapping',
      detail: 'The Assertion is unsigned. Insert a forged Assertion before the signed one; many SAML stacks trust the first assertion they find while verifying only the Response signature.',
    });
  }
  if (/<!---->/.test(xml) || /<!--[\s\S]*?-->/.test(xml)) {
    findings.push({
      severity: 'high',
      title: 'XML comment present',
      detail: 'Comment injection (e.g. admin<!---->@example.com) is the SAML variant of a truncation attack — parsers that strip comments differently from the signature canonicaliser accept a different NameID than they report.',
    });
  }
  if (/<!DOCTYPE/i.test(xml)) {
    findings.push({
      severity: 'medium',
      title: 'DOCTYPE declared — XXE candidate',
      detail: 'Any DOCTYPE with an external entity makes the parser a file-read and SSRF primitive. Test with a SYSTEM identifier pointing at oast.example.com.',
    });
  }
  if (/<!ENTITY/i.test(xml)) {
    findings.push({ severity: 'high', title: 'ENTITY declared', detail: 'Entity definitions are present. If the SP expands them, expect local file disclosure or SSRF from the assertion processor.' });
  }
  if (/DST\b|SignatureMethod\s+Algorithm="[^"]*rsa-sha1"/i.test(xml)) {
    findings.push({ severity: 'medium', title: 'SHA-1 signature', detail: 'rsa-sha1 / DSA are deprecated and collision-prone; combined with weak keys this is practical to attack.' });
  }
  const wrapped = /<\w+:Assertion[\s\S]*<\w+:Assertion/i.test(xml);
  if (wrapped) findings.push({ severity: 'high', title: 'Two Assertion elements', detail: 'Multiple assertions in one Response — the classic wrapping setup. Check which one the SP consumes.' });

  const notOnOrAfter = attr(/NotOnOrAfter="[^"]*"/i.test(xml) ? (xml.match(/<[^>]*NotOnOrAfter="[^"]*"[^>]*>/i)?.[0] ?? '') : '', 'NotOnOrAfter');
  if (notOnOrAfter) {
    const t = Date.parse(notOnOrAfter);
    if (!Number.isNaN(t) && t < Date.now()) findings.push({ severity: 'low', title: 'Assertion expired', detail: `NotOnOrAfter ${notOnOrAfter} is in the past — replaying it tests whether the SP checks the window at all.` });
    if (!Number.isNaN(t) && t - Date.now() > 1000 * 60 * 60 * 8) findings.push({ severity: 'low', title: 'Long validity window', detail: `Valid for more than 8 hours (${notOnOrAfter}).` });
  } else {
    findings.push({ severity: 'medium', title: 'No Conditions/NotOnOrAfter', detail: 'Without a validity window a captured assertion can be replayed indefinitely.' });
  }
  if (!/InResponseTo=/.test(xml)) findings.push({ severity: 'medium', title: 'No InResponseTo', detail: 'Unsolicited assertion response — the SP cannot bind it to a started login (IdP-initiated SSO accepted blindly).' });
  if (!/<(\w+:)?Audience\b/i.test(xml)) findings.push({ severity: 'medium', title: 'No Audience restriction', detail: 'A token minted for another SP may be replayed against this one.' });

  const attrBlocks = Array.from(xml.matchAll(/<((?:\w+:)?Attribute)\b([^>]*)>([\s\S]*?)<\/\1>/gi));
  const attributes: Array<[string, string]> = attrBlocks.map((m) => {
    const name = attr(m[2], 'Name') || attr(m[2], 'FriendlyName') || '(unnamed)';
    const values = Array.from(m[3].matchAll(/<((?:\w+:)?AttributeValue)\b[^>]*>([\s\S]*?)<\/\1>/gi)).map((v) => unescape(v[2].trim()));
    return [name, values.join(', ') || '(empty)'] as [string, string];
  });
  for (const [name, value] of attributes) {
    if (/role|group|admin|permission/i.test(name))
      findings.push({ severity: 'medium', title: `Privileged attribute ${name}`, detail: `Value "${value}" — tamper with this attribute in the unsigned copy and re-post.` });
  }

  return {
    xml,
    pretty: prettyXml(xml),
    how,
    issuer: firstTag(xml, 'Issuer'),
    destination: attr(xml.match(/<[^>]*Destination="[^"]*"[^>]*>/i)?.[0] ?? '', 'Destination'),
    inResponseTo: attr(xml.match(/<[^>]*InResponseTo="[^"]*"[^>]*>/i)?.[0] ?? '', 'InResponseTo'),
    nameId: firstTag(xml, 'NameID'),
    nameIdFormat: attr(xml.match(/<(?:\w+:)?NameID\b[^>]*>/i)?.[0] ?? '', 'Format'),
    notOnOrAfter,
    notBefore: attr(xml.match(/<[^>]*NotBefore="[^"]*"[^>]*>/i)?.[0] ?? '', 'NotBefore'),
    attributes,
    signatureStatus: sigStatus,
    signedElement,
    findings,
  };
}

export default function SamlDecoder() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState<Parsed | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<View>('xml');

  async function decodeNow() {
    setBusy(true);
    setError(null);
    try {
      const { xml, how } = await decode(input);
      setResult(analyse(xml, how));
      setView('xml');
    } catch (e) {
      setResult(null);
      setError(e instanceof Error ? e.message : 'decode failed');
    } finally {
      setBusy(false);
    }
  }

  const sevColour = useMemo(() => ({ high: 'var(--accent)', medium: 'var(--warn)', low: 'var(--info)' }), []);

  return (
    <>
      <Card title="SAMLResponse">
        <TextArea
          label="Paste a base64 SAMLResponse (raw or deflated)"
          value={input}
          onChange={setInput}
          rows={7}
          placeholder="PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wi..."
          hint="Decoding runs locally with DecompressionStream; a base64-first fallback handles verbose-mode captures."
          action={
            <button
              type="button"
              onClick={() => void decodeNow()}
              disabled={busy || !input.trim()}
              className="rounded border border-[var(--accent)] bg-[var(--accent-faded)] px-2.5 py-0.5 text-[12px] text-[var(--accent)] disabled:opacity-40"
            >
              {busy ? 'Decoding…' : 'Decode'}
            </button>
          }
        />
        {error && (
          <div className="mt-4">
            <Callout tone="warn" title="Could not decode">{error}</Callout>
          </div>
        )}
      </Card>

      {!result ? (
        <Card title="Result">
          <Callout tone="info" title="Awaiting input">Paste the POST body value of <span className="rf-mono">SAMLResponse</span> and press Decode.</Callout>
        </Card>
      ) : (
        <>
          <Card title="Assertion">
            <KVTable
              rows={[
                ['Decode path', result.how],
                ['Issuer', result.issuer || '—'],
                ['Destination', result.destination || '(none)'],
                ['InResponseTo', result.inResponseTo || '(none — unsolicited)'],
                ['NameID', result.nameId || '—'],
                ['NameID format', result.nameIdFormat || '—'],
                ['NotBefore', result.notBefore || '—'],
                ['NotOnOrAfter', result.notOnOrAfter || '(none)'],
                ['Signature', `${result.signatureStatus} — ${result.signedElement}`],
                ['Attributes', String(result.attributes.length)],
              ]}
            />
          </Card>

          <Card
            title="Detail"
            action={
              <Tabs
                value={view}
                onChange={setView}
                tabs={[
                  { value: 'xml', label: 'XML' },
                  { value: 'attributes', label: 'Attributes', badge: result.attributes.length },
                  { value: 'findings', label: 'Findings', badge: result.findings.length },
                ]}
              />
            }
          >
            {view === 'xml' && <CodeBlock code={result.pretty} label="pretty-printed XML" maxHeight={480} />}

            {view === 'attributes' && (
              <div className="overflow-x-auto rounded border border-[var(--card-border)]">
                <table className="w-full text-[12.5px]">
                  <thead>
                    <tr className="bg-[var(--neutral-btn)] text-[11.5px] tracking-wide text-[var(--text-muted)] uppercase">
                      <th className="px-3 py-2 text-left font-medium">Attribute</th>
                      <th className="px-3 py-2 text-left font-medium">Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.attributes.length === 0 ? (
                      <tr>
                        <td className="px-3 py-3 text-[var(--text-faint)]" colSpan={2}>No AttributeStatement found.</td>
                      </tr>
                    ) : (
                      result.attributes.map(([name, value]) => (
                        <tr key={name} className="border-t border-[var(--card-border)]">
                          <td className="rf-mono px-3 py-1.5 align-top text-[var(--text)]">{name}</td>
                          <td className="rf-mono px-3 py-1.5 align-top break-all text-[var(--text-muted)]">{value}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {view === 'findings' && (
              <div className="flex flex-col gap-2.5">
                {result.findings.length === 0 ? (
                  <Callout tone="ok" title="No structural findings">Signed assertion, validity window and audience all present — move on to testing how the SP handles a re-signed or re-ordered copy.</Callout>
                ) : (
                  result.findings.map((f) => (
                    <div key={f.title} className="rounded border border-[var(--card-border)] px-3 py-2">
                      <div className="flex items-baseline gap-2">
                        <span className="rf-mono text-[10.5px] font-semibold" style={{ color: sevColour[f.severity] }}>
                          {f.severity.toUpperCase()}
                        </span>
                        <span className="text-[12.5px] text-[var(--text)]">{f.title}</span>
                      </div>
                      <p className="mt-1 mb-0 text-[12px] leading-relaxed text-[var(--text-muted)]">{f.detail}</p>
                    </div>
                  ))
                )}
              </div>
            )}
          </Card>

          <Card title="Next steps">
            <SectionTitle>Replay harness</SectionTitle>
            <CodeBlock
              code={[
                `# 1. capture the original POST body`,
                `curl -sS -i -X POST 'https://sp.example.com/saml/acs' \\`,
                `  --data-urlencode "SAMLResponse=$SAML_B64" \\`,
                `  --data-urlencode "RelayState=$RELAY_STATE"`,
                ``,
                `# 2. decode, edit the NameID / role attribute, re-encode`,
                `python3 - <<'PY'`,
                `import base64, zlib`,
                `raw = zlib.decompress(base64.b64decode(SAML_B64), -15).decode()`,
                `edited = raw.replace("user@example.com", "admin@example.com")`,
                `co = zlib.compressobj(9, zlib.DEFLATED, -15)`,
                `print(base64.b64encode(co.compress(edited.encode()) + co.flush()).decode())`,
                `PY`,
                ``,
                `# 3. re-post with the edited assertion and compare to the baseline session`,
              ].join('\n')}
              label="curl + re-encode"
              maxHeight={280}
            />
          </Card>
        </>
      )}
    </>
  );
}
