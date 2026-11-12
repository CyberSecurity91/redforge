import { useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, CopyChip, KVTable, TextArea, Tabs } from '@/components/ui';
import { b64Decode } from '@/lib/encoding';

type Parsed = {
  ok: true;
  method: string;
  rawTarget: string;
  host: string;
  path: string;
  version: string;
  headers: Array<[string, string]>;
  body: string;
  url: string;
};

type ParseError = { ok: false; error: string };

const SAMPLE = `POST /api/v1/login HTTP/1.1
Host: app.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Content-Length: 39
Cookie: SESSION_ID=abc123

username=alice&password=hunter2&totp=123456`;

function parseRaw(raw: string): Parsed | ParseError {
  const text = raw.replace(/\r\n/g, '\n');
  const splitAt = text.indexOf('\n\n');
  const head = splitAt === -1 ? text : text.slice(0, splitAt);
  const body = splitAt === -1 ? '' : text.slice(splitAt + 2);
  const lines = head.split('\n').filter((l) => l.length > 0);
  if (lines.length === 0) return { ok: false, error: 'Empty request.' };

  const first = lines[0].trim();
  const parts = first.split(/\s+/);
  if (parts.length < 2) return { ok: false, error: 'Request line needs a method and a target, e.g. GET / HTTP/1.1.' };
  const [method, rawTarget] = parts;
  const version = parts[2] ?? 'HTTP/1.1';

  const headers: Array<[string, string]> = [];
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    headers.push([line.slice(0, idx).trim(), line.slice(idx + 1).trim()]);
  }
  const headerMap = new Map(headers.map(([k, v]) => [k.toLowerCase(), v]));
  const hostHeader = headerMap.get('host') ?? '';

  let scheme = 'https';
  let host = hostHeader;
  let path = rawTarget;
  if (/^[a-z]+:\/\//i.test(rawTarget)) {
    try {
      const u = new URL(rawTarget);
      scheme = u.protocol.replace(':', '');
      host = u.host;
      path = `${u.pathname}${u.search}`;
    } catch {
      return { ok: false, error: 'Absolute target in the request line could not be parsed.' };
    }
  } else if (!path.startsWith('/')) {
    path = `/${path}`;
  }
  if (!host) return { ok: false, error: 'No Host header — cannot construct a URL.' };
  if (/:80$/.test(host) || /^http:/i.test(host)) scheme = 'http';

  const url = `${scheme}://${host}${path}`;
  return { ok: true, method, rawTarget, host, path, version, headers, body, url };
}

function decodeParams(body: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  const contentTypeish = /(^|&)[^=&]+=[^&]*/.test(body);
  if (!contentTypeish) return out;
  for (const chunk of body.split('&')) {
    if (!chunk) continue;
    const [k, v = ''] = chunk.split('=');
    let decoded = '';
    try {
      decoded = decodeURIComponent(v.replace(/\+/g, ' '));
    } catch {
      decoded = v;
    }
    out.push([(() => { try { return decodeURIComponent(k); } catch { return k; } })(), decoded]);
  }
  return out;
}

export default function BurpToCurl() {
  const [raw, setRaw] = useState(SAMPLE);
  const [variant, setVariant] = useState<'plain' | 'http11'>('plain');

  const parsed = useMemo(() => parseRaw(raw), [raw]);

  const built = useMemo(() => {
    if (!parsed.ok) return null;
    const skip = new Set(['host', 'content-length', 'connection']);
    const headerFlags = parsed.headers
      .filter(([k]) => !skip.has(k.toLowerCase()))
      .map(([k, v]) => `-H '${k}: ${v}'`);

    const extra: string[] = [];
    if (variant === 'http11') extra.push('--http1.1', '--compressed');

    const bodyFlag = parsed.body
      ? parsed.body.trimStart().startsWith('{') || parsed.body.trimStart().startsWith('[')
        ? `--data-raw '${parsed.body.replace(/'/g, "'\\''")}'`
        : `--data '${parsed.body.replace(/'/g, "'\\''")}'`
      : null;

    const parts = [`curl -X ${parsed.method}`, ...extra, ...headerFlags];
    if (bodyFlag) parts.push(bodyFlag);
    parts.push(`'${parsed.url}'`);
    const curl = parts.join(' \\\n  ');

    const headerObj: Record<string, string> = {};
    for (const [k, v] of parsed.headers) if (!skip.has(k.toLowerCase())) headerObj[k] = v;

    const fetchLines = [
      `const res = await fetch("${parsed.url}", {`,
      `  method: "${parsed.method}",`,
      `  headers: ${JSON.stringify(headerObj, null, 4)},
`,
      ...(parsed.body ? [`  body: ${JSON.stringify(parsed.body)},`] : []),
      '});',
      'console.log(res.status, await res.text());',
    ].join('\n');

    return { curl, fetch: fetchLines };
  }, [parsed, variant]);

  const decoded = useMemo(() => {
    if (!parsed.ok || !parsed.body) return { form: [] as Array<[string, string]>, b64: '' };
    const form = decodeParams(parsed.body.trim());
    let b64 = '';
    const ctype = parsed.headers.find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? '';
    if (/base64/i.test(ctype) || /^[A-Za-z0-9+/=\s]{16,}$/.test(parsed.body.trim())) {
      try {
        const bytes = b64Decode(parsed.body.trim().replace(/\s+/g, ''));
        b64 = new TextDecoder().decode(bytes);
      } catch {
        b64 = '';
      }
    }
    return { form, b64 };
  }, [parsed]);

  return (
    <>
      <Card title="Raw request" action={<CopyChip text={raw} label="Copy request" />}>
        <TextArea
          value={raw}
          onChange={setRaw}
          rows={14}
          label="Paste from Burp (Proxy → HTTP history → right-click → Copy to clipboard)"
          placeholder={SAMPLE}
        />
      </Card>

      {!parsed.ok ? (
        <Card title="Result">
          <Callout tone="warn" title="Not a request">
            {parsed.error}
          </Callout>
        </Card>
      ) : (
        <>
          <Card title="Parsed" action={<CopyChip text={built?.curl ?? ''} label="Copy curl" />}>
            <KVTable
              rows={[
                ['Method', <span className="rf-mono">{parsed.method}</span>],
                ['Target', <span className="rf-mono">{parsed.path}</span>],
                ['Host', <span className="rf-mono">{parsed.host}</span>],
                ['Version', <span className="rf-mono">{parsed.version}</span>],
                ['URL', <span className="rf-mono">{parsed.url}</span>],
                ['Headers', String(parsed.headers.length)],
                ['Body', parsed.body ? `${parsed.body.length} chars` : 'none'],
              ]}
            />
            <div className="mt-4">
              <Tabs
                value={variant}
                onChange={setVariant}
                tabs={[
                  { value: 'plain', label: 'curl' },
                  { value: 'http11', label: 'curl (HTTP/1.1 + compressed)' },
                ]}
              />
            </div>
            <div className="mt-3">
              <CodeBlock code={built?.curl ?? ''} maxHeight={260} />
            </div>
            <div className="mt-3">
              <Callout tone="info" title="Header handling">
                <span className="rf-mono">Host</span> and <span className="rf-mono">Content-Length</span> are dropped
                because curl derives both. Everything else is replayed verbatim, including duplicate headers such as
                two <span className="rf-mono">Cookie</span> lines.
              </Callout>
            </div>
          </Card>

          <Card title="fetch() equivalent">
            <CodeBlock code={built?.fetch ?? ''} label="JavaScript" maxHeight={280} />
            <div className="mt-3 text-[11.5px] leading-relaxed text-[var(--text-faint)]">
              Browsers forbid setting <span className="rf-mono">Cookie</span> and{' '}
              <span className="rf-mono">Host</span> via fetch; run this from Node or a browser extension where those
              are permitted.
            </div>
          </Card>

          <Card title="Decoded body">
            {decoded.form.length > 0 ? (
              <KVTable rows={decoded.form} />
            ) : decoded.b64 ? (
              <CodeBlock code={decoded.b64} label="Base64 decoded" maxHeight={200} />
            ) : (
              <div className="text-[12px] text-[var(--text-faint)]">
                No urlencoded parameters or base64 payload detected in the body.
              </div>
            )}
          </Card>
        </>
      )}
    </>
  );
}
