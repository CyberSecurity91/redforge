import { useMemo, useState } from 'react';
import {
  Button,
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  CopyChip,
  IconButton,
  OutputBlock,
  Select,
  TextArea,
  TextInput,
} from '@/components/ui';
import { USER_AGENTS } from '@/lib/redteam-data';
import { DEFAULT_TARGET, DEFAULT_TARGET_IP } from '@/tools/registry';

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';
type Pair = { id: number; key: string; value: string };

let seq = 1;
const pair = (key = '', value = ''): Pair => ({ id: seq++, key, value });

const METHODS: Array<{ value: Method; label: string }> = (
  ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as Method[]
).map((m) => ({ value: m, label: m }));

export default function CurlGenerator() {
  const [url, setUrl] = useState(`https://${DEFAULT_TARGET}/api/v1/users`);
  const [method, setMethod] = useState<Method>('POST');
  const [headers, setHeaders] = useState<Pair[]>([pair('Content-Type', 'application/json')]);
  const [cookies, setCookies] = useState('SESSION_ID=abc123; csrftoken=xyz');
  const [body, setBody] = useState('{"username":"alice","role":"user"}');
  const [bodyKind, setBodyKind] = useState<'json' | 'form' | 'none'>('json');
  const [authKind, setAuthKind] = useState<'none' | 'basic' | 'bearer'>('bearer');
  const [authValue, setAuthValue] = useState('eyJhbGciOiJIUzI1NiJ9.SESSION_ID.signature');
  const [insecure, setInsecure] = useState(false);
  const [proxy, setProxy] = useState('');
  const [http1, setHttp1] = useState(false);
  const [verbose, setVerbose] = useState(true);
  const [follow, setFollow] = useState(false);
  const [binary, setBinary] = useState(false);
  const [compressed, setCompressed] = useState(false);
  const [ua, setUa] = useState('');
  const [showHttp, setShowHttp] = useState(true);

  const updatePair = (id: number, patch: Partial<Pair>) =>
    setHeaders((prev) => prev.map((h) => (h.id === id ? { ...h, ...patch } : h)));

  const model = useMemo(() => {
    const activeHeaders = headers.filter((h) => h.key.trim());
    const parts: string[] = [`curl -X ${method}`];
    const notes: Array<[string, string]> = [['-X ' + method, 'Forces the verb; curl would otherwise infer GET/HEAD.']];

    if (follow) {
      parts.push('--location');
      notes.push(['--location', 'Follow 3xx redirects (without it you inspect the 302 directly).']);
    }
    if (insecure) {
      parts.push('--insecure');
      notes.push(['--insecure', 'Skip TLS verification — needed for self-signed lab certificates.']);
    }
    if (http1) {
      parts.push('--http1.1');
      notes.push(['--http1.1', 'Pin HTTP/1.1; useful when a proxy mangles h2 framing.']);
    }
    if (verbose) {
      parts.push('--verbose');
      notes.push(['--verbose', 'Dump request/response headers to stderr.']);
    }
    if (proxy.trim()) {
      parts.push(`--proxy '${proxy.trim()}'`);
      notes.push(['--proxy', 'Route through a proxy, e.g. http://127.0.0.1:8080 for Burp.']);
    }
    if (compressed) {
      parts.push('--compressed');
      notes.push(['--compressed', 'Advertise and decode gzip/deflate/br responses.']);
    }
    if (ua) {
      parts.push(`-A '${ua}'`);
      notes.push(['-A', 'Override the User-Agent string.']);
    }
    if (cookies.trim()) {
      parts.push(`-b '${cookies.trim()}'`);
      notes.push(['-b', 'Send the Cookie header verbatim.']);
    }

    for (const h of activeHeaders) {
      parts.push(`-H '${h.key.trim()}: ${h.value}'`);
    }
    if (activeHeaders.length) {
      notes.push(['-H', `${activeHeaders.length} request header(s) preserved in order.`]);
    }

    if (authKind === 'basic') {
      parts.push(`-u '${authValue.trim()}'`);
      notes.push(['-u', 'HTTP Basic credentials as user:password.']);
    } else if (authKind === 'bearer') {
      parts.push(`-H 'Authorization: Bearer ${authValue.trim()}'`);
      notes.push(['-H Authorization', 'Bearer token in the header, not the body.']);
    }

    const sendBody = bodyKind !== 'none' && method !== 'GET' && method !== 'HEAD' && body.trim();
    if (sendBody) {
      if (bodyKind === 'form') {
        const encoded = body
          .split(/&|\n/)
          .map((l) => l.trim())
          .filter(Boolean)
          .join('&');
        parts.push(binary ? `--data-binary '${encoded}'` : `--data '${encoded}'`);
        notes.push([binary ? '--data-binary' : '--data', 'application/x-www-form-urlencoded payload.']);
      } else {
        const flag = binary ? '--data-binary' : '--data-raw';
        parts.push(`${flag} '${body.replace(/'/g, "'\\''")}'`);
        notes.push([
          flag,
          flag === '--data-raw'
            ? 'No @-file interpretation — literal JSON echoed to the server.'
            : 'Byte-exact body; avoids curl newline stripping.',
        ]);
      }
    }

    parts.push(`'${url.trim() || `https://${DEFAULT_TARGET}/`}'`);
    const command = parts.join(' \\\n  ');

    const pyHeaders = activeHeaders.reduce<Record<string, string>>((acc, h) => {
      acc[h.key.trim()] = h.value;
      return acc;
    }, {});
    if (authKind === 'bearer') pyHeaders['Authorization'] = `Bearer ${authValue.trim()}`;
    if (cookies.trim()) pyHeaders['Cookie'] = cookies.trim();
    if (ua) pyHeaders['User-Agent'] = ua;

    const pyLines = [
      'import requests',
      '',
      `url = "${url.trim() || `https://${DEFAULT_TARGET}/`}"`,
      `headers = ${JSON.stringify(pyHeaders, null, 4)}`,
    ];
    if (authKind === 'basic') {
      const [user, pass] = authValue.split(':');
      pyLines.push(`auth = ("${user ?? ''}", "${pass ?? ''}")`);
    }
    if (sendBody) {
      pyLines.push(`payload = ${bodyKind === 'form' ? `"${body.replace(/\n/g, '&')}"` : body}`);
      pyLines.push(
        `r = requests.${method.toLowerCase()}(url, headers=headers, ${bodyKind === 'form' ? 'data=payload' : 'data=payload'}${authKind === 'basic' ? ', auth=auth' : ''}${follow ? ', allow_redirects=True' : ', allow_redirects=False'}${insecure ? ', verify=False' : ''}${proxy.trim() ? `, proxies={"http": "${proxy.trim()}", "https": "${proxy.trim()}"}` : ''})`,
      );
    } else {
      pyLines.push(
        `r = requests.${method.toLowerCase()}(url, headers=headers${authKind === 'basic' ? ', auth=auth' : ''}${follow ? ', allow_redirects=True' : ', allow_redirects=False'}${insecure ? ', verify=False' : ''}${proxy.trim() ? `, proxies={"http": "${proxy.trim()}", "https": "${proxy.trim()}"}` : ''})`,
      );
    }
    pyLines.push('print(r.status_code)', 'print(dict(r.headers))', 'print(r.text[:2000])');

    // Raw HTTP preview, Burp style.
    let target = url.trim();
    let host = DEFAULT_TARGET;
    let path = '/';
    try {
      const u = new URL(target.includes('://') ? target : `https://${target}`);
      host = u.host;
      path = `${u.pathname}${u.search}`;
    } catch {
      host = DEFAULT_TARGET_IP;
    }
    const httpLines = [`${method} ${path} HTTP/1.1`, `Host: ${host}`];
    for (const h of activeHeaders) httpLines.push(`${h.key.trim()}: ${h.value}`);
    if (authKind === 'bearer') httpLines.push(`Authorization: Bearer ${authValue.trim()}`);
    if (cookies.trim()) httpLines.push(`Cookie: ${cookies.trim()}`);
    if (ua) httpLines.push(`User-Agent: ${ua}`);
    httpLines.push(`Content-Length: ${new TextEncoder().encode(body || '').length}`);
    httpLines.push('Connection: close', '', sendBody ? body : '');
    const raw = httpLines.join('\r\n');

    return { command, notes, python: pyLines.join('\n'), raw };
  }, [
    url,
    method,
    headers,
    cookies,
    body,
    bodyKind,
    authKind,
    authValue,
    insecure,
    proxy,
    http1,
    verbose,
    follow,
    binary,
    compressed,
    ua,
    showHttp,
  ]);

  return (
    <>
      <Card title="Request">
        <div className="grid gap-4 sm:grid-cols-4">
          <div className="sm:col-span-3">
            <TextInput label="URL" value={url} onChange={setUrl} mono placeholder={`https://${DEFAULT_TARGET}/api`} />
          </div>
          <Select label="Method" value={method} onChange={setMethod} options={METHODS} />
        </div>

        <div className="mt-4 grid gap-3">
          <div className="flex items-center justify-between">
            <span className="text-[12px] font-medium text-[var(--text-muted)]">Headers</span>
            <Button size="sm" variant="ghost" onClick={() => setHeaders((p) => [...p, pair()])}>
              Add header
            </Button>
          </div>
          {headers.length === 0 && (
            <div className="text-[12px] text-[var(--text-faint)]">No headers — curl sends only its defaults.</div>
          )}
          {headers.map((h) => (
            <div key={h.id} className="flex gap-2">
              <TextInput value={h.key} onChange={(v) => updatePair(h.id, { key: v })} placeholder="Header-Name" mono />
              <TextInput value={h.value} onChange={(v) => updatePair(h.id, { value: v })} placeholder="value" mono />
              <IconButton
                title="Remove header"
                onClick={() => setHeaders((prev) => prev.filter((x) => x.id !== h.id))}
              >
                ×
              </IconButton>
            </div>
          ))}
        </div>

        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <TextInput label="Cookies" value={cookies} onChange={setCookies} mono placeholder="SESSION_ID=..." />
          <Select
            label="User-Agent"
            value={ua}
            onChange={setUa}
            options={[{ value: '', label: 'curl default' }, ...USER_AGENTS.map(([label, value]) => ({ value, label }))]}
          />
        </div>
      </Card>

      <Card title="Body and auth">
        <div className="grid gap-4 sm:grid-cols-3">
          <Select
            label="Body type"
            value={bodyKind}
            onChange={setBodyKind}
            options={[
              { value: 'json', label: 'JSON (raw)' },
              { value: 'form', label: 'Form urlencoded' },
              { value: 'none', label: 'None' },
            ]}
          />
          <Select
            label="Auth"
            value={authKind}
            onChange={setAuthKind}
            options={[
              { value: 'none', label: 'None' },
              { value: 'basic', label: 'Basic (-u)' },
              { value: 'bearer', label: 'Bearer token' },
            ]}
          />
          <TextInput
            label={authKind === 'basic' ? 'user:password' : 'Token'}
            value={authValue}
            onChange={setAuthValue}
            mono
            disabled={authKind === 'none'}
          />
        </div>
        {bodyKind !== 'none' && (
          <div className="mt-4">
            <TextArea
              label="Body"
              value={body}
              onChange={setBody}
              rows={5}
              placeholder={bodyKind === 'json' ? '{"key":"value"}' : 'a=1&b=2'}
            />
          </div>
        )}
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <Checkbox checked={insecure} onChange={setInsecure} label="Insecure TLS" description="--insecure" />
          <Checkbox checked={http1} onChange={setHttp1} label="Force HTTP/1.1" description="--http1.1" />
          <Checkbox checked={verbose} onChange={setVerbose} label="Verbose" description="--verbose" />
          <Checkbox checked={follow} onChange={setFollow} label="Follow redirects" description="--location" />
          <Checkbox checked={binary} onChange={setBinary} label="Binary body" description="--data-binary" />
          <Checkbox checked={compressed} onChange={setCompressed} label="Compressed" description="--compressed" />
        </div>
        <div className="mt-4">
          <TextInput label="Proxy" value={proxy} onChange={setProxy} mono placeholder="http://127.0.0.1:8080" />
        </div>
      </Card>

      <Card title="curl" action={<CopyChip text={model.command} label="Copy curl" />}>
        <OutputBlock value={model.command} rows={14} label="Command" />
        <div className="mt-4">
          <CodeBlock code={model.notes.map(([f, why]) => `${f.padEnd(18)} ${why}`).join('\n')} label="Flags used" maxHeight={180} />
        </div>
      </Card>

      <Card title="Equivalent requests">
        <CodeBlock code={model.python} label="python requests" maxHeight={280} />
        {showHttp && (
          <div className="mt-4">
            <CodeBlock code={model.raw} label="Raw HTTP/1.1 (Burp style)" maxHeight={260} />
          </div>
        )}
        <div className="mt-3">
          <Button size="sm" variant="ghost" onClick={() => setShowHttp((v) => !v)}>
            {showHttp ? 'Hide raw request' : 'Show raw request'}
          </Button>
        </div>
        <div className="mt-4">
          <Callout tone="info" title="Note">
            The raw preview assumes <span className="rf-mono">Connection: close</span> and a computed Content-Length.
            curl adds its own <span className="rf-mono">Accept</span> and <span className="rf-mono">Host</span> headers
            on the wire, so the two will differ slightly.
          </Callout>
        </div>
      </Card>
    </>
  );
}
