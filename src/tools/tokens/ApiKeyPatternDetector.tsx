import { useMemo, useState } from 'react';
import {
  Button,
  Callout,
  Card,
  DownloadButton,
  OutputBlock,
  Select,
  Slider,
  TextArea,
} from '@/components/ui';
import { shannonEntropy } from '@/lib/bytes';

type Rule = {
  id: string;
  provider: string;
  label: string;
  pattern: string;
  group?: number;
  strip?: RegExp;
  base: number;
  note: string;
};

const RULES: Rule[] = [
  { id: 'aws-akid', provider: 'AWS', label: 'Access key id', base: 92, strip: /^(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)/,
    pattern: String.raw`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b`,
    note: 'Key id alone is not a credential — the paired secret is what signs requests.' },
  { id: 'aws-secret', provider: 'AWS', label: 'Secret access key (labelled)', base: 88, group: 1,
    pattern: String.raw`(?:aws_?secret_?access_?key|secretAccessKey)["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']`,
    note: 'Reported only when a 40-character value sits beside an AWS secret label.' },
  { id: 'gcp-key', provider: 'Google', label: 'API key', base: 95, strip: /^AIza/,
    pattern: String.raw`\bAIza[0-9A-Za-z_-]{35}\b`,
    note: 'Unrestricted keys bill to the project owner; check API and referrer restrictions.' },
  { id: 'gcp-oauth', provider: 'Google', label: 'OAuth client id', base: 90,
    pattern: String.raw`\b\d{12}-[0-9a-z]{32}\.apps\.googleusercontent\.com\b`,
    note: 'Client ids ship in every front end; the paired client secret is the finding.' },
  { id: 'stripe', provider: 'Stripe', label: 'Live key', base: 94,
    pattern: String.raw`\b(?:sk|rk|pk)_live_[0-9A-Za-z]{16,}\b`,
    note: 'sk_live is full API access, rk_live is scoped, pk_live is publishable only.' },
  { id: 'slack', provider: 'Slack', label: 'Token', base: 93,
    pattern: String.raw`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`,
    note: 'xoxb bot, xoxp user, xoxa app, xoxr refresh, xoxs session — each has its own scope.' },
  { id: 'github', provider: 'GitHub', label: 'Token', base: 95,
    pattern: String.raw`\bgh[pousr]_[0-9A-Za-z]{36}\b`,
    note: 'ghp personal, gho OAuth, ghs server, ghu user-to-server — check the audit log for use.' },
  { id: 'gitlab', provider: 'GitLab', label: 'Personal access token', base: 94,
    pattern: String.raw`\bglpat-[0-9A-Za-z_-]{20,}\b`,
    note: 'Scope decides blast radius — api scope is full read and write on the instance.' },
  { id: 'sendgrid', provider: 'SendGrid', label: 'API key', base: 96,
    pattern: String.raw`\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b`,
    note: 'Mail-send scope: usable for spoofed mail from the victim domain until revoked.' },
  { id: 'twilio-key', provider: 'Twilio', label: 'API key SID', base: 88,
    pattern: String.raw`\bSK[0-9a-fA-F]{32}\b`,
    note: 'Needs the paired secret to authenticate; the AC SID names the billing account.' },
  { id: 'twilio-acct', provider: 'Twilio', label: 'Account SID', base: 80,
    pattern: String.raw`\bAC[0-9a-fA-F]{32}\b`,
    note: 'Account SID is semi-public; pairing it with a leaked auth token is the risk.' },
  { id: 'mailgun', provider: 'Mailgun', label: 'API key', base: 92,
    pattern: String.raw`\bkey-[0-9A-Za-z]{32}\b`,
    note: 'Full account key unless a scoped sending key was issued.' },
  { id: 'jwt', provider: 'JWT', label: 'JSON Web Token', base: 91,
    pattern: String.raw`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b`,
    note: 'Decode the payload for issuer and expiry; alg=none and weak HS256 secrets are the wins.' },
  { id: 'pem', provider: 'TLS / SSH', label: 'PEM private key block', base: 99,
    pattern: String.raw`-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----`,
    note: 'The header is proof of a key in the blob — pull the whole block and check the passphrase.' },
  { id: 'azure', provider: 'Azure', label: 'Storage account key', base: 93, group: 1,
    pattern: String.raw`AccountKey=([A-Za-z0-9+/=]{40,})`,
    note: 'Storage connection string: full blob, queue and table access for the account.' },
  { id: 'db-uri', provider: 'Database', label: 'Connection URI with password', base: 86, group: 1,
    pattern: String.raw`\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s:@/]+:([^\s@/]+)@[^\s"'<>)]+`,
    note: 'Inline password plus host: the fastest pivot in most leaked configs.' },
];

type Hit = {
  key: string;
  provider: string;
  label: string;
  masked: string;
  offset: number;
  line: number;
  col: number;
  entropy: number;
  confidence: number;
  note: string;
};

const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, n));

function mask(value: string): string {
  const flat = value.replace(/\s+/g, ' ').trim();
  if (flat.length <= 12) return `${flat.slice(0, 3)}… (${flat.length} ch)`;
  return `${flat.slice(0, 8)}…${flat.slice(-4)} (${flat.length} ch)`;
}

function locate(text: string, offset: number): { line: number; col: number } {
  const before = text.slice(0, offset);
  const line = before.split('\n').length;
  return { line, col: offset - before.lastIndexOf('\n') };
}

function scan(text: string): Hit[] {
  if (!text.trim()) return [];
  const out: Hit[] = [];
  const seen = new Set<string>();

  for (const rule of RULES) {
    const re = new RegExp(rule.pattern, 'g');
    let m = re.exec(text);
    while (m) {
      const raw = m[0];
      if (raw.length > 0) {
        const secret = rule.group !== undefined ? (m[rule.group] ?? raw) : rule.strip ? raw.replace(rule.strip, '') : raw;
        const entropy = shannonEntropy(secret);
        const key = `${rule.id}:${m.index}`;
        if (!seen.has(key)) {
          seen.add(key);
          const { line, col } = locate(text, m.index);
          const confidence = clamp(rule.base + (entropy >= 4.2 ? 3 : entropy >= 3.2 ? 0 : -16), 30, 99);
          out.push({
            key, provider: rule.provider, label: rule.label, masked: mask(raw),
            offset: m.index, line, col, entropy, confidence, note: rule.note,
          });
        }
      }
      m = re.exec(text);
    }
  }

  return out.sort((a, b) => a.provider.localeCompare(b.provider) || a.offset - b.offset);
}

const csvCell = (v: string | number) => `"${String(v).replace(/"/g, '""')}"`;

function buildCsv(hits: Hit[]): string {
  const head = ['provider', 'type', 'masked_value', 'offset', 'line', 'column', 'confidence', 'entropy'];
  const rows = hits.map((h) =>
    [h.provider, h.label, h.masked, h.offset, h.line, h.col, h.confidence, h.entropy.toFixed(2)].map(csvCell).join(','),
  );
  return [head.join(','), ...rows].join('\n');
}

function buildReport(hits: Hit[]): string {
  if (hits.length === 0) return '';
  const grouped = new Map<string, Hit[]>();
  for (const h of hits) grouped.set(h.provider, [...(grouped.get(h.provider) ?? []), h]);

  const lines: string[] = [
    `# Key triage — ${hits.length} hit(s), ${grouped.size} provider(s)`,
    '# values are masked; offsets index the pasted blob',
    '',
  ];
  for (const [provider, group] of grouped) {
    lines.push(`## ${provider} (${group.length})`);
    for (const h of group) {
      lines.push(
        `- ${h.label}: ${h.masked} · L${h.line}:${h.col} (offset ${h.offset}) · ${h.confidence}% · H=${h.entropy.toFixed(2)}`,
      );
    }
    lines.push('');
  }
  lines.push('## Triage order');
  lines.push('1. Revoke or rotate anything with a live-money or mail-send scope first.');
  lines.push('2. Replay the key against the provider from a proxy to confirm it is live — one request only.');
  lines.push('3. Record the file, commit and build artefact the key came from before you delete anything.');
  return lines.join('\n');
}

const SAMPLE = `// chunk 4f2a.js — synthetic fixtures, none of these keys are live
const cfg = {
  aws: { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' },
  google: { apiKey: 'AIzaSyD9d0EXAMPLEabcdefghijklmnopqrstuv', clientId: '123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com' },
  stripe: 'sk_live_51H8xQ2eZvKYlo2C9mNpQrStU',
  slack: 'xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx',
  github: 'ghp_16C7e42F292c6912E7710c838347Ae178B4a',
  gitlab: 'glpat-9xK2mQ7vR4tY8nB3sW6z',
  sendgrid: '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',
  twilio: { keySid: 'SK9f8e7d6c5b4a39281706f5e4d3c2b1a0', accountSid: 'ACa1b2c3d4e5f60718293a4b5c6d7e8f90' },
  mailgun: 'key-3ax6xnjp29jd6fds4gc373sgvjxteol0',
  database: 'postgres://svc_reporting:S3cr3t-Passw0rd@db.example.com:5432/reporting',
  analytics: 'mongodb://admin:hunter2@mongo.example.com:27017/app',
  storage: 'DefaultEndpointsProtocol=https;AccountName=acmestore;AccountKey=Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A=;EndpointSuffix=core.windows.net',
};
const session = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ7Kk3nR2pLm5Tz8Yv1Bc4Xd6Fg9Hj2';
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
-----END RSA PRIVATE KEY-----`;

const CONF_COLOUR = (c: number) => (c >= 90 ? 'var(--ok)' : c >= 70 ? 'var(--warn)' : 'var(--accent)');

export default function ApiKeyPatternDetector() {
  const [text, setText] = useState('');
  const [provider, setProvider] = useState('all');
  const [floor, setFloor] = useState(50);

  const hits = useMemo(() => scan(text), [text]);
  const providers = useMemo(() => Array.from(new Set(hits.map((h) => h.provider))).sort(), [hits]);
  const shown = useMemo(
    () => hits.filter((h) => (provider === 'all' || h.provider === provider) && h.confidence >= floor),
    [hits, provider, floor],
  );
  const totals = useMemo(() => {
    const m = new Map<string, number>();
    for (const h of shown) m.set(h.provider, (m.get(h.provider) ?? 0) + 1);
    return Array.from(m.entries());
  }, [shown]);

  const report = useMemo(() => buildReport(shown), [shown]);
  const csv = useMemo(() => buildCsv(shown), [shown]);
  const chars = text.length;

  return (
    <>
      <Card
        title="Blob to scan"
        action={
          <div className="flex items-center gap-1">
            <Button size="sm" variant="ghost" onClick={() => setText(SAMPLE)} title="Load a synthetic fixture blob">
              Load sample
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setText('')} title="Clear the input">
              Clear
            </Button>
          </div>
        }
      >
        <TextArea
          label="Paste a bundle, config, log or environment dump"
          value={text}
          onChange={setText}
          rows={9}
          hint={`${chars.toLocaleString()} characters · ${hits.length} raw hit(s) · scanned locally, nothing leaves the page`}
          placeholder={"const cfg = { aws: 'AKIA…', stripe: 'sk_live_…' }"}
        />
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <Select
            label="Provider"
            value={provider}
            onChange={setProvider}
            options={[{ value: 'all', label: `All providers (${hits.length})` }, ...providers.map((p) => ({ value: p, label: p }))]}
            hint="Groups the table below"
          />
          <Slider
            label="Minimum confidence"
            value={floor}
            onChange={setFloor}
            min={0}
            max={99}
            step={5}
            format={(v) => `${v}%`}
          />
        </div>
      </Card>

      <Card
        title="Hits"
        action={<DownloadButton text={csv} filename="key-triage.csv" label="CSV" />}
      >
        {shown.length === 0 ? (
          <Callout tone="info" title="No matches yet">
            Paste text above, or load the sample. Detection is regex plus entropy, so a hit is a lead, not a verdict —
            confirm each key against the provider before you write it up.
          </Callout>
        ) : (
          <>
            <div className="mb-3 flex flex-wrap gap-1.5">
              {totals.map(([name, count]) => (
                <span
                  key={name}
                  className="rounded px-2 py-0.5 text-[11px] text-[var(--text-muted)]"
                  style={{ background: 'var(--neutral-btn)' }}
                >
                  {name} <span className="rf-mono text-[var(--text)]">{count}</span>
                </span>
              ))}
            </div>
            <div className="max-h-[420px] overflow-auto rounded border border-[var(--card-border)]">
              <table className="w-full border-collapse text-[12px]">
                <thead className="sticky top-0 bg-[var(--card)]">
                  <tr className="text-left text-[10.5px] tracking-wide text-[var(--text-faint)] uppercase">
                    <th className="px-2.5 py-1.5 font-medium">Provider</th>
                    <th className="px-2.5 py-1.5 font-medium">Masked value</th>
                    <th className="px-2.5 py-1.5 font-medium">Offset</th>
                    <th className="px-2.5 py-1.5 font-medium">Conf.</th>
                    <th className="px-2.5 py-1.5 font-medium">Entropy</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((h, i) => (
                    <tr key={h.key} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                      <td className="px-2.5 py-1.5 align-top whitespace-nowrap text-[var(--text)]">{h.provider}</td>
                      <td className="rf-mono px-2.5 py-1.5 align-top break-all text-[11px] text-[var(--text-muted)]">
                        {h.masked}
                        <span className="ml-1.5 text-[10px] text-[var(--text-faint)]">{h.label}</span>
                      </td>
                      <td className="rf-mono px-2.5 py-1.5 align-top whitespace-nowrap text-[11px] text-[var(--text-muted)]">
                        {h.offset}
                        <span className="ml-1 text-[10px] text-[var(--text-faint)]">
                          L{h.line}:{h.col}
                        </span>
                      </td>
                      <td className="rf-mono px-2.5 py-1.5 align-top" style={{ color: CONF_COLOUR(h.confidence) }}>
                        {h.confidence}%
                      </td>
                      <td className="rf-mono px-2.5 py-1.5 align-top text-[11px] text-[var(--text-muted)]">
                        {h.entropy.toFixed(2)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-2 mb-0 text-[11.5px] text-[var(--text-faint)]">
              Offsets are character indexes into the pasted text; entropy is Shannon over the secret portion, so a
              low-entropy match is usually a placeholder rather than a live key.
            </p>
          </>
        )}
      </Card>

      <Card title="Redacted triage report">
        <OutputBlock value={report} rows={14} label="report.md" empty="Load the sample or paste a blob to build the report." />
        <div className="mt-3">
          <Callout tone="warn" title="Entropy is a filter, not proof">
            <span className="rf-mono">AKIAIOSFODNN7EXAMPLE</span> scores low because it is a documented example. Anything
            above 3.2 bits per character with a provider prefix is worth a revocation check; anything below is worth one
            line in the notes.
          </Callout>
        </div>
      </Card>
    </>
  );
}
