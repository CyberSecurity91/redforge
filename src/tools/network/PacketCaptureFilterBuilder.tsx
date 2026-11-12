import { useMemo, useState } from 'react';
import { Button, Callout, Card, Checkbox, IconButton, OutputBlock, Select, TextInput } from '@/components/ui';
import { Trash2 } from 'lucide-react';

type Kind = 'host' | 'net' | 'port' | 'portrange' | 'proto' | 'flags' | 'raw';
type Dir = 'any' | 'src' | 'dst';
type Clause = { id: number; kind: Kind; dir: Dir; value: string; negate: boolean };

const RAW: Record<string, { bpf: string; display: string; note: string }> = {
  'http-post': {
    bpf: 'tcp port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354',
    display: 'http.request.method == "POST"',
    note: 'Reads the first payload bytes at the TCP data offset and matches the literal POST — form bodies and credentials follow.',
  },
  'tls-sni': {
    bpf: 'tcp port 443',
    display: 'tls.handshake.extensions_server_name',
    note: 'The SNI travels unencrypted in the ClientHello, so tshark can print the hostname even when the certificate is opaque.',
  },
};

const KINDS: { value: Kind; label: string }[] = [
  { value: 'host', label: 'host' },
  { value: 'net', label: 'net' },
  { value: 'port', label: 'port' },
  { value: 'portrange', label: 'port range' },
  { value: 'proto', label: 'protocol' },
  { value: 'flags', label: 'TCP flags' },
  { value: 'raw', label: 'raw expression' },
];

const PROTOCOLS = ['tcp', 'udp', 'icmp', 'icmp6', 'arp', 'ip', 'ip6'];
const FLAGS = ['syn', 'ack', 'fin', 'rst', 'psh', 'urg'];

const PRESETS: { id: string; label: string; join: 'and' | 'or'; clauses: Omit<Clause, 'id'>[] }[] = [
  {
    id: 'creds',
    label: 'Cleartext credentials',
    join: 'or',
    clauses: [
      { kind: 'port', dir: 'any', value: '21', negate: false },
      { kind: 'port', dir: 'any', value: '23', negate: false },
      { kind: 'port', dir: 'any', value: '25', negate: false },
      { kind: 'port', dir: 'any', value: '110', negate: false },
      { kind: 'port', dir: 'any', value: '143', negate: false },
    ],
  },
  {
    id: 'dns',
    label: 'DNS exfil',
    join: 'and',
    clauses: [
      { kind: 'port', dir: 'any', value: '53', negate: false },
      { kind: 'host', dir: 'dst', value: '203.0.113.10', negate: true },
    ],
  },
  { id: 'smb', label: 'SMB', join: 'and', clauses: [{ kind: 'port', dir: 'dst', value: '445', negate: false }] },
  { id: 'icmp', label: 'ICMP tunnel', join: 'and', clauses: [{ kind: 'proto', dir: 'any', value: 'icmp', negate: false }] },
  { id: 'httppost', label: 'HTTP POST bodies', join: 'and', clauses: [{ kind: 'raw', dir: 'any', value: 'http-post', negate: false }] },
  { id: 'sni', label: 'TLS SNI', join: 'and', clauses: [{ kind: 'raw', dir: 'any', value: 'tls-sni', negate: false }] },
  { id: 'arp', label: 'ARP', join: 'and', clauses: [{ kind: 'proto', dir: 'any', value: 'arp', negate: false }] },
];

function bpfClause(c: Clause): string {
  const v = c.value.trim();
  const d = c.dir === 'any' ? '' : `${c.dir} `;
  let body: string;
  switch (c.kind) {
    case 'host':
      body = `${d}host ${v}`;
      break;
    case 'net':
      body = `${d}net ${v}`;
      break;
    case 'port':
      body = `${d}port ${v}`;
      break;
    case 'portrange':
      body = `portrange ${v}`;
      break;
    case 'proto':
      body = v;
      break;
    case 'flags':
      body = `tcp[tcpflags] & tcp-${v} != 0`;
      break;
    case 'raw':
      body = RAW[v]?.bpf ?? v;
      break;
  }
  return c.negate ? `not (${body})` : body;
}

function displayClause(c: Clause): string {
  const v = c.value.trim();
  let body: string;
  switch (c.kind) {
    case 'host':
      body = `${c.dir === 'dst' ? 'ip.dst' : 'ip.src'} == ${v}`;
      if (c.dir === 'any') body = `(ip.addr == ${v} || ipv6.addr == ${v})`;
      break;
    case 'net':
      body = `${c.dir === 'dst' ? 'ip.dst' : 'ip.src'} == ${v}`;
      if (c.dir === 'any') body = `ip.addr == ${v}`;
      break;
    case 'port':
      body =
        c.dir === 'src'
          ? `(tcp.srcport == ${v} || udp.srcport == ${v})`
          : c.dir === 'dst'
            ? `(tcp.dstport == ${v} || udp.dstport == ${v})`
            : `(tcp.port == ${v} || udp.port == ${v})`;
      break;
    case 'portrange': {
      const [a, b] = v.split('-');
      body = `(tcp.port >= ${a} && tcp.port <= ${b})`;
      break;
    }
    case 'proto':
      body = v;
      break;
    case 'flags':
      body = `tcp.flags.${v} == 1`;
      break;
    case 'raw':
      body = RAW[v]?.display ?? v;
      break;
  }
  return c.negate ? `!(${body})` : body;
}

function describe(c: Clause): string {
  const v = c.value.trim() || '(empty)';
  const neg = c.negate ? 'everything except ' : '';
  const side = c.dir === 'any' ? 'either direction' : c.dir === 'src' ? 'source only' : 'destination only';
  switch (c.kind) {
    case 'host':
      return `${neg}traffic to or from ${v}, ${side}.`;
    case 'net':
      return `${neg}any address inside ${v} (CIDR), ${side}.`;
    case 'port':
      return `${neg}port ${v} on ${side.replace(' only', '')} — both TCP and UDP unless narrowed.`;
    case 'portrange':
      return `${neg}ports inside ${v} — a range keeps a scan sweep in one clause.`;
    case 'proto':
      return `${neg}the ${v} protocol only, regardless of address or port.`;
    case 'flags':
      return `${neg}packets with the ${v.toUpperCase()} flag set — useful for handshakes and resets.`;
    case 'raw':
      return RAW[v]?.note ?? 'Literal expression, emitted verbatim.';
  }
}

function validate(clauses: Clause[]): string[] {
  const errs: string[] = [];
  for (const c of clauses) {
    const v = c.value.trim();
    if (!v) errs.push(`${c.kind}: empty operand — the filter would emit an operator with nothing on one side.`);
    if (c.kind === 'port' && v) {
      if (/^\d+$/.test(v)) {
        const n = Number(v);
        if (n > 65535) errs.push(`port ${v} is above 65535 — TCP and UDP ports are 16-bit.`);
      } else if (!/^[a-zA-Z][a-zA-Z0-9-]*$/.test(v)) {
        errs.push(`port "${v}" is neither a number nor a service name.`);
      }
    }
    if (c.kind === 'portrange' && v) {
      const m = /^(\d+)\s*-\s*(\d+)$/.exec(v);
      if (!m) errs.push(`port range "${v}" must look like 8000-8100.`);
      else if (Number(m[1]) > 65535 || Number(m[2]) > 65535) errs.push(`port range "${v}" exceeds 65535.`);
      else if (Number(m[1]) >= Number(m[2])) errs.push(`port range "${v}" must ascend.`);
    }
    if ((c.kind === 'host' || c.kind === 'net') && v && !/^[0-9a-zA-Z.:_-]+(\/\d{1,3})?$/.test(v)) {
      errs.push(`${c.kind} "${v}" contains characters no address or hostname has.`);
    }
  }
  if (clauses.length === 0) errs.push('No clauses yet — add one or pick a preset.');
  return errs;
}

let nextId = 1;
const clause = (c: Omit<Clause, 'id'>): Clause => ({ ...c, id: nextId++ });

export default function PacketCaptureFilterBuilder() {
  const [iface, setIface] = useState('eth0');
  const [join, setJoin] = useState<'and' | 'or'>('and');
  const [clauses, setClauses] = useState<Clause[]>([
    clause({ kind: 'host', dir: 'any', value: '203.0.113.10', negate: false }),
    clause({ kind: 'port', dir: 'dst', value: '443', negate: false }),
  ]);

  const errors = useMemo(() => validate(clauses), [clauses]);
  const bpf = useMemo(() => clauses.map(bpfClause).join(` ${join} `), [clauses, join]);
  const display = useMemo(() => clauses.map(displayClause).join(` ${join === 'and' ? '&&' : '||'} `), [clauses, join]);

  const tcpdumpCmd = errors.length === 0
    ? `sudo tcpdump -i ${iface.trim() || 'eth0'} -nn -s 0 -w capture.pcap '${bpf}'`
    : '';
  const tsharkCmd = errors.length === 0
    ? `tshark -i ${iface.trim() || 'eth0'} -f '${bpf}' -Y '${display}'`
    : '';

  const update = (id: number, patch: Partial<Clause>) =>
    setClauses(clauses.map((c) => (c.id === id ? { ...c, ...patch } : c)));

  return (
    <>
      <Card title="Presets">
        <div className="flex flex-wrap gap-1.5">
          {PRESETS.map((p) => (
            <Button
              key={p.id}
              size="sm"
              variant="outline"
              title={`Load the ${p.label} filter`}
              onClick={() => setClauses(p.clauses.map(clause))}
            >
              {p.label}
            </Button>
          ))}
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <TextInput label="Interface" value={iface} onChange={setIface} mono hint="eth0, wlan0, any" />
          <Select
            label="Combine clauses with"
            value={join}
            onChange={setJoin}
            options={[
              { value: 'and', label: 'and — narrower' },
              { value: 'or', label: 'or — wider' },
            ]}
          />
        </div>
      </Card>

      <Card
        title="Clauses"
        action={
          <Button size="sm" variant="ghost" onClick={() => setClauses([...clauses, clause({ kind: 'port', dir: 'any', value: '', negate: false })])} title="Append a clause">
            Add clause
          </Button>
        }
      >
        <div className="flex flex-col gap-2">
          {clauses.map((c) => (
            <div key={c.id} className="flex flex-wrap items-end gap-1.5">
              <div className="w-[120px]">
                <Select value={c.kind} onChange={(v) => update(c.id, { kind: v as Kind, value: '' })} options={KINDS} />
              </div>
              <div className="w-[86px]">
                <Select
                  value={c.dir}
                  onChange={(v) => update(c.id, { dir: v as Dir })}
                  options={[
                    { value: 'any', label: 'any' },
                    { value: 'src', label: 'src' },
                    { value: 'dst', label: 'dst' },
                  ]}
                />
              </div>
              {c.kind === 'proto' ? (
                <div className="min-w-[130px] flex-1">
                  <Select value={c.value} onChange={(v) => update(c.id, { value: v })} options={PROTOCOLS.map((p) => ({ value: p, label: p }))} />
                </div>
              ) : c.kind === 'flags' ? (
                <div className="min-w-[130px] flex-1">
                  <Select value={c.value} onChange={(v) => update(c.id, { value: v })} options={FLAGS.map((f) => ({ value: f, label: f.toUpperCase() }))} />
                </div>
              ) : c.kind === 'raw' ? (
                <div className="min-w-[200px] flex-1">
                  <Select
                    value={c.value}
                    onChange={(v) => update(c.id, { value: v })}
                    options={Object.keys(RAW).map((k) => ({ value: k, label: k }))}
                  />
                </div>
              ) : (
                <div className="min-w-[180px] flex-1">
                  <TextInput
                    value={c.value}
                    onChange={(v) => update(c.id, { value: v })}
                    placeholder={c.kind === 'port' ? '443' : c.kind === 'portrange' ? '8000-8100' : c.kind === 'net' ? '10.10.0.0/16' : '203.0.113.10'}
                    mono
                  />
                </div>
              )}
              <div className="pb-2">
                <Checkbox checked={c.negate} onChange={(v) => update(c.id, { negate: v })} label="not" />
              </div>
              <IconButton title={`Remove the ${c.kind} clause`} onClick={() => setClauses(clauses.filter((x) => x.id !== c.id))}>
                <Trash2 size={13} />
              </IconButton>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Filters">
        <div className="flex flex-col gap-3">
          <OutputBlock value={bpf} label="BPF (tcpdump capture filter)" rows={4} />
          <OutputBlock value={display} label="Display filter (tshark -Y)" rows={4} />
        </div>
        <ul className="mt-3 mb-0 flex list-none flex-col gap-1 p-0">
          {clauses.map((c) => (
            <li key={c.id} className="flex gap-2 text-[11.5px] text-[var(--text-muted)]">
              <span className="rf-mono text-[var(--text-faint)]">{bpfClause(c)}</span>
              <span>— {describe(c)}</span>
            </li>
          ))}
        </ul>
      </Card>

      <Card title="Command line">
        {errors.length > 0 ? (
          <Callout tone="danger" title={`${errors.length} problem(s) to fix before this runs`}>
            <ul className="mt-1 mb-0 list-disc pl-4">
              {errors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          </Callout>
        ) : (
          <div className="flex flex-col gap-3">
            <OutputBlock value={tcpdumpCmd} label="tcpdump" rows={3} />
            <OutputBlock value={tsharkCmd} label="tshark" rows={3} />
            <p className="mb-0 text-[11.5px] text-[var(--text-faint)]">
              BPF is evaluated in the kernel, so the capture drops nothing it has not already filtered; the display filter
              runs in tshark after the fact, which means the two can legitimately differ.
            </p>
          </div>
        )}
      </Card>
    </>
  );
}
