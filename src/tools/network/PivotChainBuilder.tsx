import { useMemo, useState } from 'react';
import {
  Button,
  Callout,
  Card,
  CodeBlock,
  CopyChip,
  KVTable,
  NumberInput,
  OutputBlock,
  Select,
  TextInput,
} from '@/components/ui';
import { DEFAULT_CALLBACK_HOST, DEFAULT_TARGET_IP } from '@/tools/registry';

type HopType = 'local' | 'remote' | 'dynamic' | 'chisel-server' | 'chisel-client' | 'sshuttle' | 'socat';

type Hop = {
  id: number;
  type: HopType;
  label: string;
  user?: string;
  host: string;
  port: number;
  targetHost: string;
  targetPort: number;
  socksPort: number;
};

let seq = 100;
const hop = (type: HopType, label: string, partial: Partial<Hop> = {}): Hop => ({
  id: seq++,
  type,
  label,
  user: 'kali',
  host: DEFAULT_TARGET_IP,
  port: 22,
  targetHost: '10.10.10.240',
  targetPort: 3389,
  socksPort: 1080,
  ...partial,
});

const TYPES: Array<{ value: HopType; label: string }> = [
  { value: 'local', label: 'SSH local forward (-L)' },
  { value: 'remote', label: 'SSH remote forward (-R)' },
  { value: 'dynamic', label: 'SSH dynamic SOCKS (-D)' },
  { value: 'chisel-server', label: 'chisel server' },
  { value: 'chisel-client', label: 'chisel client' },
  { value: 'sshuttle', label: 'sshuttle' },
  { value: 'socat', label: 'socat relay' },
];

const DEFAULT_HOPS: Hop[] = [
  hop('dynamic', 'Edge host → SOCKS', { host: '203.0.113.10', user: 'kali', socksPort: 1080 }),
  hop('local', 'Pivot → internal RDP', {
    host: '127.0.0.1',
    user: 'kali',
    port: 1080,
    targetHost: '10.10.10.240',
    targetPort: 3389,
  }),
];

function commandFor(h: Hop): string {
  const user = h.user?.trim() || 'kali';
  switch (h.type) {
    case 'local':
      return `ssh -N -L 127.0.0.1:${h.targetPort}:${h.targetHost}:${h.targetPort} ${user}@${h.host} -p ${h.port}`;
    case 'remote':
      return `ssh -N -R 127.0.0.1:${h.targetPort}:${h.targetHost}:${h.targetPort} ${user}@${h.host} -p ${h.port}`;
    case 'dynamic':
      return `ssh -N -D 127.0.0.1:${h.socksPort} ${user}@${h.host} -p ${h.port}`;
    case 'chisel-server':
      return `./chisel server --reverse --socks5 --port ${h.port}`;
    case 'chisel-client':
      return `./chisel client ${h.host}:${h.port} R:socks`;
    case 'sshuttle':
      return `sshuttle -r ${user}@${h.host}:${h.port} ${h.targetHost}/24 --dns`;
    case 'socat':
      return `socat TCP-LISTEN:${h.port},fork,reuseaddr TCP:${h.targetHost}:${h.targetPort}`;
    default:
      return '';
  }
}

function diagramFor(hops: Hop[]): string {
  const width = 26;
  const box = (title: string, sub: string) => {
    const top = `┌${'─'.repeat(width)}┐`;
    const mid = `│ ${title.padEnd(width - 2)} │`;
    const subLine = `│ ${sub.padEnd(width - 2)} │`;
    const bot = `└${'─'.repeat(width)}┘`;
    return [top, mid, subLine, bot];
  };
  const blocks = [
    ...box('attacker', '127.0.0.1'),
    ...hops.map((h) => [
      ...box(h.label.slice(0, width - 2), `${h.host}:${h.port}`.slice(0, width - 2)),
    ]).flat(),
    ...box('target', 'internal service'),
  ];
  const lines: string[] = [];
  blocks.forEach((line, i) => {
    lines.push(line);
    const isBoxEnd = line.startsWith('└');
    if (isBoxEnd && i < blocks.length - 1) {
      lines.push('');
      lines.push(`        ${'│'}`);
      lines.push(`        ${'▼'}`);
    }
  });
  return lines.join('\n');
}

export default function PivotChainBuilder() {
  const [hops, setHops] = useState<Hop[]>(DEFAULT_HOPS);
  const [socksPort, setSocksPort] = useState(1080);
  const [container, setContainer] = useState('10.10.10.0/24');

  const update = (id: number, patch: Partial<Hop>) =>
    setHops((prev) => prev.map((h) => (h.id === id ? { ...h, ...patch } : h)));

  const derived = useMemo(() => {
    const commands = hops.map((h, i) => `# hop ${i + 1} — ${h.label}\n${commandFor(h)}`);
    const sshConfig = [
      'Host pivot1',
      '  HostName 203.0.113.10',
      '  Port 22',
      '  User kali',
      '  DynamicForward 127.0.0.1:1080',
      '  ServerAliveInterval 30',
      '',
      'Host pivot2',
      '  HostName 10.10.10.5',
      '  Port 22',
      '  User svc-pivot',
      '  ProxyJump pivot1',
      '  LocalForward 127.0.0.1:3389 10.10.10.240:3389',
    ].join('\n');

    const proxychains = [
      'strict_chain',
      'proxy_dns',
      'tcp_read_time_out 15000',
      'tcp_connect_time_out 8000',
      '',
      '[ProxyList]',
      `socks5 127.0.0.1 ${socksPort}`,
    ].join('\n');

    const sanity = [
      `proxychains4 -q nmap -sT -Pn -n -p 22,80,443 ${DEFAULT_TARGET_IP}`,
      `proxychains4 -q curl -s -m 10 http://${DEFAULT_TARGET_IP}/ -o /dev/null -w '%{http_code}\\n'`,
      `proxychains4 -q crackmapexec smb ${container}`,
    ].join('\n');

    return {
      commands: commands.join('\n\n'),
      sshConfig,
      proxychains,
      sanity,
      diagram: diagramFor(hops),
    };
  }, [hops, socksPort, container]);

  return (
    <>
      <Card
        title="Hops"
        action={
          <Button size="sm" variant="ghost" onClick={() => setHops((p) => [...p, hop('dynamic', 'New hop')])}>
            Add hop
          </Button>
        }
      >
        {hops.length === 0 && (
          <div className="text-[12px] text-[var(--text-faint)]">No hops yet — add one to start the chain.</div>
        )}
        <div className="grid gap-4">
          {hops.map((h, i) => (
            <div key={h.id} className="rounded-md border border-[var(--border)] p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[12px] font-medium text-[var(--text-muted)]">Hop {i + 1}</span>
                <Button size="sm" variant="ghost" onClick={() => setHops((p) => p.filter((x) => x.id !== h.id))}>
                  Remove
                </Button>
              </div>
              <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                <TextInput label="Label" value={h.label} onChange={(v) => update(h.id, { label: v })} />
                <Select
                  label="Type"
                  value={h.type}
                  onChange={(v) => update(h.id, { type: v })}
                  options={TYPES}
                />
                <TextInput label="Jump host" value={h.host} onChange={(v) => update(h.id, { host: v })} mono />
                <NumberInput label="SSH / listen port" value={h.port} onChange={(v) => update(h.id, { port: v })} min={1} max={65535} />
                <TextInput label="SSH user" value={h.user ?? ''} onChange={(v) => update(h.id, { user: v })} mono />
                <TextInput
                  label="Forward target host"
                  value={h.targetHost}
                  onChange={(v) => update(h.id, { targetHost: v })}
                  mono
                />
                <NumberInput
                  label="Forward target port"
                  value={h.targetPort}
                  onChange={(v) => update(h.id, { targetPort: v })}
                  min={1}
                  max={65535}
                />
                <NumberInput
                  label="SOCKS port"
                  value={h.socksPort}
                  onChange={(v) => update(h.id, { socksPort: v })}
                  min={1}
                  max={65535}
                />
              </div>
              <div className="mt-3">
                <CodeBlock code={commandFor(h)} maxHeight={80} />
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Topology">
        <OutputBlock value={derived.diagram} rows={hops.length * 6 + 8} label="Chain" />
      </Card>

      <Card title="Commands in order" action={<CopyChip text={derived.commands} label="Copy chain" />}>
        <CodeBlock code={derived.commands} maxHeight={300} />
        <div className="mt-4">
          <Callout tone="info" title="Ordering">
            Run each hop from the previous hop's host. <span className="rf-mono">ssh -N</span> keeps the channel open
            without a shell; add <span className="rf-mono">-f</span> to background it, then close it with{' '}
            <span className="rf-mono">kill %1</span> or by killing the pid.
          </Callout>
        </div>
      </Card>

      <Card title="Client configuration">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <TextInput
              label="SOCKS port for proxychains"
              value={String(socksPort)}
              onChange={(v) => setSocksPort(Number(v) || 1080)}
              mono
            />
            <div className="mt-3">
              <CodeBlock code={derived.proxychains} label="~/.proxychains/proxychains.conf" maxHeight={160} />
            </div>
          </div>
          <div>
            <TextInput label="Internal CIDR for sanity check" value={container} onChange={setContainer} mono />
            <div className="mt-3">
              <CodeBlock code={derived.sshConfig} label="~/.ssh/config" maxHeight={200} />
            </div>
          </div>
        </div>
        <div className="mt-4">
          <OutputBlock value={derived.sanity} rows={4} label="Sanity checks through the chain" />
        </div>
      </Card>

      <Card title="Hop summary">
        <KVTable
          rows={hops.map((h, i) => [
            <span key={h.id} className="rf-mono">
              {i + 1}. {h.label}
            </span>,
            <span key={`${h.id}-c`} className="rf-mono">
              {TYPES.find((t) => t.value === h.type)?.label} · {h.host}:{h.port}
            </span>,
          ])}
        />
        <div className="mt-3 text-[11.5px] leading-relaxed text-[var(--text-faint)]">
          Default callback host for chisel is <span className="rf-mono">{DEFAULT_CALLBACK_HOST}</span> — swap it in
          the hop fields if the reverse tunnel is initiated from inside the network.
        </div>
      </Card>
    </>
  );
}
