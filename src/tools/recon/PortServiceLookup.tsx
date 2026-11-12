import { useMemo, useState } from 'react';
import { Callout, Card, OutputBlock, SectionTitle, Tabs, TextArea, TextInput } from '@/components/ui';
import { PRIORITY_PORTS } from '@/lib/redteam-data';
import { DEFAULT_TARGET_IP } from '@/tools/registry';

type Tier = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

interface Detected {
  port: number;
  service: string;
  note: string;
  version: string;
  tier: Tier;
  next: string;
  command: string | null;
}

/** Risk tier by port — drives ordering and colour. */
const TIER: Record<number, Tier> = {
  21: 'high',
  22: 'medium',
  23: 'high',
  25: 'medium',
  53: 'medium',
  80: 'low',
  88: 'critical',
  110: 'medium',
  135: 'high',
  139: 'high',
  389: 'high',
  443: 'low',
  445: 'critical',
  636: 'medium',
  873: 'high',
  1433: 'critical',
  1521: 'high',
  2049: 'high',
  2375: 'critical',
  2376: 'high',
  3306: 'high',
  3389: 'high',
  5432: 'high',
  5672: 'medium',
  5900: 'high',
  5985: 'critical',
  5986: 'high',
  6379: 'critical',
  8080: 'low',
  8443: 'low',
  9000: 'high',
  9200: 'critical',
  11211: 'high',
  27017: 'critical',
};

const TIER_ORDER: Record<Tier, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

/** Follow-up command templates keyed by port; `{H}` is the target host. */
function followUp(port: number, host: string): { next: string; command: string | null } {
  switch (port) {
    case 21:
      return { next: 'Anonymous login, then write test', command: `ftp -p ${host}\n# try anonymous / anonymous, then: put proof.txt` };
    case 22:
      return { next: 'Banner + key type, then credential reuse', command: `ssh-keyscan -T 5 -p 22 ${host}\nnmap -p22 --script ssh-auth-methods,ssh2-enum-algos ${host}` };
    case 23:
      return { next: 'Sniff for cleartext credentials', command: `telnet ${host} 23` };
    case 25:
      return { next: 'VRFY / EXPN user enum, open relay', command: `smtp-user-enum -M VRFY -U users.txt -t ${host}\nnmap -p25 --script smtp-open-relay ${host}` };
    case 53:
      return { next: 'AXFR and recursion check', command: `dig axfr @${host} example.com\ndig +recurse @${host} google.com` };
    case 80:
    case 8080:
      return { next: 'Fingerprint the app, list vhosts', command: `whatweb -a3 http://${host}:${port}\nffuf -u http://${host}:${port} -H "Host: FUZZ.example.com" -w subdomains.txt` };
    case 443:
    case 8443:
      return { next: 'Collect cert SANs, then vhost fuzz', command: `openssl s_client -connect ${host}:${port} -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -text | grep DNS:` };
    case 88:
      return { next: 'ASREP roast users without pre-auth', command: `impacket-GetNPUsers DOMAIN/ -dc-ip ${host} -usersfile users.txt -no-pass -format hashcat` };
    case 135:
    case 139:
    case 445:
      return { next: 'Null session, shares, signing', command: `nxc smb ${host} -u '' -p '' --shares\nsmbclient -N -L //${host}\nnmap -p445 --script smb-vuln-ms17-010,smb2-security-mode ${host}` };
    case 389:
    case 636:
      return { next: 'Anonymous bind, then base DN dump', command: `ldapsearch -x -H ldap://${host} -s base namingcontexts\nldapsearch -x -H ldap://${host} -b "DC=corp,DC=local" -s sub` };
    case 873:
      return { next: 'List modules without auth', command: `rsync rsync://${host}/` };
    case 1433:
      return { next: 'Weak sa password, then xp_cmdshell', command: `nxc mssql ${host} -u sa -p 'P@ssw0rd' -q 'SELECT @@version'` };
    case 2049:
      return { next: 'Export list, then uid-spoofed mount', command: `showmount -e ${host}\nmount -t nfs ${host}:/export /mnt/nfs -o nolock` };
    case 2375:
    case 2376:
      return { next: 'Unauthenticated API — container list', command: `curl -s http://${host}:${port}/version\ncurl -s http://${host}:${port}/containers/json` };
    case 3306:
      return { next: 'root with blank password, then file read', command: `mysql -h ${host} -u root --password='' -e "SELECT user,host FROM mysql.user"` };
    case 3389:
      return { next: 'NLA check, then credential reuse', command: `nmap -p3389 --script rdp-enum-encryption ${host}\nxfreerdp /v:${host} /u:USER /p:PASS /cert-ignore` };
    case 5432:
      return { next: 'Trust auth and superuser check', command: `psql -h ${host} -U postgres -c 'select version();'` };
    case 5900:
      return { next: 'Check for no-auth VNC', command: `vncviewer ${host}:0` };
    case 5985:
    case 5986:
      return { next: 'WinRM with recovered credentials', command: `evil-winrm -i ${host} -u USER -p PASS${port === 5986 ? ' -S' : ''}` };
    case 6379:
      return { next: 'No-auth check, then module / cron write', command: `redis-cli -h ${host} -p ${port} INFO\nredis-cli -h ${host} -p ${port} CONFIG GET dir` };
    case 9200:
      return { next: 'Indices and documents', command: `curl -s http://${host}:${port}/_cat/indices?v\ncurl -s http://${host}:${port}/_search?size=5` };
    case 11211:
      return { next: 'Slab stats and key dump', command: `echo -e "stats\\nstats items\\nquit" | nc -w2 ${host} ${port}` };
    case 27017:
      return { next: 'Unauthenticated database list', command: `mongosh "mongodb://${host}:${port}" --eval 'db.adminCommand({listDatabases:1})'` };
    case 5672:
      return { next: 'guest:guest and queue dump', command: `curl -s -u guest:guest http://${host}:15672/api/queues` };
    default:
      return { next: 'Banner grab and version search', command: `nmap -p${port} -sV --version-all ${host}` };
  }
}

/** nmap output lines: `22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu` or bare `22` / `22,80`. */
function parsePorts(text: string): Map<number, string> {
  const found = new Map<number, string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const nmap = /^(\d{1,5})\/(tcp|udp)\s+(open|open\|filtered)\s+(\S+)?\s*(.*)$/i.exec(line);
    if (nmap) {
      const port = Number(nmap[1]);
      if (port > 0 && port < 65536) found.set(port, `${nmap[4] ?? ''} ${nmap[5] ?? ''}`.trim());
      continue;
    }
    const range = /^(\d{1,5})-(\d{1,5})\s*$/;
    const rm = range.exec(line);
    if (rm) {
      const lo = Number(rm[1]);
      const hi = Math.min(Number(rm[2]), lo + 200);
      for (let p = lo; p <= hi; p++) found.set(p, '');
      continue;
    }
    for (const token of line.split(/[\s,;]+/)) {
      const m = /^(\d{1,5})(?:\/\w+)?$/.exec(token);
      if (m) {
        const port = Number(m[1]);
        if (port > 0 && port < 65536) found.set(port, '');
      }
    }
  }
  return found;
}

const TIER_CLASS: Record<Tier, string> = {
  critical: 'text-[var(--accent)]',
  high: 'text-[var(--warn)]',
  medium: 'text-[var(--info)]',
  low: 'text-[var(--text-muted)]',
  unknown: 'text-[var(--text-faint)]',
};

export default function PortServiceLookup() {
  const [raw, setRaw] = useState('');
  const [host, setHost] = useState(DEFAULT_TARGET_IP);
  const [tierFilter, setTierFilter] = useState<'all' | 'critical' | 'high'>('all');

  const detected = useMemo<Detected[]>(() => {
    const ports = parsePorts(raw);
    const table = new Map(PRIORITY_PORTS.map(([p, s, n]) => [p, { service: s, note: n }]));
    return Array.from(ports.entries())
      .map(([port, version]) => {
        const known = table.get(port);
        const tier = TIER[port] ?? 'unknown';
        const { next, command } = followUp(port, host.trim() || DEFAULT_TARGET_IP);
        return {
          port,
          service: known?.service ?? (version.split(/\s+/)[0] || 'unknown'),
          note: known?.note ?? 'Not in the priority table — banner-grab first',
          version,
          tier,
          next,
          command,
        };
      })
      .sort((a, b) => TIER_ORDER[a.tier] - TIER_ORDER[b.tier] || a.port - b.port);
  }, [raw, host]);

  const shown = useMemo(
    () => (tierFilter === 'all' ? detected : detected.filter((d) => d.tier === tierFilter)),
    [detected, tierFilter],
  );

  const priorityCmd = useMemo(() => {
    if (!detected.length) return '';
    const ports = detected.map((d) => d.port).join(',');
    return [
      `# ${detected.length} ports, ordered by risk tier`,
      `nmap -p${ports} -sV -sC --version-all -oN ${host || DEFAULT_TARGET_IP}-services.txt ${host || DEFAULT_TARGET_IP}`,
      `# deeper on the top tier only`,
      `nmap -p${detected.filter((d) => d.tier === 'critical' || d.tier === 'high').map((d) => d.port).join(',') || '—'} --script "default or vuln" ${host || DEFAULT_TARGET_IP}`,
    ].join('\n');
  }, [detected, host]);

  const commands = useMemo(
    () =>
      detected
        .filter((d) => d.command)
        .map((d) => `# ── ${d.port}/${d.service} (${d.tier}) — ${d.next}\n${d.command}`)
        .join('\n\n'),
    [detected],
  );

  const counts = useMemo(() => {
    const c: Record<Tier, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    for (const d of detected) c[d.tier]++;
    return c;
  }, [detected]);

  return (
    <>
      <Card title="Scan input">
        <div className="grid gap-4 sm:grid-cols-[2fr_1fr]">
          <TextArea
            label="nmap output or port list"
            hint="Accepts `22/tcp open ssh OpenSSH 8.9`, bare `22`, or `22,80,443`"
            value={raw}
            onChange={setRaw}
            rows={8}
            placeholder={'22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6\n445/tcp  open  microsoft-ds\n5985/tcp open  wsman'}
          />
          <div className="space-y-3">
            <TextInput label="Target host" value={host} onChange={setHost} mono hint="Substituted into commands" />
            <div className="rounded border border-[var(--card-border)] px-3 py-2 text-[12px] leading-relaxed text-[var(--text-muted)]">
              <div>Ports parsed: <span className="rf-mono text-[var(--text)]">{detected.length}</span></div>
              <div className="mt-1 flex flex-wrap gap-x-3">
                <span className={TIER_CLASS.critical}>critical {counts.critical}</span>
                <span className={TIER_CLASS.high}>high {counts.high}</span>
                <span className={TIER_CLASS.medium}>medium {counts.medium}</span>
                <span className={TIER_CLASS.low}>low {counts.low}</span>
                <span className={TIER_CLASS.unknown}>unknown {counts.unknown}</span>
              </div>
            </div>
          </div>
        </div>
      </Card>

      <Card
        title="Service table"
        action={
          <Tabs
            value={tierFilter}
            onChange={setTierFilter}
            tabs={[
              { value: 'all', label: 'All', badge: detected.length },
              { value: 'critical', label: 'Critical', badge: counts.critical },
              { value: 'high', label: 'High', badge: counts.high },
            ]}
          />
        }
      >
        {shown.length === 0 ? (
          <Callout tone="warn" title="No ports detected">
            Paste nmap output or a comma-separated port list above.
          </Callout>
        ) : (
          <div className="overflow-hidden rounded border border-[var(--card-border)]">
            <table className="w-full text-[12.5px]">
              <thead>
                <tr className="border-b border-[var(--card-border)] text-left text-[11.5px] uppercase tracking-wide text-[var(--text-faint)]">
                  <th className="px-3 py-2 font-medium">Port</th>
                  <th className="px-3 py-2 font-medium">Service</th>
                  <th className="px-3 py-2 font-medium">Tier</th>
                  <th className="px-3 py-2 font-medium">Note</th>
                  <th className="px-3 py-2 font-medium">Next check</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((d, i) => (
                  <tr key={d.port} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                    <td className="rf-mono px-3 py-1.5 align-top text-[var(--text)]">{d.port}</td>
                    <td className="rf-mono px-3 py-1.5 align-top text-[var(--text)]">
                      {d.service}
                      {d.version && <div className="text-[11px] text-[var(--text-faint)]">{d.version}</div>}
                    </td>
                    <td className={`px-3 py-1.5 align-top uppercase ${TIER_CLASS[d.tier]}`}>{d.tier}</td>
                    <td className="px-3 py-1.5 align-top text-[var(--text-muted)]">{d.note}</td>
                    <td className="px-3 py-1.5 align-top text-[var(--text-muted)]">{d.next}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Priority order and follow-up commands">
        <SectionTitle>Priority order</SectionTitle>
        <OutputBlock
          value={detected.map((d, i) => `${String(i + 1).padStart(2, '0')}. ${d.port}/${d.service} — ${d.next}`).join('\n')}
          rows={Math.min(12, Math.max(4, detected.length + 1))}
          label="Attack order"
        />
        <SectionTitle>Re-scan with version detection</SectionTitle>
        <OutputBlock value={priorityCmd} rows={4} label="nmap" />
        <SectionTitle>Per-service follow-up</SectionTitle>
        <OutputBlock value={commands} rows={16} label="Commands" />
        <div className="mt-4">
          <Callout tone="info" title="Filter the noise">
            A table built from <span className="rf-mono">-sV</span> beats one from a bare port list: the banner is what
            tells you 8080 is Tomcat and not a photocopier. Re-scan the top tier with{' '}
            <span className="rf-mono">--script "default or vuln"</span> before spending time on exploits.
          </Callout>
        </div>
      </Card>
    </>
  );
}
