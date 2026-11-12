import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  DownloadButton,
  KVTable,
  NumberInput,
  OutputBlock,
  SectionTitle,
  TextInput,
} from '@/components/ui';
import { expandCidr, intToIp, ipToInt, isPrivateIp, splitCidr } from '@/lib/domain';

const HOST_CAP = 4096;

export default function CidrCalculator() {
  const [input, setInput] = useState('203.0.113.0/24');
  const [cap, setCap] = useState(HOST_CAP);
  const [withHostnames, setWithHostnames] = useState(true);

  const result = useMemo(() => {
    const value = input.trim();
    if (!value) return { info: null, error: null as string | null };
    try {
      const looksCidr = value.includes('/');
      const info = expandCidr(looksCidr ? value : `${value}/32`, Math.min(Math.max(cap, 1), 65536));
      return { info, error: null as string | null };
    } catch (e) {
      return { info: null, error: e instanceof Error ? e.message : String(e) };
    }
  }, [input, cap]);

  const info = result.info;

  const splits = useMemo(() => {
    if (!info) return { slash24: [] as string[], slash16: [] as string[] };
    const trySplit = (p: number) => {
      try {
        return splitCidr(info.cidr, p);
      } catch {
        return [];
      }
    };
    return { slash24: trySplit(24), slash16: trySplit(16) };
  }, [info]);

  const hostList = useMemo(() => {
    if (!info) return '';
    const names = withHostnames ? info.hosts.map((h) => `${h}${isPrivateIp(h) ? '\t# private' : ''}`) : info.hosts;
    const body = names.join('\n');
    return info.truncated ? `${body}\n# … ${info.usable - info.hosts.length} more addresses not shown (cap ${cap})` : body;
  }, [info, withHostnames, cap]);

  const nmapExpr = useMemo(() => {
    if (!info) return '';
    return `${info.network}/${info.prefix}\n# explicit upper bound (some scanners mis-parse the network form):\nnmap -sn ${info.first}-${info.last}`;
  }, [info]);

  const json = useMemo(() => {
    if (!info) return '';
    return JSON.stringify(
      {
        cidr: info.cidr,
        network: info.network,
        broadcast: info.broadcast,
        firstUsable: info.first,
        lastUsable: info.last,
        netmask: info.mask,
        wildcard: info.wildcard,
        prefixLength: info.prefix,
        addressCount: info.count,
        usableHosts: info.usable,
        private: isPrivateIp(info.first),
        firstHosts: info.hosts.slice(0, 16),
      },
      null,
      2,
    );
  }, [info]);

  const isPrivate = info ? isPrivateIp(info.first) : false;

  return (
    <>
      <Card title="Block">
        <div className="grid gap-4 sm:grid-cols-3">
          <TextInput
            label="IPv4 CIDR or address"
            hint="/8 to /32; a bare address is treated as /32"
            value={input}
            onChange={setInput}
            mono
            placeholder="203.0.113.0/24"
          />
          <NumberInput
            label="Host list cap"
            hint="Truncates the expansion only"
            value={cap}
            onChange={setCap}
            min={16}
            max={65536}
            step={256}
          />
          <div className="flex items-end pb-2">
            <button
              type="button"
              onClick={() => setWithHostnames((v) => !v)}
              className={`rounded border px-3 py-1.5 text-[12.5px] transition-colors ${
                withHostnames
                  ? 'border-[var(--accent)] text-[var(--accent)]'
                  : 'border-[var(--card-border)] text-[var(--text-muted)]'
              }`}
            >
              Private-range annotations {withHostnames ? 'on' : 'off'}
            </button>
          </div>
        </div>
        {result.error && (
          <div className="mt-4">
            <Callout tone="warn" title="Cannot expand">
              {result.error}
            </Callout>
          </div>
        )}
      </Card>

      {info && (
        <>
          <Card title="Summary">
            <div className="grid gap-4 lg:grid-cols-[1.15fr_1fr]">
              <KVTable
                rows={[
                  ['CIDR', info.cidr],
                  ['Network', info.network],
                  ['Broadcast', info.broadcast],
                  ['First usable', info.first],
                  ['Last usable', info.last],
                  ['Netmask', info.mask],
                  ['Wildcard', info.wildcard],
                  ['Prefix', `/${info.prefix}`],
                  ['Address count', info.count.toLocaleString('en-GB')],
                  ['Usable hosts', info.usable.toLocaleString('en-GB')],
                  [
                    'Classification',
                    <span key="cls" style={{ color: isPrivate ? 'var(--info)' : 'var(--warn)' }}>
                      {isPrivate ? 'private / reserved' : 'public'}
                    </span>,
                  ],
                ]}
              />
              <div className="space-y-3">
                <OutputBlock value={nmapExpr} rows={4} label="nmap target expression" />
                <div className="flex flex-wrap items-center gap-2">
                  {splits.slash24.length > 0 && (
                    <DownloadButton
                      text={splits.slash24.join('\n')}
                      filename={`${info.network}-24s.txt`}
                      label={`Download ${splits.slash24.length} × /24`}
                    />
                  )}
                  <DownloadButton text={hostList} filename={`${info.network}-hosts.txt`} label="Download host list" />
                </div>
              </div>
            </div>
          </Card>

          <Card title="Host list">
            <OutputBlock
              value={hostList}
              rows={12}
              label={`${info.hosts.length} of ${info.usable} hosts`}
              empty="No usable hosts in this block."
            />
            {info.truncated && (
              <div className="mt-3">
                <Callout tone="info" title="Truncated">
                  Showing the first {info.hosts.length} addresses. Raise the cap to 65536, or scan the block directly
                  with <span className="rf-mono">-iL</span> once you need the full sweep.
                </Callout>
              </div>
            )}
          </Card>

          <Card title="Sub-division">
            <SectionTitle right={<span className="text-[11.5px] text-[var(--text-faint)]">{splits.slash24.length} blocks</span>}>
              Split into /24s
            </SectionTitle>
            <OutputBlock value={splits.slash24.join('\n')} rows={6} label="/24 blocks" empty={`/${info.prefix} is already narrower than /24.`} />
            <div className="mt-4">
              <SectionTitle right={<span className="text-[11.5px] text-[var(--text-faint)]">{splits.slash16.length} blocks</span>}>
                Split into /16s
              </SectionTitle>
              <OutputBlock value={splits.slash16.join('\n')} rows={4} label="/16 blocks" empty={`/${info.prefix} is already narrower than /16.`} />
            </div>
          </Card>

          <Card
            title="JSON export"
            action={<DownloadButton text={json} filename={`${info.network}-${info.prefix}.json`} label="Download .json" />}
          >
            <OutputBlock value={json} rows={12} label="Block descriptor" />
            <div className="mt-3 text-[11.5px] text-[var(--text-faint)]">
              Sanity check: first usable {intToIp(ipToInt(info.first))} sits {ipToInt(info.broadcast) - ipToInt(info.first) + 1}{' '}
              addresses below the broadcast.
            </div>
          </Card>
        </>
      )}
    </>
  );
}
