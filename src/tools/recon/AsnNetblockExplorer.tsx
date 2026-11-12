import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  CopyChip,
  DownloadButton,
  NumberInput,
  OutputBlock,
  SectionTitle,
  Select,
  TextArea,
} from '@/components/ui';
import { expandCidr, isIpv4Range, isPrivateIp, splitCidr } from '@/lib/domain';

interface PrefixRow {
  asn: string;
  cidr: string;
  org: string;
  count: number;
  prefix: number;
  private: boolean;
}

const BUILT_IN = [
  ['AS15169', '142.250.0.0/15', 'Google'],
  ['AS16509', '52.0.0.0/11', 'Amazon'],
  ['AS13335', '104.16.0.0/13', 'Cloudflare'],
  ['AS8075', '13.64.0.0/11', 'Microsoft'],
  ['AS32934', '157.240.0.0/16', 'Meta'],
  ['AS13414', '199.16.156.0/22', 'Twitter / X'],
  ['AS54113', '151.101.0.0/16', 'Fastly'],
  ['AS20940', '23.32.0.0/11', 'Akamai'],
  ['AS396982', '34.64.0.0/10', 'Google Cloud'],
  ['AS14061', '165.227.0.0/16', 'DigitalOcean'],
  ['AS20473', '45.32.0.0/16', 'Vultr'],
  ['AS7922', '73.0.0.0/8', 'Comcast'],
] as const;

const SLASH24_CAP = 40;

function parseRows(raw: string): { rows: PrefixRow[]; errors: string[] } {
  const rows: PrefixRow[] = [];
  const errors: string[] = [];
  for (const [i, line] of raw.split('\n').entries()) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const parts = trimmed.split(/\s+/);
    const asn = (parts[0] ?? '').toUpperCase();
    const cidr = parts[1] ?? '';
    const org = parts.slice(2).join(' ') || '—';
    if (!/^AS\d+$/.test(asn)) {
      errors.push(`line ${i + 1}: "${asn}" is not an ASN`);
      continue;
    }
    if (!isIpv4Range(cidr) || !cidr.includes('/')) {
      errors.push(`line ${i + 1}: "${cidr}" is not an IPv4 CIDR`);
      continue;
    }
    try {
      const info = expandCidr(cidr, 1);
      rows.push({
        asn,
        cidr: info.cidr,
        org,
        count: info.count,
        prefix: info.prefix,
        private: isPrivateIp(info.first),
      });
    } catch (e) {
      errors.push(`line ${i + 1}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return { rows, errors };
}

const fmt = (n: number) => n.toLocaleString('en-GB');

export default function AsnNetblockExplorer() {
  const [source, setSource] = useState(BUILT_IN.map((r) => r.join(' ')).join('\n'));
  const [selected, setSelected] = useState('AS15169 142.250.0.0/15');
  const [cap, setCap] = useState(SLASH24_CAP);
  const [port, setPort] = useState(443);
  const [sortBy, setSortBy] = useState<'size' | 'asn'>('size');

  const parsed = useMemo(() => parseRows(source), [source]);

  const sorted = useMemo(() => {
    const copy = [...parsed.rows];
    copy.sort((a, b) =>
      sortBy === 'size' ? b.count - a.count || a.asn.localeCompare(b.asn) : a.asn.localeCompare(b.asn) || b.count - a.count,
    );
    return copy;
  }, [parsed.rows, sortBy]);

  const active = useMemo(
    () => sorted.find((r) => `${r.asn} ${r.cidr}` === selected) ?? sorted[0] ?? null,
    [sorted, selected],
  );

  const chunks = useMemo(() => {
    if (!active) return { list: [] as string[], total: 0, truncated: false };
    const all = splitCidr(active.cidr, 24);
    return { list: all.slice(0, Math.max(1, cap)), total: all.length, truncated: all.length > cap };
  }, [active, cap]);

  const targets = useMemo(() => {
    if (!chunks.list.length) return '';
    return [
      `# ${active?.asn} ${active?.cidr} ${active?.org}`,
      '# nmap -sV -p ' + port + ' -iL targets.txt',
      ...chunks.list,
    ].join('\n');
  }, [chunks.list, active, port]);

  const whois = useMemo(() => {
    const asn = active?.asn ?? 'AS15169';
    return [
      `whois -h whois.radb.net -- '-i origin ${asn}' | grep -E '^route:'`,
      `# ARIN fallback for legacy allocations:`,
      `whois -h whois.arin.net "n + ${asn}"`,
      `# quick prefix→ASN direction for a single address:`,
      `whois -h whois.cymru.com " -v 203.0.113.10"`,
    ].join('\n');
  }, [active]);

  const hostTotal = useMemo(() => sorted.reduce((n, r) => n + r.count, 0), [sorted]);
  const reserved = useMemo(() => sorted.filter((r) => r.private), [sorted]);

  return (
    <>
      <Card title="ASN / prefix data" action={<CopyChip text={source} label="copy input" />}>
        <TextArea
          label="One prefix per line — ASN CIDR org"
          value={source}
          onChange={setSource}
          rows={9}
          placeholder={'AS15169 142.250.0.0/15 Google\nAS13335 104.16.0.0/13 Cloudflare'}
          hint="Blank lines and # comments are ignored; malformed rows are reported instead of dropped silently"
        />
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <span className="rf-mono rounded bg-[var(--neutral-btn)] px-2 py-0.5 text-[12px] text-[var(--text-faint)]">
            {sorted.length} prefixes · {fmt(hostTotal)} addresses
          </span>
          <Select
            value={sortBy}
            onChange={setSortBy}
            options={[
              { value: 'size', label: 'Sort by prefix size (largest first)' },
              { value: 'asn', label: 'Sort by ASN' },
            ]}
            className="w-[260px]"
          />
        </div>
        {parsed.errors.length > 0 && (
          <div className="mt-3">
            <Callout tone="warn" title={`${parsed.errors.length} line(s) skipped`}>
              <ul className="m-0 list-disc pl-5">
                {parsed.errors.slice(0, 4).map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            </Callout>
          </div>
        )}
      </Card>

      {sorted.length === 0 ? (
        <Card title="Prefixes">
          <Callout tone="info" title="No prefixes parsed">
            Paste lines shaped like <span className="rf-mono">AS15169 142.250.0.0/15 Google</span>, or load the built-in
            table by clearing the box and pasting it back.
          </Callout>
        </Card>
      ) : (
        <Card title="Prefix inventory">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[12.5px]">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wide text-[var(--text-faint)]">
                  <th className="border-b border-[var(--card-border)] px-2 py-1.5">ASN</th>
                  <th className="border-b border-[var(--card-border)] px-2 py-1.5">Prefix</th>
                  <th className="border-b border-[var(--card-border)] px-2 py-1.5">Org</th>
                  <th className="border-b border-[var(--card-border)] px-2 py-1.5 text-right">Addresses</th>
                  <th className="border-b border-[var(--card-border)] px-2 py-1.5 text-right">/24s</th>
                  <th className="border-b border-[var(--card-border)] px-2 py-1.5" />
                </tr>
              </thead>
              <tbody>
                {sorted.map((r) => {
                  const key = `${r.asn} ${r.cidr}`;
                  const isActive = active ? key === `${active.asn} ${active.cidr}` : false;
                  const n24 = splitCidr(r.cidr, 24).length;
                  return (
                    <tr key={key} className={isActive ? 'bg-[var(--neutral-btn)]' : ''}>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 rf-mono text-[var(--text)]">{r.asn}</td>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 rf-mono">{r.cidr}</td>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-[var(--text-muted)]">{r.org}</td>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-right rf-mono">{fmt(r.count)}</td>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-right rf-mono">{fmt(n24)}</td>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-right">
                        {r.private ? (
                          <span className="rf-mono rounded bg-[var(--neutral-btn)] px-1.5 py-0.5 text-[11px] text-[var(--warn)]">private</span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => setSelected(key)}
                            className={`text-[11.5px] ${isActive ? 'text-[var(--accent)]' : 'text-[var(--text-faint)] hover:text-[var(--accent)]'}`}
                            title={`Expand ${r.cidr}`}
                          >
                            {isActive ? 'expanded' : 'expand'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {reserved.length > 0 && (
            <div className="mt-3">
              <Callout tone="warn" title="Reserved ranges in the set">
                {reserved.map((r) => `${r.cidr}`).join(', ')} — RFC 1918 / loopback / documentation space. Exclude them
                before writing a target list.
              </Callout>
            </div>
          )}
        </Card>
      )}

      {active && (
        <Card
          title={`Expand ${active.cidr}`}
          action={
            <DownloadButton text={targets} filename={`${active.asn}-targets.txt`} label="Download -iL list" />
          }
        >
          <div className="grid gap-4 sm:grid-cols-3">
            <NumberInput label="/24 cap" value={cap} onChange={setCap} min={1} max={SLASH24_CAP} hint={`Hard ceiling ${SLASH24_CAP}`} />
            <NumberInput label="Scan port" value={port} onChange={setPort} min={1} max={65535} hint="Written into the nmap comment" />
            <div className="flex items-end pb-1">
              <span className="rf-mono rounded bg-[var(--neutral-btn)] px-2 py-1 text-[12px] text-[var(--text-faint)]">
                {chunks.truncated ? `showing ${chunks.list.length} of ${chunks.total}` : `${chunks.total} × /24`}
              </span>
            </div>
          </div>
          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <OutputBlock value={targets} rows={12} label="nmap -iL target list" empty="No /24 chunks — the prefix is narrower than /24." />
            <div className="space-y-4">
              <OutputBlock value={whois} rows={6} label="whois / IRR lookup" />
              {chunks.truncated && (
                <Callout tone="info" title="Expansion capped">
                  {chunks.total} chunks is too many to render. Scan the parent prefix directly with{' '}
                  <span className="rf-mono">nmap -p {port} {active.cidr}</span> and let the scanner iterate.
                </Callout>
              )}
            </div>
          </div>
          <div className="mt-4">
            <SectionTitle right={<span className="text-[11.5px] text-[var(--text-faint)]">range {firstLast(active.cidr)}</span>}>
              Host counts
            </SectionTitle>
            <OutputBlock
              value={[
                `${active.asn}  ${active.cidr}  addresses=${fmt(active.count)}  usable≈${fmt(Math.max(active.count - 2, 0))}`,
                `/24 chunks=${fmt(chunks.total)}  shown=${chunks.list.length}`,
                `addressable after /24 split=${fmt(chunks.list.reduce((n, c) => n + (expandCidr(c, 1).count || 0), 0))}`,
              ].join('\n')}
              rows={4}
              label="Summary"
            />
          </div>
        </Card>
      )}
    </>
  );
}

function firstLast(cidr: string): string {
  try {
    const info = expandCidr(cidr, 1);
    return `${info.network} – ${info.broadcast}`;
  } catch {
    return 'unknown';
  }
}
