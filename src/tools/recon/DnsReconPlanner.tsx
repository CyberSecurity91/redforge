import { useMemo, useState } from 'react';
import { Callout, Card, Checkbox, DownloadButton, OutputBlock, TextArea, TextInput } from '@/components/ui';
import { expandCidr, parseHostname, registrableDomain, reverseDnsName } from '@/lib/domain';
import { DEFAULT_TARGET, DEFAULT_TARGET_IP } from '@/tools/registry';

type RecordType = 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'SOA' | 'SRV' | 'CAA';

const RECORD_TYPES: Array<[RecordType, string]> = [
  ['A', 'IPv4 address'],
  ['AAAA', 'IPv6 address'],
  ['MX', 'Mail exchangers'],
  ['TXT', 'TXT records (SPF, verification)'],
  ['NS', 'Authoritative nameservers'],
  ['SOA', 'Zone serial and admin'],
  ['SRV', 'Service locators'],
  ['CAA', 'Certificate authority constraints'],
];

const RECORD_NOTE: Record<RecordType, string> = {
  A: 'Every A record is a live host. Diff today against a 30-day-old scan for stale entries.',
  AAAA: 'IPv6 often bypasses perimeter rules written for IPv4 only — note any dual-stack target.',
  MX: 'Mail hosts usually belong to a third party; check for dangling MX pointing at a retired provider.',
  TXT: 'Look for SPF (`v=spf1`), DMARC (`v=DMARC1`), and SaaS verification strings that name vendors.',
  NS: 'Nameservers reveal the DNS provider — a self-hosted BIND is worth an AXFR try.',
  SOA: 'Serial and primary NS confirm the authoritative side; an old serial hints at a still-live secondary.',
  SRV: 'SIP, LDAP and Kerberos SRV records expose internal service topology.',
  CAA: 'CAA names the issued CAs; a missing CAA lets any CA issue for the domain.',
};

export default function DnsReconPlanner() {
  const [domainsRaw, setDomainsRaw] = useState(DEFAULT_TARGET);
  const [selected, setSelected] = useState<RecordType[]>(['A', 'AAAA', 'MX', 'TXT', 'NS']);
  const [mailProbes, setMailProbes] = useState(true);
  const [axfr, setAxfr] = useState(true);
  const [reverse, setReverse] = useState(true);
  const [cidr, setCidr] = useState(`${DEFAULT_TARGET_IP.replace(/\.\d+$/, '.0')}/24`);
  const [vhost, setVhost] = useState(false);
  const [resolver, setResolver] = useState('');

  const domains = useMemo(
    () =>
      Array.from(
        new Set(
          domainsRaw
            .split(/[\s,]+/)
            .map((d) => parseHostname(d).host)
            .filter(Boolean)
            .map((h) => registrableDomain(h)),
        ),
      ),
    [domainsRaw],
  );

  const cidrInfo = useMemo(() => {
    if (!reverse || !cidr.trim()) return null;
    try {
      return expandCidr(cidr.trim(), 64);
    } catch {
      return null;
    }
  }, [reverse, cidr]);

  const script = useMemo(() => {
    if (!domains.length) return '';
    const at = resolver.trim() ? `@${parseHostname(resolver).host || resolver.trim()}` : '';
    const lines: string[] = ['#!/usr/bin/env bash', '# DNS recon plan — run each block top to bottom', 'set -uo pipefail', ''];

    lines.push('# ── Record sweep ─────────────────────────────────────────────');
    for (const domain of domains) {
      lines.push(`# ${domain}`);
      for (const type of selected) lines.push(`dig ${at} +short ${type} ${domain}`.replace(/\s+/g, ' '));
      lines.push('dig +short A ' + domain + ' | while read ip; do echo "$ip  ' + domain + '"; done');
      lines.push('');
    }
    lines.push('# What to look for:');
    for (const type of selected) lines.push(`#   ${type} — ${RECORD_NOTE[type]}`);
    lines.push('');

    if (mailProbes) {
      lines.push('# ── Mail policy probes ───────────────────────────────────────');
      for (const domain of domains) {
        lines.push(`dig ${at} +short TXT ${domain}`.replace(/\s+/g, ' '));
        lines.push(`dig ${at} +short TXT _dmarc.${domain}`.replace(/\s+/g, ' '));
        lines.push(`dig ${at} +short TXT default._domainkey.${domain}`.replace(/\s+/g, ' '));
        lines.push(`dig ${at} +short TXT google._domainkey.${domain}`.replace(/\s+/g, ' '));
        lines.push(`dig ${at} +short MX ${domain}`.replace(/\s+/g, ' '));
      }
      lines.push('# What to look for:');
      lines.push('#   SPF with ~all or ?all — soft or no enforcement');
      lines.push('#   p=none in DMARC — monitoring only, spoofing still lands');
      lines.push('#   Missing DKIM selector — confirm which selectors are published');
      lines.push('#   A single MX with no backup — mail flow outage is a soft target');
      lines.push('');
    }

    if (axfr) {
      lines.push('# ── Zone transfer attempt ────────────────────────────────────');
      for (const domain of domains) {
        lines.push(`for ns in $(dig ${at} +short NS ${domain}); do echo "== $ns"; dig axfr @$ns ${domain} | head -40; done`);
      }
      lines.push('# What to look for:');
      lines.push('#   "Transfer failed" is normal. A full dump means the zone is world-readable —');
      lines.push('#   harvest every internal hostname and feed it back into the subdomain list.');
      lines.push('');
    }

    if (reverse && cidrInfo) {
      lines.push(`# ── Reverse lookup sweep (${cidrInfo.cidr}, ${cidrInfo.usable} addresses) ────────`);
      lines.push(`for ip in $(seq 1 ${Math.min(cidrInfo.usable, 2000)}); do`);
      lines.push(`  host ${cidrInfo.network.split('.').slice(0, 3).join('.')}.$ip | grep -v "name pointer"`);
      lines.push('done');
      lines.push(`# Spot-check with PTR form: host ${reverseDnsName(cidrInfo.first)}`);
      lines.push('# What to look for:');
      lines.push('#   PTR names usually spell out the org naming convention — reuse the labels');
      lines.push('#   as subdomain candidates. Missing PTR means the block is unmanaged.');
      lines.push('');
    }

    if (vhost) {
      lines.push('# ── Vhost discovery ──────────────────────────────────────────');
      lines.push(`for h in www mail vpn dev api staging admin; do`);
      lines.push(`  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $h.${domains[0]}" http://${DEFAULT_TARGET_IP}/)`);
      lines.push(`  echo "$code  $h.${domains[0]}"; done`);
      lines.push('# What to look for:');
      lines.push('#   Differing status codes or body sizes prove per-Host routing without');
      lines.push('#   any DNS record — the classic internal-app hinge point.');
      lines.push('');
    }
    return lines.join('\n');
  }, [domains, selected, mailProbes, axfr, reverse, cidrInfo, vhost, resolver]);

  const toggle = (type: RecordType, on: boolean) =>
    setSelected((prev) => (on ? [...prev, type] : prev.filter((t) => t !== type)));

  return (
    <>
      <Card title="Targets and options">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextArea
            label="Domains"
            hint="One per line or comma separated — reduced to the registrable domain"
            value={domainsRaw}
            onChange={setDomainsRaw}
            rows={3}
          />
          <div className="space-y-4">
            <TextInput
              label="Resolver (optional)"
              hint="Queries go to @resolver; blank uses the system resolver"
              value={resolver}
              onChange={setResolver}
              mono
              placeholder="1.1.1.1"
            />
            <TextInput
              label="Reverse sweep CIDR"
              hint="IPv4, /8 or narrower"
              value={cidr}
              onChange={setCidr}
              mono
            />
          </div>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {RECORD_TYPES.map(([type, desc]) => (
            <Checkbox
              key={type}
              checked={selected.includes(type)}
              onChange={(v) => toggle(type, v)}
              label={type}
              description={desc}
            />
          ))}
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <Checkbox checked={mailProbes} onChange={setMailProbes} label="SPF / DMARC / DKIM probes" />
          <Checkbox checked={axfr} onChange={setAxfr} label="Zone transfer attempt" description="dig axfr per NS" />
          <Checkbox checked={reverse} onChange={setReverse} label="Reverse lookup sweep" description="PTR over the CIDR" />
          <Checkbox checked={vhost} onChange={setVhost} label="Vhost fuzz" description="Host-header routing check" />
        </div>

        {reverse && cidr.trim() && !cidrInfo && (
          <div className="mt-4">
            <Callout tone="warn" title="CIDR not usable">
              Use an IPv4 block between /8 and /32, e.g. <span className="rf-mono">203.0.113.0/24</span>.
            </Callout>
          </div>
        )}
      </Card>

      <Card
        title="Command script"
        action={<DownloadButton text={script} filename="dns-recon-plan.sh" label="Download .sh" />}
      >
        {domains.length === 0 ? (
          <Callout tone="warn" title="No domain">
            Enter at least one domain to generate the plan.
          </Callout>
        ) : (
          <OutputBlock value={script} rows={22} label="dns-recon-plan.sh" />
        )}
      </Card>

      <Card title="Reading the results">
        <div className="grid gap-3 sm:grid-cols-2">
          {selected.map((type) => (
            <div key={type} className="rounded border border-[var(--card-border)] px-3 py-2">
              <div className="rf-mono mb-1 text-[12px] text-[var(--accent)]">{type}</div>
              <p className="m-0 text-[12px] leading-relaxed text-[var(--text-muted)]">{RECORD_NOTE[type]}</p>
            </div>
          ))}
          {selected.length === 0 && (
            <p className="m-0 text-[12.5px] text-[var(--text-faint)]">Select record types above to see per-type notes.</p>
          )}
        </div>
        <div className="mt-4">
          <Callout tone="info" title="Sequencing">
            Run the record sweep first, keep the NS answers, and only then try AXFR — a zone dump collapses the rest of
            the recon into one command.
          </Callout>
        </div>
      </Card>
    </>
  );
}
