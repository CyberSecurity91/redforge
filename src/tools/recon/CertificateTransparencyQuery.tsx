import { useMemo, useState } from 'react';
import { Callout, Card, Checkbox, DownloadButton, KVTable, OutputBlock, SectionTitle, TextArea, TextInput } from '@/components/ui';
import { parseHostname, registrableDomain } from '@/lib/domain';
import { DEFAULT_TARGET } from '@/tools/registry';

const HOST_RE = /^(\*\.)?([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;

const SAMPLE = `[
  {"name_value": "www.example.com", "issuer_name": "C=US, O=Let's Encrypt"},
  {"name_value": "mail.example.com\\nvpn.example.com"},
  {"name_value": "*.dev.example.com"},
  {"name_value": "api.example.com\\n*.api.example.com"},
  {"name_value": "portal.example.co.uk"},
  {"name_value": "*.portal.example.co.uk"}
]`;

/** Accepts crt.sh JSON, the HTML/table text dump, or a bare host list. */
function extractNames(raw: string): string[] {
  const trimmed = raw.trim();
  if (!trimmed) return [];
  let text = trimmed;
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    try {
      const data: unknown = JSON.parse(trimmed);
      const items = Array.isArray(data) ? data : [data];
      const names: string[] = [];
      for (const item of items) {
        if (typeof item === 'string') names.push(item);
        else if (item && typeof item === 'object') {
          const rec = item as Record<string, unknown>;
          for (const key of ['name_value', 'common_name', 'nameValue', 'commonName', 'dns_names']) {
            const v = rec[key];
            if (typeof v === 'string') names.push(v);
            else if (Array.isArray(v)) for (const x of v) if (typeof x === 'string') names.push(x);
          }
        }
      }
      if (names.length) text = names.join('\n');
    } catch {
      /* not JSON after all — scan it as text below */
    }
  }
  const out: string[] = [];
  for (const token of text.split(/[\s,;"'<>]+/)) {
    const clean = token.trim().toLowerCase().replace(/\.$/, '').replace(/^\*\./, '*.').replace(/\\n$/, '');
    if (!clean || clean.length > 253) continue;
    const bare = clean.startsWith('*.') ? clean.slice(2) : clean;
    if (HOST_RE.test(bare)) out.push(clean);
  }
  return out;
}

export default function CertificateTransparencyQuery() {
  const [rawDomain, setRawDomain] = useState(DEFAULT_TARGET);
  const [apex, setApex] = useState(true);
  const [excludeExpired, setExcludeExpired] = useState(true);
  const [excludeWildcards, setExcludeWildcards] = useState(false);
  const [dedupe, setDedupe] = useState(true);
  const [pasted, setPasted] = useState('');

  const domain = useMemo(() => {
    const host = parseHostname(rawDomain).host;
    return host ? registrableDomain(host) : '';
  }, [rawDomain]);

  const query = useMemo(() => {
    if (!domain) return null;
    const like = apex ? `(ci.NAME_VALUE ILIKE '%.${domain}' OR ci.NAME_VALUE ILIKE '${domain}')` : `ci.NAME_VALUE ILIKE '%.${domain}'`;
    const sql = [
      'SELECT ci.NAME_VALUE AS hostname',
      'FROM certificate_identity ci',
      'JOIN certificate c ON c.ID = ci.CERTIFICATE_ID',
      `WHERE ${like}`,
      excludeExpired ? '  AND c.NOT_AFTER > now()' : '',
      excludeWildcards ? "  AND ci.NAME_VALUE NOT LIKE '*.%'" : '',
      dedupe ? 'GROUP BY ci.NAME_VALUE' : '',
      'ORDER BY hostname;',
    ]
      .filter((line) => line !== '')
      .join('\n');
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json${excludeExpired ? '&exclude=expired' : ''}`;
    const curl = `curl -s '${url}' \\\n  | jq -r '.[].name_value' \\\n  | tr -d '\\r' | sort -u > ct-hosts.txt`;
    return { sql, url, curl };
  }, [domain, apex, excludeExpired, excludeWildcards, dedupe]);

  const names = useMemo(() => extractNames(pasted), [pasted]);

  const summary = useMemo(() => {
    const uniq = Array.from(new Set(names)).sort();
    const wildcards = uniq.filter((n) => n.startsWith('*.'));
    const concrete = uniq.filter((n) => !n.startsWith('*.'));
    const perDomain = new Map<string, number>();
    for (const host of concrete) {
      const root = registrableDomain(host) || host;
      perDomain.set(root, (perDomain.get(root) ?? 0) + 1);
    }
    const inScope = domain ? concrete.filter((h) => h === domain || h.endsWith(`.${domain}`)) : concrete;
    return {
      uniq,
      wildcards,
      concrete,
      inScope,
      perDomain: Array.from(perDomain.entries()).sort((a, b) => b[1] - a[1]),
      outOfScope: domain ? concrete.filter((h) => !(h === domain || h.endsWith(`.${domain}`))) : [],
    };
  }, [names, domain]);

  const hostList = summary.uniq.join('\n');

  return (
    <>
      <Card title="Query scope">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput
            label="Domain"
            value={rawDomain}
            onChange={setRawDomain}
            mono
            placeholder={DEFAULT_TARGET}
            hint="Reduced to the registrable domain so ccTLD suffixes survive"
          />
          <div className="grid gap-3 sm:grid-cols-2">
            <Checkbox checked={apex} onChange={setApex} label="Include apex" description={`Also match ${domain || 'the domain'} itself`} />
            <Checkbox checked={excludeExpired} onChange={setExcludeExpired} label="Exclude expired" description="c.NOT_AFTER > now()" />
            <Checkbox checked={excludeWildcards} onChange={setExcludeWildcards} label="Drop wildcards" description="Removes *.name rows" />
            <Checkbox checked={dedupe} onChange={setDedupe} label="One row per name" description="Drops precert duplicates" />
          </div>
        </div>
      </Card>

      <Card title="crt.sh query">
        {!query ? (
          <Callout tone="info" title="No domain">Enter a hostname to build the query.</Callout>
        ) : (
          <>
            <OutputBlock value={query.sql} label="SQL (PostgreSQL, run at crt.sh/?q=…)" rows={9} />
            <div className="mt-4 flex flex-col gap-4">
              <OutputBlock value={query.url} label="JSON API URL" rows={2} />
              <OutputBlock value={query.curl} label="curl + jq one-liner" rows={4} />
            </div>
            <div className="mt-4">
              <Callout tone="info" title="Why ILIKE '%.domain'">
                Certificate identities are stored per name; a leading wildcard matches every subdomain in one pass. The join to
                <span className="rf-mono"> certificate</span> is where expiry lives, so an expiry filter without the join silently
                matches nothing.
              </Callout>
            </div>
          </>
        )}
      </Card>

      <Card
        title="Paste results"
        action={
          <button
            type="button"
            onClick={() => setPasted(SAMPLE)}
            className="rounded px-2 py-0.5 text-[11.5px] text-[var(--text-faint)] hover:text-[var(--accent)]"
          >
            Load sample
          </button>
        }
      >
        <TextArea
          label="crt.sh JSON, table text or host list"
          value={pasted}
          onChange={setPasted}
          rows={7}
          placeholder={SAMPLE}
          hint="JSON is flattened per name_value; escaped \n separators and wildcards are split automatically."
        />
      </Card>

      {summary.uniq.length > 0 && (
        <>
          <Card title="Reduced host set">
            <KVTable
              rows={[
                ['Unique names', String(summary.uniq.length)],
                ['Concrete hosts', String(summary.concrete.length)],
                ['Wildcards', summary.wildcards.length ? summary.wildcards.join(', ') : 'none'],
                ['In scope', String(summary.inScope.length)],
                ['Out of scope', summary.outOfScope.length ? summary.outOfScope.slice(0, 6).join(', ') : 'none'],
              ]}
            />
            <div className="mt-4">
              <SectionTitle>Names per registrable domain</SectionTitle>
              <div className="flex flex-col gap-1.5">
                {summary.perDomain.slice(0, 8).map(([root, count]) => (
                  <div key={root} className="flex items-center gap-2 text-[12px]">
                    <span className="rf-mono w-[220px] shrink-0 truncate text-[var(--text)]">{root}</span>
                    <span className="h-1.5 flex-1 overflow-hidden rounded bg-[var(--neutral-btn)]">
                      <span
                        className="block h-full rounded bg-[var(--accent)]"
                        style={{ width: `${Math.round((count / summary.perDomain[0][1]) * 100)}%` }}
                      />
                    </span>
                    <span className="rf-mono w-8 text-right text-[var(--text-muted)]">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          </Card>

          <Card
            title="Host list"
            action={<DownloadButton text={hostList} filename={`${domain || 'ct'}-hosts.txt`} label="Download" />}
          >
            <OutputBlock value={hostList} label={`${summary.uniq.length} hosts`} rows={9} />
            <div className="mt-4">
              <OutputBlock
                value={`httpx -l ct-hosts.txt -silent -sc -title -td -o httpx-ct.txt\nffuf -u https://FUZZ -w ct-hosts.txt -mc 200,301,302,403 -rate 40 -t 20 -o ffuf-ct.json -of json`}
                label="Probe"
                rows={2}
              />
            </div>
            <div className="mt-4">
              <Callout tone="warn" title="Wildcards hide shared infrastructure">
                A wildcard answer turns every hostname into a 200. Probe twice with a random label first; if it resolves and
                serves the same body, filter on size (<span className="rf-mono">-fs</span>) before trusting hits.
              </Callout>
            </div>
          </Card>
        </>
      )}
    </>
  );
}
