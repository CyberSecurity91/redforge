import { useMemo, useState } from 'react';
import { Button, Callout, Card, Checkbox, OutputBlock, SectionTitle, Select, TextInput } from '@/components/ui';

type FacetKey =
  | 'org'
  | 'net'
  | 'hostname'
  | 'port'
  | 'product'
  | 'version'
  | 'os'
  | 'country'
  | 'city'
  | 'httpTitle'
  | 'httpStatus'
  | 'ssl'
  | 'vuln'
  | 'before'
  | 'after';

interface FacetDef {
  label: string;
  shodan: string;
  fofa: string | null;
  censys: string | null;
  quote: boolean;
  hint: string;
}

const FACETS: Record<FacetKey, FacetDef> = {
  org: { label: 'Organisation', shodan: 'org', fofa: 'org', censys: 'autonomous_system.name', quote: true, hint: 'AS owner as registered — "Example Hosting Ltd"' },
  net: { label: 'Netblock', shodan: 'net', fofa: 'ip', censys: 'ip', quote: false, hint: 'CIDR, e.g. 203.0.113.0/24' },
  hostname: { label: 'Hostname', shodan: 'hostname', fofa: 'domain', censys: 'names', quote: false, hint: 'Reverse DNS or certificate name, e.g. example.com' },
  port: { label: 'Port', shodan: 'port', fofa: 'port', censys: 'services.port', quote: false, hint: '1–65535, e.g. 3389' },
  product: { label: 'Product', shodan: 'product', fofa: 'body', censys: 'services.software.product', quote: true, hint: 'Banner product string, e.g. Apache Tomcat' },
  version: { label: 'Version', shodan: 'version', fofa: 'body', censys: 'services.software.version', quote: true, hint: 'Exact version string, e.g. 9.0.31' },
  os: { label: 'Operating system', shodan: 'os', fofa: 'os', censys: 'operating_system', quote: true, hint: 'e.g. Windows Server 2019' },
  country: { label: 'Country', shodan: 'country', fofa: 'country', censys: 'location.country', quote: true, hint: 'ISO-3166 alpha-2, e.g. GB' },
  city: { label: 'City', shodan: 'city', fofa: 'city', censys: 'location.city', quote: true, hint: 'e.g. Manchester' },
  httpTitle: { label: 'HTTP title', shodan: 'http.title', fofa: 'title', censys: 'services.http.response.html_title', quote: true, hint: 'Page title substring, e.g. Dashboard' },
  httpStatus: { label: 'HTTP status', shodan: 'http.status', fofa: 'header', censys: 'services.http.response.status_code', quote: false, hint: 'e.g. 401' },
  ssl: { label: 'TLS certificate CN', shodan: 'ssl', fofa: 'cert', censys: 'services.tls.certificates.leaf_data.subject.common_name', quote: true, hint: 'Matches certificate subject or SAN' },
  vuln: { label: 'Vulnerability', shodan: 'vuln', fofa: null, censys: null, quote: false, hint: 'CVE or Shodan tag, e.g. CVE-2021-44228' },
  before: { label: 'Seen before', shodan: 'before', fofa: null, censys: null, quote: false, hint: 'DD/MM/YYYY' },
  after: { label: 'Seen after', shodan: 'after', fofa: null, censys: null, quote: false, hint: 'DD/MM/YYYY' },
};

const FACET_OPTIONS = (Object.keys(FACETS) as FacetKey[]).map((value) => ({ value, label: FACETS[value].label }));

interface Row {
  id: number;
  facet: FacetKey;
  value: string;
  negate: boolean;
}

const PRESETS: Array<{ label: string; note: string; rows: Array<[FacetKey, string]>; free: string }> = [
  { label: 'Exposed Jenkins', note: 'Unauthenticated dashboards and script consoles', rows: [['product', 'Jenkins'], ['httpTitle', 'Dashboard [Jenkins]']], free: '' },
  { label: 'Default Tomcat', note: 'Manager app still reachable on 8080', rows: [['product', 'Apache Tomcat'], ['port', '8080']], free: '' },
  { label: 'RDP to the internet', note: 'NLA state is not in the banner — verify per host', rows: [['port', '3389']], free: '' },
  { label: 'Kubernetes API', note: 'Anonymous auth or exposed kubelet nearby', rows: [['port', '6443'], ['product', 'kubernetes']], free: '' },
  { label: 'S3 bucket index', note: 'Directory listing pages that Shodan has crawled', rows: [['httpTitle', 'Index of /']], free: 'amazonaws' },
  { label: 'Jenkins + vuln tag', note: 'Join a product filter to a known CVE tag', rows: [['product', 'Jenkins'], ['vuln', 'CVE-2024-23897']], free: '' },
];

function shodanValue(def: FacetDef, value: string): string {
  const v = value.trim();
  if (def.quote || /\s/.test(v)) return `"${v}"`;
  return v;
}

let nextId = 1;

export default function ShodanQueryBuilder() {
  const [rows, setRows] = useState<Row[]>([
    { id: nextId++, facet: 'product', value: 'Jenkins', negate: false },
    { id: nextId++, facet: 'country', value: 'GB', negate: false },
  ]);
  const [free, setFree] = useState('');

  const update = (id: number, patch: Partial<Row>) => setRows((prev) => prev.map((r) => (r.id === id ? { ...r, ...patch } : r)));
  const addRow = () => setRows((prev) => [...prev, { id: nextId++, facet: 'port', value: '', negate: false }]);

  const built = useMemo(() => {
    const used = rows.filter((r) => r.value.trim());
    const warnings: string[] = [];
    for (const r of used) {
      if (r.facet === 'port') {
        const n = Number(r.value);
        if (!Number.isInteger(n) || n < 1 || n > 65535) warnings.push(`Port “${r.value}” is outside 1–65535 and will return nothing.`);
      }
      if ((r.facet === 'before' || r.facet === 'after') && !/^\d{2}\/\d{2}\/\d{4}$/.test(r.value.trim())) {
        warnings.push(`${FACETS[r.facet].label} expects DD/MM/YYYY; “${r.value}” will be rejected by Shodan.`);
      }
    }
    const shodan = [
      ...used.map((r) => `${r.negate ? '-' : ''}${FACETS[r.facet].shodan}:${shodanValue(FACETS[r.facet], r.value)}`),
      free.trim(),
    ].filter(Boolean);

    const censys = used
      .map((r) => {
        const field = FACETS[r.facet].censys;
        if (!field) {
          warnings.push(`${FACETS[r.facet].label} has no Censys equivalent and was dropped from that query.`);
          return '';
        }
        const v = /\s/.test(r.value.trim()) || FACETS[r.facet].quote ? `"${r.value.trim()}"` : r.value.trim();
        return `${r.negate ? 'not ' : ''}${field}: ${v}`;
      })
      .filter(Boolean);

    const fofa = used
      .map((r) => {
        const field = FACETS[r.facet].fofa;
        if (!field) {
          warnings.push(`${FACETS[r.facet].label} has no FOFA equivalent and was dropped from that query.`);
          return '';
        }
        const v = r.value.trim();
        return `${r.negate ? `${field}!` : `${field}=`}"${v}"`;
      })
      .filter(Boolean);

    const terms = used.map((r) => ({
      term: `${r.negate ? 'NOT ' : ''}${FACETS[r.facet].label} = ${r.value.trim()}`,
      meaning: FACETS[r.facet].hint,
    }));

    return {
      shodan: shodan.join(' '),
      censys: censys.join(' and '),
      fofa: fofa.length ? fofa.join(' && ') : '',
      terms,
      warnings: Array.from(new Set(warnings)),
      freeText: free.trim(),
    };
  }, [rows, free]);

  const apiUrl = `https://api.shodan.io/shodan/host/search?key=SHODAN_API_KEY&query=${encodeURIComponent(built.shodan)}`;

  return (
    <>
      <Card
        title="Facets"
        action={
          <div className="flex gap-1">
            <Button size="sm" variant="ghost" onClick={addRow}>
              Add facet
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setRows([])}>
              Clear
            </Button>
          </div>
        }
      >
        <div className="flex flex-col gap-3">
          {rows.length === 0 && <Callout tone="info">No facets yet — add one, or load a preset in the next card.</Callout>}
          {rows.map((r) => (
            <div key={r.id} className="grid items-end gap-2 sm:grid-cols-[190px_1fr_auto_auto]">
              <Select
                value={r.facet}
                onChange={(v) => update(r.id, { facet: v })}
                options={FACET_OPTIONS}
                label="Facet"
              />
              <TextInput
                label="Value"
                value={r.value}
                onChange={(v) => update(r.id, { value: v })}
                mono
                placeholder={FACETS[r.facet].hint}
              />
              <div className="pb-2">
                <Checkbox checked={r.negate} onChange={(v) => update(r.id, { negate: v })} label="NOT" />
              </div>
              <Button size="sm" variant="ghost" onClick={() => setRows((prev) => prev.filter((x) => x.id !== r.id))} title="Remove facet">
                Remove
              </Button>
            </div>
          ))}
        </div>
        <div className="mt-5">
          <TextInput
            label="Free text"
            value={free}
            onChange={setFree}
            mono
            placeholder='e.g. "default password" or -"index of"'
            hint="Appended verbatim — useful for banner phrases no facet covers"
          />
        </div>
      </Card>

      <Card title="Presets">
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {PRESETS.map((p) => (
            <button
              key={p.label}
              type="button"
              onClick={() => {
                setRows(p.rows.map(([facet, value]) => ({ id: nextId++, facet, value, negate: false })));
                setFree(p.free);
              }}
              className="rounded border border-[var(--card-border)] px-3 py-2 text-left transition-colors hover:border-[var(--accent)]"
            >
              <span className="block text-[13px] text-[var(--text)]">{p.label}</span>
              <span className="mt-0.5 block text-[11.5px] leading-snug text-[var(--text-faint)]">{p.note}</span>
            </button>
          ))}
        </div>
      </Card>

      <Card title="Composed queries">
        {!built.shodan ? (
          <Callout tone="warn" title="Empty query">Shodan rejects an empty search — set at least one facet value.</Callout>
        ) : (
          <>
            <div className="flex flex-col gap-4">
              <OutputBlock value={built.shodan} label="Shodan" rows={3} />
              <OutputBlock value={built.censys} label="Censys" rows={3} empty="No Censys-compatible facets selected." />
              <OutputBlock value={built.fofa} label="FOFA" rows={3} empty="No FOFA-compatible facets selected." />
            </div>
            {built.warnings.length > 0 && (
              <div className="mt-4 flex flex-col gap-2">
                {built.warnings.map((w) => (
                  <Callout key={w} tone="warn">{w}</Callout>
                ))}
              </div>
            )}
            <div className="mt-4">
              <SectionTitle>Term by term</SectionTitle>
              <div className="overflow-hidden rounded border border-[var(--card-border)]">
                <table className="w-full text-[12.5px]">
                  <tbody>
                    {built.terms.map((t, i) => (
                      <tr key={t.term} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                        <td className="rf-mono w-[40%] px-3 py-1.5 align-top break-all text-[var(--text)]">{t.term}</td>
                        <td className="px-3 py-1.5 align-top text-[var(--text-muted)]">{t.meaning}</td>
                      </tr>
                    ))}
                    {built.freeText && (
                      <tr className="bg-[var(--neutral-btn)]">
                        <td className="rf-mono px-3 py-1.5 align-top break-all text-[var(--text)]">{built.freeText}</td>
                        <td className="px-3 py-1.5 align-top text-[var(--text-muted)]">Free-text match against the banner text</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </Card>

      <Card title="Run it">
        <OutputBlock
          value={built.shodan ? `shodan search --fields ip_str,port,org,hostnames '${built.shodan}' | tee shodan-results.txt\nshodan stats --facets org,country '${built.shodan}'` : ''}
          label="shodan CLI"
          rows={3}
        />
        <div className="mt-4">
          <OutputBlock value={built.shodan ? apiUrl : ''} label="Search API (GET)" rows={3} />
        </div>
        <div className="mt-4">
          <Callout tone="info" title="Query grammar">
            Shodan ANDs every term; <span className="rf-mono">-</span> negates one. Quote anything with a space, and escape
            inner quotes. <span className="rf-mono">http.title</span> matches the parsed title, not the raw body, so pairs of
            words must appear in that order.
          </Callout>
        </div>
      </Card>
    </>
  );
}
