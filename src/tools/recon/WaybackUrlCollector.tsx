import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CopyChip,
  DownloadButton,
  NumberInput,
  OutputBlock,
  SectionTitle,
  Select,
  Tabs,
  TextInput,
} from '@/components/ui';
import { DEFAULT_TARGET } from '@/tools/registry';

type MatchType = 'domain' | 'prefix' | 'exact';
type Point = 'timeline' | 'captures';

const MATCH_TYPES: Array<{ value: MatchType; label: string }> = [
  { value: 'domain', label: 'domain — every host and path under it' },
  { value: 'prefix', label: 'prefix — one path prefix only' },
  { value: 'exact', label: 'exact — one URL' },
];

const MIMES = ['', 'text/html', 'application/json', 'application/javascript', 'text/plain', 'application/xml', 'application/pdf'];

const LOOK_FOR: Array<[string, string, string]> = [
  ['?=& param URLs', 'grep -E "\\?.*=" ', 'Live endpoints, old API versions, debug flags still wired up'],
  ['Backups / dumps', '\\.(sql|bak|zip|tar\\.gz|7z|dump|env)$', 'Historic exports left at predictable paths, often still served'],
  ['Config / secrets', '\\.(env|ini|conf|yml|yaml|properties)$', 'API keys, SMTP creds, feature flags with admin overrides'],
  ['Source maps', '\\.map$', 'Original React/Vue sources, internal API routes and comments'],
  ['.git / .svn', '/(\\.git|\\.svn)/', 'Exposed VCS metadata — pulls the whole repository'],
  ['Old admin panels', '/(admin|manage|console|internal|staff)(/|$)', 'Retired panels that survived the migration'],
  ['Redirectors', '/(redir|out|go|link|url)=', 'Open-redirect and SSRF entry points kept for old links'],
  ['Upload endpoints', '/(upload|attach|file|import)(/|$)', 'Legacy uploaders with looser validation than the current app'],
];

export default function WaybackUrlCollector() {
  const [domain, setDomain] = useState(DEFAULT_TARGET);
  const [matchType, setMatchType] = useState<MatchType>('domain');
  const [collapse, setCollapse] = useState('urlkey');
  const [status, setStatus] = useState('200');
  const [fromYear, setFromYear] = useState(2018);
  const [toYear, setToYear] = useState(2026);
  const [mime, setMime] = useState('text/html');
  const [point, setPoint] = useState<Point>('timeline');
  const [limit, setLimit] = useState(5000);
  const [allStatus, setAllStatus] = useState(false);
  const [view, setView] = useState<'url' | 'curl' | 'alt' | 'pipe'>('url');

  const host = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '') || DEFAULT_TARGET;

  const urls = useMemo(() => {
    const base = 'https://web.archive.org/cdx/search/cdx';
    const statusParam = allStatus ? '' : status.trim();
    const build = (extra: Record<string, string>) => {
      const params = new URLSearchParams();
      params.set('url', host);
      params.set('matchType', matchType);
      if (collapse.trim()) params.set('collapse', collapse.trim());
      if (statusParam) params.set('filter', `statuscode:${statusParam}`);
      params.set('from', String(Math.min(fromYear, toYear)));
      params.set('to', String(Math.max(fromYear, toYear)));
      if (mime.trim()) params.set('filter', `${params.get('filter') ?? ''}${params.get('filter') ? ',' : ''}mimetype:${mime.trim()}`);
      params.set('output', point === 'timeline' ? 'json' : 'json');
      params.set('fl', 'timestamp,original,statuscode,mimetype,length');
      params.set('limit', String(Math.max(1, limit)));
      params.set('fastLatest', 'true');
      Object.entries(extra).forEach(([k, v]) => params.set(k, v));
      return `${base}?${params.toString().replace(/\+/g, '%20')}`;
    };
    return {
      primary: build({}),
      perMime: build({ filter: statusParam ? `statuscode:${statusParam}` : 'statuscode:200' }),
      raw: `${base}?url=${host}&matchType=${matchType}&output=txt&fl=original&collapse=${collapse || 'urlkey'}&limit=${limit}`,
    };
  }, [host, matchType, collapse, status, fromYear, toYear, mime, point, limit, allStatus]);

  const curl = useMemo(
    () => [
      `curl -s '${urls.primary}' \\`,
      `  | jq -r '.[1:][] | .[1]' \\`,
      `  | sort -u > ${host}.urls`,
      '',
      `# raw text variant — no jq, faster for a first sweep:`,
      `curl -s '${urls.raw}' | sort -u | head -${Math.min(limit, 2000)}`,
    ].join('\n'),
    [urls, host, limit],
  );

  const alt = useMemo(
    () => [
      `# gau (GetAllUrls) — queries Wayback, Common Crawl, OTX and URLScan in one pass`,
      `gau --threads 8 --blacklist png,jpg,gif,css,woff ${host} > ${host}.gau.txt`,
      '',
      `# waybackurls — Wayback only, faster but narrower`,
      `waybackurls ${host} | tee ${host}.wb.txt | sort -u | wc -l`,
      '',
      `# katana with Wayback as a passive source, useful when you also want JS parsing`,
      `katana -list <(echo ${host}) -passive -ps waybackarchive,commoncrawl,alienvault -silent`,
    ].join('\n'),
    [host],
  );

  const pipeline = useMemo(
    () => [
      `# 1 — dedupe canonical URL (strip fragments and trailing slash)`,
      `sed 's/#.*$//' ${host}.urls | sort -u > stage1.txt`,
      '',
      `# 2 — drop static assets by extension`,
      `grep -viE '\\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|mp4|webp)(\\?|$)' stage1.txt > stage2.txt`,
      '',
      `# 3 — keep URLs that actually carry parameters`,
      `grep -E '\\?[^=]+=' stage2.txt > params.txt`,
      '',
      `# 4 — pull the juicy extensions out of the whole set`,
      `grep -iE '\\.(sql|bak|zip|tar\\.gz|7z|dump|env|ini|conf|yml|yaml|map)(\\?|$)' stage2.txt > juicy.txt`,
      '',
      `# 5 — endpoint shapes worth replaying first`,
      `grep -Eo 'https?://[^/]+(/[^?]*)?' stage2.txt | sed -E 's#(https?://[^/]+).*#\\1#' | sort -u > hosts.txt`,
      `wc -l stage1.txt stage2.txt params.txt juicy.txt hosts.txt`,
    ].join('\n'),
    [host],
  );

  return (
    <>
      <Card title="CDX query" action={<CopyChip text={urls.primary} label="copy URL" />}>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <TextInput label="Domain" value={domain} onChange={setDomain} mono placeholder={DEFAULT_TARGET} hint="Bare host — scheme and path are stripped" />
          <Select label="matchType" value={matchType} onChange={setMatchType} options={MATCH_TYPES} hint={matchType === 'domain' ? 'Includes every subdomain, wildcards off the apex' : 'Narrow when the apex returns millions of rows'} />
          <TextInput label="collapse" value={collapse} onChange={setCollapse} mono placeholder="urlkey" hint="Deduplicate revisions of the same URL; empty string disables" />
          <TextInput label="Status filter" value={status} onChange={setStatus} mono placeholder="200" hint="Become a prefix (2, 3, 404) or clear it with 'all statuses'" />
          <Select label="MIME filter" value={mime} onChange={setMime} options={MIMES.map((m) => ({ value: m, label: m || 'any' }))} hint="Skip to JSON for API-era URLs; HTML is the default" />
          <Select label="Output point" value={point} onChange={setPoint} options={[{ value: 'timeline', label: 'timeline (all captures)' }, { value: 'captures', label: 'latest-per-URL (collapse)' }] as Array<{ value: Point; label: string }>} hint={point === 'captures' ? 'Collapse plus fastLatest gives the newest revision per URL' : 'Full history — bigger, better for spotting removed paths'} />
          <NumberInput label="From year" value={fromYear} onChange={setFromYear} min={1996} max={2030} hint="Older captures surface retired endpoints" />
          <NumberInput label="To year" value={toYear} onChange={setToYear} min={1996} max={2030} hint="Range is normalised if reversed" />
          <NumberInput label="Row limit" value={limit} onChange={setLimit} min={1} max={50000} step={500} hint="CDX caps around 15k rows per request; paginate with page=N" />
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-4">
          <Checkbox checked={allStatus} onChange={setAllStatus} label="Keep every status code" description="Drops the statuscode filter — error pages expose path structure too" />
          <span className="rf-mono rounded bg-[var(--neutral-btn)] px-2 py-0.5 text-[12px] text-[var(--text-faint)]">
            {host} · {matchType} · {allStatus ? 'any status' : status || 'any'}
          </span>
        </div>
      </Card>

      <Card
        title="Queries"
        action={<DownloadButton text={[urls.primary, urls.raw].join('\n')} filename="wayback-cdx.txt" label="Download .txt" />}
      >
        <Tabs
          value={view}
          onChange={setView}
          tabs={[
            { value: 'url', label: 'CDX URL' },
            { value: 'curl', label: 'curl + jq' },
            { value: 'alt', label: 'gau / waybackurls' },
            { value: 'pipe', label: 'Post-processing' },
          ]}
        />
        <div className="mt-3">
          {view === 'url' && (
            <>
              <OutputBlock value={urls.primary} rows={5} label="Encoded CDX request" />
              <div className="mt-4">
                <OutputBlock value={urls.raw} rows={3} label="Plain-text variant (fl=original)" />
              </div>
            </>
          )}
          {view === 'curl' && <OutputBlock value={curl} rows={9} label="Fetch → jq → sort" />}
          {view === 'alt' && <OutputBlock value={alt} rows={9} label="Tool equivalents" />}
          {view === 'pipe' && <OutputBlock value={pipeline} rows={16} label="stage1 → juicy.txt" />}
        </div>
      </Card>

      <Card title="What to look for">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[12.5px]">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wide text-[var(--text-faint)]">
                <th className="border-b border-[var(--card-border)] px-2 py-1.5">Signal</th>
                <th className="border-b border-[var(--card-border)] px-2 py-1.5">Grep</th>
                <th className="border-b border-[var(--card-border)] px-2 py-1.5">Why it matters</th>
              </tr>
            </thead>
            <tbody>
              {LOOK_FOR.map(([signal, pattern, why]) => (
                <tr key={signal} className="align-top">
                  <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-[var(--text)]">{signal}</td>
                  <td className="border-b border-[var(--card-border)] px-2 py-1.5">
                    <CopyChip text={pattern} label={pattern} />
                  </td>
                  <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-[var(--text-muted)]">{why}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4">
          <Callout tone="info" title="Timeline first, content second">
            Wayback returns what was <em>requested</em>, not what was linked. Diff the host set across years — a host that
            appears only in 2019 captures is often a staging box still resolving today. Fetch the oldest capture of any
            interesting path with <span className="rf-mono">id_</span> prefixed to the timestamp to get the raw body without
            the archive's banner rewrite.
          </Callout>
        </div>
      </Card>

      <Card title="Verification notes">
        <SectionTitle>Archive quirks</SectionTitle>
        <ul className="m-0 list-disc pl-5 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
          <li><span className="rf-mono">collapse=urlkey</span> keeps the earliest capture per URL — pair with <span className="rf-mono">fastLatest=true</span> if you want the newest instead.</li>
          <li><span className="rf-mono">filter</span> is repeatable and comma-separated; a second <span className="rf-mono">filter</span> parameter replaces the first in some clients, so keep both predicates in one value.</li>
          <li>Rate limiting is aggressive: 1 request/second, 15k rows per page, <span className="rf-mono">page=N</span> to paginate.</li>
          <li>Common Crawl indexes what Wayback misses (robots-disallowed paths, short-lived subdomains) — merge both sets before dedupe.</li>
        </ul>
      </Card>
    </>
  );
}
