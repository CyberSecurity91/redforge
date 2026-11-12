import { useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, DownloadButton, KVTable, OutputBlock, SearchInput, Select, Tabs, TextArea, TextInput } from '@/components/ui';
import { useLocalStorage } from '@/lib/hooks';

/**
 * Username sweep planner. Candidates come from a list or are generated from a name pair;
 * the site table carries the hit signature and the rate-limit note, so the matrix that
 * leaves this page can be run without anyone guessing what "found" looks like.
 */

type Mode = 'list' | 'generate';
type Sep = '' | '.' | '_' | '-';
type Suffix = 'none' | '1-9' | '01-09' | '1-99';

interface Site {
  name: string;
  template: string;
  hit: string;
  rate: string;
  fp: boolean;
}

const SITES: Site[] = [
  { name: 'GitHub', template: 'https://github.com/{u}', hit: '200 profile / 404 free', rate: '60 req/h unauthenticated', fp: false },
  { name: 'GitLab', template: 'https://gitlab.com/{u}', hit: '200 profile / 404 free', rate: '10 req/s per IP', fp: false },
  { name: 'Bitbucket', template: 'https://bitbucket.org/{u}/', hit: '200 profile / 404 free', rate: '60 req/min', fp: false },
  { name: 'npm', template: 'https://www.npmjs.com/~{u}', hit: '200 profile / 404 free', rate: 'behind CDN, burst tolerant', fp: false },
  { name: 'PyPI', template: 'https://pypi.org/user/{u}/', hit: '200 profile / 404 free', rate: 'no published limit', fp: false },
  { name: 'Codeberg', template: 'https://codeberg.org/{u}', hit: '200 profile / 404 free', rate: '60 req/min', fp: false },
  { name: 'Docker Hub', template: 'https://hub.docker.com/u/{u}', hit: '200 shell for any name', rate: 'CDN cache, 200 always', fp: true },
  { name: 'Reddit', template: 'https://www.reddit.com/user/{u}', hit: '200 profile / 404 free', rate: '60 req/min with UA', fp: false },
  { name: 'Hacker News', template: 'https://news.ycombinator.com/user?id={u}', hit: '200 with "No such user" text', rate: 'polite: 1 req/s', fp: false },
  { name: 'Keybase', template: 'https://keybase.io/{u}', hit: '200 profile / 404 free', rate: 'no published limit', fp: false },
  { name: 'Mastodon (mastodon.social)', template: 'https://mastodon.social/@{u}', hit: '200 profile / 404 free', rate: '300 req/5 min', fp: false },
  { name: 'Dev.to', template: 'https://dev.to/{u}', hit: '200 profile / 404 free', rate: 'no published limit', fp: false },
  { name: 'Medium', template: 'https://medium.com/@{u}', hit: '200 profile / 404 free', rate: 'behind CDN', fp: false },
  { name: 'SoundCloud', template: 'https://soundcloud.com/{u}', hit: '200 profile / 404 free', rate: '50 req/min', fp: false },
  { name: 'Steam', template: 'https://steamcommunity.com/id/{u}', hit: '200 profile / 200 error page', rate: 'no published limit', fp: true },
  { name: 'Twitch', template: 'https://www.twitch.tv/{u}', hit: '200 shell, result rendered client-side', rate: '800 req/min', fp: true },
  { name: 'YouTube', template: 'https://www.youtube.com/@{u}', hit: '200 shell for any handle', rate: 'quota-based', fp: true },
  { name: 'Instagram', template: 'https://www.instagram.com/{u}/', hit: '200 login wall', rate: 'aggressive bot defence', fp: true },
  { name: 'TikTok', template: 'https://www.tiktok.com/@{u}', hit: '200 shell, captcha at volume', rate: 'captcha after ~20', fp: true },
  { name: 'X (Twitter)', template: 'https://x.com/{u}', hit: '200 login wall', rate: 'login required quickly', fp: true },
  { name: 'Facebook', template: 'https://www.facebook.com/{u}', hit: '200 login wall', rate: 'login required quickly', fp: true },
  { name: 'LinkedIn', template: 'https://www.linkedin.com/in/{u}', hit: '999 or 200 authwall', rate: 'rate-limits hard, authwall', fp: true },
  { name: 'Pinterest', template: 'https://www.pinterest.com/{u}/', hit: '200 for any name', rate: 'CDN, 200 always', fp: true },
  { name: 'Gravatar', template: 'https://gravatar.com/{u}', hit: '200 with default avatar always', rate: 'no published limit', fp: true },
  { name: 'Bluesky', template: 'https://bsky.app/profile/{u}.bsky.social', hit: '200 shell, resolved client-side', rate: 'no published limit', fp: true },
];

const SEPARATORS: Array<{ value: Sep; label: string }> = [
  { value: '.', label: 'Dot — first.last' },
  { value: '_', label: 'Underscore — first_last' },
  { value: '-', label: 'Hyphen — first-last' },
  { value: '', label: 'None — firstlast' },
];

const SUFFIXES: Array<{ value: Suffix; label: string }> = [
  { value: 'none', label: 'No number suffix' },
  { value: '1-9', label: '1 to 9' },
  { value: '01-09', label: '01 to 09 (zero padded)' },
  { value: '1-99', label: '1 to 99 (wide sweep)' },
];

export default function UsernameEnumerationPlanner() {
  const [mode, setMode] = useState<Mode>('generate');
  const [listText, setListText] = useLocalStorage<string>('username-list', 'alex.turner\naturmer\nnorthwind.alex');
  const [first, setFirst] = useLocalStorage<string>('username-first', 'Alex');
  const [last, setLast] = useLocalStorage<string>('username-last', 'Turner');
  const [sep, setSep] = useState<Sep>('.');
  const [suffix, setSuffix] = useState<Suffix>('1-9');
  const [siteFilter, setSiteFilter] = useState('');
  const [runnerTab, setRunnerTab] = useState<'curl' | 'ffuf'>('curl');

  const candidates = useMemo(() => {
    if (mode === 'list') return dedupe(listText.split('\n').map((s) => s.trim().toLowerCase()).filter(Boolean));
    const f = norm(first);
    const l = norm(last);
    if (!f || !l) return [];
    const base = `${f}${sep}${l}`;
    const out = [base];
    for (const n of suffixList(suffix)) out.push(`${base}${n}`);
    return dedupe(out).slice(0, 300);
  }, [mode, listText, first, last, sep, suffix]);

  const visibleSites = useMemo(() => {
    const q = siteFilter.trim().toLowerCase();
    return q ? SITES.filter((s) => s.name.toLowerCase().includes(q) || s.template.toLowerCase().includes(q)) : SITES;
  }, [siteFilter]);

  const matrix = useMemo(() => {
    const rows: Array<{ username: string; site: Site; url: string }> = [];
    for (const u of candidates) {
      for (const s of SITES) rows.push({ username: u, site: s, url: s.template.replaceAll('{u}', encodeURIComponent(u)) });
    }
    return rows;
  }, [candidates]);

  const csv = useMemo(() => {
    const header = ['username', 'site', 'url', 'hit_signature', 'rate_limit', 'false_positive_prone'];
    const lines = matrix.map((r) =>
      [r.username, csvCell(r.site.name), csvCell(r.url), csvCell(r.site.hit), csvCell(r.site.rate), r.site.fp ? 'yes' : 'no'].join(','),
    );
    return [header.join(','), ...lines].join('\n');
  }, [matrix]);

  const curlLoop = useMemo(
    () =>
      [
        `# matrix.tsv: site<TAB>url — one row per check`,
        `# THREADS parallel workers, RATE requests per second overall`,
        `xargs -P THREADS -n 2 sh -c 'curl -s -o /dev/null -w "%{http_code}\\t%{size_download}\\t%{url_effective}\\n" --max-time 15 --retry 1 "$2"' _ < matrix.tsv > results.tsv`,
        ``,
        `# politeness gate: sleep 1/RATE between requests when the site is strict`,
        `while IFS=$'\\t' read -r site url; do`,
        `  printf '%s\\t' "$site"`,
        `  curl -s -o /dev/null -w '%{http_code}\\n' --max-time 15 "$url"`,
        `  sleep "$(awk -v r=RATE 'BEGIN { printf "%.2f", 1 / r }')"`,
        `done < matrix.tsv > results-polite.tsv`,
        ``,
        `# text-marker sites need the body, not the status code`,
        `curl -s "https://news.ycombinator.com/user?id=USERNAME" | grep -c "No such user"`,
      ].join('\n'),
    [],
  );

  const ffufLoop = useMemo(
    () =>
      [
        `# sites.tsv: one row per site, {u} replaced by FUZZ`,
        `while IFS=$'\\t' read -r site tpl; do`,
        `  ffuf -s -w usernames.txt:U -u "$tpl" -mc 200 -t THREADS -rate RATE -o "out/$site.json"`,
        `done < sites.tsv`,
        ``,
        `# single site, quick check`,
        `ffuf -w usernames.txt:U -u https://github.com/FUZZ -mc 200 -t THREADS -rate RATE -o out/github.json`,
        ``,
        `# soft-404 guard: run the same wordlist against a random name first`,
        `ffuf -w <(printf 'zz-no-such-user-%s\\n' $RANDOM) -u https://github.com/FUZZ -mc 200 -t 1 -rate 1`,
      ].join('\n'),
    [],
  );

  const fpSites = SITES.filter((s) => s.fp);

  return (
    <>
      <Card title="Candidates">
        <Tabs<Mode>
          value={mode}
          onChange={setMode}
          tabs={[
            { value: 'generate', label: 'Generate from name' },
            { value: 'list', label: 'Paste a list' },
          ]}
        />
        <div className="mt-3">
          {mode === 'generate' ? (
            <div className="grid gap-3 sm:grid-cols-2">
              <TextInput label="First name" value={first} onChange={setFirst} />
              <TextInput label="Last name" value={last} onChange={setLast} />
              <Select<Sep> label="Separator" value={sep} onChange={setSep} options={SEPARATORS} />
              <Select<Suffix> label="Number suffixes" value={suffix} onChange={setSuffix} options={SUFFIXES} />
            </div>
          ) : (
            <TextArea label="Usernames" value={listText} onChange={setListText} rows={6} hint="One per line; lower-cased and de-duplicated." />
          )}
        </div>
        <div className="mt-3">
          <KVTable
            rows={[
              ['Candidates', String(candidates.length)],
              ['Sites in dataset', String(SITES.length)],
              ['Checks to run', String(matrix.length)],
              ['Preview', candidates.slice(0, 8).join(', ') || '—'],
            ]}
          />
        </div>
        {suffix === '1-99' && (
          <div className="mt-3">
            <Callout tone="warn" title="Wide sweep">
              99 suffixes per name means {candidates.length} candidates and {matrix.length} requests. Against a site with
              a 60 per-hour limit that is a multi-day run; narrow the suffix range before you start.
            </Callout>
          </div>
        )}
      </Card>

      <Card title="Site dataset" action={<SearchInput value={siteFilter} onChange={setSiteFilter} placeholder="Filter sites" />}>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr className="text-left text-[11px] tracking-wide text-[var(--text-faint)] uppercase">
                <th className="py-1 pr-3 font-medium">Site</th>
                <th className="py-1 pr-3 font-medium">URL template</th>
                <th className="py-1 pr-3 font-medium">Hit signature</th>
                <th className="py-1 pr-3 font-medium">Rate limit</th>
                <th className="py-1 font-medium">Flag</th>
              </tr>
            </thead>
            <tbody>
              {visibleSites.map((s) => (
                <tr key={s.name} className="border-t border-[var(--card-border)]">
                  <td className="py-1.5 pr-3 text-[var(--text)]">{s.name}</td>
                  <td className="rf-mono py-1.5 pr-3 text-[var(--text-muted)]">{s.template}</td>
                  <td className="py-1.5 pr-3 text-[var(--text-muted)]">{s.hit}</td>
                  <td className="py-1.5 pr-3 text-[var(--text-faint)]">{s.rate}</td>
                  <td className="py-1.5">{s.fp && <span className="rounded-full px-2 py-[1px] text-[10.5px] font-medium" style={{ backgroundColor: 'var(--neutral-btn)', color: 'var(--warn)' }}>false-positive prone</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-3">
          <Callout tone="warn" title={`${fpSites.length} sites return 200 for almost everything`}>
            {fpSites.map((s) => s.name).join(', ')}. A 200 there proves nothing: the profile shell, login wall or
            default avatar is served for any name. Treat a hit on these as unconfirmed until a person opens the page
            and reads it, and never report a numeric result from them as an account.
          </Callout>
        </div>
      </Card>

      <Card
        title="Check matrix"
        action={<DownloadButton text={csv} filename="username-matrix.csv" label="Download CSV" />}
      >
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr className="text-left text-[11px] tracking-wide text-[var(--text-faint)] uppercase">
                <th className="py-1 pr-3 font-medium">Username</th>
                <th className="py-1 pr-3 font-medium">Site</th>
                <th className="py-1 font-medium">Check URL</th>
              </tr>
            </thead>
            <tbody>
              {matrix.slice(0, 12).map((r) => (
                <tr key={`${r.username}-${r.site.name}`} className="border-t border-[var(--card-border)]">
                  <td className="rf-mono py-1.5 pr-3 text-[var(--text)]">{r.username}</td>
                  <td className="py-1.5 pr-3 text-[var(--text-muted)]">{r.site.name}</td>
                  <td className="rf-mono py-1.5 break-all text-[var(--text-muted)]">{r.url}</td>
                </tr>
              ))}
              {matrix.length === 0 && (
                <tr>
                  <td colSpan={3} className="py-6 text-center text-[12.5px] text-[var(--text-faint)]">
                    No candidates yet — add a name pair or paste a list above.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="mt-2 text-[11.5px] text-[var(--text-faint)]">
          Showing {Math.min(12, matrix.length)} of {matrix.length} checks. The CSV carries all of them.
        </div>
        <div className="mt-3">
          <OutputBlock value={csv} label="username-matrix.csv" rows={8} />
        </div>
      </Card>

      <Card title="Runner">
        <Tabs<'curl' | 'ffuf'>
          value={runnerTab}
          onChange={setRunnerTab}
          tabs={[
            { value: 'curl', label: 'curl + xargs' },
            { value: 'ffuf', label: 'ffuf loop' },
          ]}
        />
        <div className="mt-3">
          <CodeBlock code={runnerTab === 'curl' ? curlLoop : ffufLoop} label={runnerTab === 'curl' ? 'curl-loop.sh' : 'ffuf-loop.sh'} maxHeight={320} />
        </div>
        <div className="mt-3">
          <Callout tone="info" title="Placeholders">
            THREADS and RATE are set per engagement: 4 and 2 are a sensible start for sites with a 60 per-hour limit.
            Keep a random-name baseline in the run — if the baseline also returns 200, the site's signature is broken
            and its results belong in the false-positive bucket.
          </Callout>
        </div>
      </Card>
    </>
  );
}

function norm(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

function suffixList(suffix: Suffix): string[] {
  if (suffix === 'none') return [];
  if (suffix === '1-9') return Array.from({ length: 9 }, (_, i) => String(i + 1));
  if (suffix === '01-09') return Array.from({ length: 9 }, (_, i) => String(i + 1).padStart(2, '0'));
  return Array.from({ length: 99 }, (_, i) => String(i + 1));
}

function dedupe(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of values) {
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

function csvCell(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}
