import { useMemo, useState } from 'react';
import { Callout, Card, Checkbox, CopyChip, DownloadButton, OutputBlock, TextInput } from '@/components/ui';
import { parseHostname, registrableDomain } from '@/lib/domain';
import { DEFAULT_TARGET } from '@/tools/registry';

interface DorkCategory {
  id: string;
  label: string;
  hint: string;
  /** `{d}` is substituted with the registrable domain at build time. */
  templates: string[];
}

const CATEGORIES: DorkCategory[] = [
  {
    id: 'files',
    label: 'Exposed files',
    hint: 'Documents the site never meant to index',
    templates: [
      'site:{d} filetype:{ext}',
      'site:{d} ext:{ext} intext:"confidential"',
      'site:{d} intitle:"index of" ext:{ext}',
    ],
  },
  {
    id: 'admin',
    label: 'Admin panels',
    hint: 'Login surfaces that accept the public internet',
    templates: [
      'site:{d} inurl:admin intitle:"login"',
      'site:{d} inurl:(admin|manager|console|dashboard) -inurl:"login/error"',
      'site:{d} intitle:"phpMyAdmin" | intitle:"Adminer"',
      'site:{d} inurl:"wp-admin" | inurl:"/administrator/"',
    ],
  },
  {
    id: 'listing',
    label: 'Directory listings',
    hint: 'Autoindex pages leak the tree',
    templates: [
      'site:{d} intitle:"index of /"',
      'site:{d} intitle:"index of" (parent directory)',
      'site:{d} intitle:"index of" inurl:backup',
    ],
  },
  {
    id: 'creds',
    label: 'Credential leaks',
    hint: 'Pastes, dumps and indexed secrets',
    templates: [
      'site:{d} (password | passwd | pwd) ext:txt | ext:log | ext:csv',
      'site:{d} intext:"BEGIN RSA PRIVATE KEY"',
      'site:{d} intext:"AKIA" ext:txt',
      'site:pastebin.com "{d}" password',
    ],
  },
  {
    id: 'config',
    label: 'Config / env',
    hint: 'Runtime configuration with secrets inline',
    templates: [
      'site:{d} inurl:(".env" | "config.php" | "settings.py")',
      'site:{d} ext:env | ext:ini | ext:conf intext:"password"',
      'site:{d} inurl:"wp-config.php" -intext:"index of"',
    ],
  },
  {
    id: 'git',
    label: 'Git exposure',
    hint: 'A /.git/ or .git/config on the web root is a full source read',
    templates: [
      'site:{d} inurl:"/.git/config"',
      'site:{d} intitle:"index of" inurl:".git"',
      'site:{d} inurl:".git" -inurl:"//"',
    ],
  },
  {
    id: 'errors',
    label: 'Error messages',
    hint: 'Stack traces confirm frameworks and file paths',
    templates: [
      'site:{d} intext:"Fatal error" | intext:"Parse error"',
      'site:{d} intext:"SQL syntax.*MySQL"',
      'site:{d} intext:"Traceback (most recent call last)"',
      'site:{d} intext:"Warning: mysql_connect()"',
    ],
  },
  {
    id: 'backups',
    label: 'Backup archives',
    hint: 'Old archives left in the web root',
    templates: [
      'site:{d} (ext:bak | ext:old | ext:backup | ext:orig | ext:save)',
      'site:{d} (ext:zip | ext:tar | ext:gz | ext:7z) inurl:backup',
      'site:{d} intext:"index of" (backup|bak|bkp)',
    ],
  },
];

const EXTENSIONS = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv', 'txt', 'log', 'sql', 'env', 'ini', 'conf', 'bak', 'zip', 'json', 'xml'];

export default function GoogleDorkBuilder() {
  const [domainInput, setDomainInput] = useState(DEFAULT_TARGET);
  const [active, setActive] = useState<string[]>(['files', 'admin', 'listing', 'git']);
  const [allowed, setAllowed] = useState<string[]>(['pdf', 'xls', 'csv', 'log', 'sql', 'env', 'bak', 'zip']);
  const [excludes, setExcludes] = useState('www, careers, blog');
  const [subdomainsOnly, setSubdomainsOnly] = useState(false);

  const domain = useMemo(() => {
    const parsed = parseHostname(domainInput);
    return parsed.host ? registrableDomain(parsed.host) : '';
  }, [domainInput]);

  const queries = useMemo(() => {
    if (!domain) return [];
    const extList = allowed.length ? allowed : ['pdf'];
    const variants = extList.slice(0, 6);
    const exclusion = excludes
      .split(/[\s,]+/)
      .map((e) => e.trim().toLowerCase())
      .filter((e) => /^[a-z0-9.-]+$/.test(e))
      .map((e) => (e.includes('.') ? `-site:${e}` : `-inurl:${e}`))
      .join(' ');
    const out: string[] = [];
    for (const id of active) {
      const category = CATEGORIES.find((c) => c.id === id);
      if (!category) continue;
      for (const template of category.templates) {
        if (template.includes('{ext}')) {
          for (const ext of variants) out.push(template.replace(/\{ext\}/g, ext).replace(/\{d\}/g, domain));
        } else {
          out.push(template.replace(/\{d\}/g, domain));
        }
      }
    }
    const deduped = Array.from(new Set(out));
    if (subdomainsOnly) return deduped.map((q) => `site:*.${domain}${q.replace(`site:${domain}`, '')}`);
    return deduped.map((q) => (exclusion ? `${q} ${exclusion}` : q)).map((q) => q.replace(/\s+/g, ' ').trim());
  }, [domain, active, allowed, excludes, subdomainsOnly]);

  const googleUrls = useMemo(
    () => queries.map((q, i) => `https://www.google.com/search?q=${encodeURIComponent(q)}`).join('\n'),
    [queries],
  );
  const bingUrls = useMemo(
    () => queries.map((q) => `https://www.bing.com/search?q=${encodeURIComponent(q)}`).join('\n'),
    [queries],
  );

  const toggle = (list: string[], setList: (v: string[]) => void, id: string, on: boolean) =>
    setList(on ? Array.from(new Set([...list, id])) : list.filter((x) => x !== id));

  return (
    <>
      <Card title="Target">
        <div className="grid gap-4 sm:grid-cols-3">
          <TextInput label="Target domain" value={domainInput} onChange={setDomainInput} mono placeholder={DEFAULT_TARGET} />
          <TextInput
            label="Exclude terms"
            hint="Hostnames become -site:, words become -inurl:"
            value={excludes}
            onChange={setExcludes}
            mono
          />
          <div className="flex items-end pb-3">
            <Checkbox
              checked={subdomainsOnly}
              onChange={setSubdomainsOnly}
              label="Scope to subdomains"
              description="site:*.domain — excludes the apex"
            />
          </div>
        </div>
      </Card>

      <Card
        title="Categories"
        action={
          <div className="flex gap-1">
            <button
              type="button"
              onClick={() => setActive(CATEGORIES.map((c) => c.id))}
              className="rounded px-2 py-0.5 text-[11.5px] text-[var(--text-faint)] hover:text-[var(--accent)]"
            >
              All
            </button>
            <button
              type="button"
              onClick={() => setActive([])}
              className="rounded px-2 py-0.5 text-[11.5px] text-[var(--text-faint)] hover:text-[var(--accent)]"
            >
              None
            </button>
          </div>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {CATEGORIES.map((category) => (
            <div key={category.id} className="rounded border border-[var(--card-border)] px-3 py-2">
              <Checkbox
                checked={active.includes(category.id)}
                onChange={(v) => toggle(active, setActive, category.id, v)}
                label={category.label}
                description={category.hint}
              />
            </div>
          ))}
        </div>

        <div className="mt-5">
          <div className="mb-2 text-[13px] font-medium text-[var(--text)]">File extensions</div>
          <div className="flex flex-wrap gap-2">
            {EXTENSIONS.map((ext) => {
              const on = allowed.includes(ext);
              return (
                <button
                  key={ext}
                  type="button"
                  onClick={() => toggle(allowed, setAllowed, ext, !on)}
                  className={`rf-mono rounded border px-2 py-[3px] text-[12px] transition-colors ${
                    on
                      ? 'border-[var(--accent)] bg-[var(--accent-faded)] text-[var(--accent)]'
                      : 'border-[var(--card-border)] text-[var(--text-muted)] hover:text-[var(--text)]'
                  }`}
                >
                  {ext}
                </button>
              );
            })}
          </div>
        </div>
      </Card>

      <Card
        title="Dork queries"
        action={
          <div className="flex items-center gap-2">
            <span className="text-[11.5px] text-[var(--text-faint)]">{queries.length} queries</span>
            <DownloadButton text={queries.join('\n')} filename={`${domain || 'target'}-dorks.txt`} label="Download" />
          </div>
        }
      >
        {queries.length === 0 ? (
          <Callout tone="warn" title="Nothing to compose">
            Enter a domain and select at least one category.
          </Callout>
        ) : (
          <>
            <OutputBlock value={queries.join('\n')} rows={14} label="One query per line" />
            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <div>
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="text-[13px] font-medium text-[var(--text)]">Google</span>
                  <CopyChip text={googleUrls} label="Copy all URLs" />
                </div>
                <OutputBlock value={googleUrls} rows={4} label="Google URLs" />
              </div>
              <div>
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="text-[13px] font-medium text-[var(--text)]">Bing</span>
                  <CopyChip text={bingUrls} label="Copy all URLs" />
                </div>
                <OutputBlock value={bingUrls} rows={4} label="Bing URLs" />
              </div>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              {queries.slice(0, 4).map((q) => (
                <CopyChip key={q} text={q} label={q.length > 60 ? `${q.slice(0, 57)}…` : q} />
              ))}
            </div>
          </>
        )}
      </Card>

      <Card title="Before you run these">
        <Callout tone="info" title="Discovery, not a finding">
          Search engines index what is already public, so a hit is only a discovery. Confirm every hit sits inside the
          authorised scope and record the exact query in the report.
        </Callout>
      </Card>
    </>
  );
}
