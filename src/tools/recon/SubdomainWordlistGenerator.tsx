import { useMemo, useState } from 'react';
import {
  Button,
  Callout,
  Card,
  Checkbox,
  CopyChip,
  DownloadButton,
  NumberInput,
  OutputBlock,
  SectionTitle,
  Slider,
  TextInput,
} from '@/components/ui';
import { SUBDOMAIN_PREFIXES } from '@/lib/redteam-data';
import { parseHostname, registrableDomain } from '@/lib/domain';
import { DEFAULT_TARGET } from '@/tools/registry';

const GROUPS = Object.keys(SUBDOMAIN_PREFIXES);

/** Permutation-ready suffixes — appended after a prefix as `prefix-suffix`. */
const PERM_SUFFIXES = ['dev', 'test', 'stg', 'prod', 'old', 'new', 'backup', 'bak', 'v2', 'internal'];

/** Inner `prefix:n` roots for numeric sweeps. */
const NUMERIC_ROOTS = ['dev', 'api', 'node', 'app', 'web'];

export default function SubdomainWordlistGenerator() {
  const [root, setRoot] = useState(DEFAULT_TARGET);
  const [selected, setSelected] = useState<string[]>(GROUPS);
  const [permute, setPermute] = useState(false);
  const [permLimit, setPermLimit] = useState(400);
  const [numeric, setNumeric] = useState(true);
  const [numRange, setNumRange] = useState(20);

  const host = useMemo(() => {
    const parsed = parseHostname(root);
    return parsed.host ? registrableDomain(parsed.host) : '';
  }, [root]);

  const words = useMemo(() => {
    const out: string[] = [];
    const seen = new Set<string>();
    const push = (w: string) => {
      const v = w.trim().toLowerCase();
      if (v && !seen.has(v)) {
        seen.add(v);
        out.push(v);
      }
    };
    for (const group of selected) {
      for (const prefix of SUBDOMAIN_PREFIXES[group] ?? []) push(prefix);
    }
    if (numeric) {
      for (const base of NUMERIC_ROOTS) for (let i = 1; i <= numRange; i++) push(`${base}${i}`);
    }
    if (permute) {
      const seeds = out.slice(0, 40);
      for (const seed of seeds) {
        for (const suffix of PERM_SUFFIXES) {
          if (out.length >= 40 + permLimit) break;
          push(`${seed}-${suffix}`);
        }
      }
    }
    return out;
  }, [selected, numeric, numRange, permute, permLimit]);

  const fullNames = useMemo(
    () => (host ? words.map((w) => `${w}.${host}`) : []),
    [words, host],
  );

  const toggleGroup = (group: string, on: boolean) =>
    setSelected((prev) => (on ? Array.from(new Set([...prev, group])) : prev.filter((g) => g !== group)));

  const fuzzCmd = `ffuf -u https://${host || DEFAULT_TARGET} -w wordlist.txt -H "Host: FUZZ.${host || DEFAULT_TARGET}" -mc 200,204,301,302,401,403 -fs 0 -rate 40 -t 20`;
  const dnsxCmd = `dnsx -l wordlist.txt -a -resp -silent | tee dnsx-resolved.txt`;

  return (
    <>
      <Card title="Root domain">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput
            label="Root domain"
            hint="Scheme, path and port are stripped"
            value={root}
            onChange={setRoot}
            mono
            placeholder={DEFAULT_TARGET}
          />
          <div className="flex flex-col justify-end gap-2 pb-1">
            <div className="text-[12px] text-[var(--text-muted)]">
              Registrable domain: <span className="rf-mono text-[var(--text)]">{host || '—'}</span>
            </div>
            <div className="text-[12px] text-[var(--text-muted)]">
              Words: <span className="rf-mono text-[var(--text)]">{words.length}</span> · Fully-qualified:{' '}
              <span className="rf-mono text-[var(--text)]">{fullNames.length}</span>
            </div>
          </div>
        </div>
      </Card>

      <Card
        title="Prefix groups"
        action={
          <div className="flex gap-1">
            <Button size="sm" variant="ghost" onClick={() => setSelected(GROUPS)}>
              Select all
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setSelected([])}>
              None
            </Button>
          </div>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {GROUPS.map((group) => (
            <div key={group} className="rounded border border-[var(--card-border)] px-3 py-2">
              <Checkbox
                checked={selected.includes(group)}
                onChange={(v) => toggleGroup(group, v)}
                label={group}
                description={`${SUBDOMAIN_PREFIXES[group].length} prefixes`}
              />
            </div>
          ))}
        </div>

        <div className="mt-5 grid gap-5 sm:grid-cols-2">
          <div className="space-y-3">
            <Checkbox
              checked={numeric}
              onChange={setNumeric}
              label="Numeric suffix sweep"
              description={`Appends 1–${numRange} to ${NUMERIC_ROOTS.join(', ')}`}
            />
            <NumberInput label="Sweep upper bound" value={numRange} onChange={setNumRange} min={1} max={200} />
          </div>
          <div className="space-y-3">
            <Checkbox
              checked={permute}
              onChange={setPermute}
              label="Enable permutations"
              description={`prefix-suffix combos, capped at ${permLimit}`}
            />
            <Slider
              label="Permutation cap"
              value={permLimit}
              onChange={setPermLimit}
              min={50}
              max={2000}
              step={50}
            />
          </div>
        </div>
      </Card>

      <Card
        title="Wordlist"
        action={
          <div className="flex items-center gap-1">
            <span className="text-[11.5px] text-[var(--text-faint)]">{words.length} entries</span>
            <DownloadButton text={words.join('\n')} filename={`${host || 'target'}-subdomains.txt`} label="Download" />
          </div>
        }
      >
        {words.length === 0 ? (
          <Callout tone="warn" title="Nothing selected">
            Pick at least one prefix group above to build a wordlist.
          </Callout>
        ) : (
          <OutputBlock value={words.join('\n')} rows={12} label="Bare words (one per line)" />
        )}
      </Card>

      <Card title="Resolver one-liners">
        <SectionTitle>dnsx — brute + resolve</SectionTitle>
        <OutputBlock value={host ? dnsxCmd : ''} rows={2} label="dnsx" />
        <SectionTitle>ffuf — vhost discovery with filtered sizes</SectionTitle>
        <OutputBlock value={host ? fuzzCmd : ''} rows={3} label="ffuf" />
        <div className="mt-3 flex flex-wrap gap-2">
          {fullNames.slice(0, 8).map((name) => (
            <CopyChip key={name} text={name} />
          ))}
          {fullNames.length > 8 && (
            <span className="self-center text-[11.5px] text-[var(--text-faint)]">
              +{fullNames.length - 8} more in the download
            </span>
          )}
        </div>
        <div className="mt-4">
          <Callout tone="info" title="Ordering matters">
            Resolve first with dnsx, then point ffuf at the hosts that answered — a wildcard DNS record makes every
            vhost return 200, so filter on response size (<span className="rf-mono">-fs</span>) before reading hits.
          </Callout>
        </div>
      </Card>
    </>
  );
}
