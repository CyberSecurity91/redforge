import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  DownloadButton,
  KVTable,
  OutputBlock,
  SectionTitle,
  Select,
  TextInput,
} from '@/components/ui';

/**
 * Entity pivot planner. One seed entity in, a three-stage plan out: direct
 * lookups, enrichment, then correlation. Every query is an inert string with a
 * {{SEED}} placeholder — nothing here touches the network, and nothing resolves
 * a person.
 */

type Seed = 'person' | 'org' | 'domain' | 'email' | 'phone' | 'username';
type Objective = 'identity' | 'infrastructure' | 'credentials' | 'relationships';

const SEEDS: Array<{ value: Seed; label: string; hint: string }> = [
  { value: 'person', label: 'Person (name)', hint: 'Full name as written in the brief' },
  { value: 'org', label: 'Organisation', hint: 'Registered or trading name' },
  { value: 'domain', label: 'Domain', hint: 'Apex domain, no scheme' },
  { value: 'email', label: 'Email address', hint: 'Full address' },
  { value: 'phone', label: 'Phone number', hint: 'E.164 with + prefix' },
  { value: 'username', label: 'Username / handle', hint: 'Handle without the @' },
];

const OBJECTIVES: Array<{ value: Objective; label: string; blurb: string }> = [
  { value: 'identity', label: 'Identity confirmation', blurb: 'Prove the seed maps to one real, attributable entity.' },
  { value: 'infrastructure', label: 'Infrastructure', blurb: 'Owned hosts, netblocks, certificates and third-party tenancy.' },
  { value: 'credentials', label: 'Credentials exposure', blurb: 'Breach-corpus membership and password reuse surface.' },
  { value: 'relationships', label: 'Relationships', blurb: 'Who this entity works with, reports to, or controls.' },
];

interface Query {
  op: string;
  query: string;
  positive: string;
}

interface StageDef {
  key: 1 | 2 | 3;
  title: string;
  note: string;
}

const STAGES: StageDef[] = [
  { key: 1, title: 'Stage 1 — direct lookups', note: 'Deterministic, single-record sources. Cheap, fast, and almost always admissible as a starting point.' },
  { key: 2, title: 'Stage 2 — enrichment', note: 'Second-order sources that widen the seed. Anything found here is a lead, not a fact.' },
  { key: 3, title: 'Stage 3 — correlation', note: 'Cross-checking two or more independent results. Only here does a finding start to harden.' },
];

function buildQueries(seed: Seed, objective: Objective): Record<1 | 2 | 3, Query[]> {
  const s = '{{SEED}}';
  const out: Record<1 | 2 | 3, Query[]> = { 1: [], 2: [], 3: [] };

  const identity: Record<Seed, Query[]> = {
    person: [
      { op: 'site:linkedin.com', query: `"${s}" site:linkedin.com/in OR site:linkedin.com/pub`, positive: 'One profile whose employer and dates match the brief' },
      { op: 'Registry', query: `"${s}" site:companieshouse.gov.uk`, positive: 'A director appointment naming the same person' },
      { op: 'Archive', query: `web.archive.org/web/*/${s.replace(/\s/g, '-')}.*`, positive: 'A captured page tying the name to the organisation' },
    ],
    org: [
      { op: 'OpenCorporates', query: `site:opencorporates.com "${s}"`, positive: 'Registered number plus a registered office address' },
      { op: 'GLEIF', query: `gleif.org/en/lei-search/?q=${s}`, positive: 'A LEI with a parent/child corporate tree' },
      { op: 'Companies House', query: `find-and-update.company-information.service.gov.uk/search?q=${s}`, positive: 'Filing history with officers and charges' },
    ],
    domain: [
      { op: 'RDAP', query: `https://rdap.org/domain/${s}`, positive: 'Registrar, registration date and current status flags' },
      { op: 'WHOIS history', query: `whois.domaintools.com/${s} (unarrested history view)`, positive: 'Prior registrant or an earlier creation date' },
      { op: 'Certificate transparency', query: `https://crt.sh/?q=%25.${s}&output=json`, positive: 'SAN entries naming sibling hosts' },
    ],
    email: [
      { op: 'Have I Been Pwned', query: `https://haveibeenpwned.com/account/${s}`, positive: 'A listed breach set with a date window' },
      { op: 'Gravatar', query: `https://gravatar.com/${s}`, positive: 'A profile photo or linked public identity' },
      { op: 'Github commit search', query: `"${s}" in:email`, positive: 'Commits attributing the address to a handle' },
    ],
    phone: [
      { op: 'E.164 parse', query: `libphonenumber parse "${s}" → country, carrier, line type`, positive: 'A carrier and line type that match the claimed region' },
      { op: 'Public directory', query: `"${s}" site:whitepages.com OR site:192.com`, positive: 'A name-to-number pairing in a public directory' },
      { op: 'Messenger checks', query: `currency/conversation lookup on "${s}" (manual, no automation)`, positive: 'A profile photo matching a known identity' },
    ],
    username: [
      { op: 'sherlock', query: `sherlock ${s} --timeout 10 --print-found`, positive: 'The same handle on two or more platforms with a consistent bio' },
      { op: 'WhatsMyName', query: `whatsmyname.app/?q=${s}`, positive: 'Platform list with HTTP 200 hits only' },
      { op: 'Past handles', query: `"${s}" site:namechk.com OR site:usersearch.org`, positive: 'An earlier handle pattern used by the same person' },
    ],
  };

  const infra: Record<Seed, Query[]> = {
    person: [
      { op: 'Github code', query: `"${s}" filename:.gitconfig`, positive: 'A name/email pair in a committed git config' },
      { op: 'Shodan', query: `shodan search 'http.title:"${s}"'`, positive: 'Hosted pages whose title carries the name' },
      { op: 'Keybase/dns', query: `keybase.io/${s} → dns entries`, positive: 'A published DNS TXT record proving control' },
    ],
    org: [
      { op: 'theHarvester', query: `theHarvester -d ${s}.example.com -b bing,crtsh,dnsdumpster -l 500`, positive: 'A host list whose names cluster by environment prefix' },
      { op: 'subfinder', query: `subfinder -d ${s}.example.com -all -silent | httpx -silent -sc -title`, positive: 'Live hosts beyond the documented estate' },
      { op: 'ASN', query: `bgp.he.net/search?search[search]=${s}`, positive: 'An ASN whose registration names the org' },
    ],
    domain: [
      { op: 'subfinder', query: `subfinder -d ${s} -all -silent -o subs.txt`, positive: 'Subdomains with predictable environment prefixes' },
      { op: 'Amass', query: `amass enum -passive -d ${s} -o amass.txt`, positive: 'Root domains sharing the same certificate issuer' },
      { op: 'DNS history', query: `securitytrails.com/domain/${s}/history/a`, positive: 'An earlier A record pointing at a different netblock' },
    ],
    email: [
      { op: 'MX/DMARC', query: `dig +short MX ${s.split('@')[1] ?? 'example.com'} ; dig +short TXT _dmarc.${s.split('@')[1] ?? 'example.com'}`, positive: 'A tenant whose MX points at the claimed provider' },
      { op: 'SPF include', query: `dig +short TXT ${s.split('@')[1] ?? 'example.com'} | grep spf`, positive: 'An include chain naming the sending platform' },
      { op: 'Autodiscover', query: `curl -s "https://autodiscover.${s.split('@')[1] ?? 'example.com'}/autodiscover/autodiscover.xml"`, positive: 'A redirect to an Exchange or M365 endpoint' },
    ],
    phone: [
      { op: 'Carrier lookup', query: `twilio lookups or any offline carrier table for "${s}"`, positive: 'A carrier whose footprint matches the claimed office' },
      { op: 'VoIP range', query: `"${s.slice(0, 6)}" voip provider allocation`, positive: 'An allocation owned by a cloud telephony provider' },
      { op: 'SIP host guess', query: `sip.${s.replace(/[^0-9]/g, '').slice(0, 6)}.example.com`, positive: 'An SRV record pointing at a PBX' },
    ],
    username: [
      { op: 'Github', query: `github.com/${s} → repositories and gists`, positive: 'Commits with a work email in the author field' },
      { op: 'Keybase', query: `keybase.io/${s}`, positive: 'Proofs linking to other platforms' },
      { op: 'npm/PyPI', query: `npmjs.com/~${s} ; pypi.org/user/${s}`, positive: 'Published packages whose metadata names an org' },
    ],
  };

  const creds: Query[] = [
    { op: 'Breach corpus', query: `"${s}" in the client's own breach extract set (never a public paste index)`, positive: 'An exact-record match with a breach name and date' },
    { op: 'Dehashed/LeakCheck', query: `site:dehashed.com "${s}" (metadata only, no cracking)`, positive: 'A breach membership that corroborates the breach corpus match' },
    { op: 'Password reuse surface', query: `"${s}" + common corporate patterns, checked only against systems in scope`, positive: 'A reuse indicator, which is a finding only after an authorised test' },
  ];

  const rel: Query[] = [
    { op: 'LinkedIn graph', query: `"${s}" site:linkedin.com "reports to" OR "team"`, positive: 'A named manager with a matching company tenure' },
    { op: 'Corporate filings', query: `site:opencorporates.com "${s}" officers`, positive: 'Shared directorship with another entity in scope' },
    { op: 'Meeting minutes', query: `"${s}" filetype:pdf site:example.com`, positive: 'A board or project minute naming the entity' },
  ];

  // Stage 1 is always the direct lookups for the seed type.
  out[1] = identity[seed];
  if (objective === 'identity') out[2] = identity[seed].slice(0, 3);
  if (objective === 'infrastructure') out[2] = infra[seed];
  if (objective === 'credentials') out[2] = creds;
  if (objective === 'relationships') out[2] = rel;

  out[3] = [
    ...identity[seed].slice(0, 1),
    ...(objective === 'infrastructure' ? infra[seed].slice(0, 2) : []),
    ...(objective === 'relationships' ? rel.slice(0, 2) : []),
    { op: 'Archive diff', query: `web.archive.org/web/2024*/${s.replace(/\s/g, '-')}`, positive: 'Two captures, different dates, same assertion' },
  ].filter((q, i, arr) => arr.findIndex((x) => x.query === q.query) === i);

  return out;
}

const CONFIDENCE: Array<[string, string, string]> = [
  ['Single source', 'One platform or one record says it.', 'A lead. Never report it as a fact; a handle collision is a person.'],
  ['Corroborated', 'Two independent sources agree and neither is derived from the other.', 'Reportable with the source pair named. Still not proof of identity.'],
  ['Verified', 'A controlled channel confirms it — a client-side match, a document, an out-of-band callback.', 'Reportable without caveat, and the only tier the client will accept in a deliverable.'],
];

export default function OsintEntityPivotPlanner() {
  const [seedType, setSeedType] = useState<Seed>('domain');
  const [seedValue, setSeedValue] = useState('example.com');
  const [objectives, setObjectives] = useState<Objective[]>(['identity', 'infrastructure']);
  const [archiveOn, setArchiveOn] = useState(true);
  const [authorised, setAuthorised] = useState(false);

  const seedDef = SEEDS.find((s) => s.value === seedType) ?? SEEDS[2]!;

  const plan = useMemo(() => {
    const primary = objectives[0] ?? 'identity';
    return buildQueries(seedType, primary);
  }, [seedType, objectives]);

  const rendered = useMemo(() => {
    const value = seedValue.trim() || '{{SEED}}';
    const sub = (q: string) => q.replace(/\{\{SEED\}\}/g, value);
    return {
      1: plan[1].map((q) => ({ ...q, query: sub(q.query) })),
      2: plan[2].map((q) => ({ ...q, query: sub(q.query) })),
      3: plan[3].map((q) => ({ ...q, query: sub(q.query) })),
    } as Record<1 | 2 | 3, Query[]>;
  }, [plan, seedValue]);

  const report = useMemo(() => {
    const lines = [`# Entity pivot plan — ${seedValue.trim() || '{{SEED}}'}`, '', `Seed type: ${seedDef.label}`, `Objectives: ${objectives.length ? objectives.join(', ') : 'none selected'}`, ''];
    for (const st of STAGES) {
      lines.push(`## ${st.title}`, '', st.note, '', '| Operator | Query | Positive result |', '| --- | --- | --- |');
      for (const q of rendered[st.key]) lines.push(`| ${q.op} | \`${q.query.replace(/\|/g, '\\|')}\` | ${q.positive} |`);
      lines.push('');
    }
    lines.push('## Evidence handling', '', '- Screenshot the full viewport including the URL bar, then the source record.', '- Record the retrieval timestamp in UTC and the collector identity.', archiveOn ? '- Archive every live page to web.archive.org/save/ and cite the archive URL, not the live one.' : '- Archiving is off: the finding is only as reproducible as the client’s cache.', '- Hash the raw export; keep the hash in the evidence register.', '');
    return lines.join('\n');
  }, [seedValue, seedDef, objectives, rendered, archiveOn]);

  const toggle = (o: Objective) => setObjectives((prev) => (prev.includes(o) ? prev.filter((x) => x !== o) : [...prev, o]));

  return (
    <>
      <Card title="Seed and objectives" action={<DownloadButton text={report} filename="pivot-plan.md" label="Download .md" />}>
        <div className="grid gap-4 sm:grid-cols-2">
          <Select<Seed> label="Seed entity type" value={seedType} onChange={setSeedType} options={SEEDS.map((s) => ({ value: s.value, label: s.label }))} hint={seedDef.hint} />
          <TextInput label="Seed value" value={seedValue} onChange={setSeedValue} mono placeholder="example.com" hint="Stays local — nothing here is submitted anywhere." />
        </div>
        <div className="mt-4">
          <SectionTitle>Objectives</SectionTitle>
          <div className="grid gap-2 sm:grid-cols-2">
            {OBJECTIVES.map((o) => (
              <Checkbox key={o.value} checked={objectives.includes(o.value)} onChange={() => toggle(o.value)} label={o.label} description={o.blurb} />
            ))}
          </div>
        </div>
        {objectives.length === 0 && (
          <div className="mt-3">
            <Callout tone="warn" title="No objective selected">Pick at least one; the planner shapes stages 2 and 3 from the first selection.</Callout>
          </div>
        )}
      </Card>

      {STAGES.map((st) => (
        <Card key={st.key} title={st.title}>
          <p className="m-0 mb-3 text-[12px] leading-relaxed text-[var(--text-muted)]">{st.note}</p>
          {rendered[st.key].length === 0 ? (
            <div className="rounded border border-dashed border-[var(--card-border)] px-3 py-6 text-center text-[12.5px] text-[var(--text-faint)]">
              Nothing planned for this stage yet — select an objective above.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-[12px]">
                <thead>
                  <tr className="text-left text-[11px] tracking-wide text-[var(--text-faint)] uppercase">
                    <th className="py-1 pr-3 font-medium">Operator</th>
                    <th className="py-1 pr-3 font-medium">Query</th>
                    <th className="py-1 font-medium">Positive result</th>
                  </tr>
                </thead>
                <tbody>
                  {rendered[st.key].map((q) => (
                    <tr key={q.query} className="border-t border-[var(--card-border)] align-top">
                      <td className="py-1 pr-3 whitespace-nowrap text-[var(--text)]">{q.op}</td>
                      <td className="rf-mono py-1 pr-3 break-all text-[var(--text-muted)]">{q.query}</td>
                      <td className="py-1 text-[var(--text-muted)]">{q.positive}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      ))}

      <Card title="Confidence ladder">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr className="text-left text-[11px] tracking-wide text-[var(--text-faint)] uppercase">
                <th className="py-1 pr-3 font-medium">Tier</th>
                <th className="py-1 pr-3 font-medium">Test</th>
                <th className="py-1 font-medium">What you may write</th>
              </tr>
            </thead>
            <tbody>
              {CONFIDENCE.map(([tier, test, use]) => (
                <tr key={tier} className="border-t border-[var(--card-border)] align-top">
                  <td className="py-1 pr-3 whitespace-nowrap text-[var(--text)]">{tier}</td>
                  <td className="py-1 pr-3 text-[var(--text-muted)]">{test}</td>
                  <td className="py-1 text-[var(--text-muted)]">{use}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-3">
          <KVTable rows={[['Stage 1 rows', String(rendered[1].length)], ['Stage 2 rows', String(rendered[2].length)], ['Stage 3 rows', String(rendered[3].length)], ['Highest tier reachable here', 'Corroborated — verification needs a controlled channel']]} />
        </div>
      </Card>

      <Card title="Evidence handling and guardrails">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <Checkbox checked={archiveOn} onChange={setArchiveOn} label="Archive every live page" description="cite web.archive.org/save/ URLs rather than the live ones." />
            <div className="mt-3">
              <Checkbox checked={authorised} onChange={setAuthorised} label="Collection is inside the authorised scope" description="Seed entity is named in the engagement brief or is client-owned." />
            </div>
            <div className="mt-3">
              <Callout tone="info" title="Evidence handling">
                <ul className="m-0 list-disc space-y-1 pl-4">
                  <li>Screenshot full viewport including the URL bar, then the source record itself.</li>
                  <li>Record retrieval time in UTC and the collector identity against every artefact.</li>
                  <li>{archiveOn ? 'Archive the page before citing it; live pages change under you.' : 'No archive policy — reproof depends on the client cache.'}</li>
                  <li>Keep screenshots, exports and hashes in one folder per entity, never reused across engagements.</li>
                </ul>
              </Callout>
            </div>
          </div>
          <div>
            <Callout tone={authorised ? 'ok' : 'warn'} title={authorised ? 'In scope' : 'Scope not confirmed'}>
              Proportionality: collect only what the objective needs. A single-source match is a lead, not an identity — presenting it as one is the most common way an OSINT finding fails review, and the fastest way to harm a person who shares a name.
            </Callout>
            <div className="mt-3">
              <OutputBlock value={report} label="pivot-plan.md" rows={12} />
            </div>
          </div>
        </div>
        <div className="mt-4">
          <SectionTitle>Operator commands (inert)</SectionTitle>
          <CodeBlock
            code={[
              `# stage 1 — direct`,
              `theHarvester -d ${seedValue || '{{SEED}}'} -b crtsh,bing -l 500`,
              `subfinder -d ${seedValue || '{{SEED}}'} -all -silent | httpx -silent -sc -title`,
              `sherlock ${seedValue || '{{SEED}}'} --timeout 10 --print-found`,
              ``,
              `# stage 2 — enrichment`,
              `curl -s https://rdap.org/domain/${seedValue || '{{SEED}}'} | jq '.entities[].vcardArray[1]'`,
              `whatsmyname --username ${seedValue || '{{SEED}}'} --format json`,
              ``,
              `# stage 3 — correlation (manual review, no automation)`,
            ].join('\n')}
            label="commands"
            maxHeight={220}
          />
        </div>
      </Card>
    </>
  );
}
