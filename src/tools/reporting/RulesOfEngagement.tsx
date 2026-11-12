import { useMemo, useState } from 'react';
import {
  Button,
  Callout,
  Card,
  CodeBlock,
  DownloadButton,
  KVTable,
  Select,
  Tabs,
  TextArea,
  TextInput,
} from '@/components/ui';
import { RULES_OF_ENGAGEMENT_SECTIONS } from '@/lib/redteam-data';

/**
 * Rules of Engagement document builder. Section headings come from
 * RULES_OF_ENGAGEMENT_SECTIONS so the generated document matches the house
 * template; each heading is seeded with an editable default body.
 */

type Format = 'md' | 'txt';

const SEED: Record<string, string> = {
  Scope:
    'support.example.com (web application, authenticated agent role)\napi.example.com (REST API, v2)\n10.10.14.0/24 — external attack surface only, no internal routing',
  'Out-of-scope':
    'Anything not listed above, including sibling brands and any *.partner.example.com.\nDenial-of-service, load and stress testing of any kind.\nPhysical entry, social engineering of the client’s customers, and any use of real customer data.',
  'Testing windows':
    'Standard window: Monday–Friday 09:00–17:00 UTC.\nOut-of-hours work requires written approval from the engagement contact, 24 hours in advance.\nNo testing on the last two business days of the quarter (change freeze).',
  Contacts:
    'Engagement lead (client): {{ClientLeadName}} — +44 20 7946 0000\nTechnical contact: {{TechContactName}} — +44 20 7946 0001\nEmergency stop, 24/7: {{EmergencyNumber}}\nTester lead: {{TesterLeadName}}',
};

const CLAUSES: Array<[string, string]> = [
  ['Authorisation', 'The client confirms it owns, or is authorised to test, every asset listed in the scope table, and that this authorisation covers third-party hosting arrangements in place at the start date.'],
  ['Method and restraint', 'Testing will be performed with the minimum footprint needed to demonstrate each finding. Where a proof-of-concept would cause state change, the tester will stop at the evidence and record the intended action.'],
  ['Stop conditions', 'Testing halts immediately on client instruction, on discovery of an active compromise by a third party, or on any risk to safety of persons. The tester confirms the stop in writing within one hour.'],
  ['Data handling', 'Any data encountered is minimised, stored encrypted at rest, and destroyed within 30 days of the report being accepted. Personal data is never extracted beyond what is required to demonstrate impact.'],
  ['Credentials', 'Credentials issued for the test are used only on in-scope assets, rotated at the close of the engagement, and listed below with the account and role.'],
  ['Reporting', 'A draft report is delivered within five business days of the last test day. Each finding carries a CVSS v3.1 base vector, reproduction steps and remediation guidance.'],
  ['Confidentiality', 'Both parties treat the engagement, findings and client data as confidential. Neither party publishes without the written consent of the other.'],
  ['Change control', 'Scope, windows or rules change only through the named contacts, acknowledged in writing. A verbal change is not effective.'],
];

const SEVERITIES = [
  { value: 'low', label: 'Critical / High only' },
  { value: 'med', label: 'High and above' },
  { value: 'all', label: 'Every finding, including informational' },
];

export default function RulesOfEngagement() {
  const [client, setClient] = useState('Example Holdings Ltd');
  const [start, setStart] = useState('2025-06-02');
  const [end, setEnd] = useState('2025-06-13');
  const [team, setTeam] = useState('tester-1 (lead), tester-2');
  const [emergency, setEmergency] = useState('+44 20 7946 0099');
  const [format, setFormat] = useState<Format>('md');
  const [escalation, setEscalation] = useState('med');
  const [creds, setCreds] = useState('agent01@example.com — standard agent role, MFA bypassed for testing\napi-client-test — read-only API token');
  const [sections, setSections] = useState<Record<string, string>>(SEED);

  const scopeLines = useMemo(
    () => (sections.Scope ?? '').split('\n').map((s) => s.trim()).filter(Boolean),
    [sections],
  );
  const oosLines = useMemo(
    () => (sections['Out-of-scope'] ?? '').split('\n').map((s) => s.trim()).filter(Boolean),
    [sections],
  );

  const document = useMemo(() => {
    if (format === 'txt') return renderPlain();
    return renderMarkdown();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, start, end, team, emergency, format, escalation, creds, sections, scopeLines, oosLines]);

  function header(): string[] {
    return [
      `Client: ${client}`,
      `Engagement window: ${start} to ${end}`,
      `Tester team: ${team}`,
      `Emergency stop: ${emergency}`,
    ];
  }

  function renderMarkdown(): string {
    const out: string[] = [
      `# Rules of Engagement — ${client}`,
      '',
      `**Document version:** 1.0 · **Issued:** ${new Date().toISOString().slice(0, 10)}`,
      '',
      '| Field | Value |',
      '| --- | --- |',
      `| Client | ${client} |`,
      `| Start date | ${start} |`,
      `| End date | ${end} |`,
      `| Tester team | ${team} |`,
      `| Emergency contact | ${emergency} |`,
      `| Reporting threshold | ${SEVERITIES.find((s) => s.value === escalation)?.label ?? escalation} |`,
      '',
      '## 1. Scope summary',
      '',
      '| # | In-scope asset | Category | Testing window |',
      '| --- | --- | --- | --- |',
      ...scopeLines.map((a, i) => `| ${i + 1} | ${esc(a)} | ${categoryOf(a)} | ${start} → ${end}, 09:00–17:00 UTC |`),
      '',
      '### Explicitly out of scope',
      '',
      ...(oosLines.length ? oosLines.map((l) => `- ${l}`) : ['- _None recorded — state at least one exclusion._']),
      '',
      '## 2. Clauses',
      '',
      ...CLAUSES.flatMap(([title, body], i) => [`### 2.${i + 1} ${title}`, '', body, '']),
      '## 3. Section detail',
      '',
      ...RULES_OF_ENGAGEMENT_SECTIONS.flatMap(([heading, hint], i) => [
        `### 3.${i + 1} ${heading}`,
        '',
        `_${hint}_`,
        '',
        sections[heading]?.trim() || '_Not completed._',
        '',
      ]),
      '## 4. Credentials handed over',
      '',
      fence(creds),
      '',
      '## 5. Data handling',
      '',
      sections['Data handling']?.trim() || 'Encrypted at rest, destroyed 30 days after report acceptance.',
      '',
      '## 6. Sign-off',
      '',
      '| Party | Name | Role | Signature | Date |',
      '| --- | --- | --- | --- | --- |',
      '| Client | | | | |',
      '| Client (technical) | | | | |',
      `| Tester lead | ${team.split(',')[0]?.trim() ?? ''} | Engagement lead | | |`,
      '| Tester (second) | | | | |',
      '',
      '---',
      '',
      `_Generated offline · ${header().join(' · ')}_`,
    ];
    return out.join('\n');
  }

  function renderPlain(): string {
    const rule = '='.repeat(72);
    const out: string[] = [
      rule,
      `RULES OF ENGAGEMENT — ${client.toUpperCase()}`,
      rule,
      '',
      ...header(),
      `Reporting threshold: ${SEVERITIES.find((s) => s.value === escalation)?.label ?? escalation}`,
      '',
      '1. SCOPE SUMMARY',
      '-'.repeat(72),
      ...scopeLines.map((a, i) => `  ${String(i + 1).padStart(2, '0')}. ${a}  [${categoryOf(a)}]`),
      '',
      '  OUT OF SCOPE',
      ...(oosLines.length ? oosLines.map((l) => `   - ${l}`) : ['   - (none recorded)']),
      '',
      '2. CLAUSES',
      '-'.repeat(72),
      ...CLAUSES.flatMap(([title, body], i) => [`  2.${i + 1} ${title}`, ...wrap(body, 68, '       '), '']),
      '3. SECTION DETAIL',
      '-'.repeat(72),
      ...RULES_OF_ENGAGEMENT_SECTIONS.flatMap(([heading], i) => [
        `  3.${i + 1} ${heading}`,
        ...wrap(sections[heading]?.trim() || '(not completed)', 68, '       '),
        '',
      ]),
      '4. CREDENTIALS HANDED OVER',
      '-'.repeat(72),
      ...creds.split('\n').map((c) => `  ${c}`),
      '',
      '5. DATA HANDLING',
      '-'.repeat(72),
      ...wrap(sections['Data handling']?.trim() || 'Encrypted at rest, destroyed 30 days after report acceptance.', 68, '  '),
      '',
      '6. SIGN-OFF',
      '-'.repeat(72),
      '  Client name: ______________________  Signature: ____________________  Date: __________',
      '  Client tech: ______________________  Signature: ____________________  Date: __________',
      `  Tester lead: ${(team.split(',')[0] ?? '').trim().padEnd(21, '_')}  Signature: ____________________  Date: __________`,
      '',
      rule,
    ];
    return out.join('\n');
  }

  return (
    <>
      <Card title="Engagement">
        <div className="grid gap-3 sm:grid-cols-2">
          <TextInput label="Client" value={client} onChange={setClient} />
          <TextInput label="Emergency contact" value={emergency} onChange={setEmergency} mono />
          <TextInput label="Start date" value={start} onChange={setStart} type="date" />
          <TextInput label="End date" value={end} onChange={setEnd} type="date" />
          <TextInput label="Tester team" value={team} onChange={setTeam} />
          <Select label="Report threshold" value={escalation} onChange={setEscalation} options={SEVERITIES} />
        </div>
        <div className="mt-3">
          <Callout tone="info" title="Seed the template, then edit it">
            Section bodies below start from the house template. Every change here is reflected in the document —
            including the scope table, which is generated from the in-scope textarea.
          </Callout>
        </div>
      </Card>

      <Card title="Sections">
        <div className="space-y-3">
          {RULES_OF_ENGAGEMENT_SECTIONS.map(([heading, hint]) => (
            <TextArea
              key={heading}
              label={heading}
              hint={hint}
              value={sections[heading] ?? ''}
              onChange={(v) => setSections((prev) => ({ ...prev, [heading]: v }))}
              rows={heading === 'Contacts' ? 3 : 4}
            />
          ))}
          <TextArea label="Credentials handed over" value={creds} onChange={setCreds} rows={3} />
          <TextArea
            label="Data handling"
            value={sections['Data handling'] ?? ''}
            onChange={(v) => setSections((prev) => ({ ...prev, 'Data handling': v }))}
            rows={3}
          />
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button size="sm" variant="outline" onClick={() => setSections(SEED)}>
            Reset to template
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setSections((prev) => ({ ...prev, 'Out-of-scope': `${prev['Out-of-scope'] ?? ''}\nThird-party SaaS tenants not named in this document.` }))}
          >
            Add a catch-all exclusion
          </Button>
        </div>
      </Card>

      <Card
        title="Scope summary"
        action={<Tabs<Format> value={format} onChange={setFormat} tabs={[{ value: 'md', label: 'Markdown' }, { value: 'txt', label: 'Plain text' }]} />}
      >
        <KVTable
          rows={[
            ['In-scope assets', String(scopeLines.length)],
            ['Explicit exclusions', String(oosLines.length)],
            ['Clauses', String(CLAUSES.length)],
            ['Window', `${start} → ${end}`],
          ]}
        />
      </Card>

      <Card
        title="Document"
        action={<DownloadButton text={document} filename={`roe-${slug(client) || 'engagement'}.${format === 'md' ? 'md' : 'txt'}`} label="Download" />}
      >
        <CodeBlock code={document} label={`roe.${format === 'md' ? 'md' : 'txt'}`} maxHeight={460} />
      </Card>
    </>
  );
}

function esc(s: string): string {
  return s.replace(/\|/g, '\\|');
}

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
}

function categoryOf(asset: string): string {
  if (/\d+\.\d+\.\d+\.\d+/.test(asset)) return 'Network range';
  if (/^https?:\/\//i.test(asset)) return 'Web';
  if (/^api\./i.test(asset) || /api/i.test(asset)) return 'API';
  if (/@/.test(asset)) return 'Account';
  return 'Web';
}

function fence(body: string): string {
  const t = body.trim();
  return t ? ['```text', t, '```'].join('\n') : '_No credentials issued._';
}

function wrap(text: string, width: number, indent: string): string[] {
  const out: string[] = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) {
      out.push('');
      continue;
    }
    let cur = '';
    for (const word of line.split(/\s+/)) {
      if ((cur + ' ' + word).trim().length > width) {
        out.push(indent + cur.trim());
        cur = word;
      } else {
        cur = `${cur} ${word}`;
      }
    }
    if (cur.trim()) out.push(indent + cur.trim());
  }
  return out;
}
