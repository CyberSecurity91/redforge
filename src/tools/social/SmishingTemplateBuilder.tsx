import { useMemo, useState } from 'react';
import { Callout, Card, Checkbox, DownloadButton, KVTable, OutputBlock, Select, TextInput } from '@/components/ui';

/**
 * Smishing lure builder. The value here is the encoding maths: an SMS that looks
 * like 140 characters can bill as two segments the moment one curly quote lands
 * in the body. Every variant is passed through the real GSM 03.38 septet count
 * and the UCS-2 fallback before it is shown.
 */

type Pretext = 'parcel' | 'payroll' | 'mfa' | 'invoice' | 'hr';
type Tone = 'neutral' | 'urgent' | 'soft';
type Urgency = 'low' | 'medium' | 'high';
type Field = 'first_name' | 'company' | 'deadline' | 'link';

interface PretextDef {
  value: Pretext;
  label: string;
  sender: string;
  detail: string;
  ask: string;
}

const PRETEXTS: PretextDef[] = [
  { value: 'parcel', label: 'Parcel delivery', sender: 'ParcelNet Couriers', detail: 'a parcel addressed to {company} is being held at the local depot', ask: 'book a redelivery window before {deadline} here: {link}' },
  { value: 'payroll', label: 'Payroll change', sender: 'Payroll Services', detail: 'the payroll profile for {company} has an unapproved bank-detail change', ask: 'confirm or reject it before {deadline} at {link}' },
  { value: 'mfa', label: 'MFA reset', sender: 'IT Service Desk', detail: 'an MFA reset was requested for {first_name}’s {company} account', ask: 'if this was not you, re-secure the account before {deadline}: {link}' },
  { value: 'invoice', label: 'Unpaid invoice', sender: 'Accounts Receivable', detail: 'invoice INV-4471 raised against {company} is showing as unpaid', ask: 'settle or dispute it before {deadline} at {link}' },
  { value: 'hr', label: 'HR policy', sender: 'People Team', detail: 'the {company} HR policy acknowledgement is outstanding for {first_name}', ask: 'read and sign it before {deadline} using {link}' },
];

const URGENCY_TAIL: Record<Urgency, string> = {
  low: '',
  medium: ' This link is single-use.',
  high: ' Final notice: the item is released after {deadline}.',
};

const URGENCY_OPTIONS: Array<{ value: Urgency; label: string }> = [
  { value: 'low', label: 'Low — no time pressure' },
  { value: 'medium', label: 'Medium — single-use link' },
  { value: 'high', label: 'High — final notice' },
];

const FIELDS: Array<{ key: Field; label: string; token: string; fallback: string }> = [
  { key: 'first_name', label: 'First name', token: '{first_name}', fallback: 'there' },
  { key: 'company', label: 'Company', token: '{company}', fallback: 'your organisation' },
  { key: 'deadline', label: 'Deadline', token: '{deadline}', fallback: 'the stated deadline' },
  { key: 'link', label: 'Link', token: '{link}', fallback: 'https://go.example.com/p/{{slug}}' },
];

/* GSM 03.38 default alphabet (1 septet) and the extension table (2 septets each). */
const GSM_BASIC =
  '@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !"#¤%&\'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà';
const GSM_EXT = '\f^{}\\[~]|€';

export default function SmishingTemplateBuilder() {
  const [pretext, setPretext] = useState<Pretext>('parcel');
  const [senderLabel, setSenderLabel] = useState('ParcelNet Couriers');
  const [urgency, setUrgency] = useState<Urgency>('medium');
  const [shortLink, setShortLink] = useState('https://go.example.com/p/{{slug}}');
  const [first, setFirst] = useState('Alex');
  const [company, setCompany] = useState('Northwind Logistics');
  const [deadline, setDeadline] = useState('17:00 today');
  const [fields, setFields] = useState<Record<Field, boolean>>({
    first_name: true,
    company: true,
    deadline: true,
    link: true,
  });

  const def = PRETEXTS.find((p) => p.value === pretext) ?? PRETEXTS[0]!;

  const variants = useMemo(() => {
    const sub = (s: string) =>
      s
        .replaceAll('{first_name}', fields.first_name ? first.trim() || 'there' : 'there')
        .replaceAll('{company}', fields.company ? company.trim() || 'your organisation' : 'your organisation')
        .replaceAll(
          '{deadline}',
          fields.deadline ? deadline.trim() || 'the stated deadline' : 'the stated deadline',
        )
        .replaceAll('{link}', fields.link ? shortLink.trim() || 'https://go.example.com/p/{{slug}}' : '');

    const detail = sub(def.detail);
    const ask = fields.link ? sub(def.ask) : '';
    const tail = sub(URGENCY_TAIL[urgency]);
    const greeting = fields.first_name && first.trim() ? `Hi ${first.trim()}, ` : '';
    const compose = (head: string) => (ask ? `${head} ${ask}` : head).replace(/\s+/g, ' ').trim();

    const list: Array<{ tone: Tone; label: string; text: string }> = [
      {
        tone: 'neutral',
        label: 'Neutral — transactional',
        text: compose(`${greeting}${greeting ? lowerFirst(detail) : capFirst(detail)}.`),
      },
      {
        tone: 'urgent',
        label: 'Time-pressured — deadline',
        text: compose(`Action required: ${detail}.${tail}`),
      },
      {
        tone: 'soft',
        label: 'Conciliatory — low pressure',
        text: compose(`${greeting || 'Quick note — '}${greeting ? lowerFirst(detail) : detail}.`),
      },
    ];

    return list.map((v) => ({ ...v, audit: auditText(v.text) }));
  }, [def, fields, first, company, deadline, shortLink, urgency]);

  const forced = useMemo(() => {
    const seen = new Set<string>();
    for (const v of variants) for (const f of v.audit.forced) seen.add(f);
    return Array.from(seen);
  }, [variants]);

  const senderMerged = useMemo(
    () => senderLabel.replaceAll('{company}', fields.company ? company.trim() : 'your organisation'),
    [senderLabel, company, fields.company],
  );

  const doc = useMemo(() => {
    const lines = [
      `# SMS lure set — ${def.label}`,
      '',
      '> Authorised simulation only. Every recipient must be on the approved target list and inside the engagement window.',
      '',
      `Sender label: ${senderMerged || '—'}`,
      `Short link: ${shortLink || '—'}`,
      `Urgency: ${urgency}`,
      `Merge fields in use: ${FIELDS.filter((f) => fields[f.key]).map((f) => f.token).join(' ') || 'none'}`,
      '',
    ];
    variants.forEach((v, i) => {
      lines.push(
        `## Variant ${i + 1} — ${v.label}`,
        '',
        '```text',
        v.text,
        '```',
        '',
        `Encoding: ${v.audit.encoding} · ${v.audit.chars} character(s), ${v.audit.used} ${v.audit.encoding === 'GSM-7' ? 'septets' : 'UTF-16 units'} · **${v.audit.segments} segment(s)** · ${v.audit.remaining} left in the last part`,
        '',
      );
    });
    lines.push(
      '## Reporting path',
      '',
      '- Publish the report route before the first send: the client mailbox, the SOC queue and the internal chat channel.',
      '- Every recipient who reports the message is a control success. They get a thank-you, never a remedial briefing.',
      '- Track report rate separately from click rate — a lure with 30% clicks and 0% reports is a worse result than 5% clicks and 12% reports.',
      '- Record the exact sender string, the short-link slug and the send timestamp, so reports can be matched to the wave.',
      '',
      '## Authorisation and evidence',
      '',
      '- Engagement {{ENGAGEMENT_ID}}, approved by {{APPROVER}} on {{DATE}}, scope {{TARGET_LIST}}.',
      '- Short-link domain registered for the exercise only, and taken down at the end of the window.',
      '- Message bodies, send logs and click records retained per the engagement data-handling schedule.',
    );
    return lines.join('\n');
  }, [def.label, senderMerged, shortLink, urgency, fields, variants]);

  const toggle = (key: Field) => setFields((prev) => ({ ...prev, [key]: !prev[key] }));

  return (
    <>
      <Card title="Lure setup">
        <div className="grid gap-3 sm:grid-cols-2">
          <Select<Pretext> label="Pretext" value={pretext} onChange={setPretext} options={PRETEXTS.map((p) => ({ value: p.value, label: p.label }))} />
          <TextInput label="Sender label" value={senderLabel} onChange={setSenderLabel} hint={`default: ${def.sender}`} placeholder={def.sender} />
          <Select<Urgency>
            label="Urgency level"
            value={urgency}
            onChange={setUrgency}
            options={URGENCY_OPTIONS}
          />
          <TextInput label="Short-link placeholder" value={shortLink} onChange={setShortLink} mono hint="placeholder host only" />
        </div>
        <div className="mt-3">
          <Callout tone="info" title="Merged sender">
            <span className="rf-mono">{senderMerged || '—'}</span> — the label is what the handset shows. A sender
            string that does not fit 11 characters, or that is not a shortcode, will render as a scrambled number on
            some handsets.
          </Callout>
        </div>
      </Card>

      <Card title="Merge fields">
        <div className="grid gap-4 sm:grid-cols-2">
          {FIELDS.map((f) => (
            <div key={f.key}>
              <Checkbox
                checked={fields[f.key]}
                onChange={() => toggle(f.key)}
                label={f.label}
                description={`token ${f.token}${fields[f.key] ? '' : ` — falls back to "${f.fallback}"`}`}
              />
              <div className="mt-1.5">
                {f.key === 'first_name' && <TextInput label="Sample value" value={first} onChange={setFirst} mono />}
                {f.key === 'company' && <TextInput label="Sample value" value={company} onChange={setCompany} mono />}
                {f.key === 'deadline' && <TextInput label="Sample value" value={deadline} onChange={setDeadline} mono />}
                {f.key === 'link' && <TextInput label="Sample value" value={shortLink} onChange={setShortLink} mono disabled />}
              </div>
            </div>
          ))}
        </div>
        {!fields.link && (
          <div className="mt-3">
            <Callout tone="warn" title="No link in the lure">
              With the link field off the ask sentence is dropped entirely, so the message collects no clicks. That is
              a legitimate no-link pretext test, but it measures reporting behaviour only.
            </Callout>
          </div>
        )}
      </Card>

      <Card
        title="Three tone variants"
        action={<DownloadButton text={doc} filename="smishing-variants.md" label="Download .md" />}
      >
        <div className="space-y-3">
          {variants.map((v) => (
            <div key={v.tone} className="rounded border border-[var(--card-border)] px-3 py-2.5">
              <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
                <span className="text-[12.5px] font-medium text-[var(--text)]">{v.label}</span>
                <span className="flex items-center gap-1.5">
                  <span
                    className="rounded-full px-2 py-[1px] text-[10.5px] font-medium"
                    style={{
                      backgroundColor: 'var(--neutral-btn)',
                      color: v.audit.encoding === 'GSM-7' ? 'var(--ok)' : 'var(--warn)',
                    }}
                  >
                    {v.audit.encoding}
                  </span>
                  <span className="rf-mono text-[11px] text-[var(--text-faint)]">
                    {v.audit.segments} segment{v.audit.segments === 1 ? '' : 's'} · {v.audit.used}/{v.audit.limit}
                  </span>
                </span>
              </div>
              <p className="m-0 text-[12.5px] leading-relaxed text-[var(--text-muted)]">{v.text}</p>
            </div>
          ))}
        </div>
        <div className="mt-4">
          <OutputBlock value={doc} label="smishing-variants.md" rows={12} />
        </div>
      </Card>

      <Card title="Encoding audit">
        <KVTable
          rows={[
            ['Variants generated', String(variants.length)],
            [
              'Worst-case segments',
              String(Math.max(...variants.map((v) => v.audit.segments))),
            ],
            ['GSM-7 budget', '160 septets single, 153 per part once concatenated (7 for the UDH)'],
            ['UCS-2 budget', '70 UTF-16 units single, 67 per part concatenated'],
            ['Characters forcing UCS-2', forced.length ? forced.join(', ') : 'none — all three fit the GSM alphabet'],
            ['Total characters', String(variants.reduce((n, v) => n + v.audit.chars, 0))],
          ]}
        />
        <div className="mt-3 space-y-3">
          {forced.length > 0 ? (
            <Callout tone="warn" title="UCS-2 forced">
              One character outside the GSM 03.38 alphabet moves the whole message to UCS-2, where a single part holds
              70 characters instead of 160. Curly quotes, emoji and accented letters are the usual culprits — each
              variant above is already costed at the reduced budget.
            </Callout>
          ) : (
            <Callout tone="ok" title="GSM-7 throughout">
              All three variants stay in the 7-bit alphabet. Keep the copy ASCII and straight-quoted when you edit it,
              or the segment count in this panel will jump on the next keystroke.
            </Callout>
          )}
          <Callout tone="danger" title="Reporting and authorisation">
            Send only to the approved list, inside the window, from a number and short-link domain registered for the
            exercise. Recipients who report the message are the control working as intended — thank them and log the
            report timestamp. Any real credential entered into the landing page must be dropped without replay, and
            the target told what was captured.
          </Callout>
        </div>
      </Card>
    </>
  );
}

interface Audit {
  encoding: 'GSM-7' | 'UCS-2';
  chars: number;
  used: number;
  limit: number;
  segments: number;
  remaining: number;
  forced: string[];
}

function septetCount(text: string): number | null {
  let n = 0;
  for (const ch of text) {
    if (GSM_BASIC.includes(ch)) n += 1;
    else if (GSM_EXT.includes(ch)) n += 2;
    else return null;
  }
  return n;
}

function nonGsm(text: string): string[] {
  const out: string[] = [];
  for (const ch of text) {
    if (GSM_BASIC.includes(ch) || GSM_EXT.includes(ch)) continue;
    const label = `${ch} (U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')})`;
    if (!out.includes(label)) out.push(label);
  }
  return out;
}

function auditText(text: string): Audit {
  const chars = [...text].length;
  const septets = septetCount(text);
  if (septets !== null) {
    const single = septets <= 160;
    const limit = single ? 160 : 153;
    const segments = single ? 1 : Math.ceil(septets / 153);
    return { encoding: 'GSM-7', chars, used: septets, limit, segments, remaining: segments * limit - septets, forced: [] };
  }
  // UCS-2 counts UTF-16 code units, so an emoji costs two.
  const units = text.length;
  const single = units <= 70;
  const limit = single ? 70 : 67;
  const segments = single ? 1 : Math.ceil(units / 67);
  return { encoding: 'UCS-2', chars, used: units, limit, segments, remaining: segments * limit - units, forced: nonGsm(text) };
}

function capFirst(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function lowerFirst(s: string): string {
  return s.charAt(0).toLowerCase() + s.slice(1);
}
