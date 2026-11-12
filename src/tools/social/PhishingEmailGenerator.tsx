import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  DownloadButton,
  KVTable,
  OutputBlock,
  Select,
  TextArea,
  TextInput,
} from '@/components/ui';
import { PHISHING_HOOKS, PRETEXT_PROFILES } from '@/lib/redteam-data';

/**
 * Lure copy composer for authorised phishing simulations. Produces the message
 * body, three subject variants and the header set worth testing — plus the
 * "what a trained user spots" card, which is the actual deliverable of a
 * simulation: the training value lives in the tell, not the click.
 */

type Tone = 'urgent' | 'neutral' | 'friendly';
type Channel = 'email' | 'teams' | 'sms';

const TONES: Array<{ value: Tone; label: string }> = [
  { value: 'urgent', label: 'Urgent — deadline pressure' },
  { value: 'neutral', label: 'Neutral — procedural' },
  { value: 'friendly', label: 'Friendly — colleague-to-colleague' },
];

const CHANNELS: Array<{ value: Channel; label: string }> = [
  { value: 'email', label: 'Email' },
  { value: 'teams', label: 'Teams / Slack direct message' },
  { value: 'sms', label: 'SMS' },
];

const SIGN_OFFS: Record<Tone, string> = {
  urgent: 'This needs doing today — the queue closes at 17:00.',
  neutral: 'No rush, but the system will close the request in 48 hours.',
  friendly: 'Sorry to be a pain — easier to sort now than re-file it later.',
};

function subjects(hook: string, org: string, tone: Tone): string[] {
  const core = hook.replace(/^Action required:\s*/i, '');
  const short = core.split(/[—-]/)[0].trim().slice(0, 58);
  const byTone: Record<Tone, string[]> = {
    urgent: [`Action required: ${short}`, `[${org}] 24h notice — ${short}`, `Final reminder: ${short}`],
    neutral: [`${short} — ${org} IT`, `You have 1 new item: ${short}`, `${org}: please review ${short.toLowerCase()}`],
    friendly: [`Quick one: ${short}`, `Hi {{FirstName}} — ${short.toLowerCase()}`, `${short} (takes 30 seconds)`],
  };
  return byTone[tone].map((s) => s.replace(/\s+/g, ' ').trim());
}

export default function PhishingEmailGenerator() {
  const [org, setOrg] = useState('Northwind Freight Ltd');
  const [domain, setDomain] = useState('login.example.com');
  const [persona, setPersona] = useState(PRETEXT_PROFILES[0]);
  const [hook, setHook] = useState(PHISHING_HOOKS[0]);
  const [deadline, setDeadline] = useState('today at 17:00');
  const [tone, setTone] = useState<Tone>('urgent');
  const [channel, setChannel] = useState<Channel>('email');
  const [senderName, setSenderName] = useState('IT Service Desk');
  const [replyTo, setReplyTo] = useState(true);
  const [trackPixel, setTrackPixel] = useState(true);

  const subjectLines = useMemo(() => subjects(hook, org || 'TARGET', tone), [hook, org, tone]);

  const preheader = useMemo(() => {
    const base = hook.replace(/^Action required:\s*/i, '').toLowerCase();
    return `${base.charAt(0).toUpperCase()}${base.slice(1)} — resolves in under a minute. Request ${org ? org.slice(0, 3).toUpperCase() : 'TGT'}-{{TicketID}}.`;
  }, [hook, org]);

  const cta = useMemo(
    () =>
      ({
        urgent: ['Restore access now', 'Confirmit in 30 seconds', 'Re-authenticate to continue'],
        neutral: ['Open the request', 'Review the item', 'View in portal'],
        friendly: ['Take a look', 'Check this when you get a sec', 'Approve from here'],
      })[tone][0],
    [tone],
  );

  const bodyPt = useMemo(() => {
    const greet = { urgent: 'Dear {{FirstName}},', neutral: 'Hello {{FirstName}},', friendly: 'Hi {{FirstName}},' }[tone];
    return [
      greet,
      '',
      `Our records show your ${persona.toLowerCase()} task for {{Department}} is still open and closes ${deadline}.`,
      '',
      `${hook}.`,
      '',
      `To clear it, sign in with your work account here:`,
      '',
      `  https://${domain || 'login.example.com'}/s/{{TicketID}}`,
      '',
      SIGN_OFFS[tone],
      '',
      `${senderName} · ${org}`,
      `Ref: {{TicketID}}`,
      '',
      '—',
      'This message was sent to {{Email}} as part of a scheduled security awareness simulation.',
      'If you clicked, nothing has been recorded against your name. Report it with the Phish button.',
    ].join('\n');
  }, [tone, persona, deadline, hook, domain, senderName, org]);

  const bodyHtml = useMemo(() => {
    const lines = bodyPt.split('\n').filter((l) => l.trim() !== '');
    const greet = lines.shift() ?? '';
    const bom = lines.pop() ?? '';
    const rest = lines
      .filter((l) => !l.includes('@') && !l.startsWith('Ref:'))
      .map((l) => {
        if (l.includes('https://')) {
          return `      <p style="margin:0 0 16px"><a href="{{LandingUrl}}" style="display:inline-block;background:#e11d2a;color:#fff;padding:10px 18px;border-radius:4px;text-decoration:none;font:600 14px system-ui">${cta}</a></p>`;
        }
        return `      <p style="margin:0 0 12px;font:14px/1.6 system-ui;color:#24292f">${l.replace(/&/g, '&amp;').replace(/</g, '&lt;')}</p>`;
      });
    return [
      '<!doctype html>',
      '<html><body style="margin:0;background:#f6f8fa;padding:24px">',
      '  <table role="presentation" width="600" style="margin:0 auto;background:#fff;border:1px solid #d0d7de;border-radius:6px">',
      '    <tr><td style="padding:24px">',
      `      <p style="margin:0 0 16px;font:14px/1.6 system-ui;color:#24292f">${greet}</p>`,
      ...rest,
      `      <p style="margin:0 0 8px;font:12px/1.6 system-ui;color:#57606a">${signatureLine(senderName, org)}</p>`,
      '    </td></tr>',
      '  </table>',
      `  <p style="max-width:600px;margin:12px auto 0;font:11px/1.5 system-ui;color:#8c959f">${bom}</p>`,
      ...(trackPixel ? ['  <!-- open-tracking pixel slot: insert your OAST URL here at send time -->'] : []),
      '</body></html>',
    ].join('\n');
  }, [bodyPt, cta, senderName, org, trackPixel]);

  const headers = useMemo(
    () => [
      `From: "${senderName}" <it-service@${domain.replace(/^[^.]+\./, '') || 'mail.example.com'}>`,
      replyTo ? `Reply-To: it-service@example.com` : `Reply-To: (same as From — leave aligned)`,
      `Return-Path: bounce@example.com`,
      `To: {{Email}}`,
      `Subject: ${subjectLines[0]}`,
      `Message-ID: <{{TicketID}}@example.com>`,
      `X-Mailer: (empty — a real mail client's absence is a tell)`,
      `Precedence: bulk   # remove unless the mail is genuinely bulk`,
    ],
    [senderName, domain, replyTo, subjectLines],
  );

  const posture = useMemo<Array<[string, string]>>(
    () => [
      ['SPF', 'Check the sending domain publishes v=spf1 with a policy that includes your relay; a softfail (~all) still delivers to most tenants.'],
      ['DKIM', 'Test with and without a valid selector signature — DMARC alignment is what tenants actually enforce.'],
      ['DMARC', 'p=none logs only; p=quarantine lands in junk on many tenants; p=reject is the only posture that reliably stops header-From spoofing.'],
      ['Display name', 'The display name is not authenticated. Spoofed display name + a lookalike domain is the shape that survives DMARC.'],
      ['Lookalike domain', `Register the assessment domain on a separate registrar; ${domain || 'login.example.com'} must be controlled by the tester, never a real client host.`],
    ],
    [domain],
  );

  const checklist = useMemo(
    () => [
      'Written approval names the simulation window and the target population.',
      'Sending domain registered by the test team and never a lookalike of a real brand you do not own.',
      'Landing page states "security awareness simulation" before any field is rendered.',
      'No credential field is ever posted anywhere — capture the click, not the password.',
      'Opt-out path documented for anyone who replies "take me off this".',
      'SOC notified of the campaign ID so the alert is triaged, not escalated.',
      'Report button coverage measured: which users reported, which clicked, which neither.',
      'Results delivered as aggregate metrics, not a list of "who failed".',
    ],
    [],
  );

  const tells = useMemo<Array<[string, string]>>(
    () => [
      ['Mismatched From display name vs domain', 'Hover the sender; the address does not match the org casing or the dot placement.'],
      ['Generic salutation', 'Mass simulation copy greets with a merge field the sender does not actually hold.'],
      ['Deadline pressure without a business reason', 'A real IT notice names the system and the change ticket.'],
      ['Link target differs from link text', 'Hover reveals a domain that is not the one printed.'],
      ['Unexpected attachment or "sign in here"', 'Any password prompt reached by mail should be treated as hostile until verified out of band.'],
      ['Off-brand formatting', 'Wrong logo resolution, wrong font, missing legal footer.'],
      ['Reply-To on a different domain', 'Legitimate transactional mail is usually aligned.'],
    ],
    [],
  );

  return (
    <>
      <Card title="Campaign parameters">
        <div className="grid gap-3 sm:grid-cols-2">
          <TextInput label="Target organisation" value={org} onChange={setOrg} />
          <TextInput label="Landing domain" value={domain} onChange={setDomain} mono placeholder="login.example.com" />
          <Select<string>
            value={persona}
            onChange={setPersona}
            label="Sender persona"
            options={PRETEXT_PROFILES.map((p) => ({ value: p, label: p }))}
          />
          <Select<string>
            value={hook}
            onChange={setHook}
            label="Hook"
            options={PHISHING_HOOKS.map((h) => ({ value: h, label: h }))}
          />
          <TextInput label="Deadline" value={deadline} onChange={setDeadline} placeholder="today at 17:00" />
          <Select<Tone> value={tone} onChange={setTone} label="Tone" options={TONES} />
          <Select<Channel> value={channel} onChange={setChannel} label="Channel" options={CHANNELS} />
          <TextInput label="Sender display name" value={senderName} onChange={setSenderName} />
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          <Checkbox checked={replyTo} onChange={setReplyTo} label="Mismatched Reply-To" description="Reply lands on example.com" />
          <Checkbox checked={trackPixel} onChange={setTrackPixel} label="Include 1×1 tracking pixel" description="Emits an inert slot — paste your own oast.example.com URL at send time" />
          <Checkbox
            checked={channel === 'email'}
            onChange={(v) => setChannel(v ? 'email' : 'teams')}
            label="Email body variants"
            description="Plain text + HTML"
          />
        </div>
        <div className="mt-3">
          <Callout tone="info" title="Assessment use">
            This composes copy for a simulation authorised by the named client, delivered under a signed RoE. The
            landing page must announce the simulation before any field is rendered and must never post credentials.
          </Callout>
        </div>
      </Card>

      <Card title="Subject lines and preheader">
        <div className="space-y-2">
          {subjectLines.map((s, i) => (
            <div key={i} className="flex items-center gap-2 rounded border border-[var(--card-border)] px-3 py-2">
              <span className="rf-mono text-[11px] text-[var(--text-faint)]">{i + 1}</span>
              <span className="rf-mono text-[12.5px] text-[var(--text)]">{s}</span>
            </div>
          ))}
        </div>
        <div className="mt-3">
          <KVTable
            rows={[
              ['Preheader', preheader],
              ['CTA button', cta],
              ['Channel', CHANNELS.find((c) => c.value === channel)?.label ?? channel],
            ]}
          />
        </div>
      </Card>

      <Card
        title="Message body"
        action={
          <DownloadButton
            text={[`Subject: ${subjectLines[0]}`, '', bodyPt, '', '--- HTML ---', '', bodyHtml].join('\n')}
            filename="phishing-simulation.eml"
            label="Download .eml"
          />
        }
      >
        <div className="space-y-4">
          <OutputBlock value={bodyPt} rows={14} label="Plain text" />
          <CodeBlock code={bodyHtml} label="HTML variant" maxHeight={260} />
        </div>
      </Card>

      <Card title="Headers worth testing">
        <CodeBlock code={headers.join('\n')} label="Header set" maxHeight={220} />
        <div className="mt-3">
          <KVTable rows={posture} />
        </div>
      </Card>

      <Card title="Indicators a trained user would spot">
        <div className="grid gap-2 sm:grid-cols-2">
          {tells.map(([title, detail]) => (
            <div key={title} className="rounded border border-[var(--card-border)] px-3 py-2">
              <div className="mb-1 text-[12.5px] font-medium text-[var(--text)]">{title}</div>
              <p className="m-0 text-[11.5px] leading-relaxed text-[var(--text-muted)]">{detail}</p>
            </div>
          ))}
        </div>
        <div className="mt-4">
          <TextArea
            label="Send checklist"
            value={checklist.map((c, i) => `${i + 1}. ${c}`).join('\n')}
            readOnly
            rows={9}
          />
        </div>
      </Card>
    </>
  );
}

function signatureLine(name: string, org: string): string {
  return `${name} · ${org} · Ref: {{TicketID}}`;
}
