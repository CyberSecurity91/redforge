import { useMemo, useState } from 'react';
import { Button, Callout, Card, CodeBlock, DownloadButton, KVTable, OutputBlock, Select, TextArea, TextInput } from '@/components/ui';

/**
 * Persona + pretext script builder. The output is a rehearsal document: opening
 * line, objection handling matrix, ask ladder and the log a tester must keep.
 * Cialdini levers are exposed as a select because the lever drives the wording.
 */

type Lever = 'authority' | 'urgency' | 'scarcity' | 'socialproof' | 'liking' | 'reciprocity';
type Channel = 'phone' | 'email' | 'sms' | 'inperson';

const LEVERS: Array<{ value: Lever; label: string }> = [
  { value: 'authority', label: 'Authority — "this is the service desk"' },
  { value: 'urgency', label: 'Urgency — account closes in an hour' },
  { value: 'scarcity', label: 'Scarcity — only two licence slots left' },
  { value: 'socialproof', label: 'Social proof — "your team already did this"' },
  { value: 'liking', label: 'Liking — shared team, shared office' },
  { value: 'reciprocity', label: 'Reciprocity — "I fixed your ticket yesterday"' },
];

const CHANNELS: Array<{ value: Channel; label: string }> = [
  { value: 'phone', label: 'Phone (vishing)' },
  { value: 'email', label: 'Email' },
  { value: 'sms', label: 'SMS' },
  { value: 'inperson', label: 'In person (tailgating / desk drop)' },
];

const LEVER_OPENER: Record<Lever, string> = {
  authority: 'Hi, this is {{OperatorName}} from the {{Team}} service desk — I need two minutes on the {{System}} migration.',
  urgency: 'Hi, this is {{OperatorName}}, I have {{System}} down for your group in under an hour — I need to verify one thing before it goes.',
  scarcity: 'Hi, {{OperatorName}} from IT — your team has two of the last {{System}} seats and I need to confirm you want one.',
  socialproof: 'Hi, {{OperatorName}} from IT — {{PeerName}} in your team already completed this, you are the last one on the list.',
  liking: 'Hi, {{OperatorName}} — we sat on the same floor at the {{Office}} for about a year, not sure you remember me.',
  reciprocity: 'Hi, {{OperatorName}} from IT — I cleared the {{TicketRef}} ticket for you yesterday and I need one thing to close it.',
};

const OBJECTIONS: Array<[string, string]> = [
  ['Can you email me instead?', 'Of course — what address should I use? I ask because half your group is on the old domain list.'],
  ['I was told not to give details over the phone.', 'Completely right, and I should have led with the reference. It is {{TicketRef}} — you can check it in the portal while I hold.'],
  ['Who is your manager?', 'Fair question — {{EscalationName}} on the infrastructure side. I can have them call you back, but the window closes at 17:00.'],
  ['I do not recognise your name.', 'That is expected — our team was extended with contractors for this migration. Happy to route through {{PeerName}} if you prefer.'],
  ['This feels like a phishing test.', 'Good instinct, honestly. The report button is the right call if you are unsure — I would rather be reported than have you click something real.'],
];

const RED_FLAGS: string[] = [
  'Target asks you to hold while they verify — the hold is a check, not consent.',
  'Target quotes a policy you did not know existed; you are now the subject of a control.',
  'Target gives you a name you did not have — you have data leakage, not rapport.',
  'Target insists on email-only contact; drop the voice channel rather than argue.',
  'Target is a new joiner with no ticket history; any detail you offer is unconfirmable.',
  'Call reaches a switchboard, not a person — switchboard transcripts get retained.',
];

const LOG_FIELDS: string[] = [
  'Timestamp (UTC) of the first and last contact attempt.',
  'Channel, caller ID presented and any number reached.',
  'Persona used, lever used, and the exact opening line delivered.',
  'Target identifier (employee ID or name as given) — never their password if volunteered.',
  'Outcome: no answer / refused / partial detail / full ask granted.',
  'Any information volunteered by the target, quoted verbatim.',
  'Control effectiveness observed: challenge, callback verification, report to SOC.',
  'Recording reference if the ROI permits voice capture, else "no recording".',
];

export default function PretextBuilder() {
  const [role, setRole] = useState('IT service desk contractor');
  const [lever, setLever] = useState<Lever>('authority');
  const [channel, setChannel] = useState<Channel>('phone');
  const [department, setDepartment] = useState('Finance');
  const [system, setSystem] = useState('the expense platform');
  const [ticket, setTicket] = useState('INC-{{TicketID}}');
  const [ask, setAsk] = useState('confirm the mailbox alias and the on-call mobile number');
  const [fallback, setFallback] = useState('confirm only the account display name');
  const [opening, setOpening] = useState('');

  const resolvedOpening = useMemo(() => {
    const base = opening.trim() || LEVER_OPENER[lever];
    return base
      .replace(/\{\{Team\}\}/g, role)
      .replace(/\{\{System\}\}/g, system)
      .replace(/\{\{TicketRef\}\}/g, ticket);
  }, [opening, lever, role, system, ticket]);

  const script = useMemo(() => {
    return [
      `# Pretext script — ${department} via ${CHANNELS.find((c) => c.value === channel)?.label ?? channel}`,
      '',
      `Persona: ${role}`,
      `Lever: ${LEVERS.find((l) => l.value === lever)?.label ?? lever}`,
      `Ticket reference: ${ticket}`,
      '',
      '## Opening',
      resolvedOpening,
      '',
      '## Build',
      `"I am working through ${department} accounts for ${system} and your name came up on the`,
      `list with an open item. Before I change anything I want to confirm I have the right person —`,
      `is now still an okay time for two minutes?"`,
      '',
      '## Ask (primary)',
      `"What I need is to ${ask}."`,
      '',
      '## Ask (fallback)',
      `"If that is awkward, I can close it with just the ${fallback} and follow the rest up by mail."`,
      '',
      '## Objection handling',
      ...OBJECTIONS.map(([q, a]) => `- Target: "${q}"\n  You: "${a.replace(/\{\{TicketRef\}\}/g, ticket).replace(/\{\{OperatorName\}\}/g, '{{OperatorName}}')}"`),
      '',
      '## Exit lines (use these; do not improvise an exit)',
      '- Success: "That is all I needed — you will get a confirmation mail with the ticket number."',
      '- Partial: "I have enough to move it, thank you. Anything missing I will follow up by mail."',
      '- Bail: "Looks like the system just locked the queue — I will come back to you later today."',
      '- Challenge: "Fair enough — report it. If it turns out it was me you will see the ticket update."',
      '',
      '## Red flags to stop on',
      ...RED_FLAGS.map((f) => `- ${f}`),
    ].join('\n');
  }, [department, channel, role, lever, ticket, resolvedOpening, system, ask, fallback]);

  const callFlow = useMemo(
    () => [
      `1. Pre-call (2 min) — confirm the target still sits in ${department}, note their manager and one current ticket.`,
      '2. Gatekeeper — give a name and a ticket reference; ask for the target by first name only.',
      '3. Opening — one sentence, then a question. Never a monologue longer than 15 seconds.',
      '4. Verification theatre — offer the ticket reference before being asked; refusing to give it is the loudest tell.',
      '5. Ask — one item at a time. After each answer, paraphrase it back.',
      '6. Fallback — reduce the ask to a single low-value fact rather than repeat the original.',
      '7. Exit — on your terms, with a reference the target can look up afterwards.',
      '8. Log within 10 minutes — memory degrades fast and quotes are useless when paraphrased.',
    ],
    [department],
  );

  return (
    <>
      <Card title="Persona">
        <div className="grid gap-3 sm:grid-cols-2">
          <TextInput label="Role / cover identity" value={role} onChange={setRole} />
          <Select<Lever> value={lever} onChange={setLever} label="Authority lever" options={LEVERS} />
          <Select<Channel> value={channel} onChange={setChannel} label="Channel" options={CHANNELS} />
          <TextInput label="Target department" value={department} onChange={setDepartment} />
          <TextInput label="System in play" value={system} onChange={setSystem} mono />
          <TextInput label="Ticket reference" value={ticket} onChange={setTicket} mono />
        </div>
        <div className="mt-3">
          <TextArea
            label="Opening line (leave blank to use the lever default)"
            value={opening}
            onChange={setOpening}
            rows={3}
            placeholder={LEVER_OPENER[lever]}
          />
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <TextArea label="Primary ask" value={ask} onChange={setAsk} rows={2} />
          <TextArea label="Fallback ask" value={fallback} onChange={setFallback} rows={2} />
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button size="sm" variant="outline" onClick={() => setOpening('')}>
            Reset opening to lever default
          </Button>
          <Button size="sm" variant="ghost" onClick={() => setAsk('confirm the on-call mobile number')}>
            Load a lower-risk ask
          </Button>
        </div>
        <div className="mt-3">
          <Callout tone="info" title="Resolved opening">
            <span className="rf-mono">{resolvedOpening}</span>
          </Callout>
        </div>
      </Card>

      <Card
        title="Pretext script"
        action={<DownloadButton text={script} filename="pretext-script.md" label="Download .md" />}
      >
        <OutputBlock value={script} rows={20} label="pretext-script.md" empty="Fill the persona fields above" />
      </Card>

      <Card title="Call flow">
        <CodeBlock code={callFlow.join('\n')} label="Outline" maxHeight={240} />
        <div className="mt-4">
          <KVTable
            rows={[
              ['Channel', CHANNELS.find((c) => c.value === channel)?.label ?? channel],
              ['Lever', LEVERS.find((l) => l.value === lever)?.label ?? lever],
              ['Objections rehearsed', String(OBJECTIONS.length)],
              ['Red flags', String(RED_FLAGS.length)],
            ]}
          />
        </div>
      </Card>

      <Card title="What to log afterwards">
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <ul className="m-0 list-disc space-y-1 pl-5 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
              {LOG_FIELDS.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
          </div>
          <div className="space-y-3">
            <Callout tone="warn" title="Do not re-use a failed pretext">
              If the target challenged the persona, that lever is burned for this population. Re-running it converts a
              single failed simulation into a campaign the SOC can pattern on.
            </Callout>
            <Callout tone="danger" title="Stop conditions">
              Any real distress, any disclosure of a real incident, or any request for the call to end is an immediate
              stop. Note it and stand down for that target permanently.
            </Callout>
          </div>
        </div>
      </Card>
    </>
  );
}
