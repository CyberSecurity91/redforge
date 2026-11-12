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
 * Vishing rehearsal script. The artefact is a call sheet a tester reads from
 * during an authorised assessment call — two openings, a rapport beat, a
 * three-stage ask ladder, objection responses, a hold bridge, a close and an
 * abort. Every line is templated from the inputs so the script stays in sync
 * with the pretext rather than drifting from it.
 */

type Role = 'helpdesk' | 'payroll' | 'vendor' | 'assistant';
type AskKind = 'mfa' | 'password' | 'callback' | 'install';

interface RoleDef {
  value: Role;
  label: string;
  team: string;
  /** What this role can plausibly know, used to shape the rapport line. */
  knows: string;
  tone: string;
}

const ROLES: RoleDef[] = [
  { value: 'helpdesk', label: 'IT helpdesk', team: 'the IT service desk', knows: 'the last ticket, the machine name and the last password change date', tone: 'brisk and slightly overworked' },
  { value: 'payroll', label: 'Payroll', team: 'the payroll team', knows: 'the payslip cycle and the bank-details deadline', tone: 'apologetic, deadline-driven' },
  { value: 'vendor', label: 'Vendor support', team: 'the vendor support desk', knows: 'the contract reference and the latest patch window', tone: 'formal, scripted, slightly rehearsed' },
  { value: 'assistant', label: 'Exec assistant', team: 'the executive office', knows: 'the diary, the travel booking and the approver name', tone: 'fast, clipped, mildly impatient' },
];

interface AskDef {
  value: AskKind;
  label: string;
  /** Three escalating framings of the same ask. */
  ladder: [string, string, string];
  /** What the target hands over, in risk terms. */
  risk: string;
  why: string;
}

const ASKS: AskDef[] = [
  {
    value: 'mfa',
    label: 'MFA code (read it back)',
    ladder: [
      'read the six-digit code from your authenticator so I can confirm the push reached the right device',
      'read the code again — the request timed out and I only need the one that expires in the next thirty seconds',
      'cancel the other prompt and read me the newest code; the account has two stacked challenges and I need the second one',
    ],
    risk: 'High — a code grants session access until it is used or expires',
    why: 'A single code is enough to complete an MFA-bound sign-in from any host.',
  },
  {
    value: 'password',
    label: 'Current password',
    ladder: [
      'confirm the first four characters so I can check the stored hash prefix',
      'confirm the full password so I can rule out a truncated entry on the sync job',
      'type the password into the reset dialog while I stay on the line, then read back the confirmation it shows',
    ],
    risk: 'Critical — the credential survives the call and the assessment',
    why: 'The password is reusable and will appear in the SOC log as a legitimate authentication.',
  },
  {
    value: 'callback',
    label: 'Callback to an alternative number',
    ladder: [
      'confirm the mobile number on file so I can send the reset link there',
      'give me a direct line for your manager in case the reset fails after you have gone home',
      'ring me back on the number I gave you once you are at your desk, so we are not talking across floors',
    ],
    risk: 'Medium — a controlled number lets a follow-up call land on your bridge',
    why: 'The callback is the conversation that removes the last independent verification channel.',
  },
  {
    value: 'install',
    label: 'Software installation',
    ladder: [
      'open the page I am sending and run the support tool so I can see the machine from my side',
      'approve the elevation prompt — the tool needs local admin to read the event log',
      'leave it running; it will close itself when the session ends and I will call back with the results',
    ],
    risk: 'Critical — code execution on the endpoint',
    why: 'A signed-looking runbook download converts a conversation into an implant.',
  },
];

const OBJECTIONS: Array<[string, (c: Ctx) => string]> = [
  ['busy / call me later', (c) => `Completely fine — this one line is quicker than the callback: ${c.askShort}. Thirty seconds and you are done.`],
  ['"I will raise a ticket"', (c) => `Please do — the reference is ${c.ticket}, and it closes itself the moment I finish. Raising it takes longer than answering me.`],
  ['"who is this?"', (c) => `Sorry, I should have led with that — ${c.operator}, ${c.teamLabel}. My extension is on the intranet phone list under ${c.teamLabel}, and the ticket is ${c.ticket}.`],
  ['"I do not give information over the phone"', (c) => `That is the right instinct and I would rather you held the line than gave something away. Nothing here needs to leave your screen: ${c.askShortNoValue}.`],
  ['"let me check with IT"', (c) => `Of course. Ask for ${c.operator} — if the queue is long, ring the number I gave you and I will pick up; ${c.ticket} is already open on your account.`],
  ['"this sounds like a scam"', (c) => `It does, and you should say that. Report it through the button in your mail client — if it turns out it was me, ${c.ticket} updates within the hour and nobody is annoyed.`],
];

interface Ctx {
  operator: string;
  teamLabel: string;
  ticket: string;
  askShort: string;
  askShortNoValue: string;
  target: string;
  department: string;
  reason: string;
  callback: string;
  spoofed: boolean;
}

const DETECTIONS: Array<[string, string]> = [
  ['Inbound call presented with an internal DID', 'External carrier leg carrying a number from the corporate DID range — compare CDR source trunk against the claimed extension.'],
  ['Target asked for a code read-back', 'Alert on speech-to-text match for "code", "authenticator", "read it back" in recorded contact-centre audio.'],
  ['Identity proofed by reference only', 'No callback verification event within 10 minutes of a credential-related ticket touch.'],
  ['MFA accepted while the target is on an external call', 'Correlate Entra ID / Okta sign-in risk with concurrent external telephony events for the same identity.'],
  ['Runbook downloaded from a non-catalogue domain', 'Proxy or Defender alert on an executable download initiated from a support pretext.'],
];

function buildScript(ctx: Ctx, role: RoleDef, ask: AskDef, rationale: string): string {
  const cb = ctx.spoofed ? `${ctx.callback} (presented — spoofed)` : `${ctx.callback} (not presented)`;
  return [
    `# Vishing script — ${role.label} → ${ctx.target}, ${ctx.department}`,
    '',
    `Reason for the call: ${ctx.reason}`,
    `Ticket reference: ${ctx.ticket}`,
    `Callback: ${cb}`,
    `Tone: ${role.tone}`,
    '',
    '## Opening — variant A (role-first)',
    `"Hi, is that ${ctx.target}? This is ${ctx.operator} from ${ctx.teamLabel}. I am ringing about ${ctx.reason} —`,
    `have I caught you in the middle of something?"`,
    '',
    '## Opening — variant B (reference-first)',
    `"${ctx.target}? ${ctx.operator}, ${ctx.teamLabel} — I have ticket ${ctx.ticket} open against your account and`,
    `it needs one thing from you before it can close. Two minutes, no more."`,
    '',
    '## Rapport (one sentence, then a question)',
    `"I can see you are in ${ctx.department} and that you last changed your password a while back — ${role.knows}.`,
    `Has anything in your setup changed since then, machine or phone?"`,
    '',
    '## Ask ladder',
    `1. Soft — "What I need is to ${ask.ladder[0]}."`,
    `2. Firm — "Sorry to push: ${ask.ladder[1]}."`,
    `3. Direct — "${ask.ladder[2]}."`,
    '',
    '## Objection responses',
    ...OBJECTIONS.map(([q, a]) => `- Target: "${q}"\n  You: "${a(ctx)}"`),
    '',
    '## Hold bridge',
    `"Bear with me, the console is spinning — do not go away, this is the step that takes the time."`,
    `(If the hold passes 40 seconds, repeat the ticket reference so the target hears continuity.)`,
    '',
    '## Close',
    `"That is everything — you will get a confirmation against ${ctx.ticket} in the next few minutes.`,
    `If anything looks odd, ring the number on the intranet rather than this one."`,
    '',
    '## Abort',
    `"Actually I have your file open against the wrong queue — I am going to stop here rather than change the wrong`,
    `thing. Ignore anything you see for the next ten minutes and I will re-raise it properly."`,
    `(Said once, calmly, then end the call. Do not explain twice: a second explanation is what people remember.)`,
    '',
    '## Notes for the tester',
    `- Value of the ask: ${ask.risk}. ${ask.why}`,
    `- ${rationale}`,
    `- Stop immediately if the target shows genuine distress or discloses a real security incident.`,
  ].join('\n');
}

export default function VishingScriptBuilder() {
  const [roleId, setRoleId] = useState<Role>('helpdesk');
  const [target, setTarget] = useState('A. Smith');
  const [department, setDepartment] = useState('Finance');
  const [reason, setReason] = useState('the mail migration re-authentication that expires today');
  const [askId, setAskId] = useState<AskKind>('mfa');
  const [spoofed, setSpoofed] = useState(false);
  const [operator, setOperator] = useState('D. Whitfield');
  const [callback, setCallback] = useState('+44 20 7946 0000');
  const [ticket, setTicket] = useState('INC-000000');

  const role = ROLES.find((r) => r.value === roleId) ?? ROLES[0]!;
  const ask = ASKS.find((a) => a.value === askId) ?? ASKS[0]!;

  const ctx: Ctx = useMemo(
    () => ({
      operator,
      teamLabel: role.team,
      ticket,
      askShort: ask.ladder[0],
      askShortNoValue: `nothing here needs anything typed, only confirmed — ${ask.ladder[0]}`,
      target: target.trim() || 'the target',
      department: department.trim() || 'the department',
      reason: reason.trim() || 'the account change on your record',
      callback: callback.trim() || '+44 20 7946 0000',
      spoofed,
    }),
    [operator, role, ticket, ask, target, department, reason, callback, spoofed],
  );

  const rationale = useMemo(
    () =>
      spoofed
        ? 'Callback number is presented, so a suspicious target who rings back reaches the assessment bridge rather than the real desk. That removes the only cheap verification that exists — log it as such in the findings.'
        : 'Callback number is not presented, so a target who rings the number they already have reaches the real desk and the pretext collapses. Expect a lower success rate and a higher report rate.',
    [spoofed],
  );

  const script = useMemo(() => buildScript(ctx, role, ask, rationale), [ctx, role, ask, rationale]);

  const redFlags = useMemo(
    () => [
      `Caller cannot say which queue the work sits in — ${role.team} can always name the system.`,
      `Caller pushes past the first refusal instead of offering the reference (${ticket}).`,
      'The ask moves from a yes/no question to something read aloud from the screen.',
      spoofed
        ? 'The presented number matches the intranet but the call quality is a single carrier leg.'
        : 'The presented number is withheld or from a block the corporate desk never uses.',
      'Caller knows the department but not the line manager — a real desk checks the manager first.',
      'Caller wants the target to stay on the line while an action completes elsewhere.',
      'Caller gives a mobile callback number to a target whose desk number is public.',
    ],
    [role, ticket, spoofed],
  );

  const callSheet = useMemo(
    () => [
      `Role: ${role.label} · Tone: ${role.tone}`,
      `Target: ${target || '—'} / ${department || '—'}`,
      `Ticket: ${ticket} · Ask: ${ask.label}`,
      `Callback: ${spoofed ? 'presented' : 'withheld'} — ${ctx.callback}`,
      'Flow: greet → identify → reference → rapport question → ask 1 → 2 → 3 → hold → close / abort',
    ],
    [role, target, department, ticket, ask, spoofed, ctx.callback],
  );

  return (
    <>
      <Card title="Pretext">
        <div className="grid gap-4 sm:grid-cols-2">
          <Select<Role> label="Pretext role" value={roleId} onChange={setRoleId} options={ROLES.map((r) => ({ value: r.value, label: r.label }))} hint={`Can credibly reference: ${role.knows}`} />
          <TextInput label="Target name" value={target} onChange={setTarget} placeholder="A. Smith" />
          <TextInput label="Department" value={department} onChange={setDepartment} placeholder="Finance" />
          <TextInput label="Operator name (persona)" value={operator} onChange={setOperator} placeholder="D. Whitfield" />
          <TextInput label="Ticket reference" value={ticket} onChange={setTicket} mono placeholder="INC-000000" />
          <TextInput label="Callback number" value={callback} onChange={setCallback} mono placeholder="+44 20 7946 0000" />
          <Select<AskKind> label="Detail to elicit" value={askId} onChange={setAskId} options={ASKS.map((a) => ({ value: a.value, label: a.label }))} hint={ask.risk} />
          <div className="flex items-end pb-2">
            <Checkbox checked={spoofed} onChange={setSpoofed} label="Callback number spoofed" description="Presented CLI matches the number the target can find on the intranet." />
          </div>
        </div>
        <div className="mt-4">
          <TextInput label="One-line reason for the call" value={reason} onChange={setReason} hint="Must be something the role could plausibly own and that the target can check afterwards." />
        </div>
        <div className="mt-4">
          <Callout tone="warn" title={`Value of this ask: ${ask.risk}`}>{ask.why}</Callout>
        </div>
      </Card>

      <Card title="Call script" action={<DownloadButton text={script} filename="vishing-script.md" label="Download .md" />}>
        <OutputBlock value={script} rows={22} label="vishing-script.md" empty="Fill the pretext fields above" />
      </Card>

      <Card title="Openings, ladder and bridge">
        <SectionTitle>Opening — variant A</SectionTitle>
        <p className="rf-mono m-0 mb-3 text-[12px] leading-relaxed text-[var(--text-muted)]">
          "Hi, is that {ctx.target}? This is {operator} from {role.team}. I am ringing about {ctx.reason} — have I caught you in the middle of something?"
        </p>
        <SectionTitle>Opening — variant B</SectionTitle>
        <p className="rf-mono m-0 mb-3 text-[12px] leading-relaxed text-[var(--text-muted)]">
          "{ctx.target}? {operator}, {role.team} — I have ticket {ticket} open against your account and it needs one thing from you before it can close. Two minutes, no more."
        </p>
        <SectionTitle>Rapport</SectionTitle>
        <p className="rf-mono m-0 mb-3 text-[12px] leading-relaxed text-[var(--text-muted)]">
          "I can see you are in {ctx.department} and that you last changed your password a while back — {role.knows}. Has anything in your setup changed since then, machine or phone?"
        </p>
        <SectionTitle>Ask ladder</SectionTitle>
        <div className="space-y-2">
          {ask.ladder.map((line, i) => (
            <div key={line} className="rounded border border-[var(--card-border)] px-3 py-2">
              <div className="mb-1 text-[11px] tracking-wide text-[var(--text-faint)] uppercase">
                Stage {i + 1} — {['soft', 'firm', 'direct'][i]}
              </div>
              <p className="rf-mono m-0 text-[12px] leading-relaxed text-[var(--text-muted)]">"{line}."</p>
            </div>
          ))}
        </div>
        <div className="mt-4">
          <SectionTitle>Hold bridge</SectionTitle>
          <p className="rf-mono m-0 text-[12px] leading-relaxed text-[var(--text-muted)]">
            "Bear with me, the console is spinning — do not go away, this is the step that takes the time." Repeat {ticket} if the hold passes forty seconds so the target hears continuity.
          </p>
        </div>
      </Card>

      <Card title="Objections">
        <KVTable rows={OBJECTIONS.map(([q, a]) => [q, a(ctx)])} />
      </Card>

      <Card title="Close, abort and detection">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <SectionTitle>Close</SectionTitle>
            <p className="rf-mono m-0 mb-3 text-[12px] leading-relaxed text-[var(--text-muted)]">
              "That is everything — you will get a confirmation against {ticket} in the next few minutes. If anything looks odd, ring the number on the intranet rather than this one."
            </p>
            <SectionTitle>Abort</SectionTitle>
            <p className="rf-mono m-0 text-[12px] leading-relaxed text-[var(--text-muted)]">
              "Actually I have your file open against the wrong queue — I am going to stop here rather than change the wrong thing. Ignore anything you see for the next ten minutes and I will re-raise it properly."
            </p>
            <div className="mt-3">
              <Callout tone="info" title="Say the abort line once">
                A second explanation is the part people remember, and it is the part that ends up in the awareness report. Deliver it calmly and end the call.
              </Callout>
            </div>
          </div>
          <div>
            <SectionTitle>Red flags a trained user would notice</SectionTitle>
            <ul className="m-0 list-disc space-y-1 pl-5 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
              {redFlags.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
          </div>
        </div>
        <div className="mt-5">
          <SectionTitle>Detection engineering — what the SOC should alert on</SectionTitle>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[12px]">
              <thead>
                <tr className="text-left text-[11px] tracking-wide text-[var(--text-faint)] uppercase">
                  <th className="py-1 pr-3 font-medium">Signal</th>
                  <th className="py-1 font-medium">Alert logic</th>
                </tr>
              </thead>
              <tbody>
                {DETECTIONS.map(([sig, logic]) => (
                  <tr key={sig} className="border-t border-[var(--card-border)] align-top">
                    <td className="py-1 pr-3 text-[var(--text)]">{sig}</td>
                    <td className="py-1 text-[var(--text-muted)]">{logic}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div className="mt-4">
          <SectionTitle>Call sheet</SectionTitle>
          <CodeBlock code={callSheet.join('\n')} label="One-line crib" maxHeight={180} />
        </div>
      </Card>
    </>
  );
}
