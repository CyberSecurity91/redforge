import { useMemo, useState } from 'react';
import { Callout, Card, Checkbox, KVTable, SectionTitle, TextInput } from '@/components/ui';
import { shannonEntropy } from '@/lib/encoding';

const COMMON = new Set([
  'password', 'password1', 'password123', '123456', '12345678', '123456789', 'qwerty', 'qwerty123',
  'letmein', 'welcome', 'welcome1', 'admin', 'administrator', 'monkey', 'dragon', 'iloveyou',
  'sunshine', 'princess', 'football', 'baseball', 'shadow', 'master', 'superman', 'batman',
  'trustno1', 'abc123', 'changeme', 'secret', 'summer', 'winter', 'spring', 'autumn',
  'company', 'company1', 'michael', 'jennifer', 'jordan', 'hunter2', 'passw0rd', 'p@ssw0rd',
]);

const WALKS = ['qwerty', 'asdf', 'zxcv', 'qazwsx', '1234', 'abcd', '1qaz', 'wsxedc', 'poiuy', 'lkjhg'];

const NAMES = ['james', 'john', 'mary', 'david', 'sarah', 'michael', 'chris', 'daniel', 'laura', 'emma',
  'alex', 'sam', 'kate', 'tom', 'anna', 'mark', 'paul', 'luke', 'jack', 'rose'];

const LEET: Array<[string, string]> = [['4', 'a'], ['3', 'e'], ['1', 'i'], ['0', 'o'], ['5', 's'], ['7', 't'], ['@', 'a'], ['$', 's']];

interface Model {
  id: string;
  label: string;
  rate: number;
  note: string;
}

const MODELS: Model[] = [
  { id: 'online', label: 'Online, rate-limited', rate: 10, note: '10 guesses/second against a login form' },
  { id: 'cpu', label: 'Offline, CPU', rate: 10_000, note: '10 kH/s — a single core on a fast unsalted hash' },
  { id: 'gpu', label: 'Offline, GPU', rate: 10_000_000_000, note: '10 GH/s — one RTX-class card on MD5/NTLM' },
  { id: 'bcrypt', label: 'Offline, GPU on bcrypt', rate: 10_000, note: '10 kH/s — a deliberately slow KDF' },
];

function humanTime(seconds: number): string {
  if (!Number.isFinite(seconds)) return 'effectively forever';
  if (seconds < 1) return '< 1 second';
  const units: Array<[number, string]> = [
    [60, 'second'],
    [60, 'minute'],
    [24, 'hour'],
    [365, 'day'],
    [1000, 'year'],
  ];
  let value = seconds;
  let name = 'second';
  for (const [div, label] of units) {
    if (value < div) break;
    value /= div;
    name = label;
  }
  if (name === 'year' && value > 1000) return `${(value / 1000).toFixed(1)} thousand years`;
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${name}${value >= 2 ? 's' : ''}`;
}

export default function PasswordProfiler() {
  const [password, setPassword] = useState('Autumn2024!');
  const [masked, setMasked] = useState(false);

  const analysis = useMemo(() => {
    const chars = Array.from(password);
    const classes = {
      lower: /[a-z]/.test(password),
      upper: /[A-Z]/.test(password),
      digit: /\d/.test(password),
      symbol: /[^A-Za-z0-9]/.test(password),
      space: /\s/.test(password),
    };
    const classCount = Object.values(classes).filter(Boolean).length;
    const pool =
      (classes.lower ? 26 : 0) + (classes.upper ? 26 : 0) + (classes.digit ? 10 : 0) +
      (classes.symbol ? (password.match(/[^A-Za-z0-9]/g)?.length ?? 0) > 0 ? 33 : 0 : 0) +
      (classes.space ? 1 : 0);
    const entropy = shannonEntropy(password);
    const keyspace = pool > 0 ? Math.pow(pool, chars.length) : 0;

    const lower = password.toLowerCase();
    const leetNormalised = LEET.reduce((acc, [from, to]) => acc.split(from).join(to), lower);
    const findings: Array<{ label: string; detail: string; weight: number }> = [];

    if (COMMON.has(lower)) findings.push({ label: 'In a common-password list', detail: 'Present in every top-10k wordlist; cracked instantly.', weight: 45 });
    if (WALKS.some((w) => lower.includes(w))) findings.push({ label: 'Keyboard walk', detail: 'Contains an adjacent-key run (qwerty, asdf, 1234).', weight: 25 });
    if (/\b(19|20)\d{2}\b/.test(password)) findings.push({ label: 'Contains a year', detail: 'Four-digit years 1900-2099 are in every rules file.', weight: 18 });
    if (/(0[1-9]|[12]\d|3[01])[\/\-.]?(0[1-9]|1[0-2])[\/\-.]?(19|20)?\d{2}/.test(password) || /(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])/.test(password))
      findings.push({ label: 'Date pattern', detail: 'Looks like a birth date or anniversary — try hashcat -m <mode> with a date mask.', weight: 20 });
    if (NAMES.some((n) => lower.includes(n))) findings.push({ label: 'Personal name', detail: 'Contains a common first name; name+year combinations fall to a 20-line rule.', weight: 15 });
    if (leetNormalised !== lower && COMMON.has(leetNormalised)) findings.push({ label: 'Leet substitution of a common word', detail: 'De-leeting recovers a top-list word — rules/best64 covers this.', weight: 30 });
    else if (leetNormalised !== lower) findings.push({ label: 'Leet substitutions', detail: '4→a 3→e 1→i 0→o 5→s are the first rules an attacker applies.', weight: 12 });
    if (/\d{1,4}$/.test(password)) findings.push({ label: 'Numeric suffix', detail: 'Trailing digits are appended by the `d`/`$1` rules, not guessed.', weight: 14 });
    if (chars.length > 0 && chars.length < 8) findings.push({ label: 'Short', detail: 'Under 8 characters: a mask sweep finishes in seconds.', weight: 30 });
    if (classCount <= 2) findings.push({ label: 'Low character-class diversity', detail: 'Two or fewer classes shrinks the effective search space enormously.', weight: 16 });
    if (/(.)\1{2,}/.test(password)) findings.push({ label: 'Repeated characters', detail: 'aaa/111 runs are rarely random.', weight: 8 });

    const penalty = findings.reduce((sum, f) => sum + f.weight, 0);
    const raw = Math.min(100, entropy * 4.5 + classCount * 8 + Math.min(chars.length, 20) * 1.5);
    const score = Math.max(0, Math.min(100, Math.round(raw - penalty)));

    return { chars, classes, classCount, pool, entropy, keyspace, findings, score };
  }, [password]);

  const verdict = analysis.score >= 75 ? 'ok' : analysis.score >= 45 ? 'warn' : 'bad';
  const verdictColour = verdict === 'ok' ? 'var(--ok)' : verdict === 'warn' ? 'var(--warn)' : 'var(--accent)';
  const verdictWord = verdict === 'ok' ? 'Resilient' : verdict === 'warn' ? 'Weak' : 'Trivial';

  return (
    <>
      <Card title="Password" action={<Checkbox checked={masked} onChange={setMasked} label="Mask" />}>
        <TextInput
          label="Value to profile"
          value={password}
          onChange={setPassword}
          type={masked ? 'password' : 'text'}
          mono
          placeholder="Type the password to analyse"
        />
        {!password && (
          <div className="mt-3">
            <Callout tone="info" title="Nothing to profile">
              Type a candidate above. Nothing leaves this page — the analysis runs in the browser.
            </Callout>
          </div>
        )}
        {password && (
          <div className="mt-4">
            <div className="mb-1.5 flex items-baseline justify-between">
              <span className="text-[12px] text-[var(--text-muted)]">Strength</span>
              <span className="rf-mono text-[13px]" style={{ color: verdictColour }}>
                {analysis.score}/100 · {verdictWord}
              </span>
            </div>
            <div style={{ display: 'flex', gap: 2, height: 8 }} role="progressbar" aria-valuenow={analysis.score} aria-valuemin={0} aria-valuemax={100}>
              {Array.from({ length: 20 }, (_, i) => {
                const filled = i * 5 < analysis.score;
                return (
                  <div
                    key={i}
                    style={{
                      flex: 1,
                      borderRadius: 2,
                      background: filled ? verdictColour : 'var(--neutral-btn)',
                      opacity: filled ? 1 : 0.5,
                    }}
                  />
                );
              })}
            </div>
            <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-5">
              {[
                ['lower', analysis.classes.lower],
                ['upper', analysis.classes.upper],
                ['digit', analysis.classes.digit],
                ['symbol', analysis.classes.symbol],
                ['space', analysis.classes.space],
              ].map(([label, on]) => (
                <div
                  key={label as string}
                  className="rounded border px-2 py-1 text-center text-[11px] rf-mono"
                  style={{
                    borderColor: on ? 'var(--accent)' : 'var(--card-border)',
                    color: on ? 'var(--text)' : 'var(--text-faint)',
                    background: on ? 'var(--accent-faded)' : 'transparent',
                  }}
                >
                  {label as string}
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>

      {password && (
        <Card title="Search space">
          <KVTable
            rows={[
              ['Length', `${analysis.chars.length} characters`],
              ['Effective pool', `${analysis.pool} symbols`],
              ['Shannon entropy', `${analysis.entropy.toFixed(2)} bits/char`],
              ['Keyspace', analysis.keyspace > 0 ? analysis.keyspace.toExponential(2) : '0'],
            ]}
          />
          <div className="mt-4">
            <SectionTitle>Estimated time to crack</SectionTitle>
            <div className="overflow-hidden rounded border border-[var(--card-border)]">
              {MODELS.map((m) => (
                <div
                  key={m.id}
                  className="flex items-center justify-between gap-3 border-b border-[var(--card-border)] px-3 py-2 last:border-b-0"
                >
                  <div>
                    <div className="text-[12px] text-[var(--text)]">{m.label}</div>
                    <div className="text-[11px] text-[var(--text-faint)]">{m.note}</div>
                  </div>
                  <div className="rf-mono shrink-0 text-[12px] text-[var(--text)]">
                    {humanTime(analysis.keyspace / 2 / m.rate)}
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-2 text-[11px] text-[var(--text-faint)]">
              Assumes uniform random selection over the observed pool and an average of half the keyspace.
            </div>
          </div>
        </Card>
      )}

      {password && (
        <Card title="Patterns" action={<span className="text-[11.5px] text-[var(--text-faint)]">{analysis.findings.length} found</span>}>
          {analysis.findings.length === 0 ? (
            <Callout tone="ok" title="No common pattern matched">
              Nothing in the embedded lists hit. That does not prove randomness — it only rules out the cheapest
              attacks. A targeted wordlist built from the target's own context still applies.
            </Callout>
          ) : (
            <div className="space-y-2">
              {analysis.findings.map((f) => (
                <div key={f.label} className="rounded border border-[var(--card-border)] px-3 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[12.5px] font-medium text-[var(--text)]">{f.label}</span>
                    <span className="rf-mono text-[11px]" style={{ color: 'var(--accent)' }}>
                      -{f.weight}
                    </span>
                  </div>
                  <div className="mt-0.5 text-[11.5px] leading-snug text-[var(--text-muted)]">{f.detail}</div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      <Card title="Remediation">
        <KVTable
          rows={[
            ['Length first', 'Every extra character multiplies the keyspace by the pool size; words beat symbols.'],
            ['Break the shape', 'Avoid Year/Digit suffix, Leet substitution and Title Case — these are free guesses.'],
            ['Unique per site', 'Reuse turns one breach into a credential-stuffing campaign.'],
            ['Use a KDF', 'Argon2id or bcrypt at cost 12 turns 10 GH/s into 10 kH/s.'],
          ]}
        />
        <div className="mt-4">
          <Callout tone="info" title="What the score means">
            A compound score capped at 100 that combines entropy with penalties for detected patterns — it measures
            predictability, not compliance. A 20-character passphrase of real words scores worse on entropy per
            character but is far harder to attack than <span className="rf-mono">Summer2024!</span>.
          </Callout>
        </div>
      </Card>
    </>
  );
}
