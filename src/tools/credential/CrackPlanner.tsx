import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  CopyChip,
  KVTable,
  NumberInput,
  SectionTitle,
  Select,
  TextInput,
} from '@/components/ui';

interface HashType {
  id: string;
  label: string;
  mode: string;
  rateFactor: number;
  note: string;
  salted: boolean;
}

const HASH_TYPES: HashType[] = [
  { id: 'md5', label: 'MD5', mode: '0', rateFactor: 1, note: 'Raw digest, no salt', salted: false },
  { id: 'ntlm', label: 'NTLM', mode: '1000', rateFactor: 0.95, note: 'Unsalted; fastest of the Windows family', salted: false },
  { id: 'sha1', label: 'SHA-1', mode: '100', rateFactor: 0.6, note: 'Git-era digest', salted: false },
  { id: 'sha256', label: 'SHA-256', mode: '1400', rateFactor: 0.14, note: 'Salted variants are 100x slower', salted: false },
  { id: 'sha512', label: 'SHA-512', mode: '1700', rateFactor: 0.06, note: 'Often used unsalted on Linux systems', salted: false },
  { id: 'md5crypt', label: 'md5crypt ($1$)', mode: '500', rateFactor: 0.05, note: 'Iterated 1000x', salted: true },
  { id: 'sha512crypt', label: 'sha512crypt ($6$)', mode: '1800', rateFactor: 0.008, note: 'Default shadow hash, 5000 rounds', salted: true },
  { id: 'bcrypt', label: 'bcrypt ($2b$)', mode: '3200', rateFactor: 0.00001, note: 'Cost 12 — deliberately slow', salted: true },
  { id: 'pbkdf2', label: 'Django PBKDF2-SHA256', mode: '10000', rateFactor: 0.0002, note: 'Iteration count depends on version', salted: true },
  { id: 'netntlmv2', label: 'NetNTLMv2', mode: '5600', rateFactor: 0.25, note: 'From a relay/capture, not a dump', salted: true },
  { id: 'krb5tgs', label: 'Kerberos TGS (RC4)', mode: '13100', rateFactor: 0.02, note: 'Kerberoast; etype 23 only', salted: true },
  { id: 'mysql41', label: 'MySQL 4.1+', mode: '300', rateFactor: 1.2, note: 'Double SHA-1, fast', salted: false },
  { id: 'wordpress', label: 'WordPress phpass', mode: '400', rateFactor: 0.02, note: '8192 iterations of MD5', salted: true },
  { id: 'argon2', label: 'Argon2id', mode: '—', rateFactor: 0.000001, note: 'Memory-hard; hashcat support is narrow', salted: true },
];

interface Gpu {
  id: string;
  label: string;
  md5: number;
  note: string;
}

const GPUS: Gpu[] = [
  { id: '4090', label: 'RTX 4090', md5: 164e9, note: 'Top consumer card' },
  { id: '4080', label: 'RTX 4080', md5: 106e9, note: 'High-end consumer' },
  { id: '3090', label: 'RTX 3090', md5: 75e9, note: 'Previous generation flagship' },
  { id: 'a100', label: 'A100 80GB', md5: 110e9, note: 'Datacentre; better on salted modes' },
  { id: 'm4', label: 'Apple M4', md5: 6.2e9, note: 'Unified memory, strong on bcrypt' },
  { id: 'm3', label: 'Apple M3', md5: 5.1e9, note: 'Unified memory' },
  { id: 'm2', label: 'Apple M2', md5: 4.4e9, note: 'Unified memory' },
  { id: 'cpu', label: 'CPU only (8 cores)', md5: 1.1e9, note: 'Laptop fallback' },
];

const MASK_EXAMPLES: Array<[string, string]> = [
  ['?l', 'lowercase a-z (26)'],
  ['?u', 'uppercase A-Z (26)'],
  ['?d', 'digits 0-9 (10)'],
  ['?s', 'special characters (33)'],
  ['?a', 'all printable ASCII (95)'],
  ['?b', 'raw byte 0x00-0xff'],
  ['?1 ?2', 'custom sets from -1 / -2'],
  ['-1 ?l?d', 'define custom set 1'],
];

function fmt(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds > 3.15e9) return 'centuries';
  if (seconds < 1) return '< 1 s';
  const d = seconds / 86400;
  if (d >= 365) return `${(d / 365).toFixed(1)} years`;
  if (d >= 1) return `${d.toFixed(1)} days`;
  const h = seconds / 3600;
  if (h >= 1) return `${h.toFixed(1)} h`;
  return `${(seconds / 60).toFixed(1)} min`;
}

export default function CrackPlanner() {
  const [hashId, setHashId] = useState('ntlm');
  const [gpuId, setGpuId] = useState('4090');
  const [override, setOverride] = useState('');
  const [charset, setCharset] = useState('abcdefghijklmnopqrstuvwxyz0123456789');
  const [maxLength, setMaxLength] = useState(10);
  const [dictSize, setDictSize] = useState(14_344_391);
  const [ruleCount, setRuleCount] = useState(64);
  const [targets, setTargets] = useState(1);

  const hash = HASH_TYPES.find((h) => h.id === hashId) ?? HASH_TYPES[1];
  const gpu = GPUS.find((g) => g.id === gpuId) ?? GPUS[0];

  const rate = useMemo(() => {
    const parsed = Number(override);
    if (override.trim() && Number.isFinite(parsed) && parsed > 0) return parsed;
    return Math.round(gpu.md5 * hash.rateFactor);
  }, [override, gpu, hash]);

  const lengths = useMemo(() => {
    const size = Math.max(1, charset.length);
    return Array.from({ length: 5 }, (_, i) => Math.max(4, maxLength - 4 + i)).map((len) => {
      const keyspace = Math.pow(size, len);
      return { len, keyspace, seconds: keyspace / 2 / Math.max(1, rate) };
    });
  }, [charset, maxLength, rate]);

  const dictSeconds = useMemo(
    () => (dictSize * Math.max(1, ruleCount) * Math.max(1, targets)) / Math.max(1, rate),
    [dictSize, ruleCount, targets, rate],
  );

  const verdict = dictSeconds < 3600 ? 'trivial' : dictSeconds < 86400 * 3 ? 'feasible' : dictSeconds < 86400 * 60 ? 'marginal' : 'infeasible';
  const verdictColour =
    verdict === 'trivial' ? 'var(--ok)' : verdict === 'feasible' ? 'var(--info)' : verdict === 'marginal' ? 'var(--warn)' : 'var(--accent)';

  const winning = dictSeconds < 86400 * 30 ? 'dictionary+rules' : 'mask';

  const command = useMemo(() => {
    if (winning === 'mask') {
      const maskLen = Math.min(maxLength, 12);
      return `hashcat -a 3 -m ${hash.mode} hashes.txt -1 ${charset.trim() || '?l?d'} ?1${'?1'.repeat(Math.max(0, maskLen - 1))} --status --status-timer=15`;
    }
    return `hashcat -a 0 -m ${hash.mode} hashes.txt words.txt -r rules/best64.rule -w 3 --status --status-timer=15`;
  }, [winning, hash, charset, maxLength]);

  return (
    <>
      <Card title="Target">
        <div className="grid gap-4 sm:grid-cols-2">
          <Select label="Hash type" value={hashId} onChange={setHashId} options={HASH_TYPES.map((h) => ({ value: h.id, label: `${h.label} (-m ${h.mode})` }))} hint={hash.note} />
          <Select label="Hardware" value={gpuId} onChange={setGpuId} options={GPUS.map((g) => ({ value: g.id, label: g.label }))} hint={gpu.note} />
          <TextInput label="Hash rate override (H/s)" value={override} onChange={setOverride} mono placeholder="leave empty to use the table" hint="Benchmark with: hashcat -b -m MODE" />
          <NumberInput label="Target hashes" value={targets} onChange={setTargets} min={1} max={100000} hint="Every hash multiplies the work" />
        </div>
        <div className="mt-4 rounded border border-[var(--card-border)] px-3 py-2 text-[12px] text-[var(--text-muted)]">
          Effective rate: <span className="rf-mono text-[var(--text)]">{rate.toLocaleString()}</span> H/s on{' '}
          {hash.label}
        </div>
      </Card>

      <Card title="Search space">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput label="Charset" value={charset} onChange={setCharset} mono hint={`${charset.length} symbols`} />
          <NumberInput label="Up to length" value={maxLength} onChange={setMaxLength} min={5} max={20} />
        </div>
        <div className="mt-4 overflow-hidden rounded border border-[var(--card-border)]">
          <div className="grid grid-cols-3 gap-2 border-b border-[var(--card-border)] px-3 py-1.5 text-[11px] text-[var(--text-faint)]">
            <span>Mask length</span>
            <span>Keyspace</span>
            <span className="text-right">Time</span>
          </div>
          {lengths.map((l) => (
            <div key={l.len} className="grid grid-cols-3 gap-2 border-b border-[var(--card-border)] px-3 py-1.5 text-[12px] last:border-b-0">
              <span className="rf-mono text-[var(--text)]">{l.len}</span>
              <span className="rf-mono text-[var(--text-muted)]">{l.keyspace.toExponential(2)}</span>
              <span className="rf-mono text-right" style={{ color: l.seconds < 3600 ? 'var(--ok)' : l.seconds < 86400 * 30 ? 'var(--warn)' : 'var(--accent)' }}>
                {fmt(l.seconds)}
              </span>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Dictionary estimate">
        <div className="grid gap-4 sm:grid-cols-3">
          <NumberInput label="Dictionary size" value={dictSize} onChange={setDictSize} min={0} max={2_000_000_000} hint="rockyou 2024 ≈ 14.3 M" />
          <NumberInput label="Rules per word" value={ruleCount} onChange={setRuleCount} min={1} max={100000} hint="best64 = 64" />
          <NumberInput label="Target count" value={targets} onChange={setTargets} min={1} max={100000} />
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <div className="rounded border border-[var(--card-border)] px-3 py-2">
            <div className="text-[11px] text-[var(--text-faint)]">Candidates</div>
            <div className="rf-mono text-[13px] text-[var(--text)]">
              {(dictSize * Math.max(1, ruleCount) * Math.max(1, targets)).toExponential(2)}
            </div>
          </div>
          <div className="rounded border border-[var(--card-border)] px-3 py-2">
            <div className="text-[11px] text-[var(--text-faint)]">Estimated time</div>
            <div className="rf-mono text-[13px]" style={{ color: verdictColour }}>
              {fmt(dictSeconds)}
            </div>
          </div>
          <div className="rounded border border-[var(--card-border)] px-3 py-2">
            <div className="text-[11px] text-[var(--text-faint)]">Verdict</div>
            <div className="text-[13px] font-medium" style={{ color: verdictColour }}>
              {verdict}
            </div>
          </div>
        </div>
      </Card>

      <Card title="Recommendation">
        <SectionTitle>Attack order</SectionTitle>
        <KVTable
          rows={[
            ['1 · Dictionary', 'Rockyou, SecLists top-1M, then a targeted list built from the organisation name and staff names.'],
            ['2 · Rules', `best64 → d3ad0ne → OneRuleToRuleThemAll. Current estimate: ${fmt(dictSeconds)}.`],
            ['3 · Mask', `Hybrid patterns first (?u?l?l?l?l?l?d?d), then a full sweep.`],
            ['4 · Combinator', 'Two dictionaries combined (-a 1) for word+word passphrases.'],
            ['5 · Hybrid', '-a 6/-a 7 for word+digits when the policy demands both.'],
          ]}
        />
        <div className="mt-4">
          <SectionTitle>Winning command</SectionTitle>
          <div className="flex items-start justify-between gap-2 rounded border border-[var(--input-border)] bg-[var(--input)] px-3 py-2">
            <code className="rf-mono text-[11.5px] break-all text-[var(--text)]">{command}</code>
            <CopyChip text={command} label="copy" />
          </div>
        </div>
        <div className="mt-4">
          <Callout tone={verdict === 'infeasible' ? 'danger' : 'info'} title={`${hash.label} verdict: ${verdict}`}>
            {hash.salted
              ? 'This mode is salted, so one hash costs one full run. With many targets, gather more data rather than buying more GPUs.'
              : 'This mode is unsalted, so a rainbow table or a single sweep answers every hash at once.'}
          </Callout>
        </div>
      </Card>

      <Card title="Mask cheat sheet">
        <KVTable rows={MASK_EXAMPLES.map(([a, b]) => [<span className="rf-mono">{a}</span>, b])} />
        <div className="mt-4 space-y-2">
          {[
            ['hashcat -a 3 -m 1000 h.txt ?u?l?l?l?l?l?d?d', 'Title-case word with two digits'],
            ['hashcat -a 3 -m 1000 h.txt -1 ?l?d ?1?1?1?1?1?1?1?1 -i --increment-min=6', 'Incremental alphanumeric'],
            ['hashcat -a 6 -m 1400 h.txt words.txt ?d?d?d?d', 'Word + 4 digits (hybrid)'],
          ].map(([cmd, note]) => (
            <div key={cmd} className="flex items-center justify-between gap-2 rounded border border-[var(--card-border)] px-3 py-1.5">
              <div>
                <code className="rf-mono text-[11.5px] break-all text-[var(--text)]">{cmd}</code>
                <div className="text-[11px] text-[var(--text-faint)]">{note}</div>
              </div>
              <CopyChip text={cmd} label="copy" />
            </div>
          ))}
        </div>
      </Card>
    </>
  );
}
