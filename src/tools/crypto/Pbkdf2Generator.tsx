import { useEffect, useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, CopyChip, KVTable, Select, Slider, TextInput, Tabs } from '@/components/ui';
import { base64FromBytes, fromHex, pbkdf2Hex } from '@/lib/crypto';

type Hash = 'SHA-1' | 'SHA-256';

const EXPONENTS = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

const HASHES: Array<{ value: Hash; label: string }> = [
  { value: 'SHA-1', label: 'SHA-1 (hashcat -m 12000)' },
  { value: 'SHA-256', label: 'SHA-256 (hashcat -m 10900)' },
];

function b64ToHex(b64: string): string {
  const bin = atob(b64.replace(/\s+/g, ''));
  return Array.from(bin, (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

export default function Pbkdf2Generator() {
  const [password, setPassword] = useState('hunter2');
  const [salt, setSalt] = useState('redforge-static-salt');
  const [exp, setExp] = useState(14);
  const [keyLen, setKeyLen] = useState(32);
  const [hash, setHash] = useState<Hash>('SHA-256');
  const [view, setView] = useState<'hex' | 'base64'>('hex');
  const [dk, setDk] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [elapsed, setElapsed] = useState(0);

  const iterations = Math.pow(2, exp);

  useEffect(() => {
    let cancelled = false;
    const timer = window.setTimeout(() => {
      setBusy(true);
      const started = performance.now();
      pbkdf2Hex(password, salt, iterations, keyLen, hash)
        .then((hex) => {
          if (cancelled) return;
          setDk(hex);
          setError('');
          setElapsed(performance.now() - started);
        })
        .catch((e: unknown) => {
          if (cancelled) return;
          setDk('');
          setError((e as Error).message || 'Derivation failed.');
        })
        .finally(() => {
          if (!cancelled) setBusy(false);
        });
    }, 250);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [password, salt, iterations, keyLen, hash]);

  const b64 = useMemo(() => {
    if (!dk) return '';
    return base64FromBytes(fromHex(dk));
  }, [dk]);

  const hashcat = useMemo(() => {
    const format = hash === 'SHA-256' ? 'sha256' : 'sha1';
    const dkHex = dk || 'DK_HEX';
    return `$pbkdf2-${format}$${iterations}$${btoa(salt)}$${btoa(dkHex)}`;
  }, [dk, hash, iterations, salt]);

  const python = useMemo(
    () =>
      [
        'import hashlib, base64, time',
        '',
        `start = time.perf_counter()`,
        `dk = hashlib.pbkdf2_hmac("${hash.toLowerCase().replace('-', '')}", b"${password}", b"${salt}", ${iterations}, dklen=${keyLen})`,
        `print(dk.hex())`,
        `print(base64.b64encode(dk).decode())`,
        'print(f"{(time.perf_counter() - start) * 1000:.1f} ms")',
      ].join('\n'),
    [password, salt, iterations, keyLen, hash],
  );

  const cost = useMemo(() => {
    const perGuessMs = elapsed || 1;
    const guessesPerSecond = 1000 / perGuessMs;
    const gpuFactor = 20000; // rough single-consumer-GPU advantage for this iteration count
    return {
      here: guessesPerSecond,
      gpu: guessesPerSecond * gpuFactor,
      eightChar: Math.pow(95, 8) / (guessesPerSecond * gpuFactor),
      eightCharLower: Math.pow(26, 8) / (guessesPerSecond * gpuFactor),
    };
  }, [elapsed]);

  const human = (seconds: number) => {
    if (!isFinite(seconds)) return '—';
    if (seconds < 60) return `${seconds.toFixed(1)} s`;
    if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
    if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} h`;
    if (seconds < 31536000) return `${(seconds / 86400).toFixed(1)} days`;
    return `${(seconds / 31536000).toExponential(2)} years`;
  };

  return (
    <>
      <Card title="Parameters">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput label="Password" value={password} onChange={setPassword} mono placeholder="hunter2" />
          <TextInput label="Salt" value={salt} onChange={setSalt} mono hint="Per-user random salt in practice" />
          <Select label="PRF hash" value={hash} onChange={setHash} options={HASHES} />
          <TextInput
            label="Key length (bytes)"
            value={String(keyLen)}
            onChange={(v) => setKeyLen(Math.max(1, Math.min(128, Number(v) || 32)))}
            mono
          />
        </div>
        <div className="mt-4">
          <Slider
            label="Iterations"
            value={exp}
            onChange={setExp}
            min={10}
            max={20}
            step={1}
            format={(v) => `2^${v} = ${Math.pow(2, v).toLocaleString('en-GB')}`}
          />
        </div>
        <div className="mt-2 flex gap-2">
          {EXPONENTS.filter((e) => e % 2 === 0).map((e) => (
            <button
              key={e}
              type="button"
              onClick={() => setExp(e)}
              className="rounded border border-[var(--border)] px-2 py-1 text-[11px] text-[var(--text-muted)] hover:border-[var(--accent)]"
            >
              2^{e}
            </button>
          ))}
        </div>
      </Card>

      <Card title="Derived key" action={<CopyChip text={view === 'hex' ? dk : b64} label="Copy DK" />}>
        <div className="flex items-center gap-3">
          <Tabs
            value={view}
            onChange={setView}
            tabs={[
              { value: 'hex', label: 'Hex' },
              { value: 'base64', label: 'Base64' },
            ]}
          />
          <span className="text-[11.5px] text-[var(--text-faint)]">
            {busy ? 'deriving…' : `${elapsed.toFixed(0)} ms in this tab`}
          </span>
        </div>
        <div className="mt-3">
          {error ? (
            <Callout tone="warn" title="Derivation failed">
              {error}
            </Callout>
          ) : (
            <CodeBlock code={(view === 'hex' ? dk : b64) || '—'} maxHeight={120} />
          )}
        </div>
        <div className="mt-4">
          <KVTable
            rows={[
              ['Iterations', iterations.toLocaleString('en-GB')],
              ['Hash', hash],
              ['Salt', <span key="s" className="rf-mono">{salt}</span>],
              ['Key length', `${keyLen} bytes (${keyLen * 8} bits)`],
            ]}
          />
        </div>
      </Card>

      <Card title="hashcat / cracking cost">
        <CodeBlock code={hashcat} label={hash === 'SHA-256' ? '-m 10900 hash format preview' : '-m 12000 hash format preview'} maxHeight={90} />
        <div className="mt-4">
          <KVTable
            rows={[
              ['This tab', `${Math.round(cost.here)} guesses/s`],
              ['Single consumer GPU (est.)', `${Math.round(cost.gpu).toLocaleString('en-GB')} guesses/s`],
              ['8 × lowercase alnum', human(cost.eightCharLower)],
              ['8 × full printable (95)', human(cost.eightChar)],
            ]}
          />
        </div>
        <div className="mt-4">
          <Callout tone="info" title="Reading the numbers">
            The GPU figure is a rough extrapolation (×20,000) for illustration only — real rates depend on the card and
            on hashcat's kernel. The point is the ratio: doubling iterations halves throughput, so{' '}
            {iterations.toLocaleString('en-GB')} rounds is roughly {iterations >= 600000 ? 'above' : 'below'} the
            OWASP floor of 600,000 for PBKDF2-HMAC-SHA-256. The hex digest above is the hashcat "DK hex" input; the
            format is <span className="rf-mono">$pbkdf2-sha256$iterations$salt_b64$dk_b64</span>.
          </Callout>
        </div>
        <div className="mt-4">
          <CodeBlock code={python} label="hashlib.pbkdf2_hmac" maxHeight={200} />
        </div>
      </Card>
    </>
  );
}
