import { useEffect, useState } from 'react';
import { Callout, Card, CopyChip, KVTable, OutputBlock, Select, TextInput } from '@/components/ui';
import { bytesFromBase32, utf8 } from '@/lib/bytes';

type Algo = 'SHA-1' | 'SHA-256' | 'SHA-512';

/** WebCrypto wants a plain ArrayBuffer; a shared-buffer view is rejected by the typings. */
function ab(u: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(u.byteLength);
  new Uint8Array(copy).set(u);
  return copy;
}

async function hmacBytes(algo: Algo, key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const ck = await crypto.subtle.importKey('raw', ab(key), { name: 'HMAC', hash: { name: algo } }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', ck, ab(msg));
  return new Uint8Array(sig);
}

/** RFC 4226 moving factor: 8-byte big-endian counter. */
function counterBytes(counter: number): Uint8Array {
  const out = new Uint8Array(8);
  let c = Math.floor(counter);
  for (let i = 7; i >= 0; i--) {
    out[i] = c % 256;
    c = Math.floor(c / 256);
  }
  return out;
}

/** RFC 4226 §5.3 dynamic truncation, kept in float maths so bit 31 never flips sign. */
function truncate(mac: Uint8Array, digits: number): string {
  const offset = mac[mac.length - 1] & 0x0f;
  const bin =
    (mac[offset] & 0x7f) * 2 ** 24 +
    (mac[offset + 1] & 0xff) * 2 ** 16 +
    (mac[offset + 2] & 0xff) * 256 +
    (mac[offset + 3] & 0xff);
  return String(bin % 10 ** digits).padStart(digits, '0');
}

async function hotp(algo: Algo, key: Uint8Array, counter: number, digits: number): Promise<string> {
  return truncate(await hmacBytes(algo, key, counterBytes(counter)), digits);
}

const VECTORS: Array<[number, string]> = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
];

function clock(t: number): string {
  return new Date(t * 1000).toISOString().slice(11, 19);
}

export default function TotpGenerator() {
  const [secret, setSecret] = useState('JBSWY3DPEHPK3PXP');
  const [algo, setAlgo] = useState<Algo>('SHA-1');
  const [digits, setDigits] = useState(6);
  const [period, setPeriod] = useState(30);

  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  const [codes, setCodes] = useState<string[]>([]);
  const [drift, setDrift] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [keyLength, setKeyLength] = useState(0);
  const [verify, setVerify] = useState<{ ok: boolean; lines: string[] } | null>(null);

  const step = Math.floor(now / period);
  const remaining = period - (now % period);

  useEffect(() => {
    const id = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(id);
  }, []);

  // Startup conformance check against the published RFC 6238 Appendix B values.
  useEffect(() => {
    let cancelled = false;
    const key = utf8('12345678901234567890');
    void (async () => {
      const lines: string[] = [];
      let ok = true;
      for (const [t, expected] of VECTORS) {
        const got = await hotp('SHA-1', key, Math.floor(t / 30), 8);
        const pass = got === expected;
        ok = ok && pass;
        lines.push(`T=${t} → ${got}${pass ? ' ✓' : ` ✗ expected ${expected}`}`);
      }
      if (!cancelled) setVerify({ ok, lines });
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const key = bytesFromBase32(secret);
        const next: string[] = [];
        for (let i = 0; i < 4; i++) next.push(await hotp(algo, key, step + i, digits));
        const around: string[] = [];
        for (let i = -2; i <= 2; i++) around.push(await hotp(algo, key, step + i, digits));
        if (cancelled) return;
        setCodes(next);
        setDrift(around);
        setKeyLength(key.length);
        setError(null);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : String(err));
        setCodes([]);
        setDrift([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [secret, algo, digits, period, step]);

  const display = codes[0] ? (codes[0].length === 8 ? `${codes[0].slice(0, 4)} ${codes[0].slice(4)}` : `${codes[0].slice(0, 3)} ${codes[0].slice(3)}`) : '— — —';
  const uri = `otpauth://totp/RedForge:demo@example.com?secret=${secret.toUpperCase().replace(/=+$/, '')}&issuer=RedForge&algorithm=${algo.replace('-', '')}&digits=${digits}&period=${period}`;

  return (
    <>
      <Card title="Shared secret and parameters">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput label="Base32 secret" value={secret} onChange={setSecret} mono hint={keyLength ? `${keyLength} bytes decoded` : 'RFC 4648 alphabet'} />
          <Select<Algo>
            label="HMAC algorithm"
            value={algo}
            onChange={setAlgo}
            options={[
              { value: 'SHA-1', label: 'SHA-1 (default)' },
              { value: 'SHA-256', label: 'SHA-256' },
              { value: 'SHA-512', label: 'SHA-512' },
            ]}
          />
          <Select<number>
            label="Digits"
            value={digits}
            onChange={setDigits}
            options={[
              { value: 6, label: '6 digits' },
              { value: 8, label: '8 digits' },
            ]}
          />
          <Select<number>
            label="Period"
            value={period}
            onChange={setPeriod}
            options={[
              { value: 30, label: '30 seconds' },
              { value: 60, label: '60 seconds' },
            ]}
          />
        </div>
        <div className="mt-4">
          <Callout tone={verify?.ok ? 'ok' : verify ? 'danger' : 'info'} title="RFC 6238 self-test">
            {verify ? (
              <div className="space-y-0.5">
                <p className="m-0">
                  {verify.ok
                    ? 'All published SHA-1 vectors reproduce exactly, 8-digit truncation, secret “12345678901234567890”.'
                    : 'At least one vector failed — the implementation below is not conformant, treat every code as suspect.'}
                </p>
                <pre className="rf-mono m-0 text-[11px] whitespace-pre-wrap text-[var(--text-faint)]">{verify.lines.join('\n')}</pre>
              </div>
            ) : (
              'Running the RFC 6238 vectors…'
            )}
          </Callout>
        </div>
        {error && (
          <div className="mt-3">
            <Callout tone="danger" title="Secret rejected">
              {error}
            </Callout>
          </div>
        )}
      </Card>

      <Card
        title="Current code"
        action={<span className="text-[11.5px] text-[var(--text-faint)]">window closes in {remaining}s</span>}
      >
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div className="rf-mono text-3xl tracking-[0.18em] text-[var(--text)]">{display}</div>
          <div className="flex items-center gap-2">
            <CopyChip text={codes[0] ?? ''} label="copy code" />
            <CopyChip text={uri} label="copy otpauth URI" />
          </div>
        </div>
        <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-[var(--input)]">
          <div
            className="h-full rounded-full"
            style={{ width: `${Math.max(0, (remaining / period) * 100)}%`, background: 'var(--accent)', transition: 'width 0.95s linear' }}
          />
        </div>
        <div className="mt-4">
          <KVTable
            rows={[
              ['Counter (moving factor)', String(step)],
              ['Window', `${clock(step * period)} – ${clock((step + 1) * period)} UTC`],
              ['Algorithm', `${algo} · ${digits} digits · ${period}s`],
              ['Server-side check', `accept step ±1 (${clock((step - 1) * period)} … ${clock((step + 2) * period)})`],
            ]}
          />
        </div>
        <div className="mt-4">
          <OutputBlock value={uri} label="otpauth:// provisioning URI" rows={2} />
        </div>
      </Card>

      <Card title="Upcoming windows">
        <div className="overflow-hidden rounded border border-[var(--card-border)]">
          {codes.slice(1).map((code, i) => (
            <div key={i} className="flex items-center justify-between gap-3 border-b border-[var(--card-border)] px-3 py-2 last:border-b-0">
              <div className="min-w-0">
                <div className="text-[12.5px] text-[var(--text)]">
                  +{i + 1} window{clock((step + i + 1) * period)} – {clock((step + i + 2) * period)} UTC
                </div>
                <div className="text-[11px] text-[var(--text-faint)]">counter {step + i + 1}</div>
              </div>
              <div className="flex items-center gap-2">
                <span className="rf-mono text-[15px] tracking-[0.12em] text-[var(--text)]">{code}</span>
                <CopyChip text={code} label="copy" />
              </div>
            </div>
          ))}
          {codes.length === 0 && <div className="px-3 py-3 text-[12px] text-[var(--text-faint)]">Waiting for a decodable secret.</div>}
        </div>
      </Card>

      <Card title="Drift table (±2 windows)">
        <div className="overflow-hidden rounded border border-[var(--card-border)]">
          {drift.map((code, i) => {
            const offset = i - 2;
            const current = offset === 0;
            return (
              <div
                key={i}
                className="flex items-center justify-between gap-3 border-b border-[var(--card-border)] px-3 py-2 last:border-b-0"
                style={current ? { background: 'var(--accent-faded)' } : undefined}
              >
                <span className="text-[12.5px]" style={{ color: current ? 'var(--text)' : 'var(--text-muted)' }}>
                  {offset > 0 ? `+${offset}` : offset} · {clock((step + offset) * period)}
                  {current ? ' · now' : ''}
                </span>
                <span className="rf-mono text-[13.5px] tracking-[0.1em] text-[var(--text)]">{code}</span>
              </div>
            );
          })}
        </div>
        <div className="mt-3">
          <Callout tone="info" title="Why a server accepts more than one window">
            Clock skew, network latency and the second boundary itself all shift which counter a client used. Most
            verifiers accept the previous and next window only; accepting ±2 doubles the guessing surface for very
            little benefit.
          </Callout>
        </div>
      </Card>
    </>
  );
}
