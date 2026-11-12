import { useMemo, useState } from 'react';
import { Callout, Card, KVTable, OutputBlock, SectionTitle, TextArea, TextInput } from '@/components/ui';
import { bytesToUtf8, fromHex, toHex } from '@/lib/crypto';

type Status = 'applies' | 'no' | 'skipped';
interface Finding { id: string; name: string; status: Status; detail: string; result?: string }
const COLOUR: Record<Status, string> = { applies: 'var(--ok)', no: 'var(--text-faint)', skipped: 'var(--warn)' };

function parseBig(raw: string): bigint | null {
  const s = raw.trim().replace(/[\s_]/g, '');
  if (!s) return null;
  if (/^0x[0-9a-f]+$/i.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return /^[0-9a-f]+$/i.test(s) && /[a-f]/i.test(s) ? BigInt(`0x${s}`) : null;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let r = 1n, b = ((base % mod) + mod) % mod, e = exp;
  while (e > 0n) { if (e & 1n) r = (r * b) % mod; b = (b * b) % mod; e >>= 1n; }
  return r;
}

function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a, y = b < 0n ? -b : b;
  while (y) { [x, y] = [y, x % y]; }
  return x;
}

function modInverse(a: bigint, m: bigint): bigint | null {
  let [oldR, r] = [((a % m) + m) % m, m], [oldS, s] = [1n, 0n];
  while (r !== 0n) { const q = oldR / r; [oldR, r] = [r, oldR - q * r]; [oldS, s] = [s, oldS - q * s]; }
  return oldR === 1n ? ((oldS % m) + m) % m : null;
}

function isqrt(n: bigint): bigint {
  if (n < 2n) return n;
  let x = 1n << BigInt(Math.ceil(n.toString(2).length / 2));
  let y = (x + n / x) >> 1n;
  while (y < x) { x = y; y = (x + n / x) >> 1n; }
  return x;
}

/** Integer k-th root by binary search — the small-e "no padding" attack. */
function iroot(c: bigint, k: number): { root: bigint; exact: boolean } {
  if (c < 2n) return { root: c, exact: true };
  const K = BigInt(k);
  let lo = 0n, hi = 1n << BigInt(Math.ceil(c.toString(2).length / k) + 1);
  while (lo + 1n < hi) { const mid = (lo + hi) >> 1n; if (mid ** K <= c) lo = mid; else hi = mid; }
  return { root: lo, exact: lo ** K === c };
}

function renderPlain(m: bigint): string {
  if (m <= 0n) return '(zero)';
  const bytes = fromHex(m.toString(16).padStart(m.toString(16).length + (m.toString(16).length % 2), '0'));
  const text = bytesToUtf8(bytes);
  const printable = Array.from(text).filter((ch) => ch >= ' ' && ch !== '\uFFFD').length;
  return printable / Math.max(1, text.length) > 0.85 ? text : `0x${toHex(bytes)}`;
}

/** Wiener: convergents of e/n; a small d shows up as an early denominator. */
function wiener(n: bigint, e: bigint): { d: bigint; p: bigint; q: bigint; steps: number } | null {
  let a = e, b = n, h0 = 0n, h1 = 1n, k0 = 1n, k1 = 0n;
  for (let steps = 1; steps <= 1024 && b !== 0n; steps++) {
    const q = a / b, r = a - q * b;
    [a, b] = [b, r];
    [h0, h1] = [h1, q * h1 + h0];
    [k0, k1] = [k1, q * k1 + k0];
    if (h1 === 0n || k1 === 0n) continue;
    const num = e * k1 - 1n;
    if (num <= 0n || num % h1 !== 0n) continue;
    const phi = num / h1, s = n - phi + 1n, disc = s * s - 4n * n;
    if (disc < 0n) continue;
    const root = isqrt(disc);
    if (root * root === disc) return { d: k1, p: (s + root) / 2n, q: (s - root) / 2n, steps };
  }
  return null;
}

function fermat(n: bigint, limit: number): { p: bigint; q: bigint; iterations: number } | null {
  if (n % 2n === 0n) return { p: 2n, q: n / 2n, iterations: 0 };
  let a = isqrt(n);
  if (a * a < n) a += 1n;
  for (let i = 0; i < limit; i++, a++) {
    const b2 = a * a - n, b = isqrt(b2);
    if (b * b === b2) return { p: a - b, q: a + b, iterations: i };
  }
  return null;
}

function crt(pairs: Array<[bigint, bigint]>): { x: bigint; mod: bigint } | null {
  let x = 0n, mod = 1n;
  for (const [ni, ci] of pairs) {
    if (gcd(mod, ni) !== 1n) return null;
    const inv = modInverse(mod % ni, ni);
    if (inv === null) return null;
    x = (x + mod * (((((ci - x) % ni) + ni) % ni) * inv % ni)) % (mod * ni);
    mod *= ni;
  }
  return { x, mod };
}

export default function RsaAttackPlanner() {
  const [nRaw, setNRaw] = useState('0x00b3d1a4b8e6f2c9d7a5e3b1f9c7d5a3b1e9f7c5d3a1b9e7f5c3a1d9b7e5f3c1a9d7');
  const [eRaw, setERaw] = useState('3');
  const [cRaw, setCRaw] = useState('0x00d9e1f3a5');
  const [n2Raw, setN2Raw] = useState('');
  const [c2Raw, setC2Raw] = useState('');
  const [broadcast, setBroadcast] = useState('');
  const [fermatLimit, setFermatLimit] = useState(200000);

  const n = parseBig(nRaw), e = parseBig(eRaw), c = parseBig(cRaw);
  const n2 = parseBig(n2Raw), c2 = parseBig(c2Raw) ?? c;

  const report = useMemo<Finding[]>(() => {
    const out: Finding[] = [];
    if (n === null || e === null) {
      return [{ id: 'input', name: 'Parameters', status: 'skipped', detail: 'Enter a modulus n and public exponent e as decimal or 0x-prefixed hex before any attack can run.' }];
    }
    if (e > 64n) out.push({ id: 'small-e', name: 'Small-e integer root', status: 'skipped', detail: `e = ${e} is far too large for an integer root sweep — that attack only targets e = 3, 5, 17, or 65537 against a tiny message.` });
    else if (c === null) out.push({ id: 'small-e', name: 'Small-e integer root', status: 'skipped', detail: 'No ciphertext c supplied.' });
    else if (c >= n) out.push({ id: 'small-e', name: 'Small-e integer root', status: 'no', detail: 'c ≥ n, so the plaintext was already reduced modulo n — there is no exact integer e-th power to recover.' });
    else {
      const { root, exact } = iroot(c, Number(e));
      out.push(exact
        ? { id: 'small-e', name: 'Small-e integer root', status: 'applies', detail: `c is an exact ${e}-th power and c < n, so no modular reduction happened. m = c^(1/${e}).`, result: `${root}  ·  as text: ${renderPlain(root)}` }
        : { id: 'small-e', name: 'Small-e integer root', status: 'no', detail: `c is not a perfect ${e}-th power: floor(root)^${e} ≠ c. The message wrapped the modulus or padding was applied.` });
    }
    if (n2 === null) out.push({ id: 'common-modulus', name: 'Common modulus (gcd)', status: 'skipped', detail: 'Supply a second modulus n2 to test whether two keys share a prime.' });
    else {
      const g = gcd(n, n2);
      if (g === 1n) out.push({ id: 'common-modulus', name: 'Common modulus (gcd)', status: 'no', detail: 'gcd(n, n2) = 1 — the moduli are coprime, so no factor leaks between the keys.' });
      else if (g === n || g === n2) out.push({ id: 'common-modulus', name: 'Common modulus (gcd)', status: 'no', detail: 'One modulus divides the other — this is a reused key, not a shared prime.' });
      else {
        const p = g, q = n / g, d = modInverse(e, (p - 1n) * (q - 1n));
        if (d === null) out.push({ id: 'common-modulus', name: 'Common modulus (gcd)', status: 'no', detail: 'Shared factor found, but e is not invertible mod φ(n) — the key pair is malformed.' });
        else if (c2 === null) out.push({ id: 'common-modulus', name: 'Common modulus (gcd)', status: 'applies', detail: `gcd(n, n2) = ${p} — the shared prime is recovered. d = e⁻¹ mod φ(n) follows, but there is no ciphertext to decrypt.`, result: `p = ${p}` });
        else out.push({ id: 'common-modulus', name: 'Common modulus (gcd)', status: 'applies', detail: `gcd(n, n2) = ${p} — a shared prime. Recovered d for the first modulus and decrypted the ciphertext with it.`, result: `p = ${p}\nq = ${q}\nm = ${renderPlain(modPow(c2, d, n))}` });
      }
    }
    const w = wiener(n, e);
    out.push(w
      ? { id: 'wiener', name: "Wiener's attack", status: 'applies', detail: `A convergent of e/n yielded d after ${w.steps} step(s) — d is small relative to n, which is precisely the weakness.`, result: `d = ${w.d}\np = ${w.p}\nq = ${w.q}` }
      : { id: 'wiener', name: "Wiener's attack", status: 'no', detail: 'No convergent of e/n satisfied ed − 1 ≡ 0 (mod k) with a square discriminant in 1024 steps — d is not small enough.' });
    const f = fermat(n, fermatLimit);
    out.push(f
      ? { id: 'fermat', name: 'Fermat factorisation', status: 'applies', detail: `Factors found after ${f.iterations} iteration(s) inside the ${fermatLimit.toLocaleString()} bound — p and q are close together.`, result: `p = ${f.p}\nq = ${f.q}` }
      : { id: 'fermat', name: 'Fermat factorisation', status: 'no', detail: `No square appeared in ${fermatLimit.toLocaleString()} iterations — |p − q| is larger than the current bound reaches.` });
    return out;
  }, [n, e, c, n2, c2, fermatLimit]);

  const hastad = useMemo<Finding>(() => {
    const lines = broadcast.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    if (e === null) return { id: 'hastad', name: 'Håstad broadcast', status: 'skipped', detail: 'Public exponent e is required.' };
    if (lines.length === 0) return { id: 'hastad', name: 'Håstad broadcast', status: 'skipped', detail: 'Paste one "n:c" pair per recipient — one line per intercepted ciphertext.' };
    const pairs: Array<[bigint, bigint]> = [];
    for (const [i, line] of lines.entries()) {
      const [niRaw, ciRaw] = line.split(/[:,]/).map((v) => v.trim());
      const ni = niRaw ? parseBig(niRaw) : null, ci = ciRaw ? parseBig(ciRaw) : null;
      if (ni === null || ci === null) return { id: 'hastad', name: 'Håstad broadcast', status: 'no', detail: `Line ${i + 1} is not a parsable "n:c" pair.` };
      pairs.push([ni, ci]);
    }
    if (BigInt(pairs.length) < e) return { id: 'hastad', name: 'Håstad broadcast', status: 'no', detail: `${pairs.length} ciphertext(s) supplied but e = ${e} are needed — below that the CRT modulus is smaller than m^e.` };
    const combined = crt(pairs);
    if (!combined) return { id: 'hastad', name: 'Håstad broadcast', status: 'no', detail: 'The moduli are not pairwise coprime — CRT does not apply to this set.' };
    if (e > 64n) return { id: 'hastad', name: 'Håstad broadcast', status: 'no', detail: 'e is too large to take an integer root of the CRT result.' };
    const { root, exact } = iroot(combined.x, Number(e));
    if (!exact) return { id: 'hastad', name: 'Håstad broadcast', status: 'no', detail: 'CRT succeeded but the result is not an exact e-th power — the plaintexts differ or padding was used.' };
    return { id: 'hastad', name: 'Håstad broadcast', status: 'applies', detail: `CRT over ${pairs.length} moduli reconstructed m^${e}, and its exact ${e}-th root is the plaintext.`, result: `${root}  ·  as text: ${renderPlain(root)}` };
  }, [broadcast, e]);

  const bits = n ? n.toString(2).length : 0;
  const badInput = (nRaw.trim() && n === null) || (eRaw.trim() && e === null) || (cRaw.trim() && c === null);

  return (
    <>
      <Card title="Parameters">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput label="Modulus n" value={nRaw} onChange={setNRaw} mono hint={n ? `${bits} bits` : 'decimal or 0x hex'} />
          <TextInput label="Public exponent e" value={eRaw} onChange={setERaw} mono hint="3, 5, 17 or 65537" />
          <TextInput label="Ciphertext c" value={cRaw} onChange={setCRaw} mono hint="for the first modulus" />
          <TextInput label="Second modulus n2" value={n2Raw} onChange={setN2Raw} mono hint="optional — common modulus test" />
          <TextInput label="Ciphertext c2" value={c2Raw} onChange={setC2Raw} mono hint="optional — defaults to c" />
          <TextInput label="Fermat iteration bound" value={String(fermatLimit)} onChange={(v) => setFermatLimit(Math.max(1, Math.min(2_000_000, Number(v) || 1)))} mono />
        </div>
        {badInput && (
          <div className="mt-3">
            <Callout tone="warn" title="Unparsable field">
              Use plain decimal or 0x-prefixed hex. Bare hex is accepted only when it contains a–f, so a decimal-looking
              string is never silently reinterpreted.
            </Callout>
          </div>
        )}
        <div className="mt-4">
          <KVTable
            rows={[
              ['Modulus size', n ? `${bits} bits (${Math.ceil(bits / 8)} bytes)` : '—'],
              ['n mod 4', n ? String(n % 4n) : '—'],
              ['gcd(n, n2)', n && n2 ? String(gcd(n, n2)) : '—'],
              ['Assessment', bits >= 2048 ? 'Structurally normal size — only key reuse or bad generation breaks it.' : bits > 0 ? 'Below 2048 bits; test the structural weaknesses above before spending compute on factoring.' : 'Awaiting a modulus.'],
            ]}
          />
        </div>
      </Card>

      <Card title="Attack matrix">
        <div className="overflow-hidden rounded border border-[var(--card-border)]">
          {report.map((f) => (
            <div key={f.id} className="border-b border-[var(--card-border)] px-3 py-2.5 last:border-b-0">
              <div className="flex items-baseline justify-between gap-3">
                <span className="text-[13px] text-[var(--text)]">{f.name}</span>
                <span className="shrink-0 text-[11.5px] font-medium" style={{ color: COLOUR[f.status] }}>{f.status}</span>
              </div>
              <p className="mt-1 mb-0 text-[11.5px] leading-relaxed text-[var(--text-faint)]">{f.detail}</p>
              {f.result && <div className="rf-mono mt-1.5 text-[12px] break-all whitespace-pre-wrap text-[var(--text)]">{f.result}</div>}
            </div>
          ))}
        </div>
        <div className="mt-4">
          <OutputBlock
            value={report.filter((r) => r.result).map((r) => `${r.name}\n${r.result}`).join('\n\n')}
            rows={7}
            label="Recovered factors and plaintext"
            empty="No attack produced a factor or plaintext for these parameters."
          />
        </div>
        <div className="mt-3">
          <Callout tone={report.some((r) => r.status === 'applies') ? 'ok' : 'info'} title={report.some((r) => r.status === 'applies') ? 'At least one weakness is present' : 'Nothing recovered'}>
            A “no” is a computed result, not a placeholder: the root was checked exactly, the gcd was taken, every
            convergent was tested. If no row applies, these parameters are not broken in any of these four ways.
          </Callout>
        </div>
      </Card>

      <Card title="Håstad broadcast">
        <SectionTitle right={<span className="text-[11px] text-[var(--text-faint)]">one n:c pair per line</span>}>
          Intercepted ciphertexts
        </SectionTitle>
        <TextArea value={broadcast} onChange={setBroadcast} rows={5} label="Recipients" placeholder={'n1:c1\nn2:c2\nn3:c3'} hint="Same plaintext, same small e, different moduli. Needs e pairs for the CRT to beat the modulus." />
        <div className="mt-3 overflow-hidden rounded border border-[var(--card-border)] px-3 py-2.5">
          <div className="flex items-baseline justify-between gap-3">
            <span className="text-[13px] text-[var(--text)]">{hastad.name}</span>
            <span className="text-[11.5px] font-medium" style={{ color: COLOUR[hastad.status] }}>{hastad.status}</span>
          </div>
          <p className="mt-1 mb-0 text-[11.5px] leading-relaxed text-[var(--text-faint)]">{hastad.detail}</p>
          {hastad.result && <div className="rf-mono mt-1.5 text-[12px] break-all whitespace-pre-wrap text-[var(--text)]">{hastad.result}</div>}
        </div>
        <div className="mt-3">
          <Callout tone="info" title="What each attack assumes">
            Small-e needs <span className="rf-mono">m^e &lt; n</span> (no padding). Common modulus needs one shared
            prime. Wiener needs <span className="rf-mono">d &lt; n^0.25/3</span>. Fermat needs{' '}
            <span className="rf-mono">|p − q|</span> small enough to reach inside the bound. Håstad needs e moduli and
            the identical unpadded message. All five are structural failures, which is why generation hygiene matters
            more than key length.
          </Callout>
        </div>
      </Card>
    </>
  );
}
