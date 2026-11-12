import { useEffect, useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CopyChip,
  KVTable,
  SectionTitle,
  Select,
  Tabs,
  TextArea,
  UploadButton,
} from '@/components/ui';
import { md5Hex, sha1Hex, sha256Hex, sha384Hex, sha512Hex, ntlmHash, utf8ToBytes } from '@/lib/crypto';
import { base64FromBytes } from '@/lib/bytes';
import { shannonEntropy } from '@/lib/encoding';

type AlgoId = 'md5' | 'sha1' | 'sha256' | 'sha512' | 'sha384' | 'ntlm' | 'mysql41' | 'crc32' | 'blake2b';

interface Algo {
  id: AlgoId;
  label: string;
  hashcat: string;
  bits: number;
  supported: boolean;
  note?: string;
  compute?: (bytes: Uint8Array) => string | Promise<string>;
}

/** MySQL 4.1+ double-SHA1: SHA1(SHA1(password)) upper-hex, `*` prefixed. */
const mysql41 = (bytes: Uint8Array): string => `*${sha1Hex(utf8ToBytes(sha1Hex(bytes))).toUpperCase()}`;

/** CRC32 (IEEE 802.3) over raw bytes. */
const crc32 = (bytes: Uint8Array): string => {
  let table = crc32.table;
  if (!table) {
    table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[i] = c >>> 0;
    }
    crc32.table = table;
  }
  let crc = 0xffffffff;
  for (const b of bytes) crc = (table[(crc ^ b) & 0xff] ^ (crc >>> 8)) >>> 0;
  return ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, '0');
};
crc32.table = undefined as Uint32Array | undefined;

const ALGOS: Algo[] = [
  { id: 'md5', label: 'MD5', hashcat: '-m 0', bits: 128, supported: true, compute: (b) => md5Hex(b) },
  { id: 'sha1', label: 'SHA-1', hashcat: '-m 100', bits: 160, supported: true, compute: (b) => sha1Hex(b) },
  { id: 'sha256', label: 'SHA-256', hashcat: '-m 1400', bits: 256, supported: true, compute: (b) => sha256Hex(b) },
  { id: 'sha512', label: 'SHA-512', hashcat: '-m 1700', bits: 512, supported: true, compute: (b) => sha512Hex(b) },
  { id: 'sha384', label: 'SHA-384', hashcat: '-m 10800', bits: 384, supported: true, compute: (b) => sha384Hex(b) },
  { id: 'ntlm', label: 'NT / NTLM', hashcat: '-m 1000', bits: 128, supported: true, note: 'MD4 of UTF-16LE — verify against a known account', compute: (b) => ntlmHash(new TextDecoder().decode(b)) },
  { id: 'mysql41', label: 'MySQL 4.1+', hashcat: '-m 300', bits: 160, supported: true, note: 'SHA1(SHA1(pw)) upper-hex with a leading *', compute: mysql41 },
  { id: 'crc32', label: 'CRC32', hashcat: '— (checksum, not a KDF)', bits: 32, supported: true, note: 'Integrity check only; trivial to invert', compute: crc32 },
  { id: 'blake2b', label: 'BLAKE2b-256', hashcat: '-m 600', bits: 256, supported: false, note: 'hash-wasm is not wired into @/lib/crypto — copy the digest from blake2b() if you need it' },
];

const DEFAULTS: AlgoId[] = ['md5', 'sha1', 'sha256'];

export default function HashGenerator() {
  const [input, setInput] = useState('correct horse battery staple');
  const [active, setActive] = useState<AlgoId[]>(DEFAULTS);
  const [encoding, setEncoding] = useState<'hex' | 'base64'>('hex');
  const [upper, setUpper] = useState(false);
  const [loadedName, setLoadedName] = useState('');
  const [results, setResults] = useState<Record<string, string>>({});

  const bytes = useMemo(() => utf8ToBytes(input), [input]);
  const selected = useMemo(() => ALGOS.filter((a) => active.includes(a.id) && a.supported), [active]);

  useEffect(() => {
    let alive = true;
    (async () => {
      const out: Record<string, string> = {};
      for (const algo of selected) {
        if (!algo.compute) continue;
        try {
          const raw = await algo.compute(bytes);
          out[algo.id] = raw;
        } catch {
          out[algo.id] = '';
        }
      }
      if (alive) setResults(out);
    })();
    return () => {
      alive = false;
    };
  }, [bytes, selected]);

  const render = (hex: string): string => {
    if (!hex) return '';
    const value =
      encoding === 'base64' ? base64FromBytes(Uint8Array.from(hex.match(/.{2}/g) ?? [], (h) => parseInt(h, 16))) : hex;
    return upper ? value.toUpperCase() : value.toLowerCase();
  };

  const readings = useMemo(() => {
    const len = Array.from(input).length;
    const unit = new TextEncoder().encode(input).length;
    return { chars: len, bytes: unit, entropy: shannonEntropy(input) };
  }, [input]);

  const toggle = (id: AlgoId, on: boolean) =>
    setActive((prev) => (on ? [...new Set([...prev, id])] : prev.filter((x) => x !== id)));

  return (
    <>
      <Card
        title="Input"
        action={
          <UploadButton
            onFile={(text, name) => {
              setInput(text);
              setLoadedName(`${name} · ${new TextEncoder().encode(text).length} bytes`);
            }}
            label={loadedName ? 'Replace file' : 'Load file'}
          />
        }
      >
        <TextArea
          label={loadedName ? `Content (${loadedName})` : 'Text'}
          value={input}
          onChange={setInput}
          rows={5}
          placeholder="Type or paste the value to digest"
        />
        <div className="mt-4 grid gap-4 sm:grid-cols-3">
          <div>
            <SectionTitle>Output encoding</SectionTitle>
            <Tabs
              value={encoding}
              onChange={setEncoding}
              tabs={[
                { value: 'hex', label: 'hex' },
                { value: 'base64', label: 'base64' },
              ]}
            />
          </div>
          <div className="flex items-end pb-2">
            <Checkbox checked={upper} onChange={setUpper} label="Uppercase" description="AD / MySQL style" />
          </div>
          <div className="rounded border border-[var(--card-border)] px-3 py-2 text-[11.5px] leading-relaxed text-[var(--text-muted)]">
            <div>
              Length <span className="rf-mono text-[var(--text)]">{readings.chars}</span> chars ·{' '}
              <span className="rf-mono text-[var(--text)]">{readings.bytes}</span> bytes
            </div>
            <div>
              Shannon entropy <span className="rf-mono text-[var(--text)]">{readings.entropy.toFixed(2)}</span> bits/char
            </div>
          </div>
        </div>
      </Card>

      <Card title="Algorithms">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {ALGOS.map((a) => (
            <div
              key={a.id}
              className="rounded border border-[var(--card-border)] px-3 py-2"
              style={{ opacity: a.supported ? 1 : 0.5 }}
            >
              <Checkbox
                checked={active.includes(a.id)}
                onChange={(v) => (a.supported ? toggle(a.id, v) : undefined)}
                label={a.label}
                description={a.supported ? `${a.bits} bit · hashcat ${a.hashcat}` : a.note}
              />
            </div>
          ))}
        </div>
      </Card>

      <Card
        title="Digests"
        action={<span className="text-[11.5px] text-[var(--text-faint)]">{selected.length} selected</span>}
      >
        {!input ? (
          <Callout tone="info" title="Empty input">
            An empty string still hashes (MD5 of nothing is d41d8cd98f00b204e9800998ecf8427e), but there is nothing to
            show. Type a value, or load a file for binary-accurate digests.
          </Callout>
        ) : selected.length === 0 ? (
          <Callout tone="warn" title="No algorithm selected">
            Tick at least one algorithm above.
          </Callout>
        ) : (
          <div className="space-y-3">
            {selected.map((a) => {
              const value = render(results[a.id] ?? '');
              return (
                <div key={a.id} className="rounded border border-[var(--card-border)] px-3 py-2">
                  <div className="mb-1 flex items-center justify-between gap-2">
                    <span className="text-[12.5px] font-medium text-[var(--text)]">
                      {a.label}
                      <span className="rf-mono ml-2 text-[11px] text-[var(--text-faint)]">{a.hashcat}</span>
                    </span>
                    {value && <CopyChip text={value} label="copy" />}
                  </div>
                  <div className="rf-mono text-[12px] break-all text-[var(--text)]">
                    {value || <span className="text-[var(--text-faint)]">computing…</span>}
                  </div>
                  {a.note && <div className="mt-1 text-[11px] leading-snug text-[var(--text-faint)]">{a.note}</div>}
                </div>
              );
            })}
          </div>
        )}
      </Card>

      <Card title="Hashcat modes">
        <KVTable rows={ALGOS.map((a) => [a.label, `${a.hashcat} · ${a.bits} bit`])} />
        <div className="mt-4">
          <OutputFieldStub />
        </div>
        <div className="mt-4">
          <Callout tone="warn" title="Unsalted digests are not passwords">
            MD5, SHA-1 and NTLM are hashing, not key derivation: a GPU tests tens of billions per second. Treat any hit
            here as a fingerprint, not a credential store.
          </Callout>
        </div>
      </Card>
    </>
  );
}

/** Small inline helper so the mode table also shows a ready command. */
function OutputFieldStub() {
  const cmd = 'hashcat -a 0 -m 1000 ntlm.txt words.txt -r rules/best64.rule --status';
  return (
    <div className="rounded border border-[var(--input-border)] bg-[var(--input)] px-3 py-2">
      <div className="mb-1 text-[11.5px] text-[var(--text-faint)]">Example (NTLM, rule-based dictionary)</div>
      <div className="flex items-center justify-between gap-2">
        <code className="rf-mono text-[12px] break-all text-[var(--text)]">{cmd}</code>
        <CopyChip text={cmd} label="copy" />
      </div>
    </div>
  );
}
