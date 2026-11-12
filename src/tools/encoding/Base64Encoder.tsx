import { useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, KVTable, OutputBlock, Select, Tabs, TextArea } from '@/components/ui';
import { b32Decode, b32Encode, b64Decode, b64Encode, toHex } from '@/lib/encoding';
import { fromUtf8, utf8 } from '@/lib/bytes';

/**
 * Base64 / base32 / base16 codec. Encoding is byte-exact (UTF-8), decoding is
 * strict: every non-alphabet character is reported rather than silently dropped,
 * because a silently-truncated decode is the classic way to report a false result.
 */

type Mode = 'encode' | 'decode';
type Variant = 'standard' | 'urlsafe' | 'nopad' | 'base32' | 'base16';

const VARIANTS: Array<{ value: Variant; label: string }> = [
  { value: 'standard', label: 'Base64 standard (RFC 4648, +/ with padding)' },
  { value: 'urlsafe', label: 'Base64 URL-safe (-_ with padding)' },
  { value: 'nopad', label: 'Base64 without padding' },
  { value: 'base32', label: 'Base32 (RFC 4648, A-Z2-7)' },
  { value: 'base16', label: 'Base16 / hex' },
];

const HEX_NOTE: Record<Variant, string> = {
  standard: 'The default everywhere: mail bodies, HTTP Basic, PEM armour, PowerShell -EncodedCommand payloads.',
  urlsafe: 'JWT segments, URL parameters and filenames. Swap +/ for -_ before it hits a query string.',
  nopad: 'Same alphabet, stripped "=". Some decoders require padding — restore it before pasting into strict parsers.',
  base32: 'Case-insensitive and DNS-safe. Used by TOTP secrets, some .onion names and older Windows identifiers.',
  base16: 'Plain hex pairs. No padding, no case ambiguity; the form every hexdump, hash and shellcode blob uses.',
};

const REGEXES: Array<{ name: string; re: RegExp; note: string }> = [
  { name: 'Base64 standard', re: /^[A-Za-z0-9+/]+={0,2}$/, note: 'length % 4 === 0 once padded' },
  { name: 'Base64 URL-safe', re: /^[A-Za-z0-9_-]+={0,2}$/, note: 'no +, / or whitespace' },
  { name: 'Base32', re: /^[A-Z2-7]+=*$/i, note: 'length % 8 === 0 once padded' },
  { name: 'Base16 / hex', re: /^(?:[0-9a-fA-F]{2})+$/, note: 'even character count' },
];

/** Strict base64 decode — throws with a reason instead of dropping bytes. */
function strictB64(text: string): Uint8Array {
  const clean = text.replace(/\s+/g, '');
  const normalised = clean.replace(/-/g, '+').replace(/_/g, '/');
  const bad = normalised.replace(/[A-Za-z0-9+/=]/g, '');
  if (bad) throw new Error(`Illegal base64 character(s): ${JSON.stringify(bad.slice(0, 12))}`);
  if (/=/.test(normalised.slice(0, -2))) throw new Error('Padding "=" appears before the end of the string');
  const body = normalised.replace(/=+$/, '');
  if (body.length % 4 === 1) throw new Error(`Body length ${body.length} is impossible for base64 (mod 4 = 1)`);
  return b64Decode(normalised);
}

function strictHex(text: string): Uint8Array {
  const clean = text.replace(/\s+/g, '').replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error('Hex contains characters outside 0-9a-f');
  if (clean.length % 2) throw new Error(`Odd hex length (${clean.length}) — one nibble is missing`);
  return b64Decode(b64Encode(new Uint8Array(clean.match(/../g)?.map((p) => parseInt(p, 16)) ?? [])));
}

function strictBase32(text: string): Uint8Array {
  const clean = text.replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
  const bad = clean.replace(/[A-Z2-7]/g, '');
  if (bad) throw new Error(`Illegal base32 character(s): ${JSON.stringify(bad.slice(0, 12))}`);
  return b32Decode(clean);
}

/** Does this pasted string look like base64 we could decode? */
function analyseBase64(input: string) {
  const clean = input.replace(/\s+/g, '');
  if (clean.length < 8) return { verdict: 'too short' as const, detail: 'Fewer than 8 characters — not enough signal.' };
  const printableRatio = Array.from(clean).filter((c) => /[A-Za-z0-9+/=_-]/.test(c)).length / clean.length;
  if (printableRatio < 1) {
    return {
      verdict: 'no' as const,
      detail: `${Math.round((1 - printableRatio) * 100)}% of characters are outside the base64 alphabet.`,
    };
  }
  if (clean.length % 4 !== 0 && !/[-_]/.test(clean)) {
    return { verdict: 'unlikely' as const, detail: `Length ${clean.length} is not a multiple of 4; padding looks missing.` };
  }
  try {
    const bytes = strictB64(clean);
    const text = fromUtf8(bytes);
    const textRatio = Array.from(text).filter((c) => c === '\n' || c === '\t' || (c >= ' ' && c !== '\u00a0')).length /
      Math.max(text.length, 1);
    if (textRatio < 0.85) {
      return {
        verdict: 'binary' as const,
        detail: `Decodes cleanly to ${bytes.length} bytes, but only ${Math.round(textRatio * 100)}% are printable — likely a binary blob, key or ciphertext.`,
      };
    }
    return { verdict: 'yes' as const, detail: `Decodes cleanly to ${bytes.length} bytes of plausible UTF-8 text.` };
  } catch (e) {
    return { verdict: 'no' as const, detail: e instanceof Error ? e.message : 'Decode failed' };
  }
}

export default function Base64Encoder() {
  const [mode, setMode] = useState<Mode>('encode');
  const [variant, setVariant] = useState<Variant>('standard');
  const [input, setInput] = useState('');
  const [wrap, setWrap] = useState(0);

  const result = useMemo(() => {
    if (!input.trim()) return { output: '', error: null as string | null, bytes: 0 };
    try {
      if (mode === 'encode') {
        const bytes = utf8(input);
        let out: string;
        if (variant === 'base32') out = b32Encode(bytes);
        else if (variant === 'base16') out = toHex(bytes);
        else if (variant === 'urlsafe') out = b64Encode(bytes, true);
        else if (variant === 'nopad') out = b64Encode(bytes).replace(/=+$/, '');
        else out = b64Encode(bytes);
        return { output: out, error: null, bytes: bytes.length };
      }
      const bytes =
        variant === 'base32' ? strictBase32(input) : variant === 'base16' ? strictHex(input) : strictB64(input);
      const text = fromUtf8(bytes);
      if (text.includes('\uFFFD')) throw new Error('Decoded bytes are not valid UTF-8 — treat as binary and inspect as hex');
      return { output: text, error: null, bytes: bytes.length };
    } catch (e) {
      return { output: '', error: e instanceof Error ? e.message : 'Conversion failed', bytes: 0 };
    }
  }, [mode, variant, input]);

  const wrapped = useMemo(() => {
    if (!wrap || !result.output) return result.output;
    return result.output.replace(new RegExp(`(.{1,${wrap}})`, 'g'), '$1\n').trimEnd();
  }, [result.output, wrap]);

  const detection = useMemo(() => analyseBase64(input), [input]);

  const shellEquiv = useMemo(() => {
    if (!input.trim()) return '';
    if (mode === 'encode') return `printf '%s' ${JSON.stringify(input)} | base64 -d   # gives this text back`;
    const flag = variant === 'urlsafe' || variant === 'nopad' ? '-d -i' : '-d';
    return `echo ${JSON.stringify(input.replace(/\s+/g, ''))} | base64 ${flag}`;
  }, [input, mode, variant]);

  const roundTrip = useMemo(() => {
    if (!result.output) return null;
    try {
      if (mode === 'encode') {
        const back =
          variant === 'base32'
            ? fromUtf8(strictBase32(result.output))
            : variant === 'base16'
              ? fromUtf8(strictHex(result.output))
              : fromUtf8(strictB64(result.output));
        return back === input;
      }
      return true;
    } catch {
      return false;
    }
  }, [result.output, mode, variant, input]);

  const variantNote = HEX_NOTE[variant];

  return (
    <>
      <Card title="Input">
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <Tabs<Mode>
            value={mode}
            onChange={setMode}
            tabs={[
              { value: 'encode', label: 'Encode' },
              { value: 'decode', label: 'Decode' },
            ]}
          />
          <div className="min-w-[280px] flex-1">
            <Select<Variant> value={variant} onChange={setVariant} options={VARIANTS} />
          </div>
          <div className="w-[190px]">
            <Select<string>
              value={String(wrap)}
              onChange={(v) => setWrap(Number(v))}
              options={[
                { value: '0', label: 'No line wrapping' },
                { value: '76', label: 'Wrap at 76 (MIME)' },
                { value: '64', label: 'Wrap at 64 (PEM)' },
                { value: '120', label: 'Wrap at 120' },
              ]}
            />
          </div>
        </div>

        <TextArea
          label={mode === 'encode' ? 'Plaintext' : 'Encoded input'}
          value={input}
          onChange={setInput}
          rows={6}
          placeholder={mode === 'encode' ? 'Type or paste the text to encode…' : 'Paste base64/base32/hex here…'}
        />

        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11.5px] text-[var(--text-faint)]">
          <span>
            Input: <span className="rf-mono">{input.length}</span> chars ·{' '}
            <span className="rf-mono">{utf8(input).length}</span> UTF-8 bytes
          </span>
          <span>
            Output: <span className="rf-mono">{result.bytes}</span> bytes, <span className="rf-mono">{wrapped.length}</span>{' '}
            chars
          </span>
          {roundTrip !== null && (
            <span style={{ color: roundTrip ? 'var(--ok)' : 'var(--accent)' }}>
              {roundTrip ? 'Round-trip verified' : 'Round-trip mismatch'}
            </span>
          )}
        </div>

        <div className="mt-3">
          <Callout tone="info" title="Variant note">
            {variantNote}
          </Callout>
        </div>
      </Card>

      <Card title="Output">
        {result.error ? (
          <Callout tone="danger" title="Cannot convert">
            {result.error}
          </Callout>
        ) : (
          <>
            <OutputBlock value={wrapped} rows={8} label={mode === 'encode' ? 'Encoded output' : 'Decoded text'} />
            {mode === 'decode' && (
              <div className="mt-4">
                <KVTable
                  rows={[
                    ['Bytes decoded', String(result.bytes)],
                    ['Characters', String(result.output.length)],
                    [
                      'Non-printable',
                      String(Array.from(result.output).filter((c) => c < ' ' && c !== '\n' && c !== '\t').length),
                    ],
                  ]}
                />
              </div>
            )}
          </>
        )}
      </Card>

      <Card title="Base64 detection">
        <p className="mt-0 mb-3 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
          Paste any string into the input above and this helper validates the charset, the length modulo and whether the
          decoded bytes survive a UTF-8 round-trip. It is intentionally conservative: a string that decodes to random
          bytes is reported as binary, not as text.
        </p>
        <KVTable
          rows={[
            [
              'Verdict',
              <span
                key="v"
                style={{
                  color:
                    detection.verdict === 'yes'
                      ? 'var(--ok)'
                      : detection.verdict === 'binary'
                        ? 'var(--warn)'
                        : 'var(--text-muted)',
                }}
              >
                {detection.verdict}
              </span>,
            ],
            ['Reason', detection.detail],
            ['Alphabet check', REGEXES.map((r) => `${r.name}: ${r.re.test(input.trim()) ? 'match' : 'no match'}`).join(' · ')],
            ['Length mod 4', String(input.replace(/\s+/g, '').length % 4)],
          ]}
        />
      </Card>

      <Card title="Shell equivalent">
        <CodeBlock code={shellEquiv || '# Nothing to convert yet'} label="base64(1)" />
        <div className="mt-3">
          <Callout tone="warn" title="Decode with -d, never with a library default">
            GNU base64 wants <span className="rf-mono">-d</span>; macOS wants <span className="rf-mono">-D</span>.
            URL-safe input needs <span className="rf-mono">tr '\-_' '+/'</span> first on older coreutils. A decoder that
            drops unknown characters will happily return truncated data — always compare against a known length.
          </Callout>
        </div>
      </Card>
    </>
  );
}
