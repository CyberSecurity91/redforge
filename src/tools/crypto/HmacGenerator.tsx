import { useEffect, useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, CopyChip, KVTable, Select, TextArea, TextInput, Tabs } from '@/components/ui';
import { bytesFromBase64, base64FromBytes, toHex, utf8ToBytes } from '@/lib/crypto';
import { hmacHex } from '@/lib/crypto';

type Algo = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';
type InputEnc = 'utf8' | 'hex' | 'base64';

const ALGOS: Array<{ value: Algo; label: string }> = [
  { value: 'SHA-1', label: 'HMAC-SHA-1' },
  { value: 'SHA-256', label: 'HMAC-SHA-256' },
  { value: 'SHA-384', label: 'HMAC-SHA-384' },
  { value: 'SHA-512', label: 'HMAC-SHA-512' },
];

const ENCODINGS: Array<{ value: InputEnc; label: string }> = [
  { value: 'utf8', label: 'UTF-8 text' },
  { value: 'hex', label: 'Hex bytes' },
  { value: 'base64', label: 'Base64 bytes' },
];

/** WebCrypto HMAC for the 384/512 variants crypto.ts does not cover. */
async function hmacSubtle(algo: Algo, key: string, msg: string): Promise<string> {
  const alg: HmacImportParams = { name: 'HMAC', hash: algo };
  const raw = utf8ToBytes(key) as unknown as BufferSource;
  const cryptoKey = await crypto.subtle.importKey('raw', raw, alg, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, utf8ToBytes(msg) as unknown as BufferSource);
  return toHex(new Uint8Array(sig));
}

/** Decode a hex/base64 key or message field into raw bytes, then re-encode as UTF-8 text for crypto.ts. */
function decodeInput(value: string, enc: InputEnc): { text: string; bytes: number } {
  if (enc === 'utf8') return { text: value, bytes: utf8ToBytes(value).length };
  if (enc === 'hex') {
    const clean = value.replace(/[^0-9a-fA-F]/g, '');
    const bytes = new Uint8Array(Math.floor(clean.length / 2));
    for (let i = 0; i < bytes.length; i += 1) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    return { text: new TextDecoder('utf-8', { fatal: false }).decode(bytes), bytes: bytes.length };
  }
  const bytes = bytesFromBase64(value.trim());
  return { text: new TextDecoder('utf-8', { fatal: false }).decode(bytes), bytes: bytes.length };
}

export default function HmacGenerator() {
  const [algo, setAlgo] = useState<Algo>('SHA-256');
  const [key, setKey] = useState('YQ==');
  const [message, setMessage] = useState('The quick brown fox jumps over the lazy dog');
  const [keyEnc, setKeyEnc] = useState<InputEnc>('base64');
  const [msgEnc, setMsgEnc] = useState<InputEnc>('utf8');
  const [outView, setOutView] = useState<'hex' | 'base64'>('hex');
  const [digest, setDigest] = useState('');
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);

  const inputs = useMemo(() => {
    try {
      const k = decodeInput(key, keyEnc);
      const m = decodeInput(message, msgEnc);
      return { key: k.text, msg: m.text, keyLen: k.bytes, msgLen: m.bytes, error: '' };
    } catch (e) {
      return { key: '', msg: '', keyLen: 0, msgLen: 0, error: (e as Error).message || 'Bad encoding input.' };
    }
  }, [key, keyEnc, message, msgEnc]);

  useEffect(() => {
    let cancelled = false;
    if (inputs.error) {
      setDigest('');
      setError(inputs.error);
      return () => {
        cancelled = true;
      };
    }
    setPending(true);
    const run = async () => {
      try {
        // crypto.ts covers SHA-1/SHA-256 synchronously; SHA-384/512 go via WebCrypto.
        const hex =
          algo === 'SHA-1' || algo === 'SHA-256'
            ? await hmacHex(algo, inputs.key, inputs.msg)
            : await hmacSubtle(algo, inputs.key, inputs.msg);
        if (!cancelled) {
          setDigest(hex);
          setError('');
        }
      } catch (e) {
        if (!cancelled) {
          setDigest('');
          setError((e as Error).message || 'HMAC failed.');
        }
      } finally {
        if (!cancelled) setPending(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [algo, inputs]);

  const b64 = useMemo(() => {
    if (!digest) return '';
    const bytes = new Uint8Array(digest.length / 2);
    for (let i = 0; i < bytes.length; i += 1) bytes[i] = parseInt(digest.slice(i * 2, i * 2 + 2), 16);
    return base64FromBytes(bytes);
  }, [digest]);

  const keyHex = useMemo(() => toHex(utf8ToBytes(inputs.key)), [inputs.key]);
  const msgHex = useMemo(() => toHex(utf8ToBytes(inputs.msg)), [inputs.msg]);

  const python = useMemo(
    () =>
      [
        'import hmac, hashlib, base64',
        '',
        `key = bytes.fromhex(${JSON.stringify(keyHex)})`,
        `msg = bytes.fromhex(${JSON.stringify(msgHex)})`,
        `digest = hmac.new(key, msg, hashlib.${algo.toLowerCase().replace('-', '')}).hexdigest()`,
        'print(digest)',
        "print(base64.b64encode(bytes.fromhex(digest)).decode())",
      ].join('\n'),
    [algo, keyHex, msgHex],
  );

  const output = outView === 'hex' ? digest : b64;

  return (
    <>
      <Card title="Input">
        <div className="grid gap-4 sm:grid-cols-3">
          <Select label="Algorithm" value={algo} onChange={setAlgo} options={ALGOS} />
          <Select label="Key encoding" value={keyEnc} onChange={setKeyEnc} options={ENCODINGS} />
          <Select label="Message encoding" value={msgEnc} onChange={setMsgEnc} options={ENCODINGS} />
        </div>
        <div className="mt-4 grid gap-4">
          <TextInput
            label="Key"
            value={key}
            onChange={setKey}
            mono
            hint={`${inputs.keyLen} bytes`}
            placeholder="YQ=="
          />
          <TextArea label="Message" value={message} onChange={setMessage} rows={5} hint={`${inputs.msgLen} bytes`} />
        </div>
        {keyEnc === 'hex' && key.replace(/[^0-9a-fA-F]/g, '').length % 2 !== 0 && (
          <div className="mt-3 text-[11.5px] text-[var(--warn,#eab308)]">Odd number of hex digits — trailing nibble dropped.</div>
        )}
      </Card>

      <Card title="Result" action={<CopyChip text={output} label="Copy MAC" />}>
        <div className="flex items-center gap-3">
          <Tabs
            value={outView}
            onChange={setOutView}
            tabs={[
              { value: 'hex', label: 'Hex' },
              { value: 'base64', label: 'Base64' },
            ]}
          />
          {pending && <span className="text-[11.5px] text-[var(--text-faint)]">computing…</span>}
        </div>
        <div className="mt-3">
          {error ? (
            <Callout tone="warn" title="Cannot compute">
              {error}
            </Callout>
          ) : (
            <>
              <CodeBlock code={output || '—'} maxHeight={120} />
              <div className="mt-4">
                <KVTable
                  rows={[
                    ['Algorithm', algo],
                    ['Digest length', `${digest.length / 2} bytes`],
                    ['Hex', <span key="h" className="rf-mono break-all">{digest || '—'}</span>],
                    ['Base64', <span key="b" className="rf-mono break-all">{b64 || '—'}</span>],
                  ]}
                />
              </div>
            </>
          )}
        </div>
      </Card>

      <Card title="Python equivalent">
        <CodeBlock code={python} label="hmac.new(...)" maxHeight={220} />
        <div className="mt-4">
          <Callout tone="info" title="Verification side">
            Compare with a constant-time check — <span className="rf-mono">hmac.compare_digest(a, b)</span> in Python,
            or <span className="rf-mono">crypto.timingSafeEqual</span> in Node. A plain{' '}
            <span className="rf-mono">===</span> leaks length and prefix timing.
          </Callout>
        </div>
      </Card>
    </>
  );
}
