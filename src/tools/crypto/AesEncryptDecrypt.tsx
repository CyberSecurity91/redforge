import { useMemo, useState } from 'react';
import {
  Button,
  Callout,
  Card,
  CodeBlock,
  CopyChip,
  KVTable,
  Select,
  Tabs,
  TextArea,
  TextInput,
} from '@/components/ui';
import { aesGcmDecrypt, aesGcmEncrypt, opensslDecrypt, opensslEncrypt } from '@/lib/crypto';

type Mode = 'gcm' | 'openssl';
type Direction = 'encrypt' | 'decrypt';
type Encoding = 'base64' | 'hex';

function bytesToB64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function b64ToHex(b64: string): string {
  const bin = atob(b64.replace(/\s+/g, ''));
  return Array.from(bin, (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

export default function AesEncryptDecrypt() {
  const [mode, setMode] = useState<Mode>('gcm');
  const [direction, setDirection] = useState<Direction>('encrypt');
  const [password, setPassword] = useState('correct horse battery staple');
  const [input, setInput] = useState('attack at dawn — redforge');
  const [encoding, setEncoding] = useState<Encoding>('base64');
  const [keySource, setKeySource] = useState<'password' | 'raw'>('password');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [roundTrip, setRoundTrip] = useState<null | { ok: boolean; text: string }>(null);

  const run = () => {
    setBusy(true);
    setError('');
    const job =
      mode === 'gcm'
        ? direction === 'encrypt'
          ? aesGcmEncrypt(password, input)
          : aesGcmDecrypt(password, input)
        : direction === 'encrypt'
          ? opensslEncrypt(password, input)
          : opensslDecrypt(password, input);

    job
      .then((result) => {
        let shown = result;
        if (direction === 'encrypt') {
          shown = encoding === 'hex' ? (mode === 'gcm' ? result : b64ToHex(result)) : result;
        }
        setOutput(shown);
      })
      .catch((e: unknown) => {
        setOutput('');
        setError((e as Error).message || 'Operation failed — check the key and the payload format.');
      })
      .finally(() => setBusy(false));
  };

  const roundTripCheck = () => {
    setRoundTrip(null);
    setBusy(true);
    const job = mode === 'gcm' ? aesGcmEncrypt(password, input) : opensslEncrypt(password, input);
    job
      .then((ct) => (mode === 'gcm' ? aesGcmDecrypt(password, ct) : opensslDecrypt(password, ct)))
      .then((pt) => setRoundTrip({ ok: pt === input, text: pt }))
      .catch((e: unknown) => setError((e as Error).message || 'Round-trip failed.'))
      .finally(() => setBusy(false));
  };

  const equivalent = useMemo(() => {
    if (mode === 'gcm') {
      return [
        '# AES-256-GCM, key = SHA-256(password), 12-byte IV prepended, output iv:ct in hex',
        'openssl rand -out iv.bin 12',
        'openssl enc -aes-256-gcm -K "$(printf %s "$PASS" | sha256sum | cut -d" " -f1)" \\',
        '  -iv "$(xxd -p -c 12 iv.bin)" -in plain.txt -out cipher.bin',
        '# note: the stock openssl enc GCM path is fiddly — prefer Python cryptography:',
        'python3 - <<\'PY\'',
        'from cryptography.hazmat.primitives.ciphers.aead import AESGCM',
        'import hashlib, os',
        'key = hashlib.sha256(b"correct horse battery staple").digest()',
        'iv = os.urandom(12)',
        'ct = AESGCM(key).encrypt(iv, b"attack at dawn", None)',
        'print(iv.hex() + ":" + ct.hex())',
        'PY',
      ].join('\n');
    }
    return [
      '# OpenSSL compatible: Salted__ header, MD5 EVP_BytesToKey, AES-256-CBC, base64',
      'echo -n "attack at dawn" | openssl enc -aes-256-cbc -pbkdf2 -salt -a -pass pass:"correct horse battery staple"',
      '# decrypt (no -pbkdf2 → legacy MD5 EVP_BytesToKey, matching this tool):',
      'echo "U2FsdGVkX1..." | openssl enc -d -aes-256-cbc -a -pass pass:"correct horse battery staple"',
      '# verify header bytes:',
      'echo "U2FsdGVkX1..." | base64 -d | xxd | head -2',
    ].join('\n');
  }, [mode]);

  return (
    <>
      <Card title="Mode">
        <Tabs
          value={mode}
          onChange={(v) => {
            setMode(v);
            setOutput('');
            setError('');
            setRoundTrip(null);
          }}
          tabs={[
            { value: 'gcm', label: 'AES-GCM (browser)' },
            { value: 'openssl', label: 'OpenSSL compatible (Salted__ / CBC)' },
          ]}
        />
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <Tabs
            value={direction}
            onChange={setDirection}
            tabs={[
              { value: 'encrypt', label: 'Encrypt' },
              { value: 'decrypt', label: 'Decrypt' },
            ]}
          />
          <Select
            label="Output encoding"
            value={encoding}
            onChange={setEncoding}
            options={[
              { value: 'base64', label: 'Base64' },
              { value: 'hex', label: 'Hex' },
            ]}
            hint="Encrypt direction only"
          />
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <Select
            label="Key source"
            value={keySource}
            onChange={setKeySource}
            options={[
              { value: 'password', label: 'Password (SHA-256 / EVP_BytesToKey)' },
              { value: 'raw', label: 'Raw key' },
            ]}
            hint="Raw 32-byte hex keys are stretched by the same helper"
          />
          <TextInput label="Password / key" value={password} onChange={setPassword} mono />
        </div>
        <div className="mt-4">
          <TextArea
            label={direction === 'encrypt' ? 'Plaintext' : 'Ciphertext'}
            value={input}
            onChange={setInput}
            rows={6}
            placeholder={
              direction === 'encrypt'
                ? 'attack at dawn'
                : mode === 'gcm'
                  ? '<iv-hex>:<ciphertext-hex>'
                  : 'U2FsdGVkX1...'
            }
          />
        </div>
        <div className="mt-4 flex gap-2">
          <Button variant="primary" onClick={run} disabled={busy}>
            {busy ? 'Working…' : direction === 'encrypt' ? 'Encrypt' : 'Decrypt'}
          </Button>
          <Button variant="ghost" onClick={roundTripCheck} disabled={busy}>
            Verify round-trip
          </Button>
          <Button variant="ghost" onClick={() => { setInput(''); setOutput(''); setError(''); setRoundTrip(null); }}>
            Clear
          </Button>
        </div>
      </Card>

      <Card title="Output" action={<CopyChip text={output} label="Copy output" />}>
        {error ? (
          <Callout tone="warn" title="Operation failed">
            {error}
          </Callout>
        ) : (
          <CodeBlock code={output || '—'} maxHeight={200} />
        )}
        <div className="mt-4">
          <KVTable
            rows={[
              ['Mode', mode === 'gcm' ? 'AES-256-GCM, 12-byte IV' : 'AES-256-CBC, PKCS#7, Salted__ container'],
              ['Key derivation', mode === 'gcm' ? 'SHA-256(password)' : 'MD5 EVP_BytesToKey(password, salt)'],
              ['Output format', mode === 'gcm' ? 'ivHex:ctHex' : 'base64 of Salted__ || ct'],
            ]}
          />
        </div>
        {roundTrip && (
          <div className="mt-4">
            <Callout tone={roundTrip.ok ? 'ok' : 'warn'} title={roundTrip.ok ? 'Round-trip verified' : 'Round-trip mismatch'}>
              {roundTrip.ok ? 'Decrypt(ciphertext) reproduced the plaintext byte for byte.' : `Decrypted text differed: ${roundTrip.text.slice(0, 120)}`}
            </Callout>
          </div>
        )}
      </Card>

      <Card title="Command-line equivalent">
        <CodeBlock code={equivalent} maxHeight={260} />
        <div className="mt-4">
          <Callout tone="info" title="Compatibility caveat">
            The OpenSSL path uses the legacy MD5 <span className="rf-mono">EVP_BytesToKey</span> derivation, which is
            what <span className="rf-mono">openssl enc</span> produces without <span className="rf-mono">-pbkdf2</span>.
            Modern OpenSSL 3 defaults to <span className="rf-mono">-pbkdf2</span>, so add{' '}
            <span className="rf-mono">-k</span>/<span className="rf-mono">-md md5</span> explicitly when decrypting
            older blobs. GCM output here is not an <span className="rf-mono">openssl enc</span> artefact — use the
            Python snippet for interop.
          </Callout>
        </div>
      </Card>
    </>
  );
}
