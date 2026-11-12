import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  DownloadButton,
  KVTable,
  SectionTitle,
  Select,
  TextArea,
  TextInput,
} from '@/components/ui';

type Mode = 'bits' | 'blob' | 'chunked';

const MODES = [
  { value: 'blob', label: 'Blob download (Uint8Array)' },
  { value: 'bits', label: 'Base64 data-URI (bitshift decode)' },
  { value: 'chunked', label: 'Chunked reassembly (offset loop)' },
] as const;

const escapeHtml = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** Placeholder bytes: the ASCII string "REDFORGE-INERT-FIXTURE" repeated. Nothing executes. */
const PLACEHOLDER_BYTES = Array.from(new TextEncoder().encode('REDFORGE-INERT-FIXTURE\n'));

function buildHtml(opts: {
  filename: string;
  mime: string;
  mode: Mode;
  title: string;
  body: string;
  witness: string;
  autoClick: boolean;
  decoy: boolean;
}): string {
  const { filename, mime, mode, title, body, witness, autoClick, decoy } = opts;
  const bytes = PLACEHOLDER_BYTES;
  const b64 = btoa(String.fromCharCode(...bytes));

  const delivery =
    mode === 'bits'
      ? `  const payload = "${b64}";
  const bin = atob(payload);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);`
      : mode === 'chunked'
        ? `  // Reassemble in 4 KB slices so no single literal is large
  const parts = ["${b64}"];
  const joined = parts.join("");
  const bin = atob(joined);
  const bytes = new Uint8Array(bin.length);
  for (let off = 0; off < bin.length; off += 1) bytes[off] = bin.charCodeAt(off);`
        : `  const bytes = new Uint8Array([${bytes.join(',')}]);`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<style>body{font:14px/1.5 system-ui,sans-serif;margin:40px;color:#222}</style>
</head>
<body>
${decoy ? `<h1>${escapeHtml(title)}</h1>\n<p>${escapeHtml(body)}</p>\n<div id="status">Preparing file…</div>` : `<div id="status">Preparing file…</div>`}
<script>
(function () {
  // INERT FIXTURE: the byte array below is the ASCII marker only.
  // Replace it with an authorised test artefact before use; never ship a live payload.
${delivery}
  const blob = new Blob([bytes], { type: "${mime}" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "${filename}";
  a.rel = "noopener";
  document.body.appendChild(a);
  ${autoClick ? 'a.click();' : '// manual: user clicks the generated link\n  a.textContent = "Download";'}
  document.getElementById("status").textContent = "Download ready.";
  ${witness ? `// Witness note (browser telemetry is not sent — placeholder): ${JSON.stringify(witness)}` : ''}
  setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
})();
</script>
</body>
</html>`;
}

export default function HtmlSmugglingBuilder() {
  const [filename, setFilename] = useState('invoice.pdf');
  const [mime, setMime] = useState('application/pdf');
  const [mode, setMode] = useState<Mode>('blob');
  const [title, setTitle] = useState('Invoice INV-2048');
  const [body, setBody] = useState('Your document is being prepared. If the download does not start, click the link below.');
  const [witness, setWitness] = useState('Beacon fires only from the target network — placeholder, no exfil');
  const [autoClick, setAutoClick] = useState(true);
  const [decoy, setDecoy] = useState(true);

  const html = useMemo(
    () => buildHtml({ filename: filename.trim() || 'document.bin', mime: mime.trim() || 'application/octet-stream', mode, title, body, witness, autoClick, decoy }),
    [filename, mime, mode, title, body, witness, autoClick, decoy],
  );

  return (
    <>
      <Card title="Delivery">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput label="Payload filename" value={filename} onChange={setFilename} mono hint="Extension is what the browser saves — not what it runs" />
          <TextInput label="MIME type" value={mime} onChange={setMime} mono hint="application/octet-stream for anything that should not preview" />
          <Select label="Delivery mode" value={mode} onChange={setMode} options={MODES.map((m) => ({ value: m.value, label: m.label }))} />
          <TextInput label="Witness note" value={witness} onChange={setWitness} mono hint="Documented in the output as a comment" />
          <TextInput label="Decoy page title" value={title} onChange={setTitle} />
          <div className="flex flex-col justify-end gap-2.5 pb-1">
            <Checkbox checked={autoClick} onChange={setAutoClick} label="Auto-click the download anchor" />
            <Checkbox checked={decoy} onChange={setDecoy} label="Render the decoy heading and copy" />
          </div>
        </div>
        <div className="mt-4">
          <TextArea label="Decoy body" value={body} onChange={setBody} rows={3} mono={false} />
        </div>
      </Card>

      <Card
        title="Generated page"
        action={
          <div className="flex items-center gap-2">
            <span className="rf-mono rounded bg-[var(--neutral-btn)] px-2 py-0.5 text-[12px] text-[var(--text-faint)]">
              {new TextEncoder().encode(html).length} B
            </span>
            <DownloadButton text={html} filename="smuggled-page.html" label="Download .html" />
          </div>
        }
      >
        <CodeBlock code={html} label="self-contained HTML" maxHeight={420} />
        <div className="mt-4">
          <SectionTitle>Assembly facts</SectionTitle>
          <KVTable
            rows={[
              ['Delivery', MODES.find((m) => m.value === mode)!.label],
              ['Embedded bytes', `${PLACEHOLDER_BYTES.length} — the ASCII marker REDFORGE-INERT-FIXTURE`],
              ['Filename on disk', filename || 'document.bin'],
              ['MIME', mime || 'application/octet-stream'],
              ['Middleware need', 'None — only an html/svg/js upload sink and a victim browser'],
            ]}
          />
        </div>
      </Card>

      <Card title="Operational notes">
        <Callout tone="warn" title="Why it works">
          The file is assembled in memory by the browser and saved by a <span className="rf-mono">download</span> attribute —
          the bytes never touch a server, so mail and proxy content-scanners only see HTML. Keep the decoy plausible,
          serve it from the engagement host over HTTPS, and pair it with a click-tracking pixel if the scope allows
          telemetry.
        </Callout>
        <div className="mt-3">
          <Callout tone="info" title="Fixture discipline">
            The embedded array is deliberately inert. Swap in an authorised test artefact (an EICAR-style canary or a
            signed internal tool) only inside the approved engagement window, and record the SHA-256 of the delivered file
            in the report so blue team can hunt on it.
          </Callout>
        </div>
      </Card>
    </>
  );
}
