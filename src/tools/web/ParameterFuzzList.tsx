import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  DownloadButton,
  KVTable,
  SectionTitle,
  TextInput,
} from '@/components/ui';
import { DEFAULT_TARGET } from '@/tools/registry';

const SENSITIVE = [
  'debug', 'admin', 'test', 'isAdmin', 'is_admin', 'role', 'roles', 'permission', 'privilege', 'superuser',
  'redirect_url', 'redirect_uri', 'next', 'returnUrl', 'callback', 'internal', 'preview', 'draft', 'feature_flag',
];

const API_STANDARD = [
  'id', 'user_id', 'account_id', 'tenant_id', 'org_id', 'page', 'limit', 'offset', 'sort', 'order', 'fields',
  'expand', 'include', 'filter', 'q', 'search', 'version', 'format', 'lang', 'locale', 'token', 'api_key',
  'format_type', 'access_token', 'refresh', 'client_id', 'client_secret', 'scope',
];

const MASS_ASSIGN = [
  'isAdmin', 'is_superuser', 'role', 'roles', 'permissions', 'authorized', 'active', 'verified', 'approved',
  'balance', 'credit', 'credits', 'price', 'discount', 'plan', 'subscription', 'subscription_tier',
  'email_verified', 'two_factor_enabled', 'password_reset_required', 'owner_id', 'created_at', 'deleted_at',
];

const FRAMEWORKS: Record<string, string[]> = {
  'Spring Boot': ['page', 'size', 'sort', 'search', '_csrf', 'username', 'error', 'trace', 'logfile'],
  'Rails': ['utf8', 'authenticity_token', 'commit', '_method', 'id', 'format', 'controller', 'action'],
  'Laravel': ['_token', '_method', '_previous', 'password_confirmation', 'remember', 'page'],
  'Django': ['csrfmiddlewaretoken', 'next', 'format', 'page', 'page_size', 'q'],
  'Express / Node': ['_method', '__proto__', 'constructor', 'prototype', 'json', 'callback', 'fields'],
  'PHP': ['PHPSESSID', 'cmd', 'exec', 'system', 'passwd', 'file', 'include', 'class', 'func'],
};

export default function ParameterFuzzList() {
  const [domain, setDomain] = useState(DEFAULT_TARGET);
  const [path, setPath] = useState('/api/v1/users');
  const [groups, setGroups] = useState<string[]>(['Sensitive flags', 'API standard', 'Mass assignment']);
  const [frameworks, setFrameworks] = useState<string[]>(['Spring Boot', 'Express / Node']);
  const [method, setMethod] = useState<'GET' | 'POST'>('GET');

  const words = useMemo(() => {
    const out: string[] = [];
    if (groups.includes('Sensitive flags')) out.push(...SENSITIVE);
    if (groups.includes('API standard')) out.push(...API_STANDARD);
    if (groups.includes('Mass assignment')) out.push(...MASS_ASSIGN);
    for (const f of frameworks) out.push(...(FRAMEWORKS[f] ?? []));
    return Array.from(new Set(out));
  }, [groups, frameworks]);

  const host = domain.trim() || DEFAULT_TARGET;
  const url = `https://${host}${path.startsWith('/') ? path : `/${path}`}`;

  const commands = useMemo(
    () =>
      [
        `# wordlist: ${words.length} parameters`,
        ``,
        `# arjun — hidden-parameter discovery`,
        `arjun -u '${url}' -m ${method} --stable -t 10 -w params.txt`,
        ``,
        `# ffuf — value-level discovery against each name`,
        `ffuf -u '${url}?FUZZ=1' -w params.txt -mc 200 -fs 0 -t 40 -rate 100`,
        ``,
        `# x8 — reflection and content-length diffing`,
        `x8 -u '${url}' -w params.txt -m ${method} -r 3 --output x8-out.txt`,
        ``,
        `# raw sweep with a marker value (catches reflected and error-based params)`,
        `while read p; do`,
        `  curl -sS -o /dev/null -w "$p %{http_code} %{size_download}\\n" '${url}?$p=RFMARKER';`,
        `done < params.txt`,
      ].join('\n'),
    [url, method, words.length],
  );

  const massAssign = useMemo(
    () =>
      JSON.stringify(
        {
          email: 'user@example.com',
          displayName: 'rf-test',
          role: 'admin',
          isAdmin: true,
          verified: true,
          permissions: ['users:write', 'admin:*'],
          credits: 999999,
          plan: 'enterprise',
        },
        null,
        2,
      ),
    [],
  );

  const toggle = (setter: (fn: (p: string[]) => string[]) => void) => (id: string, on: boolean) =>
    setter((prev) => (on ? [...prev, id] : prev.filter((x) => x !== id)));

  return (
    <>
      <Card title="Target">
        <div className="grid gap-4 sm:grid-cols-3">
          <TextInput label="Domain" value={domain} onChange={setDomain} mono />
          <TextInput label="Path" value={path} onChange={setPath} mono hint="An endpoint that accepts parameters" />
          <div>
            <SectionTitle>Method</SectionTitle>
            <div className="flex gap-2">
              {(['GET', 'POST'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setMethod(m)}
                  className={`rounded border px-3 py-1 text-[12.5px] transition-colors ${
                    method === m
                      ? 'border-[var(--accent)] bg-[var(--accent-faded)] text-[var(--accent)]'
                      : 'border-[var(--card-border)] text-[var(--text-muted)]'
                  }`}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <div>
            <SectionTitle>Parameter groups</SectionTitle>
            <div className="flex flex-col gap-2">
              {['Sensitive flags', 'API standard', 'Mass assignment'].map((g) => (
                <Checkbox key={g} checked={groups.includes(g)} onChange={(on) => toggle(setGroups)(g, on)} label={g} />
              ))}
            </div>
          </div>
          <div>
            <SectionTitle>Framework params</SectionTitle>
            <div className="grid grid-cols-2 gap-2">
              {Object.keys(FRAMEWORKS).map((f) => (
                <Checkbox key={f} checked={frameworks.includes(f)} onChange={(on) => toggle(setFrameworks)(f, on)} label={f} />
              ))}
            </div>
          </div>
        </div>
      </Card>

      <Card
        title={`Wordlist (${words.length})`}
        action={
          <div className="flex items-center gap-2">
            <DownloadButton text={words.join('\n')} filename="params.txt" label="Download params.txt" />
          </div>
        }
      >
        <pre className="rf-mono m-0 max-h-[220px] overflow-auto rounded border border-[var(--input-border)] bg-[var(--input)] px-3 py-2 text-[12.5px] leading-[1.6] text-[var(--text-muted)]">
          {words.join('\n')}
        </pre>
      </Card>

      <Card title="Runners">
        <CodeBlock code={commands} label="arjun / ffuf / x8" />
        <div className="mt-4">
          <SectionTitle>Mass-assignment body</SectionTitle>
          <CodeBlock
            code={`curl -sS -X ${method} '${url}' \\\n  -H 'Content-Type: application/json' \\\n  -H 'Authorization: Bearer $TOKEN' \\\n  -d '${massAssign.replace(/\n/g, '\n')}'`}
            label="POST JSON template"
          />
        </div>
      </Card>

      <Card title="Reading the results">
        <KVTable
          rows={[
            ['Baseline', `curl -sS -o /dev/null -w '%{size_download}' '${url}'`],
            ['Strong signal', 'Status or body length changes only when the parameter is present'],
            ['Mass assignment', 'Response echoes role/isAdmin, or a follow-up profile GET shows the escalated value'],
            ['Frameworks', Object.keys(FRAMEWORKS).filter((f) => frameworks.includes(f)).join(', ') || 'none'],
          ]}
        />
        <div className="mt-4">
          <Callout tone="warn" title="Order of work">
            Start with <span className="rf-mono">arjun</span> for hidden names, then <span className="rf-mono">x8</span>{' '}
            for reflection, then your own loop for error-body diffs. Compare against a baseline request without the
            parameter — a 200 for every value usually means the framework ignores unknown params, not that you found one.
            On mass assignment, verify with a second read request rather than trusting the POST response.
          </Callout>
        </div>
      </Card>
    </>
  );
}
