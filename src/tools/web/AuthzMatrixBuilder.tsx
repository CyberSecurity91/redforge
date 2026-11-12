import { useMemo, useState } from 'react';
import { Button, Callout, Card, DownloadButton, OutputBlock, SectionTitle, Select, TextInput } from '@/components/ui';
import { DEFAULT_TARGET } from '@/tools/registry';

type Kind = 'anonymous' | 'user' | 'admin';
type Status = '' | '200' | '302' | '403' | '404';

interface Role {
  id: number;
  name: string;
  kind: Kind;
  token: string;
}

interface Endpoint {
  id: number;
  method: string;
  path: string;
  owner: number | 'public';
}

const KIND_OPTIONS: Array<{ value: Kind; label: string }> = [
  { value: 'anonymous', label: 'Anonymous' },
  { value: 'user', label: 'Authenticated user' },
  { value: 'admin', label: 'Privileged' },
];

const METHOD_OPTIONS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => ({ value: m, label: m }));
const STATUS_OPTIONS: Array<{ value: Status; label: string }> = [
  { value: '', label: '—' },
  { value: '200', label: '200' },
  { value: '302', label: '302' },
  { value: '403', label: '403' },
  { value: '404', label: '404' },
];

/** Policy expectation for one cell, from ownership and role class. */
function expectedFor(role: Role, ep: Endpoint): Status {
  if (ep.owner === 'public') return '200';
  if (role.kind === 'admin') return '200';
  if (role.kind === 'anonymous') return '302';
  return ep.owner === role.id ? '200' : '403';
}

function verdictFor(expected: Status, observed: Status): { label: string; color: string } {
  if (!observed) return { label: 'untested', color: 'var(--text-faint)' };
  if (observed === expected) return { label: 'as expected', color: 'var(--ok)' };
  if (expected === '403' && observed === '200') return { label: 'BOLA / IDOR', color: 'var(--accent)' };
  if (expected === '302' && observed === '200') return { label: 'no auth', color: 'var(--accent)' };
  if (expected === '200' && observed === '403') return { label: 'broken function', color: 'var(--warn)' };
  if (observed === '404') return { label: 'not found', color: 'var(--info)' };
  return { label: 'mismatch', color: 'var(--warn)' };
}

let nextRole = 100;
let nextEp = 200;

export default function AuthzMatrixBuilder() {
  const [target, setTarget] = useState(DEFAULT_TARGET);
  const [roles, setRoles] = useState<Role[]>([
    { id: 1, name: 'anonymous', kind: 'anonymous', token: 'SESSION_ID=' },
    { id: 2, name: 'alice', kind: 'user', token: 'SESSION_ID=ROLE_A_SESSION' },
    { id: 3, name: 'bob', kind: 'user', token: 'SESSION_ID=ROLE_B_SESSION' },
    { id: 4, name: 'admin', kind: 'admin', token: 'SESSION_ID=ADMIN_SESSION' },
  ]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([
    { id: 1, method: 'GET', path: '/api/users/1001', owner: 2 },
    { id: 2, method: 'GET', path: '/api/orders/1001', owner: 3 },
    { id: 3, method: 'DELETE', path: '/api/users/1001', owner: 2 },
    { id: 4, method: 'GET', path: '/health', owner: 'public' },
  ]);
  const [observed, setObserved] = useState<Record<string, Status>>({});

  const ownerOptions = useMemo(
    () => [{ value: 'public', label: 'public (unauthenticated)' }, ...roles.map((r) => ({ value: String(r.id), label: r.name }))],
    [roles],
  );

  const cells = useMemo(
    () =>
      roles.flatMap((role) =>
        endpoints.map((ep) => {
          const key = `${role.id}|${ep.id}`;
          const expected = expectedFor(role, ep);
          const seen = observed[key] ?? '';
          return { key, role, ep, expected, seen, verdict: verdictFor(expected, seen) };
        }),
      ),
    [roles, endpoints, observed],
  );

  const findings = cells.filter((c) => c.seen && c.verdict.label !== 'as expected');

  const requests = useMemo(() => {
    const blocks = roles.map((role) => {
      const lines = endpoints.map((ep) => {
        const url = `https://${target || DEFAULT_TARGET}${ep.path}`;
        return [
          `# ${role.name} → ${ep.method} ${ep.path} (expect ${expectedFor(role, ep)})`,
          `curl -s -o /dev/null -w '%{http_code} %{size_download}\\n' \\`,
          `  -X ${ep.method} '${url}' \\`,
          `  -H 'Cookie: ${role.token || 'SESSION_ID=PLACEHOLDER'}' \\`,
          `  -H 'X-Tenant-Id: TENANT_ID'`,
        ].join('\n');
      });
      return lines.join('\n\n');
    });
    return blocks.join('\n\n# ─────────────────────────────────────────────\n\n');
  }, [roles, endpoints, target]);

  const csv = useMemo(() => {
    const head = 'role,role_kind,owner,method,endpoint,expected,observed,verdict';
    const rows = cells.map((c) =>
      [
        c.role.name,
        c.role.kind,
        c.ep.owner === 'public' ? 'public' : roles.find((r) => r.id === c.ep.owner)?.name ?? 'unknown',
        c.ep.method,
        c.ep.path,
        c.expected,
        c.seen || '',
        c.verdict.label,
      ].join(','),
    );
    return [head, ...rows].join('\n');
  }, [cells, roles]);

  const setCell = (key: string, value: Status) => setObserved((prev) => ({ ...prev, [key]: value }));

  return (
    <>
      <Card
        title="Roles"
        action={
          <Button
            size="sm"
            variant="ghost"
            onClick={() =>
              setRoles((prev) => [...prev, { id: nextRole++, name: `role-${prev.length + 1}`, kind: 'user', token: 'SESSION_ID=PLACEHOLDER' }])
            }
          >
            Add role
          </Button>
        }
      >
        <div className="mb-4 sm:max-w-sm">
          <TextInput label="Target host" value={target} onChange={setTarget} mono placeholder={DEFAULT_TARGET} hint="No scheme — only the host is used" />
        </div>
        <div className="flex flex-col gap-3">
          {roles.map((role) => (
            <div key={role.id} className="grid items-end gap-2 sm:grid-cols-[1fr_180px_1fr_auto]">
              <TextInput
                label="Role"
                value={role.name}
                onChange={(v) => setRoles((prev) => prev.map((r) => (r.id === role.id ? { ...r, name: v } : r)))}
                mono
              />
              <Select
                label="Class"
                value={role.kind}
                onChange={(v) => setRoles((prev) => prev.map((r) => (r.id === role.id ? { ...r, kind: v } : r)))}
                options={KIND_OPTIONS}
              />
              <TextInput
                label="Cookie / token header value"
                value={role.token}
                onChange={(v) => setRoles((prev) => prev.map((r) => (r.id === role.id ? { ...r, token: v } : r)))}
                mono
                hint="Placeholder only"
              />
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setRoles((prev) => prev.filter((r) => r.id !== role.id));
                  setEndpoints((prev) => prev.map((e) => (e.owner === role.id ? { ...e, owner: 'public' } : e)));
                }}
                title="Remove role"
              >
                Remove
              </Button>
            </div>
          ))}
        </div>
      </Card>

      <Card
        title="Endpoints"
        action={
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setEndpoints((prev) => [...prev, { id: nextEp++, method: 'GET', path: '/api/resource/ID', owner: 'public' }])}
          >
            Add endpoint
          </Button>
        }
      >
        <div className="flex flex-col gap-3">
          {endpoints.map((ep) => (
            <div key={ep.id} className="grid items-end gap-2 sm:grid-cols-[110px_1fr_210px_auto]">
              <Select
                label="Method"
                value={ep.method}
                onChange={(v) => setEndpoints((prev) => prev.map((e) => (e.id === ep.id ? { ...e, method: v } : e)))}
                options={METHOD_OPTIONS}
              />
              <TextInput
                label="Path"
                value={ep.path}
                onChange={(v) => setEndpoints((prev) => prev.map((e) => (e.id === ep.id ? { ...e, path: v } : e)))}
                mono
                placeholder="/api/users/1001"
              />
              <Select
                label="Resource owner"
                value={String(ep.owner)}
                onChange={(v) =>
                  setEndpoints((prev) => prev.map((e) => (e.id === ep.id ? { ...e, owner: v === 'public' ? 'public' : Number(v) } : e)))
                }
                options={ownerOptions}
              />
              <Button size="sm" variant="ghost" onClick={() => setEndpoints((prev) => prev.filter((e) => e.id !== ep.id))} title="Remove endpoint">
                Remove
              </Button>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Matrix">
        <div className="-mx-2 overflow-x-auto px-2">
          <table className="w-full text-[12px]">
            <thead>
              <tr className="text-[var(--text-faint)]">
                <th className="px-2 py-1.5 text-left font-medium">Endpoint</th>
                {roles.map((r) => (
                  <th key={r.id} className="px-2 py-1.5 text-left font-medium">
                    {r.name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {endpoints.map((ep, i) => (
                <tr key={ep.id} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                  <td className="px-2 py-1.5 align-top">
                    <span className="rf-mono text-[11.5px] text-[var(--text)]">{ep.method}</span>{' '}
                    <span className="rf-mono break-all text-[11.5px] text-[var(--text-muted)]">{ep.path}</span>
                    <span className="mt-0.5 block text-[10.5px] text-[var(--text-faint)]">
                      owner: {ep.owner === 'public' ? 'public' : roles.find((r) => r.id === ep.owner)?.name ?? 'unknown'}
                    </span>
                  </td>
                  {roles.map((role) => {
                    const key = `${role.id}|${ep.id}`;
                    const cell = cells.find((c) => c.key === key);
                    if (!cell) return <td key={key} />;
                    return (
                      <td key={key} className="px-2 py-1.5 align-top">
                        <div className="flex items-center gap-1">
                          <span className="rf-mono text-[10.5px] text-[var(--text-faint)]">exp {cell.expected}</span>
                          <span className="rf-mono rounded px-1 text-[10.5px]" style={{ color: cell.verdict.color, background: 'var(--neutral-btn)' }}>
                            {cell.verdict.label}
                          </span>
                        </div>
                        <div className="mt-1 w-[76px]">
                          <Select value={cell.seen} onChange={(v) => setCell(key, v)} options={STATUS_OPTIONS} />
                        </div>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 mb-0 text-[11.5px] leading-relaxed text-[var(--text-faint)]">
          Record the status the server actually returned for each role. Expected values follow the ownership model: a public
          resource is 200 for everyone, a privileged role gets 200, an anonymous caller is redirected (302), and a signed-in
          caller outside the owner is refused (403).
        </p>
      </Card>

      <Card
        title="Findings and request set"
        action={<DownloadButton text={csv} filename="authz-matrix.csv" label="Export CSV" />}
      >
        {findings.length === 0 ? (
          <Callout tone="info" title="Nothing recorded yet">
            Fill in the observed status column; any cell that returns 200 where the policy expects 403 becomes a BOLA/IDOR
            candidate here.
          </Callout>
        ) : (
          <div className="flex flex-col gap-2">
            {findings.map((f) => (
              <div key={f.key} className="flex items-start gap-2 text-[12.5px] leading-relaxed">
                <span className="rf-mono rounded px-1.5 py-0.5 text-[10.5px] font-semibold" style={{ color: f.verdict.color, background: 'var(--neutral-btn)' }}>
                  {f.verdict.label.toUpperCase()}
                </span>
                <span className="text-[var(--text-muted)]">
                  <span className="rf-mono text-[var(--text)]">
                    {f.ep.method} {f.ep.path}
                  </span>{' '}
                  as <span className="rf-mono">{f.role.name}</span> returned {f.seen}, expected {f.expected}.
                  {f.verdict.label === 'BOLA / IDOR' && ' Replay with the identifier of a resource owned by another account and confirm the body belongs to that account.'}
                  {f.verdict.label === 'no auth' && ' The endpoint is reachable without a session — check for data disclosure in the response body, not just the status.'}
                </span>
              </div>
            ))}
          </div>
        )}

        <div className="mt-5">
          <SectionTitle>Request set — swap cookies between roles</SectionTitle>
          <OutputBlock value={requests} label="curl" rows={12} />
        </div>
        <div className="mt-4">
          <Callout tone="warn" title="Compare bodies, not only codes">
            A 403 with a stack trace or a 200 with another tenant's data are both findings. Diff response bodies and lengths
            between roles, and re-run the pair twice to rule out caching.
          </Callout>
        </div>
      </Card>
    </>
  );
}
