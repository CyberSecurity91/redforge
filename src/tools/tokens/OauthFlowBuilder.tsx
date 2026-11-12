import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CopyChip,
  KVTable,
  OutputBlock,
  SectionTitle,
  Select,
  Tabs,
  TextInput,
} from '@/components/ui';
import { b64Decode, textToB64 } from '@/lib/encoding';

type Grant = 'code' | 'implicit' | 'client' | 'device' | 'ropc';

const GRANTS: Array<{ value: Grant; label: string }> = [
  { value: 'code', label: 'authorization_code' },
  { value: 'implicit', label: 'implicit (legacy)' },
  { value: 'client', label: 'client_credentials' },
  { value: 'device', label: 'urn:ietf:params:oauth:grant-type:device_code' },
  { value: 'ropc', label: 'password (ROPC)' },
];

const BYPASSES: Array<[string, string, string]> = [
  ['Path traversal', 'https://client.example.com/callback/../evil', 'Some validators normalise after matching the prefix'],
  ['Traversal to sibling', 'https://client.example.com/oauth/../../evil', 'Two levels escape the registered subpath'],
  ['@ confusion', 'https://client.example.com@evil.example.com/cb', 'Parser splits on the last @; the allowlist may read the first host'],
  ['Subdomain append', 'https://client.example.com.evil.example.com/cb', 'String suffix match instead of exact host comparison'],
  ['Query truncation', 'https://client.example.com/cb?.evil.example.com', 'Validator stops at the ? and compares the path only'],
  ['Fragment truncation', 'https://client.example.com/cb#.evil.example.com', 'Fragment is never sent; some validators compare it anyway'],
  ['Scheme smuggling', 'https:/client.example.com/cb', 'https:/ collapses to https:// in permissive parsers'],
  ['Scheme relative', '//evil.example.com/cb', 'Protocol-relative resolves against the IdP origin'],
  ['Backslash', 'https://client.example.com\\@evil.example.com/cb', 'Windows-style parsers treat \\ as a separator'],
  ['Port confusion', 'https://client.example.com:443@evil.example.com/cb', 'The @ still wins if the port is parsed first'],
  ['Unicode dot', 'https://client.example.com／evil', 'Fullwidth solidus normalises to / after the check'],
];

const CHECKS: Array<[string, string, string]> = [
  ['state', 'CSRF binding on the authorize request', 'Generate state per attempt; a missing or reusable state is the finding'],
  ['nonce', 'Replay protection on id_token', 'The same nonce must be rejected on a second exchange'],
  ['PKCE downgrade', 'code_verifier enforced when the client sent a challenge', 'Omit the verifier and see whether the server still accepts the code'],
  ['scope escalation', 'Scope honoured per request, widened only with consent', 'Request admin scope without the consent screen firing'],
  ['redirect_uri strictness', 'Exact-match comparison, no fragments or wildcards', 'Every variant in the table above must fail'],
  ['token in Referer', 'Access token never in the query string of a page load', 'Implicit flow leaks tokens via Referer to third-party assets'],
  ['form_post binding', 'response_mode=form_post requires SameSite=None + Secure', 'A lax cookie silently drops the POST and breaks the flow'],
  ['code reuse', 'Authorization code is single-use', 'Replay the same code twice; the second exchange must fail'],
];

export default function OauthFlowBuilder() {
  const [grant, setGrant] = useState<Grant>('code');
  const [authorize, setAuthorize] = useState('https://idp.example.com/oauth2/authorize');
  const [token, setToken] = useState('https://idp.example.com/oauth2/token');
  const [clientId, setClientId] = useState('CLIENT_ID');
  const [redirect, setRedirect] = useState('https://client.example.com/callback');
  const [scope, setScope] = useState('openid profile email');
  const [state, setState] = useState('STATE_RANDOM_32');
  const [pkce, setPkce] = useState(true);
  const [formPost, setFormPost] = useState(false);
  const [tab, setTab] = useState<'authorize' | 'token' | 'bypass' | 'checks'>('authorize');

  const verifier = useMemo(() => 'VERIFIER_PKCE_43_CHARS_MINIMUM_AAAAAAAAAAAAA', []);
  const challenge = useMemo(() => textToB64(verifier).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), [verifier]);

  const authorizeUrl = useMemo(() => {
    const p = new URLSearchParams();
    p.set('response_type', grant === 'implicit' ? 'token id_token' : 'code');
    p.set('client_id', clientId.trim() || 'CLIENT_ID');
    p.set('redirect_uri', redirect.trim() || 'https://client.example.com/callback');
    p.set('scope', scope.trim() || 'openid');
    if (grant !== 'client' && grant !== 'device') p.set('state', state.trim() || 'STATE');
    if (grant === 'implicit') p.set('nonce', 'NONCE_RANDOM');
    if (pkce && (grant === 'code' || grant === 'implicit')) {
      p.set('code_challenge', challenge);
      p.set('code_challenge_method', 'S256');
    }
    if (formPost) p.set('response_mode', 'form_post');
    return `${(authorize.trim() || 'https://idp.example.com/oauth2/authorize')}?${p.toString()}`;
  }, [grant, clientId, redirect, scope, state, pkce, formPost, authorize, challenge]);

  const tokenCurl = useMemo(() => {
    const t = token.trim() || 'https://idp.example.com/oauth2/token';
    if (grant === 'code')
      return [
        `curl -s -X POST '${t}' \\`,
        `  -H 'Content-Type: application/x-www-form-urlencoded' \\`,
        `  -d 'grant_type=authorization_code' \\`,
        `  -d 'code=AUTH_CODE_FROM_REDIRECT' \\`,
        `  -d 'redirect_uri=${encodeURIComponent(redirect.trim() || 'https://client.example.com/callback')}' \\`,
        `  -d 'client_id=${clientId.trim() || 'CLIENT_ID'}' \\`,
        `  -d 'client_secret=CLIENT_SECRET'${pkce ? ' \\\n  -d \'code_verifier=' + verifier + "'" : ''}`,
        `# PKCE downgrade test: drop the code_verifier line and re-send`,
      ].join('\n');
    if (grant === 'implicit')
      return `# implicit has no token endpoint — the access token arrives in the fragment:\n# ${redirect.trim()}#access_token=…&token_type=Bearer&expires_in=3600&state=${state}\ncurl -s '${authorizeUrl}' -i | head -20`;
    if (grant === 'client')
      return [
        `curl -s -X POST '${t}' \\`,
        `  -u '${clientId.trim() || 'CLIENT_ID'}:CLIENT_SECRET' \\`,
        `  -H 'Content-Type: application/x-www-form-urlencoded' \\`,
        `  -d 'grant_type=client_credentials' \\`,
        `  -d 'scope=${encodeURIComponent(scope.trim() || 'openid')}'`,
      ].join('\n');
    if (grant === 'device')
      return [
        `# 1. initiate`,
        `curl -s -X POST '${t}' -d 'client_id=${clientId.trim() || 'CLIENT_ID'}' -d 'scope=${encodeURIComponent(scope)}' \\`,
        `  | python3 -m json.tool`,
        `# 2. poll — expect authorisation_pending until the user approves`,
        `curl -s -X POST '${t}' -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \\`,
        `  -d 'device_code=DEVICE_CODE' -d 'client_id=${clientId.trim() || 'CLIENT_ID'}'`,
      ].join('\n');
    return [
      `curl -s -X POST '${t}' \\`,
      `  -H 'Content-Type: application/x-www-form-urlencoded' \\`,
      `  -d 'grant_type=password' -d 'username=user@example.com' -d 'password=REDACTED' \\`,
      `  -d 'client_id=${clientId.trim() || 'CLIENT_ID'}' -d 'scope=${encodeURIComponent(scope)}'`,
    ].join('\n');
  }, [grant, token, clientId, redirect, scope, pkce, verifier, authorizeUrl, state]);

  const claimExpectation = useMemo(
    () => [
      '# id_token (unsigned display only — decode the real one before trusting it)',
      'header  = {"alg":"RS256","kid":"…"}',
      'payload = {',
      '  "iss": "https://idp.example.com",',
      `  "aud": "${clientId.trim() || 'CLIENT_ID'}",`,
      '  "sub": "user-unique-id",',
      '  "exp": <now + 3600>, "iat": <now>,',
      '  "nonce": "NONCE_RANDOM",        // must equal the nonce you sent',
      '  "email_verified": true,',
      '  "roles": ["user"]              // any admin claim here is the privilege target',
      '}',
      '',
      `redirect_uri echoed back to: ${redirect.trim() || 'https://client.example.com/callback'}`,
      `sample b64 payload placeholder: ${textToB64('{"iss":"https://idp.example.com","aud":"CLIENT_ID"}').slice(0, 40)}…`,
      `(decodes to: ${b64Decode(textToB64('{"iss":"https://idp.example.com","aud":"CLIENT_ID"}'))})`,
    ].join('\n'),
    [clientId, redirect],
  );

  return (
    <>
      <Card title="Client configuration">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Select label="Grant type" value={grant} onChange={setGrant} options={GRANTS} hint={grant === 'implicit' ? 'Deprecated; tokens appear in the fragment and leak via Referer' : grant === 'ropc' ? 'Deprecated; sends credentials to the token endpoint' : grant === 'device' ? 'No browser involved — poll for the token' : ''} />
          <TextInput label="Authorize endpoint" value={authorize} onChange={setAuthorize} mono placeholder="https://idp.example.com/oauth2/authorize" />
          <TextInput label="Token endpoint" value={token} onChange={setToken} mono placeholder="https://idp.example.com/oauth2/token" />
          <TextInput label="client_id" value={clientId} onChange={setClientId} mono placeholder="CLIENT_ID" />
          <TextInput label="redirect_uri" value={redirect} onChange={setRedirect} mono placeholder="https://client.example.com/callback" hint="Must be registered exactly — sight it in the authorize request" />
          <TextInput label="scope" value={scope} onChange={setScope} mono placeholder="openid profile email" />
          <TextInput label="state" value={state} onChange={setState} mono placeholder="STATE_RANDOM_32" hint="Per-attempt random value; absence is a CSRF finding" />
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-6">
          <Checkbox checked={pkce} onChange={setPkce} label="PKCE (S256)" description={`challenge ${challenge.slice(0, 16)}…`} />
          <Checkbox checked={formPost} onChange={setFormPost} label="response_mode=form_post" description="POSTs the code/token to redirect_uri" />
        </div>
      </Card>

      <Card
        title="Flow artefacts"
        action={<CopyChip text={authorizeUrl} label="copy authorize URL" />}
      >
        <Tabs
          value={tab}
          onChange={setTab}
          tabs={[
            { value: 'authorize', label: 'Authorize URL' },
            { value: 'token', label: 'Token request' },
            { value: 'bypass', label: 'redirect_uri bypass' },
            { value: 'checks', label: 'Checks' },
          ]}
        />
        <div className="mt-3">
          {tab === 'authorize' && (
            <>
              <OutputBlock value={authorizeUrl} rows={5} label="Authorize request" />
              <div className="mt-4">
                <SectionTitle>id_token expectation</SectionTitle>
                <OutputBlock value={claimExpectation} rows={14} label="Claims set" />
              </div>
            </>
          )}
          {tab === 'token' && <OutputBlock value={tokenCurl} rows={12} label={`${grant} token request`} />}
          {tab === 'bypass' && (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-[12px]">
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-wide text-[var(--text-faint)]">
                    <th className="border-b border-[var(--card-border)] px-2 py-1.5">Variant</th>
                    <th className="border-b border-[var(--card-border)] px-2 py-1.5">redirect_uri</th>
                    <th className="border-b border-[var(--card-border)] px-2 py-1.5">Why it lands</th>
                  </tr>
                </thead>
                <tbody>
                  {BYPASSES.map(([name, uri, why]) => (
                    <tr key={name} className="align-top">
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-[var(--text)]">{name}</td>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5">
                        <CopyChip text={uri} label={uri.length > 46 ? `${uri.slice(0, 46)}…` : uri} />
                      </td>
                      <td className="border-b border-[var(--card-border)] px-2 py-1.5 text-[var(--text-muted)]">{why}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {tab === 'checks' && (
            <KVTable
              rows={CHECKS.map(([key, what, how]) => [
                <span key={key} className="rf-mono text-[var(--text)]">{key}</span>,
                <span key={`${key}-v`}>
                  {what}
                  <span className="mt-0.5 block text-[11.5px] text-[var(--text-faint)]">{how}</span>
                </span>,
              ])}
            />
          )}
        </div>
      </Card>

      <Card title="response_mode & PKCE notes">
        <div className="grid gap-4 lg:grid-cols-2">
          <Callout tone="info" title="form_post vs query">
            <span className="rf-mono">response_mode=form_post</span> sends the code in a POST body, which keeps it out of
            logs and the Referer. It also requires the session cookie to be <span className="rf-mono">SameSite=None; Secure</span>{' '}
            — under <span className="rf-mono">Lax</span> the browser drops the cookie and the flow fails closed rather than
            open. If the IdP accepts <span className="rf-mono">fragment</span> for a confidential client, that is a finding.
          </Callout>
          <Callout tone="warn" title="PKCE downgrade">
            Send the challenge, then exchange the code without a <span className="rf-mono">code_verifier</span>. A server
            that still returns a token has not bound the code to the client. Repeat with{' '}
            <span className="rf-mono">code_challenge_method=plain</span> and a verifier equal to the challenge — if accepted,
            the strength of S256 is purely cosmetic.
          </Callout>
        </div>
      </Card>
    </>
  );
}
