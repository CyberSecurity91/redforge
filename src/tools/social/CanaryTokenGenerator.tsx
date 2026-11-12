import { useMemo, useState } from 'react';
import {
  Button,
  Callout,
  Card,
  CodeBlock,
  CopyChip,
  DownloadButton,
  KVTable,
  OutputField,
  Select,
  TextArea,
  TextInput,
} from '@/components/ui';
import { ALNUM, HEXCHARS, randomHex, randomToken } from '@/lib/rng';
import { DEFAULT_OOB_DOMAIN } from '@/tools/registry';

/**
 * Honeytoken generator. Every value is fake by construction: AWS keys use the
 * documented AKIA/ASIA prefixes but the account segment is a placeholder, and
 * the secret is visibly random rather than a real credential shape.
 */

type TokenType = 'url' | 'aws' | 'password' | 'document' | 'dns' | 'qr';

const TYPES: Array<{ value: TokenType; label: string }> = [
  { value: 'url', label: 'Unique tracking URL' },
  { value: 'aws', label: 'Fake AWS access key pair' },
  { value: 'password', label: 'Fake password in a credential file' },
  { value: 'document', label: 'Fake document name with marker' },
  { value: 'dns', label: 'DNS-only token (subdomain)' },
  { value: 'qr', label: 'QR bait (URL + label)' },
];

const PLACEMENT: Record<TokenType, string[]> = {
  url: ['Wiki page footer', 'Browser bookmark named "VPN portal"', 'README in an internal repo'],
  aws: ['~/.aws/credentials on a build runner', 'ENV block in a legacy deploy script', 'Jenkins global credential'],
  password: ['Passwords.docx on a file share', '`.env.example` committed to a repo', 'Confluence page "service accounts"'],
  document: ['SharePoint folder named "Board minutes"', 'Shared drive root', 'Mailbox draft folder'],
  dns: ['Internal DNS zone as a CNAME nobody owns', 'Certificate SAN list', 'SPF include that nobody checks'],
  qr: ['Printed sticker on a meeting-room desk', 'Physical badge-holder insert', 'Office kitchen noticeboard'],
};

const NOISE: Record<TokenType, string> = {
  url: 'Expect noise from link scanners (Defender Safe Links, mail gateways) that fetch every URL. Baseline for two weeks before alerting.',
  aws: 'Continuous integration may sweep for keys. Alert on use from any source IP that is not the CI egress, not on the key merely existing.',
  password: 'Password-manager crawlers and DLP scans will read the file. Deduplicate by user agent before opening a ticket.',
  document: 'Backup jobs touch every file. Exclude the backup service account at the share level, not in the SIEM.',
  dns: 'Recursive resolvers produce cache-miss noise. Only alert on an authoritative query from an internal resolver.',
  qr: 'Phone-based scanners leave no useful user agent. Correlate on the IP range of the site Wi-Fi, not the client fingerprint.',
};

export default function CanaryTokenGenerator() {
  const [type, setType] = useState<TokenType>('url');
  const [label, setLabel] = useState('finance-share-bait');
  const [owner, setOwner] = useState('red-team');
  const [domain, setDomain] = useState(DEFAULT_OOB_DOMAIN);
  const [nonce, setNonce] = useState(0);
  const [notes, setNotes] = useState('');

  const token = useMemo(() => {
    const seedPart = `${label}:${owner}:${nonce}`;
    const id = randomToken(ALNUM, 10) + randomHex(2);
    const marker = `CNRY-${randomToken('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 6)}`;
    const host = domain.trim() || DEFAULT_OOB_DOMAIN;
    return {
      id,
      marker,
      seedPart,
      url: `https://${host}/${label || 'bait'}?t=${id}`,
      dns: `${label || 'bait'}-${id.toLowerCase()}.${host}`,
      awsKeyId: `AKIA${randomToken('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16)}`,
      awsSecret: randomToken(ALNUM + '+/', 40),
      password: `Svc!${randomToken(ALNUM, 14)}`,
      document: `Q4-Planning-${marker}.xlsx`,
      qr: `https://${host}/qr/${id}`,
    };
  }, [label, owner, nonce, domain]);

  const artefacts = useMemo(() => {
    switch (type) {
      case 'url':
        return [
          ['Tracking URL', token.url],
          ['Short identifier', token.id],
          ['Marker', token.marker],
        ] as Array<[string, string]>;
      case 'aws':
        return [
          ['Access key ID', token.awsKeyId],
          ['Secret access key', token.awsSecret],
          ['Region', 'eu-west-2'],
          ['Profile name', 'legacy-import'],
        ] as Array<[string, string]>;
      case 'password':
        return [
          ['Password', token.password],
          ['Username', `svc_${label.replace(/[^a-z0-9]/gi, '').toLowerCase() || 'backup'}`],
          ['Marker', token.marker],
        ] as Array<[string, string]>;
      case 'document':
        return [
          ['File name', token.document],
          ['Marker', token.marker],
          ['Tracking URL inside file', token.url],
        ] as Array<[string, string]>;
      case 'dns':
        return [
          ['FQDN', token.dns],
          ['Return record', `203.0.113.10`],
          ['Marker', token.marker],
        ] as Array<[string, string]>;
      case 'qr':
        return [
          ['QR payload URL', token.qr],
          ['Printed label', `Scan to open ${label || 'notice'}`],
          ['Marker', token.marker],
        ] as Array<[string, string]>;
    }
  }, [type, token, label]);

  const manifest = useMemo(
    () =>
      JSON.stringify(
        {
          manifest_version: 1,
          generated_utc: new Date().toISOString(),
          owner_team: owner,
          tokens: [
            {
              type,
              label,
              marker: token.marker,
              id: token.id,
              domain: domain.trim() || DEFAULT_OOB_DOMAIN,
              artefacts: Object.fromEntries(artefacts),
              placement: PLACEMENT[type],
              expected_noise: NOISE[type],
              notes: notes.trim() || undefined,
              fake: true,
            },
          ],
        },
        null,
        2,
      ),
    [type, label, owner, token, domain, artefacts, notes],
  );

  const siem = useMemo(() => {
    const host = domain.trim() || DEFAULT_OOB_DOMAIN;
    switch (type) {
      case 'aws':
        return [
          '# CloudTrail / GuardDuty',
          `userIdentity.accessKeyId = "${token.awsKeyId}"`,
          '',
          '# Splunk',
          `index=aws_cloudtrail accessKeyId="${token.awsKeyId}" | stats count min(_time) as first max(_time) as last by src_ip, userAgent`,
          '',
          '# CloudTrail Lake SQL',
          `SELECT eventTime, sourceIPAddress, userAgent FROM $EDS.CloudTrail WHERE userIdentity.accessKeyId = '${token.awsKeyId}'`,
        ].join('\n');
      case 'dns':
        return [
          '# Bind / CoreDNS query log',
          `grep -F '${token.dns}' /var/log/named/query.log`,
          '',
          '# Zeek',
          `zeek-cut query id.orig_h < dns.log | grep -F '${token.dns}'`,
          '',
          '# Splunk',
          `index=dns query="${token.dns}" | stats count by src_ip`,
        ].join('\n');
      default:
        return [
          '# Web / proxy access log',
          `grep -F '${token.id}' /var/log/nginx/access.log`,
          '',
          '# Zeek http.log',
          `zeek-cut host uri id.orig_h < http.log | grep -F '${token.id}'`,
          '',
          '# Splunk',
          `index=proxy url="*${token.id}*" | stats count min(_time) as first by src_ip, user`,
          '',
          '# Sentinel KQL',
          `CommonSecurityLog | where RequestURL contains "${token.id}" | project TimeGenerated, SourceIP, RequestURL`,
        ].join('\n');
    }
  }, [type, token, domain]);

  return (
    <>
      <Card title="Token definition">
        <div className="grid gap-3 sm:grid-cols-2">
          <Select<TokenType> value={type} onChange={setType} label="Token type" options={TYPES} />
          <TextInput label="Label" value={label} onChange={setLabel} mono hint="Used in the host name and the path" />
          <TextInput label="Owner team" value={owner} onChange={setOwner} hint="Carried in the manifest" />
          <TextInput label="Monitoring domain" value={domain} onChange={setDomain} mono placeholder="oast.example.com" />
        </div>
        <div className="mt-3">
          <TextArea
            label="Deployment notes"
            value={notes}
            onChange={setNotes}
            rows={2}
            placeholder="Where exactly it was planted, and when"
          />
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Button size="sm" variant="outline" onClick={() => setNonce((n) => n + 1)}>
            Rotate token values
          </Button>
          <span className="text-[11.5px] text-[var(--text-faint)]">
            Rotation #{nonce} · every value below is inert and regenerates on demand
          </span>
        </div>
        <div className="mt-3">
          <Callout tone="warn" title="Fake by construction">
            The AWS pair uses a real-looking prefix but a random secret that resolves to no account. Do not paste it into
            any cloud console — the provider will log the attempt, which is itself the alert you are testing for.
          </Callout>
        </div>
      </Card>

      <Card
        title="Generated artefacts"
        action={<DownloadButton text={manifest} filename={`canary-${label || 'token'}.json`} label="Download manifest" />}
      >
        <div className="space-y-3">
          {artefacts.map(([k, v]) => (
            <OutputField key={k} label={k} value={v} />
          ))}
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          {artefacts.map(([k, v]) => (
            <CopyChip key={`chip-${k}`} text={v} label={`${k}: ${v.length > 28 ? `${v.slice(0, 28)}…` : v}`} />
          ))}
        </div>
      </Card>

      <Card title="Placement and monitoring plan">
        <KVTable
          rows={[
            ['Where to plant it', PLACEMENT[type].join(' · ')],
            ['What an alert means', alertMeaning(type)],
            ['Expected noise', NOISE[type]],
            ['Escalation', `Notify ${owner} within 1 hour with source IP, user agent and time. Never disable the token.`],
          ]}
        />
      </Card>

      <Card title="Detection query">
        <CodeBlock code={siem} label="SIEM / grep template" maxHeight={320} />
        <div className="mt-3">
          <Callout tone="ok" title="Baseline first">
            Run the query in "count only" mode for 14 days before it pages anyone. A honeytoken that fires on day one
            because of a backup scan gets muted, and a muted token is worse than none.
          </Callout>
        </div>
      </Card>
    </>
  );
}

function alertMeaning(type: TokenType): string {
  switch (type) {
    case 'aws':
      return 'Someone read the credentials file and re-used the key. Treat as active credential misuse — the source IP tells you whether it left the estate.';
    case 'password':
      return 'Either the file was opened by a human or a DLP crawl reached it. User agent decides which.';
    case 'document':
      return 'The document was opened, copied or synced off the share. Timestamp plus the account gives the custody chain.';
    case 'dns':
      return 'Something resolved a name that only exists in a document. Internal resolver query = host-based collection.';
    case 'qr':
      return 'A device on the site Wi-Fi scanned the code. Correlate with badge or Wi-Fi logs for the physical layer.';
    default:
      return 'The URL was resolved. Fetched from an internal proxy means a human clicked; fetched from a cloud scanner means noise.';
  }
}
