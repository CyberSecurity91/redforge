import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  Checkbox,
  CopyChip,
  KVTable,
  OutputBlock,
  Select,
  Slider,
  TextInput,
} from '@/components/ui';
import { DEFAULT_TARGET_IP } from '@/tools/registry';

type Profile = 'syn' | 'connect' | 'udp' | 'fulltcp' | 'ping' | 'vuln' | 'discovery';

const PROFILES: Array<{ value: Profile; label: string }> = [
  { value: 'syn', label: 'SYN stealth (-sS)' },
  { value: 'connect', label: 'TCP connect (-sT)' },
  { value: 'udp', label: 'UDP top-100 (-sU --top-ports 100)' },
  { value: 'fulltcp', label: 'Full TCP 1-65535 (-p-)' },
  { value: 'ping', label: 'Ping sweep (-sn)' },
  { value: 'vuln', label: 'Vuln NSE (--script vuln)' },
  { value: 'discovery', label: 'Service discovery (-sV -sC)' },
];

const TIMING_LABEL = ['paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'];

export default function NmapCommandBuilder() {
  const [target, setTarget] = useState(DEFAULT_TARGET_IP);
  const [profile, setProfile] = useState<Profile>('discovery');
  const [ports, setPorts] = useState('1-1000');
  const [timing, setTiming] = useState(4);
  const [serviceDetect, setServiceDetect] = useState(true);
  const [intensity, setIntensity] = useState(7);
  const [versionAll, setVersionAll] = useState(false);
  const [osDetect, setOsDetect] = useState(false);
  const [aggressive, setAggressive] = useState(false);
  const [script, setScript] = useState('');
  const [decoys, setDecoys] = useState('');
  const [sourcePort, setSourcePort] = useState('');
  const [randomise, setRandomise] = useState(false);
  const [noPing, setNoPing] = useState(false);
  const [fragment, setFragment] = useState(false);
  const [outPrefix, setOutPrefix] = useState('scan');

  const build = useMemo(() => {
    const flags: Array<[string, string]> = [];
    // Each entry is one complete CLI token group, so joining is unambiguous.
    const tokens: string[] = ['nmap'];
    const add = (token: string, why: string) => {
      tokens.push(token);
      flags.push([token, why]);
    };

    if (profile === 'syn') add('-sS', 'Half-open SYN scan — raw sockets, so root or CAP_NET_RAW.');
    if (profile === 'connect') add('-sT', 'Full three-way handshake; logged by the target, no root needed.');
    if (profile === 'udp') {
      add('-sU', 'UDP scan — slow, and default rate-limited.');
      add('--top-ports 100', 'The 100 most common UDP services.');
    }
    if (profile === 'ping') add('-sn', 'Host discovery only, no port scan.');
    if (profile === 'vuln') add('--script vuln', 'Every NSE vuln-category check; noisy and slow.');
    if (profile === 'discovery') add('-sC', 'Default NSE category — safe service scripts.');

    if (profile === 'fulltcp') add('-p-', 'All 65535 TCP ports.');
    else if (profile !== 'ping' && profile !== 'udp' && ports.trim()) add(`-p ${ports.trim()}`, 'Explicit port selection.');

    if (serviceDetect && profile !== 'ping') {
      add('-sV', 'Banner-grab every open port.');
      if (intensity !== 7) add(`--version-intensity ${intensity}`, `Probe intensity ${intensity}/9 — lower is quieter.`);
      if (versionAll) add('--version-all', 'Try every probe; slowest, catches stubborn services.');
    }
    if (osDetect) add('-O', 'TCP/IP stack fingerprinting; needs one open and one closed port.');
    if (aggressive) add('-A', 'Bundle of -sV -O -sC --traceroute.');
    if (script.trim()) add(`--script ${script.trim()}`, 'Named NSE scripts or categories.');
    if (decoys.trim()) add(`-D ${decoys.trim()}`, 'Decoy sources; the real IP is still in the RST.');
    if (sourcePort.trim()) add(`--source-port ${sourcePort.trim()}`, 'Source-port spoof to slip past ACLs trusting 53/88.');
    if (randomise) add('--randomize-hosts', 'Shuffle target order.');
    if (noPing) add('-Pn', 'Skip host discovery; treat every target as up.');

    add(`-T${timing}`, `Timing template ${timing} (${TIMING_LABEL[timing]}).`);
    if (fragment) add('--mtu 8', 'Fragment packets into 8-byte chunks.');
    if (outPrefix.trim()) add(`-oA ${outPrefix.trim()}`, 'Normal, XML and grepable output in one pass.');

    const finalTarget = target.trim() || DEFAULT_TARGET_IP;
    const command = [tokens.join(' '), finalTarget].join(' \\\n  ');
    const targetHost = finalTarget.split('/')[0].split(/\s+/)[0];

    return {
      command,
      flags,
      rustscan: `rustscan -a ${targetHost} --range 1-65535 --ulimit 5000 -- -sV -sC -Pn`,
      masscan: `sudo masscan -p1-65535 ${targetHost} --rate 1000 -oL masscan.txt`,
    };
  }, [
    target, profile, ports, timing, serviceDetect, intensity, versionAll, osDetect, aggressive,
    script, decoys, sourcePort, randomise, noPing, fragment, outPrefix,
  ]);

  return (
    <>
      <Card title="Target and profile">
        <div className="grid gap-4 sm:grid-cols-3">
          <TextInput label="Target" value={target} onChange={setTarget} mono placeholder={DEFAULT_TARGET_IP} />
          <Select label="Scan profile" value={profile} onChange={setProfile} options={PROFILES} />
          <TextInput
            label="Port spec"
            hint="Ignored for UDP, ping and full-TCP profiles"
            value={ports}
            onChange={setPorts}
            mono
            placeholder="22,80,443 or 1-65535"
          />
          <TextInput label="NSE script" hint="smb-enum-shares,http-title,…" value={script} onChange={setScript} mono />
          <TextInput label="Decoys" hint="-D form, e.g. 10.0.0.1,ME,10.0.0.9" value={decoys} onChange={setDecoys} mono />
          <TextInput label="Spoof source port" hint="53 / 88 / 443 pass most ACLs" value={sourcePort} onChange={setSourcePort} mono placeholder="53" />
        </div>
        <div className="mt-4">
          <Slider
            label="Timing template"
            value={timing}
            onChange={setTiming}
            min={0}
            max={5}
            format={(v) => `-T${v} · ${TIMING_LABEL[v]}`}
          />
        </div>
      </Card>

      <Card title="Options">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Checkbox checked={serviceDetect} onChange={setServiceDetect} label="Service detection" description="-sV banner grab" />
          <Checkbox checked={versionAll} onChange={setVersionAll} label="Version all" description="--version-all, slowest" />
          <Checkbox checked={osDetect} onChange={setOsDetect} label="OS detection" description="-O, privileged" />
          <Checkbox checked={aggressive} onChange={setAggressive} label="Aggressive" description="-A bundle" />
          <Checkbox checked={noPing} onChange={setNoPing} label="No ping" description="-Pn for filtered hosts" />
          <Checkbox checked={randomise} onChange={setRandomise} label="Randomise hosts" description="--randomize-hosts" />
          <Checkbox checked={fragment} onChange={setFragment} label="Fragment packets" description="--mtu 8" />
        </div>
        <div className="mt-5 grid gap-4 sm:grid-cols-2">
          <Slider
            label="Version intensity"
            value={intensity}
            onChange={setIntensity}
            min={0}
            max={9}
            format={(v) => `${v} / 9`}
          />
          <TextInput label="Output prefix" hint="-oA writes .nmap / .xml / .gnmap" value={outPrefix} onChange={setOutPrefix} mono />
        </div>
      </Card>

      <Card title="Command">
        <OutputBlock value={build.command} rows={12} label="nmap" />
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <div>
            <OutputBlock value={build.rustscan} rows={3} label="rustscan → nmap hand-off" />
            <div className="mt-2">
              <CopyChip text={build.rustscan} label="rustscan" />
            </div>
          </div>
          <div>
            <OutputBlock value={build.masscan} rows={3} label="masscan — stateless sweep" />
            <div className="mt-2">
              <CopyChip text={build.masscan} label="masscan" />
            </div>
          </div>
        </div>
      </Card>

      <Card title="Flag reference">
        <KVTable rows={build.flags.map(([flag, why]) => [<span key={flag} className="rf-mono">{flag}</span>, why])} />
        <div className="mt-4">
          <Callout tone="info" title="Detection trade-off">
            <span className="rf-mono">-T4 -sV</span> is the usual internal balance. With an IDS in the path drop to{' '}
            <span className="rf-mono">-T2</span> and bound the rate with{' '}
            <span className="rf-mono">--max-rate</span>. Fragmentation and decoys raise noise more than they hide you on
            modern sensors.
          </Callout>
        </div>
      </Card>
    </>
  );
}
