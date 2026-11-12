import { useMemo } from 'react';
import { Callout, Card, CopyChip, DownloadButton, KVTable, NumberInput, OutputBlock, Select, TextArea, TextInput } from '@/components/ui';
import { useLocalStorage } from '@/lib/hooks';

/**
 * Executive summary generator. The prose is assembled from the numbers, not typed:
 * every figure in the paragraphs comes from the inputs below, and the word count is
 * measured on the composed text so a client's one-page limit can actually be met.
 */

type EngagementType = 'external' | 'internal' | 'web' | 'cloud' | 'social' | 'assumed';
type Posture = 'weak' | 'developing' | 'adequate' | 'strong';

interface Config {
  client: string;
  type: EngagementType;
  start: string;
  end: string;
  assets: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  issue1: string;
  issue2: string;
  posture: Posture;
  nextSteps: string;
}

const TYPES: Array<{ value: EngagementType; label: string }> = [
  { value: 'external', label: 'External infrastructure' },
  { value: 'internal', label: 'Internal network' },
  { value: 'web', label: 'Web application' },
  { value: 'cloud', label: 'Cloud configuration review' },
  { value: 'social', label: 'Social engineering' },
  { value: 'assumed', label: 'Assumed breach' },
];

const POSTURES: Array<{ value: Posture; label: string }> = [
  { value: 'weak', label: 'Weak — exploitable exposure' },
  { value: 'developing', label: 'Developing — controls partial' },
  { value: 'adequate', label: 'Adequate — isolated gaps' },
  { value: 'strong', label: 'Strong — contained' },
];

const POSTURE_PHRASE: Record<Posture, string> = {
  weak: 'the estate presents a weak security posture, with issues reachable without valid credentials',
  developing: 'the security posture is developing, with foundational controls present but exposure management incomplete',
  adequate: 'the security posture is adequate for the current threat model, with isolated weaknesses to close',
  strong: 'the security posture is strong, with no critical exposure identified and high-severity issues contained',
};

const DEFAULT_CONFIG: Config = {
  client: 'Northwind Logistics',
  type: 'external',
  start: '2026-10-06',
  end: '2026-10-17',
  assets: 48,
  critical: 1,
  high: 4,
  medium: 9,
  low: 12,
  info: 6,
  issue1: 'Anonymous read access to the customer document store',
  issue2: 'Unpatched internet-facing VPN appliance behind a single factor',
  posture: 'developing',
  nextSteps: [
    'Close the document store exposure and confirm the access logs are retained.',
    'Patch the VPN appliance and enforce MFA for all remote sessions.',
    'Re-test the high-severity findings within 30 days of remediation.',
  ].join('\n'),
};

export default function ExecutiveSummaryGenerator() {
  const [cfg, setCfg] = useLocalStorage<Config>('exec-summary-config', DEFAULT_CONFIG);
  const patch = (p: Partial<Config>) => setCfg((prev) => ({ ...prev, ...p }));

  const derived = useMemo(() => {
    const counts = [cfg.critical, cfg.high, cfg.medium, cfg.low, cfg.info].map((n) => Math.max(0, Math.round(n)));
    const total = counts.reduce((a, b) => a + b, 0);
    const criticalHigh = (counts[0] ?? 0) + (counts[1] ?? 0);
    const assets = Math.max(0, Math.round(cfg.assets));
    return {
      counts,
      total,
      criticalHigh,
      share: total ? (criticalHigh / total) * 100 : 0,
      density: assets ? total / assets : 0,
      assets,
    };
  }, [cfg.critical, cfg.high, cfg.medium, cfg.low, cfg.info, cfg.assets]);

  const steps = useMemo(
    () => cfg.nextSteps.split('\n').map((s) => s.replace(/^[-*]\s*/, '').trim()).filter(Boolean),
    [cfg.nextSteps],
  );

  const paragraphs = useMemo(() => {
    const [crit, high, med, low, info] = derived.counts;
    const typeLabel = TYPES.find((t) => t.value === cfg.type)?.label ?? 'assessment';
    const windowText = `${cfg.start || '{{START}}'} to ${cfg.end || '{{END}}'}`;
    return [
      `${cfg.client || 'The client'} commissioned a ${typeLabel.toLowerCase()} assessment covering ${derived.assets} in-scope assets between ${windowText}. Testing followed the agreed rules of engagement, and every finding recorded here was validated on a live system rather than inferred from a scan.`,
      `${derived.total} findings were raised: ${crit} critical, ${high} high, ${med} medium, ${low} low and ${info} informational. ${derived.criticalHigh} of the ${derived.total} (${derived.share.toFixed(0)}%) are rated high or critical, and the overall density is ${derived.density.toFixed(2)} findings per in-scope asset.`,
      derived.criticalHigh > 0
        ? `Two issues carry the most business weight. ${cfg.issue1 || '{{ISSUE_1}}'} and ${cfg.issue2 || '{{ISSUE_2}}'} both sit on paths that a motivated attacker would reach early, and neither depends on a compromised endpoint.`
        : `The two issues the business should track most closely are ${cfg.issue1 || '{{ISSUE_1}}'} and ${cfg.issue2 || '{{ISSUE_2}}'}. Neither is directly exploitable without preconditions, which is why they are tracked rather than escalated.`,
      `Overall, ${POSTURE_PHRASE[cfg.posture]}. ${steps.length} next steps are proposed, the first of which should be scheduled inside the current remediation cycle. Severity ratings and remediation dates follow the agreed CVSS thresholds and the client's published SLA table; nothing in this summary changes those ratings.`,
    ];
  }, [cfg, derived, steps.length]);

  const bullets = useMemo(() => {
    const [crit, high] = derived.counts;
    const out = [
      crit > 0
        ? `${crit} critical finding${crit === 1 ? '' : 's'} can be exercised without valid credentials and should be closed first.`
        : 'No critical exposure was identified; the highest risk sits with the high-severity issues.',
      `${derived.criticalHigh} high or critical issues represent ${derived.share.toFixed(0)}% of the total, so remediation effort is concentrated rather than spread.`,
      `At ${derived.density.toFixed(2)} findings per asset, the exposure is ${derived.density > 1 ? 'broad rather than isolated' : 'isolated rather than systemic'}.`,
      high > 0
        ? `${high} high-severity issue${high === 1 ? '' : 's'} sit within the 30-day remediation window and drive the near-term plan.`
        : 'No high-severity issues remain open, so the plan can follow the standard cycle.',
      `Reporting reflects the position at the close of the window; later changes are tracked in the remediation board.`,
    ];
    return out;
  }, [derived]);

  const markdown = useMemo(() => {
    return [
      `# Executive summary — ${cfg.client || '{{CLIENT}}'}`,
      '',
      '> Placeholder figures are replaced from the engagement record. Ratings unchanged from the technical report.',
      '',
      ...paragraphs.flatMap((p) => [p, '']),
      '## What this means',
      '',
      ...bullets.map((b) => `- ${b}`),
      '',
      '## Recommended next steps',
      '',
      ...(steps.length ? steps.map((s, i) => `${i + 1}. ${s}`) : ['1. {{NEXT_STEP}}']),
    ].join('\n');
  }, [cfg.client, paragraphs, bullets, steps]);

  const words = useMemo(() => {
    const text = [...paragraphs, ...bullets, ...steps].join(' ');
    return text.split(/\s+/).filter(Boolean).length;
  }, [paragraphs, bullets, steps]);

  return (
    <>
      <Card title="Engagement">
        <div className="grid gap-3 sm:grid-cols-2">
          <TextInput label="Client" value={cfg.client} onChange={(v) => patch({ client: v })} />
          <Select<EngagementType> label="Engagement type" value={cfg.type} onChange={(v) => patch({ type: v })} options={TYPES} />
          <TextInput label="Window start" value={cfg.start} onChange={(v) => patch({ start: v })} type="date" mono />
          <TextInput label="Window end" value={cfg.end} onChange={(v) => patch({ end: v })} type="date" mono />
          <NumberInput label="Assets in scope" value={cfg.assets} onChange={(v) => patch({ assets: v })} min={0} max={100000} />
        </div>
        <div className="mt-3">
          <Callout tone="info" title="Neutral by design">
            The generator states what was found and when. It does not score the client's team, and every judgement in
            the text is tied to a number you can point at in the technical report.
          </Callout>
        </div>
      </Card>

      <Card title="Findings">
        <div className="grid gap-3 sm:grid-cols-3">
          <NumberInput label="Critical" value={cfg.critical} onChange={(v) => patch({ critical: v })} min={0} max={9999} />
          <NumberInput label="High" value={cfg.high} onChange={(v) => patch({ high: v })} min={0} max={9999} />
          <NumberInput label="Medium" value={cfg.medium} onChange={(v) => patch({ medium: v })} min={0} max={9999} />
          <NumberInput label="Low" value={cfg.low} onChange={(v) => patch({ low: v })} min={0} max={9999} />
          <NumberInput label="Informational" value={cfg.info} onChange={(v) => patch({ info: v })} min={0} max={9999} />
          <div className="flex items-end pb-1">
            <span className="text-[12px] text-[var(--text-faint)]">
              {derived.total} total · {derived.share.toFixed(0)}% high or critical
            </span>
          </div>
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <TextInput label="Business issue 1" value={cfg.issue1} onChange={(v) => patch({ issue1: v })} hint="the one-liner leadership repeats" />
          <TextInput label="Business issue 2" value={cfg.issue2} onChange={(v) => patch({ issue2: v })} />
        </div>
      </Card>

      <Card title="Posture and next steps">
        <Select<Posture> label="Overall posture" value={cfg.posture} onChange={(v) => patch({ posture: v })} options={POSTURES} hint={POSTURE_PHRASE[cfg.posture]} />
        <div className="mt-3">
          <TextArea label="Recommended next steps" value={cfg.nextSteps} onChange={(v) => patch({ nextSteps: v })} rows={5} hint="One per line; numbered in the summary." />
        </div>
      </Card>

      <Card
        title="Summary"
        action={
          <span className="flex items-center gap-2">
            <span className="rounded-full px-2 py-[1px] text-[11px] font-medium" style={{ backgroundColor: 'var(--neutral-btn)', color: 'var(--text-muted)' }}>
              {words} words
            </span>
            <CopyChip text={markdown} label="Copy" />
            <DownloadButton text={markdown} filename="executive-summary.md" label="Download .md" />
          </span>
        }
      >
        <div className="space-y-3">
          {paragraphs.map((p, i) => (
            <p key={i} className="m-0 text-[13px] leading-relaxed text-[var(--text-muted)]">{p}</p>
          ))}
        </div>
        <div className="mt-4">
          <div className="mb-1.5 text-[12px] font-medium text-[var(--text)]">What this means</div>
          <ul className="m-0 list-disc space-y-1 pl-5 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
            {bullets.map((b, i) => (
              <li key={i}>{b}</li>
            ))}
          </ul>
        </div>
        <div className="mt-4">
          <KVTable
            rows={[
              ['Findings', `${derived.total} across ${derived.assets} assets`],
              ['High and critical', `${derived.criticalHigh} (${derived.share.toFixed(0)}% of total)`],
              ['Density', `${derived.density.toFixed(2)} per asset`],
              ['Next steps', String(steps.length)],
              ['Words in summary', String(words)],
            ]}
          />
        </div>
        <div className="mt-4">
          <OutputBlock value={markdown} label="executive-summary.md" rows={14} />
        </div>
      </Card>
    </>
  );
}
