import { useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, CopyChip, KVTable, OutputField, Select } from '@/components/ui';

/**
 * CVSS v3.1 base score. The maths follows the specification exactly:
 *   ISS  = 1 - (1-C)(1-I)(1-A)
 *   Impact = 6.42 * ISS                              (S:U)
 *          = 7.52 (ISS-0.029) - 3.25 (ISS-0.02)^15   (S:C)
 *   Exploitability = 8.22 * AV * AC * PR * UI
 *   Base = 0 (if Impact <= 0)
 *        = roundup(min(Impact + Exploitability, 10))                 (S:U)
 *        = roundup(min(1.08 (Impact + Exploitability), 10))          (S:C)
 * roundup(x) = round to 1 dp, upwards (spec Appendix A).
 */

type Axis = 'AV' | 'AC' | 'PR' | 'UI' | 'S' | 'C' | 'I' | 'A';

const METRIC_LABELS: Record<Axis, string> = {
  AV: 'Attack Vector',
  AC: 'Attack Complexity',
  PR: 'Privileges Required',
  UI: 'User Interaction',
  S: 'Scope',
  C: 'Confidentiality',
  I: 'Integrity',
  A: 'Availability',
};

interface Choice {
  value: string;
  label: string;
}

const CHOICES: Record<Axis, Choice[]> = {
  AV: [
    { value: 'N', label: 'Network (N)' },
    { value: 'A', label: 'Adjacent (A)' },
    { value: 'L', label: 'Local (L)' },
    { value: 'P', label: 'Physical (P)' },
  ],
  AC: [
    { value: 'L', label: 'Low (L)' },
    { value: 'H', label: 'High (H)' },
  ],
  PR: [
    { value: 'N', label: 'None (N)' },
    { value: 'L', label: 'Low (L)' },
    { value: 'H', label: 'High (H)' },
  ],
  UI: [
    { value: 'N', label: 'None (N)' },
    { value: 'R', label: 'Required (R)' },
  ],
  S: [
    { value: 'U', label: 'Unchanged (U)' },
    { value: 'C', label: 'Changed (C)' },
  ],
  C: [
    { value: 'H', label: 'High (H)' },
    { value: 'L', label: 'Low (L)' },
    { value: 'N', label: 'None (N)' },
  ],
  I: [
    { value: 'H', label: 'High (H)' },
    { value: 'L', label: 'Low (L)' },
    { value: 'N', label: 'None (N)' },
  ],
  A: [
    { value: 'H', label: 'High (H)' },
    { value: 'L', label: 'Low (L)' },
    { value: 'N', label: 'None (N)' },
  ],
};

const CIA_WEIGHT: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
const AV_WEIGHT: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_WEIGHT: Record<string, number> = { L: 0.77, H: 0.44 };
const UI_WEIGHT: Record<string, number> = { N: 0.85, R: 0.62 };
const PR_WEIGHT: Record<string, Record<string, number>> = {
  U: { N: 0.85, L: 0.62, H: 0.27 },
  C: { N: 0.85, L: 0.68, H: 0.5 },
};

/** Spec Appendix A round-up: only *corrects* an already-rounded-to-1dp value. */
export function roundUp(input: number): number {
  const scaled = Math.round(input * 100000);
  if (scaled % 10000 === 0) return scaled / 100000;
  return (Math.floor(scaled / 10000) + 1) / 10;
}

export function cvssBase(m: Record<Axis, string>) {
  const iss = 1 - (1 - CIA_WEIGHT[m.C]) * (1 - CIA_WEIGHT[m.I]) * (1 - CIA_WEIGHT[m.A]);
  const scopeChanged = m.S === 'C';
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const pr = PR_WEIGHT[scopeChanged ? 'C' : 'U'][m.PR];
  const exploitability = 8.22 * AV_WEIGHT[m.AV] * AC_WEIGHT[m.AC] * pr * UI_WEIGHT[m.UI];
  const raw = impact <= 0 ? 0 : scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  const score = impact <= 0 ? 0 : roundUp(raw);
  return { iss, impact, exploitability, raw, score };
}

export function severity(score: number): { label: string; token: string } {
  if (score === 0) return { label: 'None', token: 'var(--text-muted)' };
  if (score < 4) return { label: 'Low', token: 'var(--ok)' };
  if (score < 7) return { label: 'Medium', token: 'var(--warn)' };
  if (score < 9) return { label: 'High', token: 'var(--danger, var(--warn))' };
  return { label: 'Critical', token: 'var(--danger, var(--accent))' };
}

export function buildVector(m: Record<Axis, string>): string {
  return `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
}

/** Parse a v3.0 or v3.1 base vector. Returns null when a metric is missing/invalid. */
export function parseVector(vector: string): Record<Axis, string> | null {
  const parts = vector.trim().replace(/^CVSS:3\.[01]\//i, '').split('/');
  const out: Partial<Record<Axis, string>> = {};
  for (const part of parts) {
    const [k, v] = part.split(':');
    const axis = k?.toUpperCase() as Axis | undefined;
    if (!axis || !(axis in CHOICES)) continue;
    const val = (v ?? '').toUpperCase();
    if (!CHOICES[axis].some((c) => c.value === val)) return null;
    out[axis] = val;
  }
  const axes: Axis[] = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
  if (axes.some((a) => !out[a])) return null;
  return out as Record<Axis, string>;
}

export default function CvssCalculator() {
  const [m, setM] = useState<Record<Axis, string>>({
    AV: 'N',
    AC: 'L',
    PR: 'N',
    UI: 'N',
    S: 'U',
    C: 'H',
    I: 'H',
    A: 'H',
  });

  const result = useMemo(() => cvssBase(m), [m]);
  const vector = useMemo(() => buildVector(m), [m]);
  const band = severity(result.score);

  const table = useMemo(() => {
    const pr = PR_WEIGHT[m.S === 'C' ? 'C' : 'U'][m.PR];
    return [
      ['ISS (1-(1-C)(1-I)(1-A))', result.iss.toFixed(4)],
      ['Impact', result.impact.toFixed(4)],
      ['Exploitability (8.22·AV·AC·PR·UI)', result.exploitability.toFixed(4)],
      ['AV weight', AV_WEIGHT[m.AV].toFixed(2)],
      ['AC weight', AC_WEIGHT[m.AC].toFixed(2)],
      ['PR weight (scope-adjusted)', pr.toFixed(2)],
      ['UI weight', UI_WEIGHT[m.UI].toFixed(2)],
      ['Pre-round total', result.raw.toFixed(4)],
      ['Base score (round-up)', result.score.toFixed(1)],
    ] as Array<[string, string]>;
  }, [m, result]);

  const hint = useMemo(() => dropHint(m, result.score), [m, result.score]);

  return (
    <>
      <Card title="Base metrics">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {(Object.keys(CHOICES) as Axis[]).map((axis) => (
            <Select<string>
              key={axis}
              label={`${axis} — ${METRIC_LABELS[axis]}`}
              value={m[axis]}
              onChange={(v) => setM((prev) => ({ ...prev, [axis]: v }))}
              options={CHOICES[axis]}
            />
          ))}
        </div>
        <div className="mt-4 flex flex-wrap items-end gap-4">
          <div>
            <div className="text-[11px] uppercase tracking-wide text-[var(--text-faint)]">Base score</div>
            <div className="rf-mono text-3xl font-semibold" style={{ color: band.token }}>
              {result.score.toFixed(1)}
            </div>
          </div>
          <div className="pb-1">
            <span
              className="rounded px-2 py-1 text-[12px] font-medium"
              style={{ background: 'var(--accent-faded)', color: band.token }}
            >
              {band.label}
            </span>
          </div>
          <div className="pb-1">
            <CopyChip text={vector} label="Copy vector" />
          </div>
        </div>
        <div className="mt-3">
          <OutputField label="Vector string" value={vector} />
        </div>
      </Card>

      <Card title="Score derivation">
        <KVTable rows={table} />
        <div className="mt-3">
          <CodeBlock
            label="Worked arithmetic"
            maxHeight={220}
            code={[
              `ISS        = 1 - (1-${CIA_WEIGHT[m.C]}) x (1-${CIA_WEIGHT[m.I]}) x (1-${CIA_WEIGHT[m.A]}) = ${result.iss.toFixed(4)}`,
              m.S === 'C'
                ? `Impact     = 7.52 x (ISS-0.029) - 3.25 x (ISS-0.02)^15 = ${result.impact.toFixed(4)}`
                : `Impact     = 6.42 x ISS = ${result.impact.toFixed(4)}`,
              `Exploit.   = 8.22 x ${AV_WEIGHT[m.AV]} x ${AC_WEIGHT[m.AC]} x ${PR_WEIGHT[m.S === 'C' ? 'C' : 'U'][m.PR]} x ${UI_WEIGHT[m.UI]} = ${result.exploitability.toFixed(4)}`,
              m.S === 'C'
                ? `Base       = roundup(min(1.08 x (${result.impact.toFixed(4)} + ${result.exploitability.toFixed(4)}), 10)) = ${result.score.toFixed(1)}`
                : `Base       = roundup(min(${result.impact.toFixed(4)} + ${result.exploitability.toFixed(4)}, 10)) = ${result.score.toFixed(1)}`,
            ].join('\n')}
          />
        </div>
      </Card>

      <Card title="What would move this band">
        <div className="space-y-3">
          <Callout tone={result.score >= 7 ? 'warn' : 'ok'} title="Next band boundary">
            {hint}
          </Callout>
          <Callout tone="info" title="Base only — no temporal or environmental metrics">
            CVSS v3.1 defines two further metric groups that this tool does not compute. Temporal (E, RL, RC) adjusts the
            score by exploit maturity, remediation level and report confidence; Environmental (CR, IR, AR, MAV, MAC, MPR,
            MUI, MS, MC, MI, MA) re-weights the base metrics for the client's asset context. Report the base vector and
            state explicitly that temporal/environmental scoring was not applied — a bare "9.8" invites the client to
            argue about it.
          </Callout>
        </div>
      </Card>

      <Card title="Reference">
        <CodeBlock
          label="Anchors worth memorising"
          maxHeight={220}
          code={[
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  = 9.8  Critical',
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N  = 7.5  High',
            'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N  = 6.4  Medium',
            'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N  = 3.1  Low',
            '',
            'Severity bands: 0.0 none | 0.1-3.9 low | 4.0-6.9 medium | 7.0-8.9 high | 9.0-10.0 critical',
          ].join('\n')}
        />
      </Card>
    </>
  );
}

function dropHint(m: Record<Axis, string>, score: number): string {
  if (score < 7) {
    return `Already below 7.0 at ${score.toFixed(1)}. Raising PR to High and UI to Required in combination is the usual route back up, but do not grade the finding for the band you want.`;
  }
  const candidates: string[] = [];
  if (m.AV === 'N') candidates.push('AV:N→A drops the AV weight from 0.85 to 0.62');
  if (m.UI === 'N') candidates.push('UI:N→R drops the UI weight from 0.85 to 0.62');
  if (m.PR === 'N') candidates.push('PR:N→L drops the PR weight from 0.85 to 0.62');
  if (m.AC === 'L') candidates.push('AC:L→H drops the AC weight from 0.77 to 0.44');
  candidates.push('C/I/A down to Low takes the ISS from its current value to 0.47 at most');
  return `At ${score.toFixed(1)} this sits in the ${severity(score).label} band. To fall below 7.0, any two of: ${candidates.join('; ')}. Pick the change the evidence actually supports — an unsupported downgrade is what gets a finding argued down in triage.`;
}
