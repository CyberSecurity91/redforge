import { useMemo, useState } from 'react';
import { Card, TextInput, Select, NumberInput, KVTable, OutputBlock, Callout, CopyChip, Button } from '@/components/ui';
import { ALL_TOOLS, CATEGORIES } from '@/tools';

/**
 * Pretext working-hours window: pick the target's time zone and your own, get
 * the overlap in both zones plus a per-weekday table. Pure Intl maths, no deps.
 */

const ZONES = [
  'UTC',
  'Europe/London',
  'Europe/Dublin',
  'Europe/Paris',
  'Europe/Berlin',
  'Europe/Madrid',
  'Europe/Rome',
  'Europe/Amsterdam',
  'Europe/Stockholm',
  'Europe/Warsaw',
  'Europe/Kyiv',
  'Europe/Moscow',
  'Europe/Istanbul',
  'Africa/Lagos',
  'Africa/Johannesburg',
  'Africa/Nairobi',
  'Asia/Dubai',
  'Asia/Karachi',
  'Asia/Kolkata',
  'Asia/Dhaka',
  'Asia/Bangkok',
  'Asia/Jakarta',
  'Asia/Shanghai',
  'Asia/Singapore',
  'Asia/Tokyo',
  'Asia/Seoul',
  'Australia/Perth',
  'Australia/Sydney',
  'Pacific/Auckland',
  'America/Sao_Paulo',
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'America/Vancouver',
  'Pacific/Honolulu',
];

const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'] as const;

function offsetMinutes(zone: string, date: Date): number {
  const fmt = new Intl.DateTimeFormat('en-GB', {
    timeZone: zone,
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  });
  const parts = fmt.formatToParts(date);
  const get = (t: string) => Number(parts.find((p) => p.type === t)?.value ?? 0);
  const asUtc = Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'));
  return Math.round((asUtc - Math.floor(date.getTime() / 60000) * 60000) / 60000);
}

const hhmm = (minutes: number): string => {
  const m = ((minutes % 1440) + 1440) % 1440;
  return `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
};

const zoneLabel = (zone: string, date: Date): string => {
  const off = offsetMinutes(zone, date);
  const sign = off >= 0 ? '+' : '-';
  const abs = Math.abs(off);
  return `UTC${sign}${String(Math.floor(abs / 60)).padStart(2, '0')}:${String(abs % 60).padStart(2, '0')}`;
};

export default function TimezoneWindow() {
  const [targetZone, setTargetZone] = useState('America/New_York');
  const [operatorZone, setOperatorZone] = useState('Europe/London');
  const [start, setTargetNumeric] = useSlot(9);
  const [hours, setHours] = useState(8);
  const [dayIndex, setDayIndex] = useState(2);

  // A reference date inside the current week so offsets reflect live DST rules.
  const reference = useMemo(() => {
    const now = new Date();
    const d = new Date(now);
    const day = (now.getUTCDay() + 6) % 7; // Monday-based
    d.setUTCDate(now.getUTCDate() - day + dayIndex);
    d.setUTCHours(12, 0, 0, 0);
    return d;
  }, [dayIndex]);

  const targetOffset = offsetMinutes(targetZone, reference);
  const operatorOffset = offsetMinutes(operatorZone, reference);
  const skew = operatorOffset - targetOffset;

  // Convert the target's local window into UTC, then into the operator's clock.
  const windowInUtcStart = start * 60 - targetOffset;
  const windowInUtcEnd = windowInUtcStart + hours * 60;
  const operatorStart = windowInUtcStart + operatorOffset;
  const operatorEnd = windowInUtcEnd + operatorOffset;

  const overlapStart = Math.max(windowInUtcStart, 9 * 60 - operatorOffset);
  const overlapEnd = Math.min(windowInUtcEnd, 18 * 60 - operatorOffset);
  const overlapMinutes = Math.max(0, overlapEnd - overlapStart);

  const weekRows = DAYS.map((day, i) => {
    const d = new Date(reference);
    d.setUTCDate(reference.getUTCDate() - dayIndex + i);
    const tOff = offsetMinutes(targetZone, d);
    const oOff = offsetMinutes(operatorZone, d);
    const s = start * 60 - tOff;
    const e = s + hours * 60;
    return [day, `${hhmm(s + oOff)}–${hhmm(e + oOff)}`, `${hhmm(s + tOff)}–${hhmm(e + tOff)}`];
  });

  const callWindow = `Target: ${hhmm(start * 60)}–${hhmm(start * 60 + hours * 60)} ${zoneLabel(targetZone, reference)}
Operator: ${hhmm(operatorStart)}–${hhmm(operatorEnd)} ${zoneLabel(operatorZone, reference)}
Offset: ${skew >= 0 ? '+' : ''}${(skew / 60).toFixed(1)}h behind the target
Overlap with a 09:00–18:00 operator day: ${overlapMinutes > 0 ? `${(overlapMinutes / 60).toFixed(1)}h` : 'none — need an out-of-hours call'}`;

  return (
    <>
      <Card title="Window">
        <div className="grid gap-4 sm:grid-cols-2">
          <Select
            label="Target time zone"
            value={targetZone}
            onChange={setTargetZone}
            options={ZONES.map((z) => ({ value: z, label: z }))}
          />
          <Select
            label="Operator time zone"
            value={operatorZone}
            onChange={setOperatorZone}
            options={ZONES.map((z) => ({ value: z, label: z }))}
          />
          <NumberInput label="Target office opens (local hour)" value={start} onChange={setTargetNumeric} min={0} max={23} />
          <NumberInput label="Open for (hours)" value={hours} onChange={setHours} min={1} max={14} />
          <Select
            label="Reference weekday"
            value={String(dayIndex)}
            onChange={(v) => setDayIndex(Number(v))}
            options={DAYS.map((d, i) => ({ value: String(i), label: d }))}
          />
        </div>
      </Card>

      <Card title="Call window">
        <OutputBlock value={callWindow} rows={6} label="Briefing note" />
        <div className="mt-3">
          <KVTable
            rows={[
              ['Target local', `${hhmm(start * 60)}–${hhmm(start * 60 + hours * 60)} (${zoneLabel(targetZone, reference)})`],
              ['Operator local', `${hhmm(operatorStart)}–${hhmm(operatorEnd)} (${zoneLabel(operatorZone, reference)})`],
              ['Skew', `${skew >= 0 ? '+' : ''}${skew} min`],
              ['Overlap', overlapMinutes > 0 ? `${(overlapMinutes / 60).toFixed(1)} hours` : 'none'],
            ]}
          />
        </div>
      </Card>

      <Card title="Week view">
        <KVTable rows={[['Day', 'Operator clock'], ...weekRows.map((r) => [r[0], r[1]] as [string, string])]} />
        <p className="mt-2 mb-0 text-[11.5px] text-[var(--text-faint)]">
          DST transitions are resolved per day with <span className="rf-mono">Intl</span>, so a week that straddles a
          change shows two different offsets.
        </p>
      </Card>

      <Card title="Timing notes">
        <div className="flex flex-col gap-3">
          <Callout tone="info" title="Pick the slot that survives scrutiny">
            A vishing call reads as legitimate when it lands inside the target's stated business hours <em>and</em> at
            least an hour away from lunch and end-of-day. Avoid the first hour — staff are triaging a backlog and will
            defer anything that needs a decision.
          </Callout>
          <Callout tone="warn" title="Holidays beat time zones">
            Regional public holidays and month-end finance freezes invert normal availability. Check the target's
            country calendar before committing a wave.
          </Callout>
          <div className="flex flex-wrap gap-1.5">
            <CopyChip text={`${hhmm(operatorStart)}–${hhmm(operatorEnd)} ${zoneLabel(operatorZone, reference)}`} label="Copy slot" />
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setTargetZone('Europe/London');
                setOperatorZone('Europe/London');
                setTargetNumeric(9);
                setHours(8);
              }}
            >
              Reset to same-zone
            </Button>
            <span className="ml-auto text-[11.5px] text-[var(--text-faint)]">
              {ALL_TOOLS.length} tools · {CATEGORIES.length} categories
            </span>
          </div>
        </div>
      </Card>
    </>
  );
}

/** Local alias so the numeric setter reads like the others in this file. */
function useSlot(initial: number) {
  return useState(initial);
}
