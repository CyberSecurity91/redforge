import { useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, CopyChip, KVTable, TextArea } from '@/components/ui';
import { shannonEntropy } from '@/lib/bytes';

type Guess = { label: string; confidence: 'high' | 'medium' | 'low'; reason: string };

const SAMPLE = 'ghp_9f2Kq7LmXvB4tR8sW1cD6yN0aE3uH5jG';

function classify(value: string, entropy: number): Guess[] {
  const s = value.trim();
  const guesses: Guess[] = [];
  const push = (label: string, confidence: 'high' | 'medium' | 'low', reason: string) =>
    guesses.push({ label, confidence, reason });

  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0 && s.length >= 16) {
    push('hex', 'high', `Only [0-9a-f] characters and an even length (${s.length}) — likely a hex digest or hex-encoded key.`);
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length % 4 === 0 && /[+/=]/.test(s)) {
    push('base64', 'high', 'Alphabet and padding match base64 with explicit +/= characters.');
  } else if (/^[A-Za-z0-9+/]{20,}$/.test(s) && s.length % 4 === 0) {
    push('base64', 'medium', 'Alphabet fits base64 and the length is a multiple of 4, but no padding is present.');
  }
  if (/^[A-Z2-7]+=*$/.test(s) && s.length >= 16) {
    push('base32', 'high', 'Only A–Z and 2–7 — base32 alphabet.');
  }
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s)) {
    push('UUID v1–v5', 'high', 'Hyphen placement and RFC 4122 version/variant nibbles match.');
  }
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(s)) {
    push('JWT', 'high', 'Three base64url segments separated by dots — header.payload.signature.');
  }
  if (/^[a-z]+_[A-Za-z0-9]{16,}$/.test(s)) {
    push('prefixed API token', 'medium', 'Vendor-style prefix (e.g. ghp_, sk_, AKIA) followed by a high-entropy body.');
  }
  if (/^https?:\/\//.test(s)) push('URL', 'high', 'Starts with a scheme.');
  if (s.length >= 24 && entropy > 4.5) {
    push('random / cryptographic secret', 'medium', `High entropy (${entropy.toFixed(2)} bits/char) over ${new Set(s).size} distinct characters.`);
  }
  if (entropy < 3.2 && s.length > 12) {
    push('natural language or structured text', 'low', 'Low entropy with a wide alphabet usually means human-readable text.');
  }
  if (guesses.length === 0) push('unclassified', 'low', 'No signature matched — inspect the bytes manually.');
  return guesses;
}

function Chip({ label }: { label: string }) {
  return (
    <span
      className="rf-mono inline-block rounded border px-1.5 py-0.5 text-[10.5px] uppercase tracking-wide"
      style={{ borderColor: 'var(--accent)', color: 'var(--accent)' }}
    >
      {label}
    </span>
  );
}

export default function EntropyAnalyser() {
  const [input, setInput] = useState(SAMPLE);

  const analysis = useMemo(() => {
    const s = input;
    const len = s.length;
    const entropy = shannonEntropy(s);
    const counts = new Map<string, number>();
    for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
    const unique = counts.size;
    const classes = {
      lowercase: /[a-z]/.test(s),
      uppercase: /[A-Z]/.test(s),
      digits: /[0-9]/.test(s),
      symbols: /[^a-zA-Z0-9]/.test(s),
    };
    const classCount = Object.values(classes).filter(Boolean).length;
    const repeatedPairs = (() => {
      let repeats = 0;
      for (const c of counts.values()) repeats += c - 1;
      return len ? repeats / len : 0;
    })();
    const keyspace = Math.pow(unique || 1, len);
    const bitsTotal = entropy * len;
    const verdict: 'weak' | 'moderate' | 'strong' =
      bitsTotal < 40 ? 'weak' : bitsTotal < 80 ? 'moderate' : 'strong';
    const frequency = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    return {
      len,
      entropy,
      bitsTotal,
      unique,
      classes,
      classCount,
      repeatedPairs,
      keyspace,
      verdict,
      frequency,
      guesses: len ? classify(s, entropy) : [],
    };
  }, [input]);

  const verdictTone = analysis.verdict === 'strong' ? 'ok' : analysis.verdict === 'moderate' ? 'warn' : 'danger';

  return (
    <>
      <Card title="Input" action={<CopyChip text={input} label="Copy" />}>
        <TextArea
          value={input}
          onChange={setInput}
          rows={4}
          label="Token or secret"
          hint={`${analysis.len} characters`}
          placeholder={SAMPLE}
        />
      </Card>

      <Card title="Metrics">
        <KVTable
          rows={[
            ['Length', `${analysis.len} chars`],
            ['Shannon entropy', `${analysis.entropy.toFixed(3)} bits/char`],
            ['Total entropy', `${analysis.bitsTotal.toFixed(1)} bits`],
            ['Unique characters', `${analysis.unique} of ${analysis.len || 0}`],
            ['Character classes', `${analysis.classCount} / 4 (${Object.entries(analysis.classes).filter(([, v]) => v).map(([k]) => k).join(', ') || 'none'})`],
            ['Repetition ratio', `${(analysis.repeatedPairs * 100).toFixed(1)} %`],
            ['Raw keyspace', analysis.keyspace > 1e12 ? analysis.keyspace.toExponential(2) : analysis.keyspace.toLocaleString('en-GB')],
          ]}
        />
        <div className="mt-4 flex items-center gap-3">
          <span className="text-[12px] text-[var(--text-muted)]">Verdict</span>
          <Chip label={analysis.verdict} />
          <span className="text-[11.5px] text-[var(--text-faint)]">
            thresholds: &lt;40 bits weak, 40–80 moderate, &gt;80 strong
          </span>
        </div>
        <div className="mt-4">
          <Callout tone={verdictTone} title={`${analysis.verdict} entropy`}>
            {analysis.verdict === 'strong'
              ? `${analysis.bitsTotal.toFixed(0)} bits is well past brute-force reach for an offline attacker; the risk moves to reuse and leakage, not guessing.`
              : analysis.verdict === 'moderate'
                ? `${analysis.bitsTotal.toFixed(0)} bits resists casual guessing but falls quickly to a dictionary or rule-based attack if the token is derived from words.`
                : `${analysis.bitsTotal.toFixed(0)} bits is trivially searchable — treat this as a weak secret regardless of how random it looks.`}
          </Callout>
        </div>
      </Card>

      <Card title="What it looks like">
        {analysis.guesses.length === 0 ? (
          <div className="text-[12px] text-[var(--text-faint)]">Enter a token to classify it.</div>
        ) : (
          <KVTable
            rows={analysis.guesses.map((g) => [
              <span key={g.label} className="flex items-center gap-2">
                <Chip label={g.label} />
                <span className="text-[11px] text-[var(--text-faint)]">{g.confidence}</span>
              </span>,
              g.reason,
            ])}
          />
        )}
      </Card>

      <Card title="Character frequency">
        {analysis.frequency.length === 0 ? (
          <div className="text-[12px] text-[var(--text-faint)]">No input.</div>
        ) : (
          <>
            <CodeBlock
              code={analysis.frequency
                .slice(0, 40)
                .map(([ch, n]) => {
                  const bar = '█'.repeat(Math.min(40, Math.round((n / analysis.frequency[0][1]) * 40)));
                  return `${JSON.stringify(ch).padEnd(6)} ${String(n).padStart(4)}  ${bar}`;
                })
                .join('\n')}
              label="Top 40 characters"
              maxHeight={300}
            />
            <div className="mt-3 text-[11.5px] leading-relaxed text-[var(--text-faint)]">
              A flat distribution with every character appearing once is what a random key looks like; a long tail
              with a few dominant characters is what English looks like.
            </div>
          </>
        )}
      </Card>
    </>
  );
}
