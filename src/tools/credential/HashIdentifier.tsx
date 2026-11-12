import { useMemo, useState } from 'react';
import { Callout, Card, CopyChip, DownloadButton, KVTable, SectionTitle, TextArea } from '@/components/ui';

interface Rule {
  id: string;
  label: string;
  regex: RegExp;
  confidence: number;
  hashcat: string;
  command: string;
  note: string;
}

const CMD = (mode: string) => `hashcat -a 0 -m ${mode} hashes.txt words.txt`;

const RULES: Rule[] = [
  { id: 'bcrypt', label: 'bcrypt', regex: /^\$2[abxy]?\$\d{1,2}\$[./A-Za-z0-9]{53}$/, confidence: 99, hashcat: '3200', command: CMD('3200'), note: 'Cost factor is the 2-digit field; 12+ is slow even on GPU' },
  { id: 'argon2id', label: 'Argon2id', regex: /^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/, confidence: 99, hashcat: '—', command: 'john --format=argon2 hashes.txt', note: 'GPU-hostile; John or a CPU cluster is the realistic path' },
  { id: 'scrypt', label: 'scrypt', regex: /^\$scrypt\$[A-Za-z0-9+/.,=]+\$[A-Za-z0-9+/]+$/, confidence: 95, hashcat: '8900', command: CMD('8900'), note: 'N, r, p parameters decide feasibility' },
  { id: 'krb5tgs', label: 'Kerberos TGS-REP (Kerberoast)', regex: /^\$krb5tgs\$\d{1,2}\$/, confidence: 99, hashcat: '13100', command: CMD('13100'), note: 'RC4 etype 23 cracks far faster than AES256 (19700)' },
  { id: 'krb5asrep', label: 'Kerberos AS-REP (AS-REP roast)', regex: /^\$krb5asrep\$\d{1,2}\$/, confidence: 99, hashcat: '18200', command: CMD('18200'), note: 'No pre-auth required on the account' },
  { id: 'pbkdf2', label: 'Django PBKDF2-SHA256', regex: /^pbkdf2_sha256\$\d+\$[A-Za-z0-9]+\$[A-Za-z0-9+/=]+$/, confidence: 98, hashcat: '10000', command: CMD('10000'), note: 'Iteration count is the second field' },
  { id: 'sha512crypt', label: 'sha512crypt', regex: /^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}$/, confidence: 98, hashcat: '1800', command: CMD('1800'), note: 'Linux /etc/shadow default' },
  { id: 'sha256crypt', label: 'sha256crypt', regex: /^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}$/, confidence: 98, hashcat: '7400', command: CMD('7400'), note: 'Older shadow default, still common on RHEL 6' },
  { id: 'md5crypt', label: 'md5crypt', regex: /^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$/, confidence: 98, hashcat: '500', command: CMD('500'), note: 'Practically instant on GPU' },
  { id: 'md5apr1', label: 'Apache APR1-MD5', regex: /^\$apr1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$/, confidence: 97, hashcat: '1600', command: CMD('1600'), note: 'htpasswd default' },
  { id: 'wordpress', label: 'WordPress phpass', regex: /^\$[PH]\$[./A-Za-z0-9]{31}$/, confidence: 97, hashcat: '400', command: CMD('400'), note: '$P$ portable, $H$ older — same mode' },
  { id: 'drupal7', label: 'Drupal 7', regex: /^\$S\$[./A-Za-z0-9]{52}$/, confidence: 93, hashcat: '7900', command: CMD('7900'), note: 'Drupal 8+ uses sha512crypt — look for $6$' },
  { id: 'drupal9', label: 'Drupal 9+ bcrypt', regex: /^\$2y\$\d{2}\$[./A-Za-z0-9]{53}$/, confidence: 80, hashcat: '3200', command: CMD('3200'), note: '$2y$ prefix is PHP-origin bcrypt' },
  { id: 'joomla', label: 'Joomla (bcrypt / md5 prefix)', regex: /^\{SHA256\}[A-Za-z0-9+/=]{44}:[A-Za-z0-9+/=]{1,64}:/, confidence: 90, hashcat: '—', command: 'john --format=joomla', note: 'Salt is embedded after the colon' },
  { id: 'netntlmv2', label: 'NetNTLMv2', regex: /^[^:]+::[A-Za-z0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]+$/, confidence: 96, hashcat: '5600', command: CMD('5600'), note: 'Captured from responder/ntlmrelayx; cannot be relayed, only cracked' },
  { id: 'netntlmv1', label: 'NetNTLMv1', regex: /^[^:]+::[A-Za-z0-9]+:[A-Fa-f0-9]{48}:[A-Fa-f0-9]{48}:[A-Fa-f0-9]{16}$/, confidence: 96, hashcat: '5500', command: CMD('5500'), note: 'Downgrade via ntlmrelayx --remove-mic; crack to NT hash then pass-the-hash' },
  { id: 'mysql41', label: 'MySQL 4.1+', regex: /^\*[A-F0-9]{40}$/, confidence: 95, hashcat: '300', command: CMD('300'), note: 'Double SHA-1, upper hex' },
  { id: 'mysql323', label: 'MySQL 3.23', regex: /^[0-9a-f]{16}$/, confidence: 45, hashcat: '200', command: CMD('200'), note: 'Ambiguous 16-hex — also matches half an MD5' },
  { id: 'postgres', label: 'PostgreSQL md5', regex: /^md5[a-f0-9]{32}$/, confidence: 99, hashcat: '12', command: CMD('12'), note: 'md5(password || username)' },
  { id: 'mssql', label: 'MSSQL 2012+', regex: /^0x0200[A-F0-9]{8}[A-F0-9]{32}[A-F0-9]{32}$/, confidence: 96, hashcat: '1731', command: CMD('1731'), note: 'SHA-512 with a UTF-16 salt' },
  { id: 'oracle11g', label: 'Oracle 11g', regex: /^S:[A-F0-9]{60}$/, confidence: 90, hashcat: '112', command: CMD('112'), note: 'From sys.user$' },
  { id: 'cisco7', label: 'Cisco type 7', regex: /^[0-9]{1,2}[0-9A-F]{4,}$/, confidence: 60, hashcat: '—', command: 'python3 cisco7.py "<value>"', note: 'XOR, not hashing — trivially reversible' },
  { id: 'jwt', label: 'JWT', regex: /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/, confidence: 99, hashcat: '16500', command: CMD('16500'), note: 'HS256 secret recovery; alg=none needs no cracking at all' },
  { id: 'ldap', label: 'LDAP {SSHA}', regex: /^\{SSHA\}[A-Za-z0-9+/=]{28,}$/, confidence: 95, hashcat: '111', command: CMD('111'), note: 'SHA-1 with appended 4-byte salt' },
  { id: 'sha512', label: 'SHA-512', regex: /^[A-Fa-f0-9]{128}$/, confidence: 94, hashcat: '1700', command: CMD('1700'), note: 'Could be a double-SHA-512; try -m 1700 first' },
  { id: 'sha384', label: 'SHA-384', regex: /^[A-Fa-f0-9]{96}$/, confidence: 94, hashcat: '10800', command: CMD('10800'), note: '96 hex chars is also 3 × SHA-256 concatenations' },
  { id: 'sha256', label: 'SHA-256', regex: /^[A-Fa-f0-9]{64}$/, confidence: 94, hashcat: '1400', command: CMD('1400'), note: 'Also the shape of a SHA-256 checksum' },
  { id: 'sha224', label: 'SHA-224', regex: /^[A-Fa-f0-9]{56}$/, confidence: 88, hashcat: '1300', command: CMD('1300'), note: 'Rare outside TLS internals' },
  { id: 'ntlm', label: 'NTLM / NT hash', regex: /^[A-Fa-f0-9]{32}$/, confidence: 72, hashcat: '1000', command: CMD('1000'), note: 'Indistinguishable from MD5 by shape; AD context disambiguates' },
  { id: 'md5', label: 'MD5', regex: /^[A-Fa-f0-9]{32}$/, confidence: 70, hashcat: '0', command: CMD('0'), note: 'Also matches NTLM — 32 hex is 16 raw bytes' },
  { id: 'sha1', label: 'SHA-1', regex: /^[A-Fa-f0-9]{40}$/, confidence: 92, hashcat: '100', command: CMD('100'), note: '40 hex is also a RIPEMD-160 digest' },
];

interface Match {
  rule: Rule;
  confidence: number;
}

function classify(line: string): Match[] {
  const v = line.trim();
  if (!v) return [];
  const hits = RULES.filter((r) => r.regex.test(v)).map((r) => ({ rule: r, confidence: r.confidence }));
  // Shape ambiguity: 32-hex is both MD5 and NTLM; prefer the AD reading for uppercase input.
  if (/^[A-F0-9]{32}$/.test(v)) {
    const ntlm = hits.find((h) => h.rule.id === 'ntlm');
    if (ntlm) ntlm.confidence = 76;
    const md5 = hits.find((h) => h.rule.id === 'md5');
    if (md5) md5.confidence = 66;
  }
  return hits.sort((a, b) => b.confidence - a.confidence);
}

const SAMPLE = `5f4dcc3b5aa765d61d8327deb882cf99
8846f7eaee8fb117ad06bdd830b7586c
$2b$12$KIXQJ1Q0hUpQPU8Y9y6lUeQ0nZ0t0k9Yx1kQ1Yh2m3n4o5p6q7r8s
$6$rounds=5000$abcdefgh$1J5pR9Yf4zQ3sT1uV2wX3yZ4aB5cD6eF7gH8iJ9kL0mN1oP2qR3sT4uV5wX6yZ7aB8cD9eF0gH1iJ2kL3mN
pbkdf2_sha256$1200000$c2FsdHNhbHQ$aGVsbG93b3JsZGhhc2h2YWx1ZQ==
$krb5tgs$23$*svc_sql$CORP.EXAMPLE.COM$cifs/sql.example.com*$a1b2c3d4e5f6`;

export default function HashIdentifier() {
  const [input, setInput] = useState(SAMPLE);

  const rows = useMemo(() => {
    return input
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const matches = classify(line);
        return { line, best: matches[0], rest: matches.slice(1) };
      });
  }, [input]);

  const resolved = rows.filter((r) => r.best).length;

  const report = useMemo(
    () =>
      rows
        .map((r) =>
          r.best
            ? `${r.line}\n  → ${r.best.rule.label} (${r.best.confidence}%) · hashcat ${r.best.rule.hashcat}\n  ${r.best.rule.command}`
            : `${r.line}\n  → no match`,
        )
        .join('\n\n'),
    [rows],
  );

  return (
    <>
      <Card
        title="Hashes"
        action={<DownloadButton text={report} filename="hash-identification.txt" label="Download report" />}
      >
        <TextArea
          label="Paste one or many hashes (one per line)"
          value={input}
          onChange={setInput}
          rows={8}
          hint={`${rows.length} line(s) · ${resolved} identified`}
        />
      </Card>

      <Card title="Identification">
        {rows.length === 0 ? (
          <Callout tone="info" title="Nothing to identify">
            Paste a hash — or a whole dump — one per line. Shadow files and Kerberos output work line-for-line.
          </Callout>
        ) : (
          <div className="space-y-2">
            {rows.map((r, idx) => (
              <div key={`${r.line}-${idx}`} className="rounded border border-[var(--card-border)] px-3 py-2.5">
                <div className="mb-1.5 flex items-start justify-between gap-3">
                  <code className="rf-mono text-[11.5px] break-all text-[var(--text-muted)]">{r.line}</code>
                  {r.best && (
                    <span
                      className="shrink-0 rounded px-1.5 py-0.5 text-[10.5px] font-semibold"
                      style={{
                        color: r.best.confidence >= 90 ? 'var(--ok)' : r.best.confidence >= 70 ? 'var(--warn)' : 'var(--accent)',
                        background: 'var(--neutral-btn)',
                      }}
                    >
                      {r.best.confidence}% · {r.best.rule.hashcat.startsWith('-') ? r.best.rule.hashcat : r.best.rule.hashcat}
                    </span>
                  )}
                </div>
                {r.best ? (
                  <>
                    <div className="text-[13px] font-medium text-[var(--text)]">{r.best.rule.label}</div>
                    <div className="mt-0.5 text-[11.5px] leading-snug text-[var(--text-muted)]">{r.best.rule.note}</div>
                    <div className="mt-1.5 flex flex-wrap items-center gap-2">
                      <CopyChip text={r.best.rule.command} label={r.best.rule.command} />
                    </div>
                    {r.rest.length > 0 && (
                      <div className="mt-2 text-[11.5px] text-[var(--text-faint)]">
                        Runner-ups:{' '}
                        {r.rest
                          .slice(0, 4)
                          .map((m) => `${m.rule.label} (${m.confidence}%, ${m.rule.hashcat})`)
                          .join(' · ')}
                      </div>
                    )}
                  </>
                ) : (
                  <div className="text-[12px] text-[var(--accent)]">
                    No structural match — check for truncation, a missing salt field, or an encoding wrapper (base64, hex
                    of hex).
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="Algorithm reference">
        <SectionTitle right={<span className="text-[11.5px] text-[var(--text-faint)]">{RULES.length} signatures</span>}>
          Regex, mode and the note that matters
        </SectionTitle>
        <KVTable
          rows={RULES.slice(0, 14).map((r) => [
            r.label,
            <>
              <span className="rf-mono">{r.hashcat}</span> — {r.note}
            </>,
          ])}
        />
        <div className="mt-4">
          <Callout tone="warn" title="Shape is not proof">
            32 hex characters is MD5, NTLM or half of something else. Confirm with context: a shadow file entry, an AD
            hash dump, or a known-plaintext test are the only real confirmations.
          </Callout>
        </div>
      </Card>
    </>
  );
}
