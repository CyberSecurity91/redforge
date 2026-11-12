import { useMemo, useState } from 'react';
import { Callout, Card, CopyChip, KVTable, OutputBlock, SectionTitle, TextArea } from '@/components/ui';
import { sha256Hex, utf8ToBytes } from '@/lib/crypto';
import { bytesFromBase64 } from '@/lib/bytes';
import { pemBody } from '@/lib/encoding';

/** Pull every UTF8String / PrintableString / IA5String run out of the DER body. */
function extractStrings(der: Uint8Array): string[] {
  const out: string[] = [];
  let run = '';
  const flush = () => {
    if (run.trim().length >= 2) out.push(run.trim());
    run = '';
  };
  for (const b of der) {
    if (b >= 0x20 && b <= 0x7e) run += String.fromCharCode(b);
    else flush();
  }
  flush();
  return out;
}

const DATE_RE =
  /\b(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z\b|\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+GMT)\b/g;

/** UTCTime (YYMMDDHHMMSSZ) or GeneralisedTime (YYYYMMDDHHMMSSZ) → ISO-ish string. */
function decodeAsn1Date(token: string): string {
  const m = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(token);
  if (!m) return token;
  let year = Number(m[1]);
  if (m[1].length === 2) year += year < 50 ? 2000 : 1900;
  const iso = `${year}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] ?? '00'}Z`;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? iso : `${iso}`;
}

export default function CertificateInspector() {
  const [pem, setPem] = useState('');

  const analysis = useMemo(() => {
    const text = pem.trim();
    if (!text) return null;
    const body = pemBody(text);
    let der: Uint8Array;
    try {
      der = bytesFromBase64(body);
    } catch {
      return { error: 'Could not base64-decode the PEM body — check for truncated or line-wrapped armour.' } as const;
    }
    if (der.length < 32) return { error: 'DER body is too short to be a certificate.' } as const;

    const raw = Array.from(der, (b) => String.fromCharCode(b)).join('');
    const strings = extractStrings(der);

    // Common names: the CN OID is 2.5.4.3; the label follows the OID bytes.
    const cns: string[] = [];
    for (let i = 0; i < strings.length; i++) {
      const s = strings[i];
      if (s === 'commonName' || s === 'CN') {
        const next = strings[i + 1];
        if (next && next.length <= 128 && !/^(organizationName|organizationalUnitName|countryName)$/.test(next)) cns.push(next);
      }
    }

    const sans = Array.from(new Set(strings.filter((s) => /^(\*?[a-z0-9-]+\.)+[a-z]{2,}$/i.test(s) || /^\d{1,3}(\.\d{1,3}){3}$/.test(s))));
    const dates = Array.from(raw.matchAll(DATE_RE), (m) => decodeAsn1Date(m[0])).filter(Boolean);
    const uniqueDates = Array.from(new Set(dates));

    const oids: string[] = Array.from(new Set(raw.match(/\b(2\.5\.4\.\d{1,3}|1\.2\.840\.113549\.1\.1\.\d{1,2}|1\.3\.6\.1\.5\.5\.7\.3\.\d)\b/g) ?? []));
    const keyAlgo = raw.includes('\x06\x09*\x86H\x86\xf7\r\x01\x01\x0b') || strings.some((s) => s.includes('sha256WithRSAEncryption'))
      ? 'RSA (sha256WithRSAEncryption hint)'
      : strings.some((s) => /ecdsa|ECDSA/.test(s))
        ? 'ECDSA'
        : strings.some((s) => /ed25519|EdDSA/i.test(s))
          ? 'Ed25519'
          : 'undetermined — heuristic only';
    const curveHint = strings.find((s) => /^(prime256v1|secp384r1|secp521r1)$/.test(s)) ?? '';

    // Serial: the integer immediately after the tbsCertificate SEQUENCE header + version tags is
    // awkward to locate, so read it from the heuristic: the longest 16-40 char hex run in the DER.
    const serialHint = (raw.match(/[0-9a-f]{16,40}/g) ?? [''])[0] ?? '';

    const kinds = new Set<string>();
    for (const s of strings) {
      if (/^sha(1|256|384|512)With/.test(s)) kinds.add('signature algorithm');
      if (/^(RSASSA-PSS|ecdsa-with-SHA)/.test(s)) kinds.add('signature algorithm');
    }

    return {
      error: null,
      fingerprint: sha256Hex(der),
      size: der.length,
      cns: Array.from(new Set(cns)),
      sans,
      dates: uniqueDates,
      oids,
      keyAlgo,
      curveHint,
      serialHint,
      notBefore: uniqueDates[0] ?? '',
      notAfter: uniqueDates[1] ?? '',
      strings: strings.slice(0, 40),
      signatureHints: Array.from(kinds),
    } as const;
  }, [pem]);

  const opensslCmd = useMemo(() => {
    if (!analysis || analysis.error) return '';
    return [
      '# DER already in hand:',
      'openssl x509 -inform DER -in cert.der -text -noout',
      '# From a live endpoint, including the SANs:',
      'echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null | openssl x509 -noout -text',
      '# Subject alternative names only:',
      'openssl x509 -in cert.pem -noout -ext subjectAltName',
      '# Fingerprint (match against the SHA-256 above):',
      'openssl x509 -in cert.pem -noout -fingerprint -sha256',
    ].join('\n');
  }, [analysis]);

  return (
    <>
      <Card title="Certificate">
        <TextArea
          label="PEM or base64 DER"
          hint="Paste the block including the BEGIN/END armour — the tool strips it"
          value={pem}
          onChange={setPem}
          rows={10}
          placeholder={'-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----'}
        />
      </Card>

      {!analysis && (
        <Card title="Result">
          <Callout tone="info" title="Waiting for input">
            Paste a PEM certificate to extract names, validity and fingerprint.
          </Callout>
        </Card>
      )}

      {analysis?.error && (
        <Card title="Result">
          <Callout tone="warn" title="Parse failed">
            {analysis.error}
          </Callout>
        </Card>
      )}

      {analysis && !analysis.error && (
        <>
          <Card title="Fields">
            <KVTable
              rows={[
                ['SHA-256 fingerprint', analysis.fingerprint],
                ['DER size', `${analysis.size} bytes`],
                ['Common name(s)', analysis.cns.length ? analysis.cns.join(', ') : 'not detected'],
                ['Not before', analysis.notBefore || 'not detected'],
                ['Not after', analysis.notAfter || 'not detected'],
                ['Key algorithm', analysis.keyAlgo],
                ['Named curve', analysis.curveHint || '—'],
                ['Serial (heuristic)', analysis.serialHint || 'not detected'],
                ['OIDs seen', analysis.oids.length ? analysis.oids.join(', ') : '—'],
              ]}
            />
          </Card>

          <Card
            title="Subject alternative names"
            action={<CopyChip text={analysis.sans.join('\n')} label="Copy all SANs" />}
          >
            {analysis.sans.length === 0 ? (
              <Callout tone="warn" title="No SANs found">
                The string scan found no DNS names. Either the certificate has none or it is wrapped in a format the
                heuristic does not read.
              </Callout>
            ) : (
              <div className="flex flex-wrap gap-2">
                {analysis.sans.map((san) => (
                  <CopyChip key={san} text={san} />
                ))}
              </div>
            )}
            <div className="mt-4">
              <SectionTitle>Printable strings (first 40)</SectionTitle>
              <OutputBlock value={analysis.strings.join('\n')} rows={8} label="Strings" />
            </div>
          </Card>

          <Card title="Equivalent openssl">
            <OutputBlock value={opensslCmd} rows={8} label="openssl commands" />
            <div className="mt-4">
              <Callout tone="warn" title="Heuristic parse">
                This is string extraction over the DER bytes, not a full ASN.1 walk: dates come from the first two
                UTCTime/GeneralisedTime runs, and the serial is the longest hex-looking run. Confirm anything that
                matters with <span className="rf-mono">openssl x509 -text</span> before it goes in a report.
              </Callout>
            </div>
          </Card>
        </>
      )}
    </>
  );
}
