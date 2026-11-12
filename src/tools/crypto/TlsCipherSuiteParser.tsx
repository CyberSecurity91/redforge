import { useMemo, useState } from 'react';
import { Callout, Card, CodeBlock, KVTable, OutputBlock, SearchInput, Select, TextArea } from '@/components/ui';
import { DEFAULT_TARGET } from '@/tools/registry';

/**
 * TLS cipher-suite parser. The dictionary is hand-curated from the IANA TLS
 * registry and OpenSSL's naming: the parser works on the name's structure and
 * the lookup table, never on the network, so the verdict for a suite is stable.
 */

type Grading = 'good' | 'warn' | 'fail' | 'unknown';

interface Suite {
  id: string;
  iana: string;
  ossl: string;
  version: string;
  kx: string;
  auth: string;
  enc: string;
  mode: string;
  mac: string;
  bits: number;
  fs: boolean;
  aead: boolean;
  grade: Grading;
  note: string;
}

const S = (
  id: string,
  iana: string,
  ossl: string,
  version: string,
  kx: string,
  auth: string,
  enc: string,
  mode: string,
  mac: string,
  bits: number,
  fs: boolean,
  aead: boolean,
  grade: Grading,
  note: string,
): Suite => ({ id, iana, ossl, version, kx, auth, enc, mode, mac, bits, fs, aead, grade, note });

const SUITES: Suite[] = [
  S('0x13 01', 'TLS_AES_256_GCM_SHA384', 'TLS_AES_256_GCM_SHA384', 'TLS 1.3', 'any', 'cert', 'AES', 'GCM', 'SHA-384', 256, true, true, 'good', 'Default first choice for TLS 1.3 clients.'),
  S('0x13 02', 'TLS_AES_128_GCM_SHA256', 'TLS_AES_128_GCM_SHA256', 'TLS 1.3', 'any', 'cert', 'AES', 'GCM', 'SHA-256', 128, true, true, 'good', 'Lower-latency AES choice; still AEAD with a certificate key exchange.'),
  S('0x13 03', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS 1.3', 'any', 'cert', 'ChaCha20', 'Poly1305', 'SHA-256', 256, true, true, 'good', 'Preferred on CPUs without AES-NI; constant-time in software.'),
  S('0x13 04', 'TLS_AES_128_CCM_SHA256', 'TLS_AES_128_CCM_SHA256', 'TLS 1.3', 'any', 'cert', 'AES', 'CCM', 'SHA-256', 128, true, true, 'good', 'IoT-oriented AEAD; rarely negotiated outside embedded stacks.'),
  S('0x13 05', 'TLS_AES_128_CCM_8_SHA256', 'TLS_AES_128_CCM_8_SHA256', 'TLS 1.3', 'any', 'cert', 'AES', 'CCM-8', 'SHA-256', 128, true, true, 'warn', 'Eight-byte tag — a shorter forgery margin than the rest of TLS 1.3.'),
  S('0xc0 2b', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'ECDHE-ECDSA-AES128-GCM-SHA256', 'TLS 1.2', 'ECDHE', 'ECDSA', 'AES', 'GCM', 'SHA-256', 128, true, true, 'good', 'Modern default pair with an ECDSA certificate.'),
  S('0xc0 2c', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'ECDHE-ECDSA-AES256-GCM-SHA384', 'TLS 1.2', 'ECDHE', 'ECDSA', 'AES', 'GCM', 'SHA-384', 256, true, true, 'good', 'Same as above with a 256-bit key.'),
  S('0xc0 2f', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'TLS 1.2', 'ECDHE', 'RSA', 'AES', 'GCM', 'SHA-256', 128, true, true, 'good', 'The most common TLS 1.2 suite on the public web.'),
  S('0xc0 30', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'ECDHE-RSA-AES256-GCM-SHA384', 'TLS 1.2', 'ECDHE', 'RSA', 'AES', 'GCM', 'SHA-384', 256, true, true, 'good', 'Same, 256-bit AES.'),
  S('0xcc a8', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'ECDHE-RSA-CHACHA20-POLY1305', 'TLS 1.2', 'ECDHE', 'RSA', 'ChaCha20', 'Poly1305', 'SHA-256', 256, true, true, 'good', 'Software constant-time AEAD for x86 without AES-NI.'),
  S('0xcc a9', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'ECDHE-ECDSA-CHACHA20-POLY1305', 'TLS 1.2', 'ECDHE', 'ECDSA', 'ChaCha20', 'Poly1305', 'SHA-256', 256, true, true, 'good', 'ECDSA variant of the above.'),
  S('0xcc aa', 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'DHE-RSA-CHACHA20-POLY1305', 'TLS 1.2', 'DHE', 'RSA', 'ChaCha20', 'Poly1305', 'SHA-256', 256, true, true, 'warn', 'Finite-field DHE — inherits the 1024-bit group weakness when misconfigured.'),
  S('0x00 9c', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'AES128-GCM-SHA256', 'TLS 1.2', 'RSA', 'RSA', 'AES', 'GCM', 'SHA-256', 128, false, true, 'fail', 'No forward secrecy: one captured RSA key decrypts all recorded traffic.'),
  S('0x00 9d', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'AES256-GCM-SHA384', 'TLS 1.2', 'RSA', 'RSA', 'AES', 'GCM', 'SHA-384', 256, false, true, 'fail', 'Same as above with 256-bit AES.'),
  S('0x00 9e', 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'DHE-RSA-AES128-GCM-SHA256', 'TLS 1.2', 'DHE', 'RSA', 'AES', 'GCM', 'SHA-256', 128, true, true, 'warn', 'Secure only while the DH group is at least 2048 bits.'),
  S('0x00 9f', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', 'DHE-RSA-AES256-GCM-SHA384', 'TLS 1.2', 'DHE', 'RSA', 'AES', 'GCM', 'SHA-384', 256, true, true, 'warn', 'Same DH-group caveat.'),
  S('0xc0 09', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'ECDHE-ECDSA-AES128-SHA', 'TLS 1.0', 'ECDHE', 'ECDSA', 'AES', 'CBC', 'SHA-1', 128, true, false, 'fail', 'CBC + SHA-1: MAC-then-pad ordering and a broken PRF hash.'),
  S('0xc0 0a', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'ECDHE-ECDSA-AES256-SHA', 'TLS 1.0', 'ECDHE', 'ECDSA', 'AES', 'CBC', 'SHA-1', 256, true, false, 'fail', 'Same weaknesses, larger key does not help the mode.'),
  S('0xc0 13', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'ECDHE-RSA-AES128-SHA', 'TLS 1.0', 'ECDHE', 'RSA', 'AES', 'CBC', 'SHA-1', 128, true, false, 'fail', 'Lucky13-style padding oracle surface.'),
  S('0xc0 14', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'ECDHE-RSA-AES256-SHA', 'TLS 1.0', 'ECDHE', 'RSA', 'AES', 'CBC', 'SHA-1', 256, true, false, 'fail', 'Same as above.'),
  S('0xc0 23', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'ECDHE-ECDSA-AES128-SHA256', 'TLS 1.2', 'ECDHE', 'ECDSA', 'AES', 'CBC', 'SHA-256', 128, true, false, 'warn', 'SHA-1 is gone but CBC padding remains.'),
  S('0xc0 27', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'ECDHE-RSA-AES128-SHA256', 'TLS 1.2', 'ECDHE', 'RSA', 'AES', 'CBC', 'SHA-256', 128, true, false, 'warn', 'Best-case CBC: still vulnerable to padding-oracle pressure.'),
  S('0xc0 28', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'ECDHE-RSA-AES256-SHA384', 'TLS 1.2', 'ECDHE', 'RSA', 'AES', 'CBC', 'SHA-384', 256, true, false, 'warn', 'CBC with a strong PRF; treat as compatibility-only.'),
  S('0x00 2f', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'AES128-SHA', 'TLS 1.0', 'RSA', 'RSA', 'AES', 'CBC', 'SHA-1', 128, false, false, 'fail', 'No PFS, CBC, SHA-1: the triple of what to remove first.'),
  S('0x00 35', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'AES256-SHA', 'TLS 1.0', 'RSA', 'RSA', 'AES', 'CBC', 'SHA-1', 256, false, false, 'fail', 'Same as above.'),
  S('0x00 3c', 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'AES128-SHA256', 'TLS 1.2', 'RSA', 'RSA', 'AES', 'CBC', 'SHA-256', 128, false, false, 'fail', 'Static RSA means no forward secrecy regardless of the PRF.'),
  S('0x00 3d', 'TLS_RSA_WITH_AES_256_CBC_SHA256', 'AES256-SHA256', 'TLS 1.2', 'RSA', 'RSA', 'AES', 'CBC', 'SHA-256', 256, false, false, 'fail', 'Same as above.'),
  S('0x00 05', 'TLS_RSA_WITH_RC4_128_SHA', 'RC4-SHA', 'TLS 1.0', 'RSA', 'RSA', 'RC4', 'stream', 'SHA-1', 128, false, false, 'fail', 'RC4 biases are exploitable from ~2^26 captures; browsers removed it in 2016.'),
  S('0x00 04', 'TLS_RSA_WITH_RC4_128_MD5', 'RC4-MD5', 'TLS 1.0', 'RSA', 'RSA', 'RC4', 'stream', 'MD5', 128, false, false, 'fail', 'RC4 plus a broken MAC.'),
  S('0xc0 07', 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'ECDHE-ECDSA-RC4-SHA', 'TLS 1.0', 'ECDHE', 'ECDSA', 'RC4', 'stream', 'SHA-1', 128, true, false, 'fail', 'Forward secrecy does not rescue a broken stream cipher.'),
  S('0xc0 11', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'ECDHE-RSA-RC4-SHA', 'TLS 1.0', 'ECDHE', 'RSA', 'RC4', 'stream', 'SHA-1', 128, true, false, 'fail', 'Same as above.'),
  S('0xc0 08', 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA', 'ECDHE-ECDSA-DES-CBC3-SHA', 'TLS 1.0', 'ECDHE', 'ECDSA', '3DES', 'CBC', 'SHA-1', 112, true, false, 'fail', '64-bit block: SWEET32 birthday collisions at ~2^32 records.'),
  S('0xc0 12', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'ECDHE-RSA-DES-CBC3-SHA', 'TLS 1.0', 'ECDHE', 'RSA', '3DES', 'CBC', 'SHA-1', 112, true, false, 'fail', 'Same as above.'),
  S('0x00 0a', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'DES-CBC3-SHA', 'TLS 1.0', 'RSA', 'RSA', '3DES', 'CBC', 'SHA-1', 112, false, false, 'fail', 'SWEET32 plus no PFS.'),
  S('0x00 16', 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA', 'DHE-RSA-DES-CBC3-SHA', 'TLS 1.0', 'DHE', 'RSA', '3DES', 'CBC', 'SHA-1', 112, true, false, 'fail', 'DHE does not fix a 64-bit block cipher.'),
  S('0xc0 78', 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'ECDHE-RSA-CAMELLIA128-SHA256', 'TLS 1.0', 'DHE', 'RSA', '3DES', 'CBC', 'SHA-1', 112, true, false, 'fail', 'Camellia block cipher in CBC mode — no AEAD, compatibility only.'),
  S('0x00 0b', 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA', 'DH-DSS-DES-CBC3-SHA', 'TLS 1.0', 'DH', 'DSS', '3DES', 'CBC', 'SHA-1', 112, false, false, 'fail', 'Static DH with an obsolete certificate type.'),
  S('0xc0 18', 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256', 'ECDH-ECDSA-AES128-GCM-SHA256', 'TLS 1.2', 'ECDH', 'ECDSA', 'AES', 'GCM', 'SHA-256', 128, false, true, 'fail', 'Static ECDH: the private key is baked into the certificate, so no PFS.'),
  S('0xc0 19', 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384', 'ECDH-ECDSA-AES256-GCM-SHA384', 'TLS 1.2', 'ECDH', 'ECDSA', 'AES', 'GCM', 'SHA-384', 256, false, true, 'fail', 'Same as above.'),
  S('0xc0 1e', 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256', 'ECDH-RSA-AES128-GCM-SHA256', 'TLS 1.2', 'ECDH', 'RSA', 'AES', 'GCM', 'SHA-256', 128, false, true, 'fail', 'Same as above.'),
  S('0xc0 1f', 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384', 'ECDH-RSA-AES256-GCM-SHA384', 'TLS 1.2', 'ECDH', 'RSA', 'AES', 'GCM', 'SHA-384', 256, false, true, 'fail', 'Same as above.'),
  S('0xc0 ac', 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM', 'ECDHE-ECDSA-AES128-CCM', 'TLS 1.2', 'ECDHE', 'ECDSA', 'AES', 'CCM', 'SHA-256', 128, true, true, 'warn', 'AEAD but with an eight-byte tag in most stacks — check the tag length.'),
  S('0xc0 24', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', 'ECDHE-ECDSA-AES256-SHA384', 'TLS 1.2', 'ECDHE', 'ECDSA', 'AES', 'CBC', 'SHA-384', 256, true, false, 'warn', 'CBC with a strong PRF.'),
  S('0xc0 2e', 'TLS_RSA_WITH_AES_128_CCM', 'AES128-CCM', 'TLS 1.2', 'RSA', 'RSA', 'AES', 'CCM', 'SHA-256', 128, false, true, 'fail', 'AEAD, but static RSA key transport.'),
  S('0x00 03', 'TLS_RSA_EXPORT_WITH_RC4_40_MD5', 'EXP-RC4-MD5', 'TLS 1.0', 'RSA', 'RSA', 'RC4', 'stream', 'MD5', 40, false, false, 'fail', 'EXPORT grade: 40 bits, breakable in minutes (FREAK).'),
  S('0x00 06', 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5', 'EXP-RC2-CBC-MD5', 'TLS 1.0', 'RSA', 'RSA', 'RC2', 'CBC', 'MD5', 40, false, false, 'fail', 'EXPORT RC2 — retained only for scanner signatures.'),
  S('0x00 09', 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA', 'EXP1024-DES-CBC-SHA', 'TLS 1.0', 'RSA', 'RSA', 'DES', 'CBC', 'SHA-1', 56, false, false, 'fail', '56-bit DES with an export key.'),
  S('0x00 08', 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA', 'EXP-DES-CBC-SHA', 'TLS 1.0', 'RSA', 'RSA', 'DES', 'CBC', 'SHA-1', 40, false, false, 'fail', '40-bit DES export suite.'),
  S('0x00 17', 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA', 'ADH-EXP-DES-CBC-SHA', 'TLS 1.0', 'DH-anon', 'none', 'DES', 'CBC', 'SHA-1', 40, false, false, 'fail', 'Anonymous: no authentication and an export key.'),
  S('0x00 1b', 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA', 'ADH-DES-CBC3-SHA', 'TLS 1.0', 'DH-anon', 'none', '3DES', 'CBC', 'SHA-1', 112, false, false, 'fail', 'Anonymous DH: any on-path attacker can impersonate the server.'),
  S('0x00 3b', 'TLS_RSA_WITH_NULL_SHA256', 'NULL-SHA256', 'TLS 1.2', 'RSA', 'RSA', 'none', 'none', 'SHA-256', 0, false, false, 'fail', 'NULL encryption: the plaintext is on the wire with a MAC only.'),
  S('0x00 02', 'TLS_RSA_WITH_NULL_SHA', 'NULL-SHA', 'TLS 1.0', 'RSA', 'RSA', 'NULL', 'none', 'SHA-1', 0, false, false, 'fail', 'NULL encryption plus SHA-1.'),
  S('0x00 01', 'TLS_RSA_WITH_NULL_MD5', 'NULL-MD5', 'TLS 1.0', 'RSA', 'RSA', 'NULL', 'none', 'MD5', 0, false, false, 'fail', 'The worst suite in the registry.'),
  S('0x00 ff', 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV', 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV', 'any', 'none', 'none', 'none', 'none', 'none', 0, false, false, 'unknown', 'Signalling value, not a real suite — it requests secure renegotiation.'),
  S('0x56 00', 'TLS_FALLBACK_SCSV', 'TLS_FALLBACK_SCSV', 'any', 'none', 'none', 'none', 'none', 'none', 0, false, false, 'unknown', 'Signalling value: marks a deliberate downgrade so a server can refuse it.'),
  S('0x00 33', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 'DHE-RSA-AES128-SHA', 'TLS 1.0', 'DHE', 'RSA', 'AES', 'CBC', 'SHA-1', 128, true, false, 'fail', 'CBC + SHA-1 over finite-field DH.'),
  S('0x00 39', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 'DHE-RSA-AES256-SHA', 'TLS 1.0', 'DHE', 'RSA', 'AES', 'CBC', 'SHA-1', 256, true, false, 'fail', 'Same as above.'),
  S('0xc0 2d', 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM', 'ECDHE-ECDSA-AES256-CCM', 'TLS 1.2', 'ECDHE', 'ECDSA', 'AES', 'CCM', 'SHA-256', 256, true, true, 'warn', 'AEAD variant limited to embedded deployments.'),
];

const GRADING_COLOR: Record<Grading, string> = {
  good: 'var(--ok)',
  warn: 'var(--warn)',
  fail: 'var(--accent)',
  unknown: 'var(--text-muted)',
};

/** Normalise any accepted spelling of a suite to the IANA name. */
function canonical(token: string, list: Suite[]): Suite | null {
  const t = token.trim().replace(/^["',]+|["',]+$/g, '');
  if (!t) return null;
  const hex = t.replace(/^0x/i, '').replace(/[\s:_-]/g, '').toLowerCase();
  if (/^[0-9a-f]{4}$/.test(hex)) {
    const byId = list.find((s) => s.id.replace(/\s/g, '').toLowerCase().replace(/^0x/, '') === hex);
    if (byId) return byId;
  }
  // Currency: OpenSSL writes ECDHE-RSA-AES128-GCM-SHA256, the registry
  // writes TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 and IANA drops the "WITH".
  const squash = (v: string) => v.toUpperCase().replace(/^TLS_/, '').replace(/_WITH_|_/g, '-').replace(/AES-?(\d+)/g, 'AES$1');
  const key = squash(t);
  const upper = t.toUpperCase();
  const ianaHit = list.find((s) => s.iana.toUpperCase() === upper);
  if (ianaHit) return ianaHit;
  const osslHit = list.find((s) => s.ossl.toUpperCase() === upper);
  if (osslHit) return osslHit;
  const squashed = list.find((s) => squash(s.iana) === key || squash(s.ossl) === key);
  if (squashed) return squashed;
  return list.find((s) => s.iana.toUpperCase().endsWith(upper) || s.ossl.toUpperCase().endsWith(upper)) ?? null;
}

/** Parse structure out of an unknown OpenSSL-style name so it still gets a verdict. */
function structural(name: string): Suite | null {
  const n = name.toUpperCase().replace(/^TLS_/, '');
  if (!n.includes('_WITH_') && !n.includes('-')) return null;
  const body = (n.includes('_WITH_') ? n.split('_WITH_')[1] : n).replace(/-/g, '_');
  const parts = body.split('_').filter(Boolean);
  if (parts.length < 3) return null;
  const encPart = parts.find((p) => /^(AES|ARIA|CAMELLIA|CHACHA|RC4|RC2|3DES|DES|SEED|SM4|NULL)/.test(p)) ?? '';
  const macPart = parts[parts.length - 1];
  const mode = /GCM/.test(encPart) ? 'GCM' : /CCM/.test(encPart) ? 'CCM' : /CBC/.test(encPart) ? 'CBC' : /RC4/.test(encPart) ? 'stream' : 'none';
  const bits = /256/.test(encPart) ? 256 : /128/.test(encPart) ? 128 : /40/.test(encPart) ? 40 : /3DES/.test(encPart) ? 112 : /DES/.test(encPart) ? 56 : 0;
  const kx = /ECDHE/.test(n) ? 'ECDHE' : /^DHE/.test(n) ? 'DHE' : /ECDH/.test(n) ? 'ECDH' : /RSA_WITH|^RSA/.test(n) ? 'RSA' : 'unknown';
  const auth = /ECDSA/.test(n) ? 'ECDSA' : /RSA/.test(n) ? 'RSA' : /DSS/.test(n) ? 'DSS' : 'unknown';
  const bad = /RC4|3DES|DES|RC2|NULL|EXPORT|anon/i.test(n);
  const warn = /CBC|SHA$|-SHA$/i.test(n);
  return {
    id: '—',
    iana: name.trim().toUpperCase(),
    ossl: name.trim(),
    version: 'unknown',
    kx,
    auth,
    enc: encPart || 'unknown',
    mode,
    mac: macPart,
    bits,
    fs: kx === 'ECDHE' || kx === 'DHE',
    aead: mode === 'GCM' || mode === 'CCM' || /POLY1305/.test(n),
    grade: bad ? 'fail' : warn ? 'warn' : 'good',
    note: 'Not in the built-in dictionary — fields derived from the name structure only.',
  };
}

export default function TlsCipherSuiteParser() {
  const [input, setText] = useState('TLS_AES_256_GCM_SHA384\n0x1302\nTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\nECDHE-RSA-AES256-SHA\nTLS_RSA_WITH_RC4_128_SHA');
  const [filter, setFilter] = useState('');

  const parsed = useMemo(() => {
    const tokens = input.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean);
    const unmatched: string[] = [];
    const found: Suite[] = [];
    const seen = new Set<string>();
    for (const token of tokens) {
      const hit = canonical(token, SUITES) ?? structural(token);
      if (!hit) {
        unmatched.push(token);
        continue;
      }
      const key = `${hit.iana}|${hit.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      found.push(hit);
    }
    const weak = found.filter((s) => s.grade === 'fail');
    const warned = found.filter((s) => s.grade === 'warn');
    const withFs = found.filter((s) => s.fs);
    const versions = Array.from(new Set(found.map((s) => s.version))).sort();
    return { found, unmatched, weak, warned, withFs, versions };
  }, [input]);

  const summary = useMemo(() => {
    const { found, weak, withFs } = parsed;
    if (!found.length) return 'No suites parsed yet — paste one name or 0x code per line.';
    const fsClause = withFs.length === 0 ? 'no forward secrecy' : `${withFs.length} of ${found.length} with forward secrecy`;
    const weakClause = weak.length ? `${weak.length} weak` : 'none weak';
    return `${found.length} suite${found.length === 1 ? '' : 's'}, ${weakClause}, ${fsClause}.`;
  }, [parsed]);

  const osslCmd = useMemo(() => {
    const names = parsed.found.map((s) => s.ossl).filter((n) => !/SCSV/.test(n));
    const colon = names.join(':');
    return [
      `# reproduce the negotiated list on a live endpoint`,
      `openssl ciphers -v '${colon || 'HIGH:!aNULL:!MD5'}' | column -t`,
      '',
      `# only what the server actually offers (TLS 1.2 and below)`,
      `openssl s_client -connect ${DEFAULT_TARGET}:443 -tls1_2 </dev/null 2>/dev/null | grep -i cipher`,
      '',
      `# TLS 1.3 suites are printed separately — they are not tunable via ciphers(1)`,
      `openssl s_client -connect ${DEFAULT_TARGET}:443 -tls1_3 </dev/null 2>/dev/null | grep -i cipher`,
    ].join('\n');
  }, [parsed.found]);

  const nmapCmd = useMemo(
    () =>
      [
        `nmap --script ssl-enum-ciphers -p 443 ${DEFAULT_TARGET}`,
        `# grade-only view`,
        `nmap -Pn -p 443 --script ssl-enum-ciphers ${DEFAULT_TARGET} | sed -n '/ssl-enum-ciphers/,/Service Info/p'`,
      ].join('\n'),
    [],
  );

  const dictionary = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const list = SUITES.filter((s) => {
      if (!q) return true;
      return (
        s.iana.toLowerCase().includes(q) ||
        s.ossl.toLowerCase().includes(q) ||
        s.version.toLowerCase().includes(q) ||
        s.enc.toLowerCase().includes(q) ||
        s.grade.includes(q)
      );
    });
    const chosen = new Set(parsed.found.map((s) => s.iana));
    return { list: list.slice(0, 40), total: list.length, chosen };
  }, [filter, parsed.found]);

  return (
    <>
      <Card
        title="Suites to parse"
        action={<span className="text-[12px] text-[var(--text-muted)]">{summary}</span>}
      >
        <TextArea
          label="One IANA name, OpenSSL name or 0x code per line"
          value={input}
          onChange={setText}
          rows={6}
          placeholder={'TLS_AES_256_GCM_SHA384\n0x1301\nECDHE-RSA-AES128-GCM-SHA256'}
          hint="Duplicates collapse; unknown names are parsed from their structure rather than dropped."
        />
        {parsed.unmatched.length > 0 && (
          <div className="mt-3 space-y-1">
            {parsed.unmatched.map((t) => (
              <div key={t} className="text-[11.5px] text-[var(--warn)]">
                ? {t} — not recognised, not even structurally
              </div>
            ))}
          </div>
        )}
        <div className="mt-4">
          <Callout tone={parsed.weak.length ? 'danger' : parsed.warned.length ? 'warn' : 'ok'} title="Grading summary">
            {summary} Fail: RC4, 3DES, DES, RC2, EXPORT, NULL, anonymous key exchange and static
            RSA/ECDH key transport. Warn: CBC mode, SHA-1 PRF and eight-byte AEAD tags.
          </Callout>
        </div>
      </Card>

      <Card title="Parsed table">
        {parsed.found.length === 0 ? (
          <div className="text-[12px] text-[var(--text-faint)]">
            Nothing parsed yet — paste a suite name above, or click one in the dictionary below.
          </div>
        ) : (
          <div className="overflow-x-auto rounded border border-[var(--card-border)]">
            <table className="w-full text-[12px]">
              <thead>
                <tr className="bg-[var(--neutral-btn)] text-left text-[var(--text-muted)]">
                  {['Suite', 'Ver', 'KX', 'Auth', 'Enc', 'Mode', 'MAC/PRF', 'Bits', 'FS', 'AEAD', 'Verdict'].map((h) => (
                    <th key={h} className="px-2.5 py-1.5 font-medium whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {parsed.found.map((s, i) => (
                  <tr key={`${s.iana}-${s.id}-${i}`} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
                    <td className="rf-mono px-2.5 py-1.5">
                      <div className="text-[var(--text)]">{s.iana}</div>
                      <div className="text-[11px] text-[var(--text-faint)]">
                        {s.id !== '—' ? `${s.id} · ` : ''}
                        {s.ossl}
                      </div>
                    </td>
                    <td className="px-2.5 py-1.5 whitespace-nowrap">{s.version}</td>
                    <td className="rf-mono px-2.5 py-1.5">{s.kx}</td>
                    <td className="rf-mono px-2.5 py-1.5">{s.auth}</td>
                    <td className="rf-mono px-2.5 py-1.5">{s.enc}</td>
                    <td className="rf-mono px-2.5 py-1.5">{s.mode}</td>
                    <td className="rf-mono px-2.5 py-1.5">{s.mac}</td>
                    <td className="rf-mono px-2.5 py-1.5">{s.bits || '—'}</td>
                    <td className="px-2.5 py-1.5" style={{ color: s.fs ? 'var(--ok)' : 'var(--accent)' }}>
                      {s.fs ? 'yes' : 'no'}
                    </td>
                    <td className="px-2.5 py-1.5" style={{ color: s.aead ? 'var(--ok)' : 'var(--text-muted)' }}>
                      {s.aead ? 'yes' : 'no'}
                    </td>
                    <td className="px-2.5 py-1.5 font-medium" style={{ color: GRADING_COLOR[s.grade] }}>
                      {s.grade}
                      <div className="max-w-[240px] text-[11px] font-normal text-[var(--text-muted)]">{s.note}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="mt-4">
          <KVTable
            rows={[
              ['Protocol versions seen', parsed.versions.join(', ') || '—'],
              ['Weak suites', parsed.weak.map((s) => s.ossl).join(', ') || 'none'],
              ['Compatibility-only suites', parsed.warned.map((s) => s.ossl).join(', ') || 'none'],
              ['Forward secrecy coverage', `${parsed.withFs.length} / ${parsed.found.length}`],
            ]}
          />
        </div>
      </Card>

      <Card
        title="Dictionary"
        action={<span className="text-[12px] text-[var(--text-muted)]">{dictionary.total} matches</span>}
      >
        <SearchInput value={filter} onChange={setFilter} placeholder="Filter by name, version, cipher or verdict…" />
        <div className="mt-3 max-h-[320px] overflow-y-auto rounded border border-[var(--card-border)]">
          <table className="w-full text-[12px]">
            <tbody>
              {dictionary.list.map((s, i) => {
                const active = dictionary.chosen.has(s.iana);
                return (
                  <tr
                    key={`${s.iana}-${i}`}
                    className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}
                    onClick={() => !active && setText((prev) => `${prev.trimEnd()}\n${s.iana}`)}
                    style={{ cursor: active ? 'default' : 'pointer', opacity: active ? 0.5 : 1 }}
                    title={active ? 'Already added' : 'Add to the parsed list'}
                  >
                    <td className="rf-mono px-2.5 py-1.5">{s.id !== '—' ? s.id : ''}</td>
                    <td className="rf-mono px-2.5 py-1.5">{s.ossl}</td>
                    <td className="px-2.5 py-1.5 whitespace-nowrap text-[var(--text-muted)]">{s.version}</td>
                    <td className="px-2.5 py-1.5" style={{ color: GRADING_COLOR[s.grade] }}>
                      {s.grade}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {dictionary.list.length === 0 && (
            <div className="px-3 py-4 text-[12px] text-[var(--text-faint)]">No suite matches “{filter}”.</div>
          )}
        </div>
      </Card>

      <Card title="Reproduce it">
        <OutputBlock value={osslCmd} rows={8} label="openssl" />
        <div className="mt-4">
          <CodeBlock code={nmapCmd} label="nmap" maxHeight={120} />
        </div>
        <div className="mt-3">
          <Callout tone="info" title="TLS 1.3 is not configurable by suite ordering">
            The three TLS 1.3 suites are tied to the AEAD choice, so <span className="rf-mono">ciphers(1)</span> cannot remove
            them — the only lever is <span className="rf-mono">-tls1_3</span> itself. A scanner that lists TLS 1.3 suites and
            grades the endpoint on them will therefore overstate the operator's control over the config.
          </Callout>
        </div>
      </Card>
    </>
  );
}
