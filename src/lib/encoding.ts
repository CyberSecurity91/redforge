// String / byte encodings shared by the recon + encoding tools.
// All pure functions; nothing here touches the network.
import { fromHex, toHex, utf8ToBytes, bytesToUtf8, md5Hex, sha1Hex, sha256Hex } from './crypto';

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export const s2b = (s: string): Uint8Array => utf8ToBytes(s);
export const b2s = (b: Uint8Array): string => bytesToUtf8(b);

export function b64Encode(bytes: Uint8Array, urlSafe = false): string {
  const table = urlSafe ? B64URL : B64;
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += table[(n >> 18) & 63] + table[(n >> 12) & 63] + table[(n >> 6) & 63] + table[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += table[(n >> 18) & 63] + table[(n >> 12) & 63];
    if (!urlSafe) out += '==';
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += table[(n >> 18) & 63] + table[(n >> 12) & 63] + table[(n >> 6) & 63];
    if (!urlSafe) out += '=';
  }
  return out;
}

export function b64Decode(input: string): Uint8Array {
  let s = input.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4 !== 0) s += '=';
  s = s.replace(/=+$/, '');
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of s) {
    const idx = B64.indexOf(ch);
    if (idx < 0) continue;
    buffer = (buffer << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      out.push((buffer >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function b32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  while (out.length % 8 !== 0) out += '=';
  return out;
}

export function b32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/=+$/, '').replace(/[^A-Z2-7]/g, '');
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function urlSafeB64(bytes: Uint8Array): string {
  return b64Encode(bytes, true);
}

export function percentEncode(s: string): string {
  return encodeURIComponent(s);
}

const REVERSE_ALPHA = 'zyxwvutsrqponmlkjihgfedcba';

export function rot13(s: string): string {
  return s.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

export function caesar(s: string, shift: number): string {
  const k = ((shift % 26) + 26) % 26;
  return s.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + k) % 26) + base);
  });
}

export function atbash(s: string): string {
  return s.replace(/[a-z]/g, (c) => REVERSE_ALPHA[c.charCodeAt(0) - 97]).replace(/[A-Z]/g, (c) => REVERSE_ALPHA[c.charCodeAt(0) - 65].toUpperCase());
}

/** Standard (non-URL-safe) base64 with proper padding, from a JavaScript string. */
export function textToB64(s: string): string {
  return b64Encode(s2b(s));
}

/** Deterministic UUID-v4-shaped identifier from an input (deterministic means repeatable in reports). */
export function uuidFromSeed(input: string): string {
  const h = sha256Hex(s2b(input));
  const variant = ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

export function hexdump(bytes: Uint8Array, width = 16): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += width) {
    const chunk = bytes.subarray(i, i + width);
    const hex = Array.from(chunk, (b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(chunk, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${i.toString(16).padStart(8, '0')}  ${hex.padEnd(width * 3 - 1)}  ${ascii}`);
  }
  return lines.join('\n');
}

/** Entropy in bits per symbol (Shannon) — fast check for base64/hex-encoded blobs. */
export function shannonEntropy(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export { md5Hex, sha1Hex, sha256Hex, fromHex, toHex };

/** Strip prettified whitespace from a PEM block (for fingerprinting). */
export const pemBody = (pem: string): string =>
  pem
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');

/** Re-wrap a base64/DER blob at 64 chars with PEM armour. */
export function toPem(label: string, body: string): string {
  const wrapped = body.replace(/\s+/g, '').match(/.{1,64}/g)?.join('\n') ?? '';
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}

/** Resolve a URL path's first segment, ignoring trailing slashes. */
export const firstSegment = (pathname: string): string =>
  pathname.split('?')[0].replace(/^\/+/, '').split('/')[0] ?? '';
