/**
 * File + bytes helpers shared by the converters. Deliberately dependency-free:
 * every parse error bubbles up as a thrown Error with a human message, so tool
 * pages can render it in a callout instead of crashing the route.
 */

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
export const fromUtf8 = (b: Uint8Array): string => new TextDecoder('utf-8', { fatal: false }).decode(b);

export function bytesFromBase64(input: string): Uint8Array {
  const clean = input.replace(/^data:[^,]*,/, '').replace(/[\s\r\n]/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) throw new Error('Not valid base64 — check for stray characters');
  const padded = clean + '='.repeat((4 - (clean.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function base64FromBytes(bytes: Uint8Array, urlSafe = false): string {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  const b64 = btoa(bin);
  return urlSafe ? b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : b64;
}

export function base32FromBytes(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

export function bytesFromBase32(input: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) throw new Error(`Invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function hexdump(bytes: Uint8Array, width = 16, offsetBase = 0): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += width) {
    const slice = bytes.subarray(i, i + width);
    const hex = Array.from(slice, (b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(slice, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    const addr = (i + (Number.isFinite(offsetBase) ? offsetBase : 0)).toString(16).padStart(8, '0');
    lines.push(`${addr}  ${hex.padEnd(width * 3 - 1)}  |${ascii}|`);
  }
  return lines.join('\n');
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(input: string): number {
  if (!input) return 0;
  const freq = new Map<string, number>();
  for (const ch of input) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

/** UTF-16LE code units — needed for NT hashes and PowerShell -EncodedCommand. */
export function utf16leBytes(s: string, bom = false): Uint8Array {
  const out = new Uint8Array(s.length * 2 + (bom ? 2 : 0));
  let o = 0;
  if (bom) {
    out[o++] = 0xff;
    out[o++] = 0xfe;
  }
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    out[o++] = code & 0xff;
    out[o++] = (code >> 8) & 0xff;
  }
  return out;
}

export function fromUtf16le(bytes: Uint8Array): string {
  let s = '';
  const start = bytes[0] === 0xff && bytes[1] === 0xfe ? 2 : 0;
  for (let i = start; i + 1 < bytes.length; i += 2) s += String.fromCharCode(bytes[i] | (bytes[i + 1] << 8));
  return s;
}

/** Fill a hex-encoded payload with 0x90 NOPs — handy for shellcode padding. */
export function hexNops(count: number): string {
  return '90'.repeat(count);
}
