/**
 * Hash + KDF façade. Uses vetted, dependency-free implementations (js-sha1 /
 * js-sha256) rather than hand-rolled SHA in the app bundle; SHA-384/512 come
 */
import { sha1 as jsSha1 } from 'js-sha1';
import { sha256 as jsSha256 } from 'js-sha256';

export const utf8ToBytes = (s: string): Uint8Array => new TextEncoder().encode(s);
const bs = (u: Uint8Array): BufferSource => u as unknown as BufferSource;
export const bytesToUtf8 = (b: Uint8Array): string => new TextDecoder('utf-8', { fatal: false }).decode(b);

export const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export const fromHex = (hex: string): Uint8Array => {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(clean.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
};

/** MD5 (RFC 1321) — kept local because WebCrypto omits it and it's still everywhere in CTF/admin panels. */
const MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

function md5Bytes(input: Uint8Array): Uint8Array {
  const len = input.length;
  const paddedLen = len + 1 + ((56 - ((len + 1) % 64) + 64) % 64) + 8;
  const buf = new Uint8Array(paddedLen);
  buf.set(input);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  const bits = BigInt(len) * 8n;
  dv.setUint32(paddedLen - 8, Number(bits & 0xffffffffn), true);
  dv.setUint32(paddedLen - 4, Number(bits >> 32n), true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Uint32Array(16);
  for (let off = 0; off < paddedLen; off += 64) {
    for (let j = 0; j < 16; j++) M[j] = dv.getUint32(off + j * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number; let g: number;
      if (i < 16) { F = ((B & C) | (~B & D)) >>> 0; g = i; }
      else if (i < 32) { F = ((D & B) | (~D & C)) >>> 0; g = (5 * i + 1) % 16; }
      else if (i < 48) { F = (B ^ C ^ D) >>> 0; g = (3 * i + 5) % 16; }
      else { F = (C ^ (B | ~D)) >>> 0; g = (7 * i) % 16; }
      F = (F + A + MD5_K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + (((F << MD5_S[i]) | (F >>> (32 - MD5_S[i]))) >>> 0)) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16);
  const ov = new DataView(out.buffer);
  ov.setUint32(0, a0, true); ov.setUint32(4, b0, true); ov.setUint32(8, c0, true); ov.setUint32(12, d0, true);
  return out;
}

export const md5Hex = (input: Uint8Array | string): string =>
  toHex(md5Bytes(typeof input === 'string' ? utf8ToBytes(input) : input));

export const sha1Hex = (input: Uint8Array | string): string =>
  typeof input === 'string' ? jsSha1(input) : jsSha1(input);

export const sha256Hex = (input: Uint8Array | string): string =>
  typeof input === 'string' ? jsSha256(input) : jsSha256(input);

export type HashAlgorithm = 'md5' | 'sha1' | 'sha256';

export function hashText(algo: HashAlgorithm, text: string): string {
  if (algo === 'md5') return md5Hex(text);
  if (algo === 'sha1') return sha1Hex(text);
  return sha256Hex(text);
}

/* ── HMAC / PBKDF2 / AES via WebCrypto (available in all modern browsers) ── */

const subtle = () => globalThis.crypto.subtle;

export async function hmacHex(algo: 'SHA-1' | 'SHA-256', key: string, message: string): Promise<string> {
  const k = await subtle().importKey('raw', bs(utf8ToBytes(key)), { name: 'HMAC', hash: algo }, false, ['sign']);
  const sig = await subtle().sign('HMAC', k, bs(utf8ToBytes(message)));
  return toHex(new Uint8Array(sig));
}

export async function pbkdf2Hex(
  password: string,
  salt: string,
  iterations: number,
  lengthBytes = 32,
  algo: 'SHA-1' | 'SHA-256' = 'SHA-256',
): Promise<string> {
  const base = await subtle().importKey('raw', bs(utf8ToBytes(password)), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle().deriveBits(
    { name: 'PBKDF2', salt: bs(utf8ToBytes(salt)), iterations, hash: algo },
    base,
    lengthBytes * 8,
  );
  return toHex(new Uint8Array(bits));
}

/** SHA-256 over a password → 32-byte AES key (simple, deterministic). */
async function keyFromPassword(password: string): Promise<CryptoKey> {
  const raw = fromHex(sha256Hex(password));
  return subtle().importKey('raw', bs(raw), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function aesGcmEncrypt(password: string, plaintext: string): Promise<string> {
  const key = await keyFromPassword(password);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: bs(iv) }, key, bs(utf8ToBytes(plaintext))));
  return `${toHex(iv)}:${toHex(ct)}`;
}

export async function aesGcmDecrypt(password: string, payload: string): Promise<string> {
  const [ivHex, ctHex] = payload.trim().split(':');
  if (!ivHex || !ctHex) throw new Error('Expected "<iv-hex>:<ciphertext-hex>"');
  const key = await keyFromPassword(password);
  const pt = await subtle().decrypt(
    { name: 'AES-GCM', iv: bs(fromHex(ivHex)) },
    key,
    bs(fromHex(ctHex)),
  );
  return bytesToUtf8(new Uint8Array(pt));
}

export function base64FromBytes(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function bytesFromBase64(b64: string): Uint8Array {
  const bin = atob(b64.replace(/\s+/g, ''));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(buf);
  else for (let i = 0; i < bytes; i++) buf[i] = Math.floor(Math.random() * 256);
  return toHex(buf);
}


/* ─────────────────────────────────────────────────────────────────────────────
   OpenSSL-compatible AES-CBC helper: EVP_BytesToKey(MD5) + PKCS#7, producing
   the same "Salted__" container as `openssl enc -aes-256-cbc -salt -a`.
   WebCrypto only ships CBC mode, so padding is handled by hand.
   ──────────────────────────────────────────────────────────────────────────── */

function evpBytesToKey(password: Uint8Array, salt: Uint8Array, keyLen: number, ivLen: number) {
  const chunks: Uint8Array[] = [];
  let prev: Uint8Array = new Uint8Array(0);
  let total = 0;
  while (total < keyLen + ivLen) {
    const input = new Uint8Array(prev.length + password.length + salt.length);
    input.set(prev, 0);
    input.set(password, prev.length);
    input.set(salt, prev.length + password.length);
    prev = md5Bytes(input);
    chunks.push(prev);
    total += prev.length;
  }
  const all = new Uint8Array(total);
  let off = 0;
  for (const chunk of chunks) {
    all.set(chunk, off);
    off += chunk.length;
  }
  return { key: all.slice(0, keyLen), iv: all.slice(keyLen, keyLen + ivLen) };
}

function pkcs7Pad(data: Uint8Array): Uint8Array {
  const pad = 16 - (data.length % 16);
  const out = new Uint8Array(data.length + pad);
  out.set(data, 0);
  out.fill(pad, data.length);
  return out;
}

function pkcs7Unpad(data: Uint8Array): Uint8Array {
  if (!data.length) return data;
  const n = data[data.length - 1];
  if (n < 1 || n > 16 || n > data.length) return data;
  return data.subarray(0, data.length - n);
}

function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', keyBuf(raw), { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
}

function keyBuf(raw: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(raw.length);
  new Uint8Array(out).set(raw);
  return out;
}


/** `openssl enc -aes-256-cbc -salt -a` compatible encryption. Returns base64. */
export async function opensslEncrypt(password: string, plaintext: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(8));
  const { key, iv } = evpBytesToKey(utf8ToBytes(password), salt, 32, 16);
  const ck = await importAesKey(key);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CBC', iv: keyBuf(iv) }, ck, keyBuf(pkcs7Pad(utf8ToBytes(plaintext)))),
  );
  const framed = new Uint8Array(16 + ct.length);
  framed.set(utf8ToBytes('Salted__'), 0);
  framed.set(salt, 8);
  framed.set(ct, 16);
  return base64FromBytes(framed);
}

/** Inverse of {@link opensslEncrypt}; accepts base64 or raw Salted__ bytes. */
export async function opensslDecrypt(password: string, payloadBase64: string): Promise<string> {
  const framed = bytesFromBase64(payloadBase64.trim());
  if (framed.length < 32) throw new Error('Ciphertext is shorter than one block');
  if (bytesToUtf8(framed.subarray(0, 8)) !== 'Salted__') throw new Error('Missing "Salted__" header — not an OpenSSL blob');
  const salt = framed.subarray(8, 16);
  const ct = framed.subarray(16);
  const { key, iv } = evpBytesToKey(utf8ToBytes(password), salt, 32, 16);
  const ck = await importAesKey(key);
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: keyBuf(iv) }, ck, keyBuf(ct)));
  return bytesToUtf8(pkcs7Unpad(pt));
}

/* ─────────────────────────────────────────────────────────────────────────────
   Extra digests used by the fingerprint tool. WebCrypto handles SHA-384/512,
   so no second home-grown implementation ships in the bundle.
   ──────────────────────────────────────────────────────────────────────────── */

export async function sha512Hex(input: Uint8Array | string): Promise<string> {
  const data = typeof input === 'string' ? utf8ToBytes(input) : input;
  const buf = await crypto.subtle.digest('SHA-512', keyBuf(data));
  return toHex(new Uint8Array(buf));
}

export async function sha384Hex(input: Uint8Array | string): Promise<string> {
  const data = typeof input === 'string' ? utf8ToBytes(input) : input;
  const buf = await crypto.subtle.digest('SHA-384', keyBuf(data));
  return toHex(new Uint8Array(buf));
}

/** NTLM (NT hash) of a password string — DES-free MD4 is supplied by js-sha1? No:
 *  implemented inline below because NT hash is just MD4(UTF-16LE(password)). */
export function ntlmHash(password: string): string {
  const utf16 = new Uint8Array(password.length * 2);
  for (let i = 0; i < password.length; i++) {
    const code = password.charCodeAt(i);
    utf16[i * 2] = code & 0xff;
    utf16[i * 2 + 1] = code >> 8;
  }
  return md4Hex(utf16);
}

/** RFC 1320 MD4 — needed for NT hashes and some NTLMv1 work. */
function md4Hex(input: Uint8Array): string {
  const K = [0, 1518500249, 1859775393, 3878403774];
  const S1 = [3, 7, 11, 19];
  const S2 = [3, 5, 9, 13];
  const S3 = [3, 9, 11, 15];
  const bitLen = input.length * 8;
  const padded = new Uint8Array((((input.length + 8) >> 6) + 1) * 64);
  padded.set(input);
  padded[input.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, bitLen >>> 0, true);
  view.setUint32(padded.length - 4, Math.floor(bitLen / 0x100000000), true);

  let a = 0x67452301;
  let b = 0xefcdab89;
  let c = 0x98badcfe;
  let d = 0x10325476;

  const rotl = (x: number, n: number) => (x << n) | (x >>> (32 - n));

  for (let off = 0; off < padded.length; off += 64) {
    const X: number[] = [];
    for (let i = 0; i < 16; i++) X.push(view.getUint32(off + i * 4, true));
    const [aa, bb, cc, dd] = [a, b, c, d];

    for (let i = 0; i < 16; i++) {
      const f = (b & c) | (~b & d);
      a = rotl((a + f + X[i] + K[0]) | 0, S1[i % 4]);
      [a, b, c, d] = [d, a, b, c];
    }
    for (let i = 0; i < 16; i++) {
      const f = (b & c) | (b & d) | (c & d);
      const idx = (i % 4) * 4 + Math.floor(i / 4);
      a = rotl((a + f + X[idx] + K[1]) | 0, S2[i % 4]);
      [a, b, c, d] = [d, a, b, c];
    }
    for (let i = 0; i < 16; i++) {
      const f = b ^ c ^ d;
      const order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
      a = rotl((a + f + X[order[i]] + K[2]) | 0, S3[i % 4]);
      [a, b, c, d] = [d, a, b, c];
    }

    a = (a + aa) | 0;
    b = (b + bb) | 0;
    c = (c + cc) | 0;
    d = (d + dd) | 0;
  }

  const out = new DataView(new ArrayBuffer(16));
  out.setUint32(0, a >>> 0, true);
  out.setUint32(4, b >>> 0, true);
  out.setUint32(8, c >>> 0, true);
  out.setUint32(12, d >>> 0, true);
  return toHex(new Uint8Array(out.buffer));
}
