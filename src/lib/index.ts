/**
 * Shared library surface. Re-exported selectively so overlapping helper names
 * (bytes vs crypto vs rng) resolve to one canonical implementation each.
 */
export * from './hooks';
export * from './rng';
export * from './redteam-data';
export {
  utf8ToBytes,
  bytesToUtf8,
  toHex,
  fromHex,
  md5Hex,
  sha1Hex,
  sha256Hex,
  sha384Hex,
  sha512Hex,
  hashText,
  ntlmHash,
  hmacHex,
  pbkdf2Hex,
  aesGcmEncrypt,
  aesGcmDecrypt,
  opensslEncrypt,
  opensslDecrypt,
  base64FromBytes,
  bytesFromBase64,
  randomHex,
  type HashAlgorithm,
} from './crypto';
export {
  hexdump,
  shannonEntropy,
  formatBytes,
  utf16leBytes,
  fromUtf16le,
  hexNops,
} from './bytes';
export {
  s2b,
  b2s,
  b64Encode,
  b64Decode,
  b32Encode,
  b32Decode,
  urlSafeB64,
  percentEncode,
  rot13,
  caesar,
  atbash,
  textToB64,
  uuidFromSeed,
  pemBody,
  toPem,
  firstSegment,
} from './encoding';
