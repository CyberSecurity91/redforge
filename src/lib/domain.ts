/**
 * Deterministic hostname / IPv4 helpers for the recon tools.
 * Pure functions, no dependencies, no I/O — every parse either returns a value
 * or throws an Error with an operator-readable message.
 */

/* ── IPv4 integer conversion ─────────────────────────────────────────────── */

/** Dotted quad → unsigned 32-bit integer. Throws on anything that is not IPv4. */
export function ipToInt(ip: string): number {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) throw new Error(`Not an IPv4 address: ${ip}`);
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) throw new Error(`Not an IPv4 address: ${ip}`);
    const octet = Number(part);
    if (octet > 255) throw new Error(`Octet out of range in ${ip}`);
    n = (n * 256 + octet) >>> 0;
  }
  return n;
}

/** Unsigned 32-bit integer → dotted quad. */
export function intToIp(n: number): string {
  const v = n >>> 0;
  return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.');
}

/** RFC 1918 / loopback / link-local / CGNAT / documentation ranges. */
export function isPrivateIp(ip: string): boolean {
  let n: number;
  try {
    n = ipToInt(ip);
  } catch {
    return false;
  }
  const a = (n >>> 24) & 255;
  const b = (n >>> 16) & 255;
  if (a === 10 || a === 127) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true; // link-local / metadata
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 0 || a >= 224) return true; // this-net, multicast, reserved
  if (a === 192 && b === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  return false;
}

/** `203.0.113.10` → `10.113.0.203.in-addr.arpa`. */
export function reverseDnsName(ip: string): string {
  return `${intToIp(ipToInt(ip)).split('.').reverse().join('.')}.in-addr.arpa`;
}

/* ── CIDR ────────────────────────────────────────────────────────────────── */

export interface CidrInfo {
  /** `a.b.c.d/len` normalised form. */
  cidr: string;
  network: string;
  broadcast: string;
  first: string;
  last: string;
  /** Expanded usable hosts, capped at `limit` (default 4096). */
  hosts: string[];
  /** Total address count including network + broadcast (2^(32-len)). */
  count: number;
  /** Usable host count for a classic subnet (count-2, or 1 for /32). */
  usable: number;
  /** Dotted-decimal netmask. */
  mask: string;
  /** Inverted mask, e.g. `0.0.0.255`. */
  wildcard: string;
  prefix: number;
  /** True when the expansion was truncated by `limit`. */
  truncated: boolean;
}

/**
 * Expand an IPv4 CIDR block. Refuses prefixes shorter than /8 because a /0-/7
 * sweep is never something this page should render as a host list.
 */
export function expandCidr(cidr: string, limit = 4096): CidrInfo {
  const raw = cidr.trim();
  const [addr, lenRaw] = raw.split('/');
  if (!addr || lenRaw === undefined) throw new Error('Expected CIDR form a.b.c.d/len');
  if (!/^\d{1,2}$/.test(lenRaw)) throw new Error(`Bad prefix length: /${lenRaw}`);
  const prefix = Number(lenRaw);
  if (prefix < 8 || prefix > 32) throw new Error('Prefix must be between /8 and /32 — wider blocks are not expandable');
  const ip = ipToInt(addr);
  const size = 2 ** (32 - prefix);
  const hostMask = size - 1;
  const networkInt = (ip & ~hostMask) >>> 0;
  const broadcastInt = (networkInt + size - 1) >>> 0;
  const total = size;
  // /31 and /32 have no network/broadcast reservation in modern practice.
  const firstInt = prefix >= 31 ? networkInt : networkInt + 1;
  const lastInt = prefix >= 31 ? broadcastInt : broadcastInt - 1;
  const usable = prefix >= 31 ? total : Math.max(total - 2, 0);

  const hosts: string[] = [];
  const cap = Math.min(usable, limit);
  for (let i = 0; i < cap; i++) hosts.push(intToIp(firstInt + i));

  const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return {
    cidr: `${intToIp(networkInt)}/${prefix}`,
    network: intToIp(networkInt),
    broadcast: intToIp(broadcastInt),
    first: intToIp(firstInt),
    last: intToIp(lastInt),
    hosts,
    count: total,
    usable,
    mask: intToIp(maskInt),
    wildcard: intToIp(~maskInt >>> 0),
    prefix,
    truncated: usable > cap,
  };
}

/** Split a CIDR into the sub-blocks of `targetPrefix` (e.g. /16 → four /24s). */
export function splitCidr(cidr: string, targetPrefix: number): string[] {
  const info = expandCidr(cidr);
  if (targetPrefix < info.prefix) throw new Error(`Cannot split /${info.prefix} into /${targetPrefix}`);
  if (targetPrefix > 32) throw new Error('Prefix out of range');
  const blockSize = 2 ** (32 - targetPrefix);
  const start = ipToInt(info.network);
  const out: string[] = [];
  for (let n = start; n <= ipToInt(info.broadcast) && out.length < 256; n += blockSize) {
    out.push(`${intToIp(n)}/${targetPrefix}`);
  }
  return out;
}

/* ── Hostname parsing ────────────────────────────────────────────────────── */

export interface HostnameParts {
  host: string;
  port?: number;
  scheme?: string;
}

/**
 * Tolerant hostname extractor: accepts `https://user@host:8443/path?q`,
 * `host:22`, a bare host, or an email-shaped `user@domain`. CIDR input keeps
 * the address part only (`10.0.0.0/24` → `10.0.0.0`).
 */
export function parseHostname(input: string): HostnameParts {
  let s = input.trim();
  if (!s) return { host: '' };
  let scheme: string | undefined;
  const m = /^([a-z][a-z0-9+.-]*):\/\//i.exec(s);
  if (m) {
    scheme = m[1].toLowerCase();
    s = s.slice(m[0].length);
  }
  s = s.split(/[/?#]/)[0];
  s = s.slice(s.lastIndexOf('@') + 1);
  s = s.split('/')[0];
  let port: number | undefined;
  const portMatch = /^(\[[^\]]+\]|[^:]+):(\d{1,5})$/.exec(s);
  if (portMatch) {
    s = portMatch[1];
    port = Number(portMatch[2]);
    if (port > 65535) port = undefined;
  }
  s = s.split('/')[0].replace(/\.$/, '').toLowerCase();
  if (!scheme && port === 443) scheme = 'https';
  return { host: s, port, scheme };
}

/** Strip a leading `www.` only — leaves `www2.` and other labels intact. */
export function stripWww(host: string): string {
  return host.replace(/^www\./i, '');
}

/** Last one or two labels, good enough for a dork `site:` operator. */
export function tldOf(host: string): string {
  const labels = stripWww(host).split('.').filter(Boolean);
  if (labels.length < 2) return labels[0] ?? '';
  const last = labels[labels.length - 1];
  const secondLast = labels[labels.length - 2];
  const twoLevel = /^(co|com|net|org|gov|edu|ac|or|ne|go|gen|ind|firm|info|nic|nom)$/i.test(secondLast) &&
    !!last &&
    last.length === 2;
  return twoLevel ? `${secondLast}.${last}` : last;
}

/** Root/registrable domain guess (no public-suffix list, but handles ccTLD 2LDs). */
export function registrableDomain(host: string): string {
  const labels = stripWww(host).split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const tld = tldOf(labels.join('.'));
  const tldLabels = tld.split('.').length;
  return labels.slice(-(tldLabels + 1)).join('.');
}

/** Classify a host as IPv4, IPv6, localhost or a DNS name. */
export function hostKind(host: string): 'ipv4' | 'ipv6' | 'loopback' | 'dns' | 'empty' {
  if (!host) return 'empty';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return 'ipv4';
  if (host.includes(':')) return 'ipv6';
  if (host === 'localhost') return 'loopback';
  return 'dns';
}

export interface UrlParts {
  scheme: string;
  host: string;
  port: string;
  path: string;
  query: string;
}

/** Forgiving URL splitter — never throws, fills blanks on malformed input. */
export function parseUrlParts(input: string): UrlParts {
  const empty: UrlParts = { scheme: '', host: '', port: '', path: '', query: '' };
  const s = input.trim();
  if (!s) return empty;
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?/i.exec(s);
  if (!m) {
    const { host, port } = parseHostname(s);
    const pathPart = s.includes('/') ? s.slice(s.indexOf('/')) : '';
    return { scheme: '', host, port: port ? String(port) : '', path: pathPart.split('?')[0] ?? '', query: pathPart.split('?')[1] ?? '' };
  }
  const authority = m[2];
  const { host, port } = parseHostname(authority.includes('@') ? authority.slice(authority.lastIndexOf('@') + 1) : authority);
  return {
    scheme: m[1].toLowerCase(),
    host,
    port: port ? String(port) : '',
    path: m[3] || '/',
    query: m[4] ?? '',
  };
}

/** Default port for a scheme, or '' when unknown. */
export function defaultPortFor(scheme: string): string {
  const map: Record<string, string> = { http: '80', https: '443', ftp: '21', ssh: '22', ws: '80', wss: '443', smtp: '25', ldap: '389', ldaps: '636', rdp: '3389' };
  return map[scheme.toLowerCase()] ?? '';
}

/** True when a CIDR or single IP string parses as IPv4. */
export function isIpv4Range(value: string): boolean {
  const [addr, len] = value.trim().split('/');
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(addr ?? '')) return false;
  if (len === undefined) return true;
  return /^\d{1,2}$/.test(len) && Number(len) <= 32;
}
