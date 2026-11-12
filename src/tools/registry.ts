import { lazy, type ComponentType } from 'react';

export interface ToolDef {
  /** URL segment, also the registry key. */
  path: string;
  name: string;
  description: string;
  /** Category id — must exist in CATEGORIES. */
  category: string;
  keywords?: string[];
  component: ComponentType;
}

export interface Category {
  id: string;
  title: string;
  blurb: string;
}

/** Sidebar + home ordering, mirroring the it-tools category rhythm. */
export const CATEGORIES: Category[] = [
  { id: 'recon', title: 'Recon', blurb: 'Passive mapping, wordlists and target triage.' },
  { id: 'network', title: 'Network', blurb: 'Scanning, pivoting and transport-layer tooling.' },
  { id: 'web', title: 'Web', blurb: 'Injection payloads, header abuse and request crafting.' },
  { id: 'tokens', title: 'Web tokens', blurb: 'JWT and SAML inspection, forging and signature recovery.' },
  { id: 'exploit', title: 'Exploit', blurb: 'Payload scaffolding, privesc and AD tradecraft.' },
  { id: 'credential', title: 'Credentials', blurb: 'Hash identification, cracking plans and credential generation.' },
  { id: 'crypto', title: 'Crypto', blurb: 'Digests, key derivation, XOR and classical ciphers.' },
  { id: 'encoding', title: 'Encoding', blurb: 'Encode, escape and obfuscate payloads for transport.' },
  { id: 'social', title: 'Social engineering', blurb: 'Pretext design, lure copy and phishing-assessment planning.' },
  { id: 'osint', title: 'OSINT', blurb: 'Entity pivots, breach and identity correlation planning.' },
  { id: 'reporting', title: 'Reporting', blurb: 'Scoring, findings, evidence and rules-of-engagement.' },
];

export const categoryTitle = (id: string): string => CATEGORIES.find((c) => c.id === id)?.title ?? id;

/** Origin the generated one-liners point at. Purely a template value. */
export const DEFAULT_CALLBACK_HOST = '10.10.14.7';
export const DEFAULT_OOB_DOMAIN = 'oast.example.com';
export const DEFAULT_TARGET = 'example.com';
export const DEFAULT_TARGET_IP = '203.0.113.10';

/* Every tool is code-split; the registry only holds lazy handles so the first
 * paint ships the shell and nothing else. */
export const ALL_TOOLS: ToolDef[] = [
  /* ── Recon ─────────────────────────────────────────────────────────────── */
  {
    path: 'subdomain-wordlist-generator',
    name: 'Subdomain wordlist generator',
    description: 'Build a deduplicated dnsx/ffuf wordlist from a root domain plus attack-class prefixes.',
    category: 'recon',
    keywords: ['subdomain', 'wordlist', 'dns', 'enumeration', 'permutation'],
    component: lazy(() => import('./recon/SubdomainWordlistGenerator')),
  },
  {
    path: 'dns-recon-planner',
    name: 'DNS recon planner',
    description: 'Generate the dig/host command set for zone transfer, mail records and vhost discovery.',
    category: 'recon',
    keywords: ['dns', 'dig', 'axfr', 'mx', 'txt', 'dmarc'],
    component: lazy(() => import('./recon/DnsReconPlanner')),
  },
  {
    path: 'google-dork-builder',
    name: 'Google dork builder',
    description: 'Compose advanced search operators for exposed files, panels and credential leaks.',
    category: 'recon',
    keywords: ['dork', 'osint', 'shodan', 'search', 'exposure'],
    component: lazy(() => import('./recon/GoogleDorkBuilder')),
  },
  {
    path: 'port-service-lookup',
    name: 'Port & service lookup',
    description: 'Map an open port list to typical services, misconfigurations and next-step checks.',
    category: 'recon',
    keywords: ['port', 'service', 'nmap', 'banner', 'triage'],
    component: lazy(() => import('./recon/PortServiceLookup')),
  },
  {
    path: 'cidr-ip-calculator',
    name: 'CIDR & IP range calculator',
    description: 'Expand CIDR blocks, find the broadcast range and export a scannable host list.',
    category: 'recon',
    keywords: ['cidr', 'ipv4', 'subnet', 'range', 'scope'],
    component: lazy(() => import('./recon/CidrCalculator')),
  },
  {
    path: 'certificate-inspector',
    name: 'TLS certificate inspector',
    description: 'Parse a PEM certificate for SANs, validity window, key type and subject details.',
    category: 'recon',
    keywords: ['tls', 'certificate', 'pem', 'san', 'x509'],
    component: lazy(() => import('./recon/CertificateInspector')),
  },

  /* ── Network ───────────────────────────────────────────────────────────── */
  {
    path: 'nmap-command-builder',
    name: 'Nmap command builder',
    description: 'Assemble a scan profile with timing, port ranges, NSE scripts and output flags.',
    category: 'network',
    keywords: ['nmap', 'scan', 'nse', 'port', 'recon'],
    component: lazy(() => import('./network/NmapCommandBuilder')),
  },
  {
    name: 'Reverse shell generator',
    path: 'reverse-shell-generator',
    description: 'Generate a listener-and-shell pair for every common runtime, sized to your callback host.',
    category: 'network',
    keywords: ['reverse shell', 'listener', 'payload', 'bash', 'powershell', 'nc'],
    component: lazy(() => import('./network/ReverseShellGenerator')),
  },
  {
    name: 'Curl command generator',
    path: 'curl-generator',
    description: 'Build a fully-formed curl request from a method, headers, cookies and a JSON body.',
    category: 'network',
    keywords: ['curl', 'http', 'request', 'headers', 'poc'],
    component: lazy(() => import('./network/CurlGenerator')),
  },
  {
    name: 'Burp to curl converter',
    path: 'burp-to-curl',
    description: 'Paste a raw HTTP/1.1 request from Burp and get a copyable curl equivalent.',
    category: 'network',
    keywords: ['burp', 'curl', 'convert', 'raw request', 'poc'],
    component: lazy(() => import('./network/BurpToCurl')),
  },
  {
    name: 'Proxy / pivot chain builder',
    path: 'pivot-chain-builder',
    description: 'Describe a multi-hop tunnel and emit the exact proxychains and ssh flag lines.',
    category: 'network',
    keywords: ['pivot', 'proxy', 'proxychains', 'ssh', 'chisel'],
    component: lazy(() => import('./network/PivotChainBuilder')),
  },

  /* ── Web ───────────────────────────────────────────────────────────────── */
  {
    name: 'XSS payload generator',
    path: 'xss-payload-generator',
    description: 'Generate a context-aware XSS corpus with OAST beacons and encoding variants.',
    category: 'web',
    keywords: ['xss', 'payload', 'script', 'browser', 'injection'],
    component: lazy(() => import('./web/XssPayloadGenerator')),
  },
  {
    name: 'SQL injection payload builder',
    path: 'sql-injection-payload-builder',
    description: 'Assemble union, boolean, time-based and stacked payloads for a parameter and DBMS.',
    category: 'web',
    keywords: ['sql', 'sqli', 'injection', 'boolean', 'union'],
    component: lazy(() => import('./web/SqlInjectionBuilder')),
  },
  {
    name: 'SSRF payload builder',
    path: 'ssrf-payload-builder',
    description: 'Build SSRF probes against cloud metadata, internal services and gopher targets.',
    category: 'web',
    keywords: ['ssrf', 'metadata', 'gopher', 'redirect', 'bypass'],
    component: lazy(() => import('./web/SsrfPayloadBuilder')),
  },
  {
    name: 'LFI / path traversal generator',
    path: 'lfi-path-generator',
    description: 'Generate traversal depth variants, filter chains and log-poisoning payloads.',
    category: 'web',
    keywords: ['lfi', 'traversal', 'include', 'filter', 'rfi'],
    component: lazy(() => import('./web/LfiPathGenerator')),
  },
  {
    name: 'WAF bypass encoder',
    path: 'waf-bypass-encoder',
    description: 'Apply case, entity, double-encoding and comment transforms to a blocked payload.',
    category: 'web',
    keywords: ['waf', 'bypass', 'encode', 'obfuscate', 'filter'],
    component: lazy(() => import('./web/WafBypassEncoder')),
  },
  {
    name: 'Command injection cheatsheet',
    path: 'command-injection-cheatsheet',
    description: 'Separator, blind and OAST variants for OS command injection, per platform.',
    category: 'web',
    keywords: ['rce', 'command injection', 'shell', 'blind', 'oast'],
    component: lazy(() => import('./web/CommandInjectionCheatsheet')),
  },
  {
    name: 'XPath / NoSQL / LDAP injection',
    path: 'nosql-injection-builder',
    description: 'Payload families for NoSQL, XPath and LDAP filter injection points.',
    category: 'web',
    keywords: ['nosql', 'mongodb', 'xpath', 'ldap', 'injection'],
    component: lazy(() => import('./web/NoSqlInjectionBuilder')),
  },
  {
    name: 'CSP analyser',
    path: 'csp-analyser',
    description: 'Check a Content-Security-Policy for bypassable directives, wildcards and missing protections.',
    category: 'web',
    keywords: ['csp', 'header', 'bypass', 'xss', 'policy'],
    component: lazy(() => import('./web/CspAnalyser')),
  },
  {
    name: 'Open redirect generator',
    path: 'open-redirect-generator',
    description: 'Build redirect-bypass variants for allow-list filters and URL parsers.',
    category: 'web',
    keywords: ['redirect', 'open redirect', 'bypass', 'phishing'],
    component: lazy(() => import('./web/OpenRedirectGenerator')),
  },
  {
    name: 'Security header auditor',
    path: 'security-header-auditor',
    description: 'Score a response header set and surface the missing hardening directives.',
    category: 'web',
    keywords: ['headers', 'hardening', 'hsts', 'cors', 'audit'],
    component: lazy(() => import('./web/SecurityHeaderAuditor')),
  },
  {
    name: 'HTML Smuggling / download payload builder',
    path: 'html-smuggling-builder',
    description: 'Produce a self-contained HTML page that assembles an attachment client-side.',
    category: 'web',
    keywords: ['smuggling', 'html', 'download', 'blob', 'lure'],
    component: lazy(() => import('./web/HtmlSmugglingBuilder')),
  },
  {
    name: 'Parameter fuzz list',
    path: 'parameter-fuzz-list',
    description: 'Generate parameter-name wordlists for hidden-parameter and mass-assignment discovery.',
    category: 'web',
    keywords: ['parameter', 'fuzz', 'arjun', 'mass assignment', 'wordlist'],
    component: lazy(() => import('./web/ParameterFuzzList')),
  },

  /* ── Web tokens ────────────────────────────────────────────────────────── */
  {
    name: 'JWT decoder',
    path: 'jwt-decoder',
    description: 'Decode header, payload and signature; flag risky claims and mismatched algorithms.',
    category: 'tokens',
    keywords: ['jwt', 'decode', 'token', 'claims', 'jose'],
    component: lazy(() => import('./tokens/JwtDecoder')),
  },
  {
    name: 'JWT forger',
    path: 'jwt-forger',
    description: 'Sign a test token with HS256, none, or an attacker-supplied RSA key.',
    category: 'tokens',
    keywords: ['jwt', 'forge', 'sign', 'alg:none', 'token'],
    component: lazy(() => import('./tokens/JwtForger')),
  },
  {
    name: 'Basic auth & header builder',
    path: 'basic-auth-header',
    description: 'Encode a username and password into Basic, Bearer or Digest-style headers.',
    category: 'tokens',
    keywords: ['basic', 'auth', 'authorization', 'header', 'base64'],
    component: lazy(() => import('./tokens/BasicAuthHeader')),
  },
  {
    name: 'SAML assertion decoder',
    path: 'saml-decoder',
    description: 'Decode a SAMLResponse, extract claims and spot unsigned attribute trust.',
    category: 'tokens',
    keywords: ['saml', 'sso', 'assertion', 'xml', 'decode'],
    component: lazy(() => import('./tokens/SamlDecoder')),
  },

  /* ── Exploit ───────────────────────────────────────────────────────────── */
  {
    name: 'XXE payload generator',
    path: 'xxe-payload-generator',
    description: 'Generate in-band, OAST and file-read XML entities for XML parser testing.',
    category: 'exploit',
    keywords: ['xxe', 'xml', 'entity', 'ssrf', 'oast'],
    component: lazy(() => import('./exploit/XxePayloadGenerator')),
  },
  {
    name: 'Deserialization payload builder',
    path: 'deserialization-payload-builder',
    description: 'Build gadget chains and marker payloads for Java, PHP, Python and .NET.',
    category: 'exploit',
    keywords: ['deserialization', 'java', 'php', 'yso', 'gadget'],
    component: lazy(() => import('./exploit/DeserializationBuilder')),
  },
  {
    name: 'MSFvenom command builder',
    path: 'msfvenom-builder',
    description: 'Compose a msfvenom line for a chosen payload, LHOST, LPORT and output format.',
    category: 'exploit',
    keywords: ['msfvenom', 'meterpreter', 'payload', 'shell', 'exe'],
    component: lazy(() => import('./exploit/MsfvenomBuilder')),
  },
  {
    name: 'Linux privesc checklist',
    path: 'linux-privesc-checklist',
    description: 'Prioritised enumeration checklist with the commands that find each bug.',
    category: 'exploit',
    keywords: ['privesc', 'linux', 'suid', 'sudo', 'capabilities'],
    component: lazy(() => import('./exploit/LinuxPrivescChecklist')),
  },
  {
    name: 'Active Directory attack plan',
    path: 'ad-attack-plan',
    description: 'Map a domain posture to the next credential, delegation or ACL step.',
    category: 'exploit',
    keywords: ['active directory', 'kerberos', 'adcs', 'delegation', 'acl'],
    component: lazy(() => import('./exploit/AdAttackPlan')),
  },
  {
    name: 'Nuclei template generator',
    path: 'nuclei-template-generator',
    description: 'Draft a YAML template from a request, matcher type and severity.',
    category: 'exploit',
    keywords: ['nuclei', 'template', 'yaml', 'matcher', 'scan'],
    component: lazy(() => import('./exploit/NucleiTemplateGenerator')),
  },
  {
    name: 'Wordlist mutator (hashcat rules)',
    path: 'wordlist-mutator',
    description: 'Apply or generate hashcat rule chains and preview the resulting mutations.',
    category: 'exploit',
    keywords: ['wordlist', 'rule', 'hashcat', 'mutation', 'cracking'],
    component: lazy(() => import('./exploit/WordlistMutator')),
  },

  /* ── Credentials ───────────────────────────────────────────────────────── */
  {
    name: 'Hash generator',
    path: 'hash-generator',
    description: 'Compute MD5, SHA-1/2/3, NT, CRC32 and BLAKE digests plus base64 encodings.',
    category: 'credential',
    keywords: ['hash', 'md5', 'sha', 'ntlm', 'crc32'],
    component: lazy(() => import('./credential/HashGenerator')),
  },
  {
    name: 'Hash identifier',
    path: 'hash-identifier',
    description: 'Match a hash to its likely algorithm and get the matching hashcat mode.',
    category: 'credential',
    keywords: ['hash', 'identify', 'hashcat', 'mode', 'netntlm'],
    component: lazy(() => import('./credential/HashIdentifier')),
  },
  {
    name: 'Password profiler',
    path: 'password-profiler',
    description: 'Score a password strength and estimate offline crack time across attack models.',
    category: 'credential',
    keywords: ['password', 'strength', 'crack time', 'entropy', 'profiler'],
    component: lazy(() => import('./credential/PasswordProfiler')),
  },
  {
    name: 'Credential generator',
    path: 'credential-generator',
    description: 'Generate policy-compliant test accounts or seeded password candidates.',
    category: 'credential',
    keywords: ['password', 'generate', 'credential', 'leak corpus', 'test accounts'],
    component: lazy(() => import('./credential/CredentialGenerator')),
  },
  {
    name: 'Offline crack planner',
    path: 'crack-planner',
    description: 'Estimate crack time per GPU hash rate and choose the attack strategy.',
    category: 'credential',
    keywords: ['cracking', 'hashcat', 'gpu', 'rate', 'john'],
    component: lazy(() => import('./credential/CrackPlanner')),
  },

  /* ── Crypto ────────────────────────────────────────────────────────────── */
  {
    name: 'HMAC generator',
    path: 'hmac-generator',
    description: 'Compute an HMAC over a message with SHA-1/256/384/512 in hex or base64.',
    category: 'crypto',
    keywords: ['hmac', 'sha256', 'signature', 'key', 'mac'],
    component: lazy(() => import('./crypto/HmacGenerator')),
  },
  {
    name: 'PBKDF2 generator',
    path: 'pbkdf2-generator',
    description: 'Derive a hex key from a password, salt, iteration count and length.',
    category: 'crypto',
    keywords: ['pbkdf2', 'kdf', 'derive', 'salt', 'iterations'],
    component: lazy(() => import('./crypto/Pbkdf2Generator')),
  },
  {
    name: 'AES encrypt / decrypt',
    path: 'aes-encrypt-decrypt',
    description: 'GCM and OpenSSL-compatible CBC round-trips for payload and config handling.',
    category: 'crypto',
    keywords: ['aes', 'encrypt', 'decrypt', 'cbc', 'openssl'],
    component: lazy(() => import('./crypto/AesEncryptDecrypt')),
  },
  {
    name: 'XOR cracker',
    path: 'xor-cracker',
    description: 'Single-byte and repeating-key XOR with scoring, key recovery and hex output.',
    category: 'crypto',
    keywords: ['xor', 'cipher', 'bruteforce', 'key', 'score'],
    component: lazy(() => import('./crypto/XorCracker')),
  },
  {
    name: 'Classical cipher workbench',
    path: 'classical-ciphers',
    description: 'ROT, Atbash, Vigenère, Beaufort and rail-fence encode and decode.',
    category: 'crypto',
    keywords: ['rot13', 'caesar', 'vigenere', 'atbash', 'cipher'],
    component: lazy(() => import('./crypto/ClassicalCiphers')),
  },
  {
    name: 'Entropy & randomness analyser',
    path: 'entropy-analyser',
    description: 'Shannon entropy, character-class spread and repetition scoring for secrets.',
    category: 'crypto',
    keywords: ['entropy', 'random', 'token', 'secrets', 'analysis'],
    component: lazy(() => import('./crypto/EntropyAnalyser')),
  },

  /* ── Encoding ──────────────────────────────────────────────────────────── */
  {
    name: 'Base64 encoder / decoder',
    path: 'base64-encoder',
    description: 'Text, URL-safe and base32 variants with strict validation on decode.',
    category: 'encoding',
    keywords: ['base64', 'base32', 'encode', 'decode', 'urlsafe'],
    component: lazy(() => import('./encoding/Base64Encoder')),
  },
  {
    name: 'URL encoder / decoder',
    path: 'url-encoder',
    description: 'Percent-encoding, double-encoding and Unicode escapes for request smuggling tests.',
    category: 'encoding',
    keywords: ['url', 'percent', 'encode', 'decode', 'unicode'],
    component: lazy(() => import('./encoding/UrlEncoder')),
  },
  {
    name: 'Hex & binary converter',
    path: 'hex-binary-converter',
    description: 'Convert hex, binary, decimal and ASCII with hexdump preview.',
    category: 'encoding',
    keywords: ['hex', 'binary', 'ascii', 'convert', 'dump'],
    component: lazy(() => import('./encoding/HexBinaryConverter')),
  },
  {
    name: 'PowerShell obfuscator',
    path: 'powershell-obfuscator',
    description: 'Produce a base64 UTF-16LE -EncodedCommand form of any PowerShell one-liner.',
    category: 'encoding',
    keywords: ['powershell', 'obfuscate', 'encodedcommand', 'base64', 'windows'],
    component: lazy(() => import('./encoding/PowershellObfuscator')),
  },
  {
    name: 'Unicode homoglyph obfuscator',
    path: 'homoglyph-obfuscator',
    description: 'Swap characters for lookalikes to test filters and IDN handling.',
    category: 'encoding',
    keywords: ['unicode', 'homoglyph', 'idn', 'obfuscate', 'filter'],
    component: lazy(() => import('./encoding/HomoglyphObfuscator')),
  },
  {
    name: 'Text repertoire (NATO + leetspeak)',
    path: 'text-repertoire',
    description: 'NATO phonetic spelling, leetspeak and case mutation for spoken and visual pretexts.',
    category: 'encoding',
    keywords: ['nato', 'leetspeak', 'phonetic', 'case', 'mutation'],
    component: lazy(() => import('./encoding/TextRepertoire')),
  },

  /* ── Social engineering ────────────────────────────────────────────────── */
  {
    name: 'Phishing email composer',
    path: 'phishing-email-generator',
    description: 'Draft lure copy, headers and a pretext skeleton for an authorised assessment.',
    category: 'social',
    keywords: ['phishing', 'email', 'pretext', 'lure', 'awareness'],
    component: lazy(() => import('./social/PhishingEmailGenerator')),
  },
  {
    name: 'Pretext builder',
    path: 'pretext-builder',
    description: 'Adapt a pretext to a target persona, channel and authority lever.',
    category: 'social',
    keywords: ['pretext', 'social engineering', 'vishing', 'script', 'persona'],
    component: lazy(() => import('./social/PretextBuilder')),
  },
  {
    name: 'Canary token generator',
    path: 'canary-token-generator',
    description: 'Create a detectable token or fake credential with a monitoring plan.',
    category: 'social',
    keywords: ['canary', 'honeytoken', 'tripwire', 'detection', 'bait'],
    component: lazy(() => import('./social/CanaryTokenGenerator')),
  },
  {
    name: 'Pretext working-hours calculator',
    path: 'timezone-window',
    description: 'Find the overlapping business hours for a target location and your operator team.',
    category: 'social',
    keywords: ['timezone', 'hours', 'window', 'vishing', 'schedule'],
    component: lazy(() => import('./social/TimezoneWindow')),
  },

  /* ── Reporting ─────────────────────────────────────────────────────────── */
  {
    name: 'CVSS 3.1 calculator',
    path: 'cvss-calculator',
    description: 'Score a finding from the base metrics and get the vector string plus rating.',
    category: 'reporting',
    keywords: ['cvss', 'score', 'severity', 'vector', 'finding'],
    component: lazy(() => import('./reporting/CvssCalculator')),
  },
  {
    name: 'Finding writer',
    path: 'finding-writer',
    description: 'Fill a structured finding template and export clean Markdown.',
    category: 'reporting',
    keywords: ['finding', 'report', 'markdown', 'template', 'write-up'],
    component: lazy(() => import('./reporting/FindingWriter')),
  },
  {
    name: 'Rules of engagement builder',
    path: 'rules-of-engagement',
    description: 'Assemble a scope, timeline, contact and limitations block for the assessment.',
    category: 'reporting',
    keywords: ['roe', 'scope', 'engagement', 'authorisation', 'sow'],
    component: lazy(() => import('./reporting/RulesOfEngagement')),
  },
  {
    name: 'Evidence timeline',
    path: 'evidence-timeline',
    description: 'Timestamp and normalise log evidence into a consistent UTC sequence.',
    category: 'reporting',
    keywords: ['timeline', 'evidence', 'timestamp', 'utc', 'forensics'],
    component: lazy(() => import('./reporting/EvidenceTimeline')),
  },
  {
    name: 'Engagement notes',
    path: 'engagement-notes',
    description: 'Keep a persistent operator log in this browser and export it as Markdown.',
    category: 'reporting',
    keywords: ['notes', 'workspace', 'log', 'markdown', 'export'],
    component: lazy(() => import('./reporting/EngagementNotes')),
  },

  /* ── New wave: recon ───────────────────────────────────────────────────── */
  {
    name: 'DNS rebinding helper',
    path: 'dns-rebinding-helper',
    description: 'Plan a rebinding payload: zone stanza, browser harness and TTL timing model.',
    category: 'recon',
    keywords: ['dns rebinding', 'ttl', 'ssrf', 'browser', 'harness'],
    component: lazy(() => import('./recon/DnsRebindingHelper')),
  },
  {
    name: 'ASN & netblock explorer',
    path: 'asn-netblock-explorer',
    description: 'Parse ASN/prefix data, split it into /24 chunks and emit scannable target lists.',
    category: 'recon',
    keywords: ['asn', 'netblock', 'cidr', 'whois', 'radb', 'bgp'],
    component: lazy(() => import('./recon/AsnNetblockExplorer')),
  },
  {
    name: 'Wayback URL collector',
    path: 'wayback-url-collector',
    description: 'Build CDX API queries for archived URLs, then filter them for parameters and backups.',
    category: 'recon',
    keywords: ['wayback', 'cdx', 'archive', 'gau', 'urls', 'endpoints'],
    component: lazy(() => import('./recon/WaybackUrlCollector')),
  },

  /* ── New wave: web ─────────────────────────────────────────────────────── */
  {
    name: 'XS-Leak generator',
    path: 'xs-leak-generator',
    description: 'Cross-site leak payloads: frame counting, onload oracles and timing probes.',
    category: 'web',
    keywords: ['xs-leak', 'xsleak', 'corb', 'coop', 'timing', 'frame counting'],
    component: lazy(() => import('./web/XsLeakGenerator')),
  },
  {
    name: 'CSRF PoC builder',
    path: 'csrf-poc-builder',
    description: 'Emit an auto-submitting cross-site request forgery PoC and test it against each defence.',
    category: 'web',
    keywords: ['csrf', 'poc', 'samesite', 'origin', 'token'],
    component: lazy(() => import('./web/CsrfPocBuilder')),
  },
  {
    name: 'SSTI payload builder',
    path: 'ssti-payload-builder',
    description: 'Template-injection detection ladder for Jinja2, Twig, Freemarker and six more engines.',
    category: 'web',
    keywords: ['ssti', 'template injection', 'jinja2', 'twig', 'freemarker', 'rce'],
    component: lazy(() => import('./web/SstiPayloadBuilder')),
  },
  {
    name: 'GraphQL attack builder',
    path: 'graphql-attack-builder',
    description: 'Introspection, suggestion enumeration, alias overloading and depth-cost queries.',
    category: 'web',
    keywords: ['graphql', 'introspection', 'alias', 'batch', 'api'],
    component: lazy(() => import('./web/GraphqlAttackBuilder')),
  },

  /* ── New wave: tokens ──────────────────────────────────────────────────── */
  {
    name: 'OAuth flow builder',
    path: 'oauth-flow-builder',
    description: 'Assemble an OAuth2/OIDC flow and the redirect_uri bypass variants worth trying.',
    category: 'tokens',
    keywords: ['oauth', 'oidc', 'redirect_uri', 'pkce', 'id_token', 'authorization code'],
    component: lazy(() => import('./tokens/OauthFlowBuilder')),
  },

  /* ── New wave: exploit ─────────────────────────────────────────────────── */
  {
    name: 'CVE PoC scaffolder',
    path: 'cve-poc-scaffolder',
    description: 'Scaffold a reproducible proof of concept with assertions, evidence list and disclosure note.',
    category: 'exploit',
    keywords: ['cve', 'poc', 'exploit', 'reproduce', 'cvss', 'disclosure'],
    component: lazy(() => import('./exploit/CvePocScaffolder')),
  },

  /* ── New wave: credentials ─────────────────────────────────────────────── */
  {
    name: 'Password spray planner',
    path: 'password-spray-planner',
    description: 'Size a spray against a lockout policy and emit the exact tool commands and schedule.',
    category: 'credential',
    keywords: ['spray', 'lockout', 'kerbrute', 'netexec', 'hydra', 'ad'],
    component: lazy(() => import('./credential/PasswordSprayPlanner')),
  },

  /* ── New wave: crypto ──────────────────────────────────────────────────── */
  {
    name: 'Hash length extension planner',
    path: 'hash-length-extension-planner',
    description: 'Compute glue padding and the forged digest state for MD5/SHA-1 length extension.',
    category: 'crypto',
    keywords: ['length extension', 'md5', 'sha1', 'padding', 'mac'],
    component: lazy(() => import('./crypto/HashLengthExtensionPlanner')),
  },
  {
    name: 'TLS cipher suite parser',
    path: 'tls-cipher-suite-parser',
    description: 'Decode IANA and OpenSSL cipher names into key exchange, strength and weakness verdicts.',
    category: 'crypto',
    keywords: ['tls', 'cipher', 'openssl', 'aead', 'forward secrecy', 'rc4'],
    component: lazy(() => import('./crypto/TlsCipherSuiteParser')),
  },

  /* ── New wave: encoding ────────────────────────────────────────────────── */
  {
    name: 'Unicode normalisation lab',
    path: 'unicode-normalisation-lab',
    description: 'Compare NFC/NFD/NFKC/NFKD forms and see which characters survive sanitisation.',
    category: 'encoding',
    keywords: ['unicode', 'nfkc', 'normalisation', 'homoglyph', 'codepoint'],
    component: lazy(() => import('./encoding/UnicodeNormalisationLab')),
  },
  {
    name: 'Quoted-printable codec',
    path: 'quoted-printable-codec',
    description: 'Encode and decode MIME quoted-printable with soft line breaks and strict error reporting.',
    category: 'encoding',
    keywords: ['quoted printable', 'mime', 'qp', 'email', 'soft break'],
    component: lazy(() => import('./encoding/QuotedPrintableCodec')),
  },

  /* ── New wave: social ──────────────────────────────────────────────────── */
  {
    name: 'Vishing script builder',
    path: 'vishing-script-builder',
    description: 'Build a call script with escalation steps, objection handling and abort lines.',
    category: 'social',
    keywords: ['vishing', 'phone', 'script', 'pretext', 'helpdesk'],
    component: lazy(() => import('./social/VishingScriptBuilder')),
  },

  /* ── New wave: OSINT ──────────────────────────────────────────────────── */
  {
    name: 'OSINT entity pivot planner',
    path: 'osint-entity-pivot-planner',
    description: 'Turn one seed entity into a staged lookup, enrichment and correlation plan.',
    category: 'osint',
    keywords: ['osint', 'pivot', 'identity', 'rdap', 'theharvester', 'sherlock'],
    component: lazy(() => import('./osint/OsintEntityPivotPlanner')),
  },

  /* ── New wave: reporting ───────────────────────────────────────────────── */
  {
    name: 'Attack narrative timeline',
    path: 'attack-narrative-timeline',
    description: 'Order engagement actions into a MITRE-mapped narrative with evidence refs and exports.',
    category: 'reporting',
    keywords: ['timeline', 'mitre', 'att&ck', 'narrative', 'report', 'mermaid'],
    component: lazy(() => import('./reporting/AttackNarrativeTimeline')),
  },
  /* ── Recon (cont.) ─────────────────────────────────────────────────────── */
  {
    path: 'email-security-auditor',
    name: 'Email security auditor',
    description: 'Score SPF, DKIM and DMARC answers and decide whether the domain can be spoofed.',
    category: 'recon',
    keywords: ['spf', 'dmarc', 'dkim', 'email', 'spoofing', 'dns'],
    component: lazy(() => import('./recon/EmailSecurityAuditor')),
  },
  {
    path: 'shodan-query-builder',
    name: 'Shodan query builder',
    description: 'Compose Shodan, Censys and FOFA queries from facets, product filters and netblocks.',
    category: 'recon',
    keywords: ['shodan', 'censys', 'fofa', 'facet', 'exposure', 'banner'],
    component: lazy(() => import('./recon/ShodanQueryBuilder')),
  },
  {
    path: 'certificate-transparency-query',
    name: 'Certificate transparency query',
    description: 'Build crt.sh queries and reduce certificate output to unique hostnames.',
    category: 'recon',
    keywords: ['ct', 'crt.sh', 'certificate', 'subdomain', 'transparency'],
    component: lazy(() => import('./recon/CertificateTransparencyQuery')),
  },
  /* ── Web (cont.) ───────────────────────────────────────────────────────── */
  {
    path: 'authz-matrix-builder',
    name: 'Authorisation matrix builder',
    description: 'Build a role-by-endpoint access-control matrix and the request set that tests it.',
    category: 'web',
    keywords: ['idor', 'bola', 'authz', 'access control', 'matrix', 'privilege'],
    component: lazy(() => import('./web/AuthzMatrixBuilder')),
  },
  {
    path: 'file-upload-bypass-plan',
    name: 'File upload bypass plan',
    description: 'Plan extension, MIME, magic-byte and parser-confusion variants for an upload form.',
    category: 'web',
    keywords: ['upload', 'bypass', 'mime', 'magic byte', 'polyglot', 'rce'],
    component: lazy(() => import('./web/FileUploadBypassPlan')),
  },
  {
    path: 'cookie-security-analyser',
    name: 'Cookie security analyser',
    description: 'Parse Set-Cookie headers and judge flags, prefixes, scope and SameSite behaviour.',
    category: 'web',
    keywords: ['cookie', 'samesite', 'httponly', 'secure', 'session', 'prefix'],
    component: lazy(() => import('./web/CookieSecurityAnalyser')),
  },
  {
    path: 'http-smuggling-analyser',
    name: 'HTTP smuggling analyser',
    description: 'Detect Content-Length and Transfer-Encoding conflicts in a raw request and pick a probe.',
    category: 'web',
    keywords: ['smuggling', 'desync', 'content-length', 'transfer-encoding', 'request'],
    component: lazy(() => import('./web/HttpSmugglingAnalyser')),
  },
  /* ── Web tokens (cont.) ────────────────────────────────────────────────── */
  {
    path: 'api-key-pattern-detector',
    name: 'API key pattern detector',
    description: 'Scan text for AWS, GCP, Stripe, Slack and GitHub key formats with entropy scoring.',
    category: 'tokens',
    keywords: ['api key', 'secret', 'token', 'entropy', 'leak', 'detector'],
    component: lazy(() => import('./tokens/ApiKeyPatternDetector')),
  },
  /* ── Exploit (cont.) ───────────────────────────────────────────────────── */
  {
    path: 'linux-capability-explorer',
    name: 'Linux capability explorer',
    description: 'Match SUID binaries and file capabilities against known escalation paths.',
    category: 'exploit',
    keywords: ['suid', 'capabilities', 'gtfobins', 'privesc', 'linux', 'setuid'],
    component: lazy(() => import('./exploit/LinuxCapabilityExplorer')),
  },
  {
    path: 'windows-privesc-checklist',
    name: 'Windows privesc checklist',
    description: 'Work through Windows escalation checks with the command and the tell for each.',
    category: 'exploit',
    keywords: ['windows', 'privesc', 'seimpersonate', 'unquoted', 'token', 'acl'],
    component: lazy(() => import('./exploit/WindowsPrivescChecklist')),
  },
  {
    path: 'c2-profile-builder',
    name: 'C2 profile builder',
    description: 'Compose a malleable C2 profile with URIs, headers, jitter and staging blocks.',
    category: 'exploit',
    keywords: ['c2', 'profile', 'malleable', 'jitter', 'staging', 'beacon'],
    component: lazy(() => import('./exploit/C2ProfileBuilder')),
  },
  /* ── Network (cont.) ───────────────────────────────────────────────────── */
  {
    path: 'wifi-attack-planner',
    name: 'WiFi attack planner',
    description: 'Plan a WPA capture and crack run with aircrack-ng, hcxdumptool and hashcat.',
    category: 'network',
    keywords: ['wifi', 'wpa', 'handshake', 'pmkid', 'aircrack', 'wireless'],
    component: lazy(() => import('./network/WifiAttackPlanner')),
  },
  {
    path: 'packet-capture-filter-builder',
    name: 'Packet capture filter builder',
    description: 'Build and validate tcpdump BPF and tshark display filters for an engagement.',
    category: 'network',
    keywords: ['tcpdump', 'bpf', 'tshark', 'wireshark', 'filter', 'capture'],
    component: lazy(() => import('./network/PacketCaptureFilterBuilder')),
  },
  /* ── Credentials (cont.) ───────────────────────────────────────────────── */
  {
    path: 'kerberos-attack-planner',
    name: 'Kerberos attack planner',
    description: 'Plan AS-REP roasting, Kerberoasting and delegation abuse with the commands.',
    category: 'credential',
    keywords: ['kerberos', 'kerberoast', 'asrep', 'ticket', 'delegation', 'ad'],
    component: lazy(() => import('./credential/KerberosAttackPlanner')),
  },
  {
    path: 'ntlm-relay-planner',
    name: 'NTLM relay planner',
    description: 'Plan a relay path: coercion primitive, listener flags, targets and signing checks.',
    category: 'credential',
    keywords: ['ntlm', 'relay', 'responder', 'coerce', 'smb signing', 'petitpotam'],
    component: lazy(() => import('./credential/NtlmRelayPlanner')),
  },
  /* ── Crypto (cont.) ────────────────────────────────────────────────────── */
  {
    path: 'rsa-attack-planner',
    name: 'RSA attack planner',
    description: 'Test RSA parameters for small-e, common-modulus, Wiener and shared-prime weaknesses.',
    category: 'crypto',
    keywords: ['rsa', 'wiener', 'common modulus', 'fermat', 'gcd', 'public key'],
    component: lazy(() => import('./crypto/RsaAttackPlanner')),
  },
  {
    path: 'totp-generator',
    name: 'TOTP generator',
    description: 'Generate HOTP and TOTP codes from a base32 secret and test the surrounding windows.',
    category: 'crypto',
    keywords: ['totp', 'hotp', 'otp', '2fa', 'mfa', 'rfc 6238'],
    component: lazy(() => import('./crypto/TotpGenerator')),
  },
  /* ── Encoding (cont.) ──────────────────────────────────────────────────── */
  {
    path: 'base58-base85-codec',
    name: 'Base58 / Base85 codec',
    description: 'Encode and decode Base58, Base85 and Base91 with the common alphabet variants.',
    category: 'encoding',
    keywords: ['base58', 'base85', 'ascii85', 'z85', 'base91', 'codec'],
    component: lazy(() => import('./encoding/Base58Base85Codec')),
  },
  {
    path: 'string-escaping-lab',
    name: 'String escaping lab',
    description: 'Escape and unescape strings for C, JSON, SQL, XML, shell and regex contexts.',
    category: 'encoding',
    keywords: ['escape', 'unescape', 'json', 'sql', 'xml', 'shell', 'regex'],
    component: lazy(() => import('./encoding/StringEscapingLab')),
  },
  /* ── Social engineering (cont.) ────────────────────────────────────────── */
  {
    path: 'smishing-template-builder',
    name: 'Smishing template builder',
    description: 'Draft SMS lure variants with segment counts, merge fields and short-link slots.',
    category: 'social',
    keywords: ['smishing', 'sms', 'lure', 'template', 'phishing', 'link'],
    component: lazy(() => import('./social/SmishingTemplateBuilder')),
  },
  {
    path: 'usb-drop-brief',
    name: 'USB drop brief',
    description: 'Plan a USB drop assessment: bait, payload shape, persistence and beacon expectations.',
    category: 'social',
    keywords: ['usb', 'drop', 'bait', 'badusb', 'physical', 'assessment'],
    component: lazy(() => import('./social/UsbDropBrief')),
  },
  /* ── OSINT (cont.) ─────────────────────────────────────────────────────── */
  {
    path: 'social-graph-mapper',
    name: 'Social graph mapper',
    description: 'Map entities and relationships into a graph and export DOT or Mermaid.',
    category: 'osint',
    keywords: ['graph', 'entity', 'relationship', 'mermaid', 'dot', 'pivot'],
    component: lazy(() => import('./osint/SocialGraphMapper')),
  },
  {
    path: 'username-enumeration-planner',
    name: 'Username enumeration planner',
    description: 'Plan a username sweep across sites with the check URL and what a hit looks like.',
    category: 'osint',
    keywords: ['username', 'enumeration', 'sherlock', 'account', 'sweep', 'osint'],
    component: lazy(() => import('./osint/UsernameEnumerationPlanner')),
  },
  /* ── Reporting (cont.) ─────────────────────────────────────────────────── */
  {
    path: 'remediation-tracker',
    name: 'Remediation tracker',
    description: 'Track findings to remediation with owners, SLA clocks and CSV export.',
    category: 'reporting',
    keywords: ['remediation', 'sla', 'tracker', 'owner', 'status', 'csv'],
    component: lazy(() => import('./reporting/RemediationTracker')),
  },
  {
    path: 'executive-summary-generator',
    name: 'Executive summary generator',
    description: 'Turn engagement facts into an executive summary plus a short risk narrative.',
    category: 'reporting',
    keywords: ['executive', 'summary', 'narrative', 'report', 'risk', 'board'],
    component: lazy(() => import('./reporting/ExecutiveSummaryGenerator')),
  },
];

export const TOOLS_BY_PATH: Record<string, ToolDef> = Object.fromEntries(ALL_TOOLS.map((t) => [t.path, t]));

export function toolsByCategory(categoryId: string): ToolDef[] {
  return ALL_TOOLS.filter((t) => t.category === categoryId).sort((a, b) => a.name.localeCompare(b.name));
}

/** Rank tools by name → keywords → description → category. */
export function searchTools(query: string, limit = 14): ToolDef[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return ALL_TOOLS.slice(0, 14);
  const scored = ALL_TOOLS.map((tool) => {
    const name = tool.name.toLowerCase();
    const keywords = (tool.keywords ?? []).join(' ').toLowerCase();
    const description = tool.description.toLowerCase();
    let score = 0;
    if (name === needle) score += 200;
    if (name.startsWith(needle)) score += 120;
    if (name.includes(needle)) score += 70;
    if (keywords.includes(needle)) score += 40;
    if (description.includes(needle)) score += 20;
    if (tool.category.includes(needle)) score += 12;
    for (const word of needle.split(/\s+/)) {
      if (word.length > 2 && (name.includes(word) || keywords.includes(word))) score += 15;
    }
    return { tool, score };
  })
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score);
  return scored.slice(0, limit).map((s) => s.tool);
}
