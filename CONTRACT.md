# RedForge tool component contract

Read this fully before writing code. It is the only style guide that matters; consistency across every tool depends on it.

## Project facts

- Root: the repository checkout (all paths below are relative to it)
- React 19, react-router 8, Tailwind CSS v4, lucide-react, TypeScript 5.9 (`npx tsc --noEmit -p tsconfig.json`).
- Path alias `@/*` → `src/*`.
- Every tool file exports a **default** component taking no props:

```tsx
export default function SomeTool() { ... }
```

- The tool page shell (h1, description, breadcrumb, footer) is provided by `ToolLayout`. A tool component renders ONLY its body: a vertical stack of `<Card>`s. Never render another `<h1>`, never re-render the description.

## Mandatory imports

```tsx
import { Card, TextInput, TextArea, Select, Checkbox, Slider, NumberInput, Callout, OutputBlock, OutputField, Button, Tabs, SectionTitle, DownloadButton, KVTable, CodeBlock, CopyChip, usePersistentNumber } from '@/components/ui';
```

Everything you need is exported from `@/components/ui` — read `src/components/ui.tsx` before you start (720 lines, the authoritative prop list). Highlights:

| Component | Props |
|---|---|
| `Card` | `title?`, `action?`, `icon?`, `children`, `className?` — the container for every block |
| `TextInput` | `value`, `onChange(v)`, `placeholder?`, `label?`, `hint?`, `mono?`, `type?`, `className?` |
| `TextArea` | `value`, `onChange?`, `placeholder?`, `label?`, `hint?`, `rows?`, `mono?`, `action?`, `readOnly?` |
| `NumberInput` | `value`, `onChange(v:number)`, `min?`, `max?`, `step?`, `label?`, `hint?` |
| `Select` | `value`, `onChange(v)`, `options: {value,label}[]`, `label?`, `hint?` |
| `Checkbox` | `checked`, `onChange(v:boolean)`, `label`, `description?` |
| `Slider` | `value`, `onChange`, `min`, `max`, `step?`, `label?`, `format?(v)=>string` |
| `Callout` | `tone?: 'info'|'warn'|'danger'|'ok'`, `title?`, `children` |
| `OutputBlock` | `value`, `label?`, `rows?`, `actions?`, `empty?` — read-only output textarea with copy |
| `OutputField` | `label`, `value`, `mono?`, `placeholder?`, `action?` — single-line output with copy |
| `Button` | `children`, `onClick`, `variant?: 'default'|'primary'|'ghost'|'outline'`, `size?: 'sm'|'md'`, `icon?`, `disabled?`, `title?` |
| `Tabs` | `value`, `onChange`, `tabs: {value,label,badge?}[]` |
| `SectionTitle` | `children`, `right?` |
| `CodeBlock` | `code`, `label?`, `actions?`, `maxHeight?` |
| `KVTable` | `rows: Array<[ReactNode, ReactNode]>` |
| `DownloadButton` | `text`, `filename`, `label?` |
| `CopyChip` | `text`, `label?` |
| `usePersistentNumber(key, initial)` | returns `[value, setValue]` |

Outputs must be **copyable**: `OutputBlock` and `OutputField` include a copy button automatically. Prefer them over raw `<pre>`.

## Theme tokens

Use CSS variables, never raw colours (except semantic severity): `--card`, `--card-border`, `--input`, `--input-border`, `--accent` (red), `--accent-faded`, `--neutral-btn`, `--text`, `--text-muted`, `--text-faint`, `--ok`, `--warn`, `--info`.
Tailwind form: `bg-[var(--card)] text-[var(--text-muted)] border-[var(--card-border)]`.
Fonts: `rf-mono` class for anything monospaced. Dark mode is the default; every colour must read in both themes.

## Data & helpers already available

`src/lib/redteam-data.ts` (import from `@/lib/redteam-data`):
`SSRF_PARAMS`, `METADATA_TARGETS`, `LFI_TARGETS`, `lfiVariants(path)`, `PRIORITY_PORTS: [number,string,string][]`, `SUBDOMAIN_PREFIXES: Record<string,[string]>`, `XSS_TEMPLATES`, `WAF_TRANSFORMS: [string,(p:string)=>string][]`, `USER_AGENTS: [string,string][]`, `RULES_OF_ENGAGEMENT_SECTIONS: [string,string][]`, `PRETEXT_PROFILES: string[]`, `PHISHING_HOOKS: string[]`.

`src/lib/crypto.ts`: `utf8ToBytes`, `bytesToUtf8`, `toHex`, `fromHex`, `md5Hex`, `sha1Hex`, `sha256Hex`, `sha512Hex`/`sha384Hex` (async), `hashText(algo,'md5'|'sha1'|'sha256')`, `ntlmHash`, `hmacHex(algo,'SHA-1'|'SHA-256',key,msg)` (async), `pbkdf2Hex`, `aesGcmEncrypt/Decrypt`, `opensslEncrypt(password,plaintext)`/`opensslDecrypt` (async, `Salted__` base64), `base64FromBytes`, `bytesFromBase64`, `randomHex`.

`src/lib/encoding.ts`: `s2b`, `b2s`, `b64Encode(bytes,urlSafe?)`, `b64Decode`, `b32Encode`, `b32Decode`, `urlSafeB64`, `percentEncode`, `rot13`, `caesar`, `atbash`, `textToB64`, `uuidFromSeed`, `pemBody`, `toPem`, `firstSegment`.

`src/lib/bytes.ts`: `utf8`, `fromUtf8`, `bytesFromBase64`, `base64FromBytes`, `base32FromBytes`, `hexdump`, `shannonEntropy`, `formatBytes`, `utf16leBytes`, `fromUtf16le`, `hexNops`.

`src/lib/rng.ts`: `seeded(seed)`, `pick(rng,arr)`, `shuffle(rng,arr)`, `dedupe`, `randomInt`, `randomToken(alphabet,len)`, `randomHex`, `ALNUM`, `HEXCHARS`.

`src/tools/registry.ts`: constants `DEFAULT_CALLBACK_HOST = '10.10.14.7'`, `DEFAULT_OOB_DOMAIN = 'oast.example.com'`, `DEFAULT_TARGET = 'example.com'`, `DEFAULT_TARGET_IP = '203.0.113.10'`.

Do not invent new dependencies. Do not fetch anything at runtime; everything is computed locally and synchronously (WebCrypto async helpers are the only exception).

## Quality bar

1. **Real, working logic** — not a static list. Inputs change the output deterministically.
2. **2–5 cards per tool.** Typ pattern: settings card → results card(s) → an explanatory `Callout` where it helps.
3. Generated strings use placeholder values (`example.com`, `10.10.14.7`, `203.0.113.10`, `oast.example.com`, `TARGET`, `SESSION_ID`), never a real victim.
4. Dense, operator-grade copy: no filler, no marketing tone, British English.
5. `useMemo` for derived output; no `useEffect` chains. Guard empty input and return early with a helpful hint instead of throwing.
6. Keyboard and a11y: labels on every input, `title` on icon-only buttons. No `dangerouslySetInnerHTML` anywhere.
7. Files stay under ~350 lines. Keep one component per file plus small local sub-components.
8. Never import from another tool folder — share through `@/lib`.

## Reference shape

```tsx
import { useMemo, useState } from 'react';
import { Card, TextInput, OutputBlock, Callout, Select, Checkbox } from '@/components/ui';
import { DEFAULT_TARGET } from '@/tools/registry';

export default function ExampleTool() {
  const [target, setTarget] = useState(DEFAULT_TARGET);
  const [deep, setDeep] = useState(true);

  const output = useMemo(() => {
    if (!target.trim()) return '';
    return [`# ${target}`, deep ? '  --deep' : ''].filter(Boolean).join('\n');
  }, [target, deep]);

  return (
    <>
      <Card title="Input">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput label="Target" value={target} onChange={setTarget} mono />
          <div className="flex items-end pb-2">
            <Checkbox checked={deep} onChange={setDeep} label="Recursive" description="Walk one level of links" />
          </div>
        </div>
      </Card>

      <Card title="Output">
        <OutputBlock value={output} rows={10} label="Command" />
      </Card>
    </>
  );
}
```
