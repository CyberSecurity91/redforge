import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Check, Copy, Download, Info, RefreshCw, Search, ShieldAlert, Trash2, TriangleAlert, Upload } from 'lucide-react';
import { useCopy } from '@/lib/hooks';

/* ── Buttons ─────────────────────────────────────────────────────────────── */

type ButtonVariant = 'default' | 'primary' | 'ghost' | 'outline';

export function Button({
  children,
  onClick,
  variant = 'default',
  size = 'md',
  icon,
  className = '',
  disabled,
  title,
  type = 'button',
}: {
  children?: ReactNode;
  onClick?: () => void;
  variant?: ButtonVariant;
  size?: 'sm' | 'md';
  icon?: ReactNode;
  className?: string;
  disabled?: boolean;
  title?: string;
  type?: 'button' | 'submit';
}) {
  const sizing = size === 'sm' ? 'h-[30px] px-3 text-[12.5px] gap-1.5' : 'h-9 px-4 text-[13.5px] gap-2';
  const variants: Record<ButtonVariant, string> = {
    default:
      'border border-[var(--card-border)] bg-[var(--card)] text-[var(--text)] hover:border-[var(--accent)] hover:text-[var(--accent)]',
    primary: 'border border-transparent bg-[var(--accent)] text-white hover:brightness-110',
    ghost: 'border border-transparent text-[var(--text-muted)] hover:bg-[var(--neutral-btn)] hover:text-[var(--text)]',
    outline:
      'border border-[var(--card-border)] bg-transparent text-[var(--text)] hover:border-[var(--accent)] hover:text-[var(--accent)]',
  };
  return (
    <button
      type={type}
      title={title}
      disabled={disabled}
      onClick={onClick}
      className={`inline-flex shrink-0 items-center justify-center rounded font-medium transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-50 ${sizing} ${variants[variant]} ${className}`}
    >
      {icon}
      {children}
    </button>
  );
}

export function IconButton({
  onClick,
  title,
  children,
  active,
  className = '',
}: {
  onClick?: () => void;
  title: string;
  children: ReactNode;
  active?: boolean;
  className?: string;
}) {
  return (
    <button
      type="button"
      title={title}
      aria-label={title}
      onClick={onClick}
      className={`inline-flex h-7 w-7 shrink-0 items-center justify-center rounded transition-colors ${
        active
          ? 'bg-[var(--accent-faded)] text-[var(--accent)]'
          : 'text-[var(--text-faint)] hover:bg-[var(--neutral-btn)] hover:text-[var(--text)]'
      } ${className}`}
    >
      {children}
    </button>
  );
}

/* ── Form fields ─────────────────────────────────────────────────────────── */

export function Label({ children, hint }: { children: ReactNode; hint?: ReactNode }) {
  return (
    <div className="mb-1.5 flex items-baseline justify-between gap-3">
      <span className="text-[13px] font-medium text-[var(--text)]">{children}</span>
      {hint !== undefined && <span className="text-[11.5px] text-[var(--text-faint)]">{hint}</span>}
    </div>
  );
}

export const inputCls =
  'w-full rounded border border-[var(--input-border)] bg-[var(--input)] px-3 py-2 text-[13.5px] text-[var(--text)] outline-none transition-colors placeholder:text-[var(--text-faint)] focus:border-[var(--accent)]';

export function TextInput({
  value,
  onChange,
  placeholder,
  label,
  hint,
  mono,
  type = 'text',
  className = '',
  disabled,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  label?: string;
  hint?: ReactNode;
  mono?: boolean;
  type?: string;
  className?: string;
  disabled?: boolean;
}) {
  return (
    <div className={className}>
      {label && <Label hint={hint}>{label}</Label>}
      <input
        type={type}
        value={value}
        disabled={disabled}
        spellCheck={false}
        autoComplete="off"
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={`${inputCls} ${mono ? 'rf-mono text-[13px]' : ''}`}
      />
    </div>
  );
}

export function NumberInput({
  value,
  onChange,
  min,
  max,
  step = 1,
  label,
  hint,
  className = '',
}: {
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
  step?: number;
  label?: string;
  hint?: ReactNode;
  className?: string;
}) {
  return (
    <div className={className}>
      {label && <Label hint={hint}>{label}</Label>}
      <input
        type="number"
        value={Number.isFinite(value) ? value : ''}
        min={min}
        max={max}
        step={step}
        onChange={(e) => onChange(Number(e.target.value))}
        className={`${inputCls} rf-mono text-[13px]`}
      />
    </div>
  );
}

export function TextArea({
  value,
  onChange,
  placeholder,
  label,
  hint,
  rows = 6,
  mono = true,
  action,
  className = '',
  readOnly,
}: {
  value: string;
  onChange?: (v: string) => void;
  placeholder?: string;
  label?: string;
  hint?: ReactNode;
  rows?: number;
  mono?: boolean;
  action?: ReactNode;
  className?: string;
  readOnly?: boolean;
}) {
  return (
    <div className={className}>
      {(label || action) && (
        <div className="mb-1.5 flex min-h-[20px] items-center justify-between gap-3">
          <span className="text-[13px] font-medium text-[var(--text)]">{label}</span>
          <div className="flex items-center gap-1">{action}</div>
        </div>
      )}
      {hint && <p className="mt-0 mb-1.5 text-[11.5px] leading-relaxed text-[var(--text-faint)]">{hint}</p>}
      <textarea
        value={value}
        rows={rows}
        spellCheck={false}
        readOnly={readOnly}
        onChange={(e) => onChange?.(e.target.value)}
        placeholder={placeholder}
        className={`${inputCls} resize-y leading-relaxed ${mono ? 'rf-mono text-[12.5px]' : ''}`}
      />
    </div>
  );
}

export function Select<T extends string | number>({
  value,
  onChange,
  options,
  label,
  hint,
  className = '',
}: {
  value: T;
  onChange: (v: T) => void;
  options: Array<{ value: T; label: string }>;
  label?: string;
  hint?: ReactNode;
  className?: string;
}) {
  return (
    <div className={className}>
      {label && <Label hint={hint}>{label}</Label>}
      <select
        value={value}
        onChange={(e) => {
          const raw = e.target.value;
          const found = options.find((o) => String(o.value) === raw);
          onChange((found ? found.value : (raw as T)) as T);
        }}
        className={`${inputCls} cursor-pointer appearance-none pr-8`}
        style={{
          backgroundImage:
            "url(\"data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23888' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E\")",
          backgroundRepeat: 'no-repeat',
          backgroundPosition: 'right 10px center',
        }}
      >
        {options.map((o) => (
          <option key={String(o.value)} value={String(o.value)}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

export function Checkbox({
  checked,
  onChange,
  label,
  description,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  description?: string;
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className="group flex w-full items-start gap-2 text-left"
    >
      <span
        className={`mt-px flex h-[15px] w-[15px] shrink-0 items-center justify-center rounded-[3px] border transition-colors ${
          checked ? 'border-[var(--accent)] bg-[var(--accent)]' : 'border-[var(--input-border)] bg-transparent'
        }`}
      >
        {checked && <Check size={11} className="text-white" strokeWidth={3} />}
      </span>
      <span className="min-w-0">
        <span className="block text-[13px] leading-4 text-[var(--text)] group-hover:text-[var(--accent)]">{label}</span>
        {description && (
          <span className="mt-0.5 block text-[11.5px] leading-snug text-[var(--text-faint)]">{description}</span>
        )}
      </span>
    </button>
  );
}

export function Slider({
  value,
  onChange,
  min,
  max,
  step = 1,
  label,
  format,
}: {
  value: number;
  onChange: (v: number) => void;
  min: number;
  max: number;
  step?: number;
  label?: string;
  format?: (v: number) => string;
}) {
  return (
    <div>
      {label && <Label hint={format ? format(value) : String(value)}>{label}</Label>}
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="rf-range w-full cursor-pointer"
      />
    </div>
  );
}

/* ── Containers ──────────────────────────────────────────────────────────── */

export function Card({
  title,
  children,
  className = '',
  action,
  icon,
}: {
  title?: ReactNode;
  children: ReactNode;
  className?: string;
  action?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <section
      className={`rounded border border-[var(--card-border)] bg-[var(--card)] px-6 py-5 max-[700px]:px-4 ${className}`}
    >
      {(title || action) && (
        <div className="mb-4 flex items-center justify-between gap-3">
          <h2 className="m-0 flex items-center gap-2 text-[15px] font-medium text-[var(--text)]">
            {icon}
            {title}
          </h2>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export function Callout({
  tone = 'info',
  title,
  children,
}: {
  tone?: 'info' | 'warn' | 'danger' | 'ok';
  title?: ReactNode;
  children?: ReactNode;
}) {
  const map = {
    info: { bar: 'var(--info)', Icon: Info, color: 'text-[var(--info)]' },
    warn: { bar: 'var(--warn)', Icon: TriangleAlert, color: 'text-[var(--warn)]' },
    danger: { bar: 'var(--accent)', Icon: ShieldAlert, color: 'text-[var(--accent)]' },
    ok: { bar: 'var(--ok)', Icon: Check, color: 'text-[var(--ok)]' },
  }[tone];
  const { Icon } = map;
  return (
    <div
      className="rounded-r border border-l-2 border-[var(--card-border)] bg-[var(--neutral-btn)] px-3 py-2.5 text-[12.5px] leading-relaxed"
      style={{ borderLeftColor: map.bar }}
    >
      {title && (
        <div className={`mb-1 flex items-center gap-1.5 font-medium ${map.color}`}>
          <Icon size={13} />
          {title}
        </div>
      )}
      <div className="text-[var(--text-muted)]">{children}</div>
    </div>
  );
}

/** Section heading used inside a multi-part tool body. */
export function SectionTitle({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mt-1 mb-2 flex items-center justify-between gap-2">
      <h3 className="m-0 text-[13px] font-semibold tracking-wide text-[var(--text-muted)] uppercase">{children}</h3>
      {right}
    </div>
  );
}

/* ── Output surfaces ─────────────────────────────────────────────────────── */

function Copyable({ value, keyName }: { value: string; keyName: string }) {
  const { copy, isCopied } = useCopy();
  return (
    <button
      type="button"
      onClick={() => copy(value, keyName)}
      disabled={!value}
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] transition-colors disabled:opacity-40 ${
        isCopied(keyName) ? 'text-[var(--ok)]' : 'text-[var(--text-faint)] hover:text-[var(--accent)]'
      }`}
    >
      {isCopied(keyName) ? <Check size={11} /> : <Copy size={11} />}
      {isCopied(keyName) ? 'Copied' : 'Copy'}
    </button>
  );
}

export function OutputField({
  label,
  value,
  mono = true,
  placeholder,
  action,
}: {
  label: string;
  value: string;
  mono?: boolean;
  placeholder?: string;
  action?: ReactNode;
}) {
  return (
    <div>
      <div className="mb-1.5 flex min-h-[20px] items-center justify-between gap-3">
        <span className="text-[13px] font-medium text-[var(--text)]">{label}</span>
        <div className="flex items-center gap-1">
          {action}
          <Copyable value={value} keyName={label} />
        </div>
      </div>
      <div
        className={`max-h-[220px] overflow-y-auto rounded border border-[var(--input-border)] bg-[var(--input)] px-3 py-2 text-[12.5px] break-all whitespace-pre-wrap ${
          mono ? 'rf-mono' : ''
        }`}
      >
        {value || <span className="text-[var(--text-faint)]">{placeholder ?? '—'}</span>}
      </div>
    </div>
  );
}

export function OutputBlock({
  value,
  label = 'Output',
  rows = 10,
  actions,
  empty = 'Nothing to show yet — adjust the inputs above.',
}: {
  value: string;
  label?: string;
  rows?: number;
  actions?: ReactNode;
  empty?: string;
}) {
  return (
    <div>
      <div className="mb-1.5 flex min-h-[20px] items-center justify-between gap-2">
        <span className="text-[13px] font-medium text-[var(--text)]">{label}</span>
        <div className="flex items-center gap-1">
          {actions}
          <Copyable value={value} keyName={label} />
        </div>
      </div>
      <textarea
        readOnly
        rows={rows}
        value={value}
        placeholder={empty}
        className={`${inputCls} rf-mono resize-y text-[12.5px] leading-relaxed`}
      />
    </div>
  );
}

/* ── Utility components ──────────────────────────────────────────────────── */

export function CopyChip({ text, label }: { text: string; label?: string }) {
  const { copy, isCopied } = useCopy();
  return (
    <button
      type="button"
      onClick={() => copy(text, text)}
      className="group inline-flex max-w-full items-center gap-1.5 rounded border border-[var(--card-border)] bg-[var(--card)] px-2 py-[3px] text-[12px] transition-colors hover:border-[var(--accent)]"
      title={`Copy ${text}`}
    >
      <span className="rf-mono truncate text-[var(--text)]">{label ?? text}</span>
      {isCopied(text) ? (
        <Check size={11} className="shrink-0 text-[var(--ok)]" />
      ) : (
        <Copy size={11} className="shrink-0 text-[var(--text-faint)] group-hover:text-[var(--accent)]" />
      )}
    </button>
  );
}

export function DownloadButton({ text, filename, label = 'Download' }: { text: string; filename: string; label?: string }) {
  const download = () => {
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };
  return (
    <Button size="sm" variant="ghost" icon={<Download size={13} />} onClick={download} title={`Download ${filename}`}>
      {label}
    </Button>
  );
}

export function UploadButton({
  onFile,
  label = 'Load file',
  accept,
}: {
  onFile: (text: string, name: string) => void;
  label?: string;
  accept?: string;
}) {
  return (
    <label className="inline-flex h-[30px] cursor-pointer items-center gap-1.5 rounded px-2.5 text-[12.5px] text-[var(--text-muted)] transition-colors hover:bg-[var(--neutral-btn)] hover:text-[var(--text)]">
      <Upload size={13} />
      {label}
      <input
        type="file"
        accept={accept}
        className="hidden"
        onChange={async (e) => {
          const file = e.target.files?.[0];
          if (!file) return;
          onFile(await file.text(), file.name);
          e.target.value = '';
        }}
      />
    </label>
  );
}

export function ClearButton({ onClick, label = 'Clear' }: { onClick: () => void; label?: string }) {
  return (
    <IconButton title={label} onClick={onClick}>
      <Trash2 size={13} />
    </IconButton>
  );
}

export function RefreshButton({ onClick, label = 'Regenerate' }: { onClick: () => void; label?: string }) {
  return (
    <Button size="sm" variant="ghost" icon={<RefreshCw size={13} />} onClick={onClick}>
      {label}
    </Button>
  );
}

export function Tabs<T extends string>({
  value,
  onChange,
  tabs,
}: {
  value: T;
  onChange: (v: T) => void;
  tabs: Array<{ value: T; label: string; badge?: string | number }>;
}) {
  return (
    <div className="inline-flex flex-wrap gap-1 rounded bg-[var(--neutral-btn)] p-1">
      {tabs.map((t) => (
        <button
          key={t.value}
          type="button"
          onClick={() => onChange(t.value)}
          className={`inline-flex items-center gap-1.5 rounded px-3 py-1 text-[12.5px] font-medium transition-colors ${
            value === t.value
              ? 'bg-[var(--card)] text-[var(--text)] shadow-sm'
              : 'text-[var(--text-muted)] hover:text-[var(--text)]'
          }`}
        >
          {t.label}
          {t.badge !== undefined && (
            <span className="rounded-full bg-[var(--neutral-btn)] px-1.5 text-[10px] text-[var(--text-faint)]">
              {t.badge}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

export function SearchInput({
  value,
  onChange,
  placeholder,
  className = '',
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
}) {
  return (
    <div className={`relative ${className}`}>
      <Search size={13} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-[var(--text-faint)]" />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder ?? 'Filter…'}
        className={`${inputCls} h-[30px] py-1 pl-7 text-[12.5px]`}
      />
    </div>
  );
}

/** Two-column key/value table used across the recon tools. */
export function KVTable({ rows }: { rows: Array<[ReactNode, ReactNode]> }) {
  return (
    <div className="overflow-hidden rounded border border-[var(--card-border)]">
      <table className="w-full text-[12.5px]">
        <tbody>
          {rows.map(([k, v], i) => (
            <tr key={i} className={i % 2 ? 'bg-[var(--neutral-btn)]' : ''}>
              <th className="w-[38%] px-3 py-1.5 text-left align-top font-medium text-[var(--text-muted)]">{k}</th>
              <td
                className="rf-mono px-3 py-1.5 align-top text-[var(--text)]"
                style={{ overflowWrap: 'anywhere' }}
              >
                {v}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Readable code panel with a copy affordance — used for generated commands. */
export function CodeBlock({
  code,
  label,
  actions,
  maxHeight = 340,
}: {
  code: string;
  label?: string;
  actions?: ReactNode;
  maxHeight?: number;
}) {
  return (
    <div>
      {(label || actions) && (
        <div className="mb-1.5 flex min-h-[20px] items-center justify-between gap-2">
          <span className="text-[13px] font-medium text-[var(--text)]">{label}</span>
          <div className="flex items-center gap-1">
            {actions}
            <Copyable value={code} keyName={label ?? 'code'} />
          </div>
        </div>
      )}
      <pre
        className="rf-mono m-0 overflow-auto rounded border border-[var(--input-border)] bg-[var(--input)] px-3 py-2.5 text-[12.5px] leading-[1.65] text-[var(--text)]"
        style={{ maxHeight }}
      >
        <code>{code || '\u00a0'}</code>
      </pre>
    </div>
  );
}

/* ── Hooks ───────────────────────────────────────────────────────────────── */

/** Number persisted under `redforge:num:<key>` — survives tab switches. */
export function usePersistentNumber(key: string, initial: number) {
  const [v, setV] = useState(() => {
    try {
      const raw = localStorage.getItem(`redforge:num:${key}`);
      return raw === null ? initial : Number(raw);
    } catch {
      return initial;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(`redforge:num:${key}`, String(v));
    } catch {
      /* storage blocked */
    }
  }, [key, v]);
  return [v, setV] as const;
}

/** Memoised compute that captures errors instead of blowing up the page. */
export function useComputed<T>(fn: () => T, deps: unknown[]): { value: T | undefined; error: string | null } {
  return useMemo(() => {
    try {
      return { value: fn(), error: null };
    } catch (e) {
      return { value: undefined, error: e instanceof Error ? e.message : String(e) };
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}

/** Copy helper re-exported so tools only import from one place. */
export { useCopy };

/** Adds a `.dark`-aware class to an element once, avoiding layout thrash. */
export function useStableCallback<T extends (...args: never[]) => unknown>(fn: T): T {
  const ref = useRef(fn);
  ref.current = fn;
  return useCallback(((...args: never[]) => ref.current(...args)) as T, []);
}
