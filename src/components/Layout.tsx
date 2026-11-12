import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation, useNavigate } from 'react-router';
import {
  Bookmark,
  ChevronDown,
  Command,
  ExternalLink,
  GitBranch,
  Menu,
  Moon,
  Search,
  Sun,
  X,
} from 'lucide-react';
import { CATEGORIES, categoryTitle, type ToolDef } from '@/tools/types';
import { ALL_TOOLS } from '@/tools/registry';
import { useHotkey, useLocalStorage, useMediaQuery } from '@/lib/hooks';
import { HeroGradient } from './HeroGradient';
import { ToolIcon } from './ToolIcon';
import { searchTools } from '@/tools/registry';

/* ─────────────────────────────────────────────────────────────────────────────
   Layout: 240px sticky sidebar (it-tools proportions), sticky transparent
   navbar, and the command palette. Everything is client-side.
   ──────────────────────────────────────────────────────────────────────────── */

const FAV_KEY = 'favorites';

export default function Layout({ children }: { children: ReactNode }) {
  const [collapsed, setCollapsed] = useLocalStorage('menu-collapsed', false);
  const [drawer, setDrawer] = useState(false);
  const [palette, setPalette] = useState(false);
  const isSmall = useMediaQuery('(max-width: 700px)');
  const location = useLocation();

  useHotkey('k', () => setPalette((p) => !p), { mod: true });
  useHotkey('/', () => setPalette(true));

  useEffect(() => {
    setDrawer(false);
  }, [location.pathname]);

  useEffect(() => {
    document.body.style.overflow = drawer || palette ? 'hidden' : '';
  }, [drawer, palette]);

  // A window resize past the breakpoint should never leave a stuck drawer.
  useEffect(() => {
    if (!isSmall) setDrawer(false);
  }, [isSmall]);

  const showSider = !isSmall && !collapsed;

  return (
    <div className="flex min-h-screen">
      {showSider && <Sidebar />}

      <div className="flex min-w-0 flex-1 flex-col">
        <Navbar
          onToggleMenu={() => (isSmall ? setDrawer((d) => !d) : setCollapsed((c) => !c))}
          onOpenSearch={() => setPalette(true)}
        />
        <main className="min-w-0 flex-1 p-[26px] max-[700px]:p-[13px]">{children}</main>
      </div>

      {isSmall && drawer && (
        <div className="fixed inset-x-0 top-[56px] bottom-0 z-40 overflow-y-auto bg-[var(--body)] rf-fade-up">
          <div className="flex items-center justify-end px-4 pt-2">
            <button
              onClick={() => setDrawer(false)}
              aria-label="Close menu"
              className="inline-flex h-8 w-8 items-center justify-center rounded text-[var(--text-muted)] hover:bg-[var(--neutral-btn)]"
            >
              <X size={18} />
            </button>
          </div>
          <div className="px-3 pb-24">
            <MenuTree onNavigate={() => setDrawer(false)} />
          </div>
        </div>
      )}

      <CommandPalette open={palette} onClose={() => setPalette(false)} />
    </div>
  );
}

/* ── Sidebar ─────────────────────────────────────────────────────────────── */

function Sidebar() {
  return (
    <aside className="sticky top-0 flex h-[100dvh] w-[240px] shrink-0 flex-col overflow-hidden border-r border-[var(--sider-border)] bg-[var(--sider)]">
      <Link to="/" className="relative block h-[125px] shrink-0 overflow-hidden no-underline">
        <HeroGradient />
        <div className="absolute inset-x-0 top-4 text-center text-white">
          <div className="text-[25px] leading-none font-semibold tracking-tight">REDFORGE</div>
          <div className="mx-auto mt-[7px] mb-[6px] h-[2px] w-[50px] rounded bg-white/90" />
          <div className="text-[13.5px] leading-tight opacity-95">Red-team toolkit</div>
        </div>
      </Link>

      <div className="flex-1 overflow-y-auto px-3 pt-5 pb-14">
        <MenuTree />
        <div className="mt-5 border-t border-[var(--sider-border)] pt-3 text-center text-[11.5px] leading-relaxed text-[var(--text-muted)]">
          <div className="opacity-70">v1.0.0 — offline build</div>
          <div className="opacity-70">© {new Date().getFullYear()} RedForge</div>
        </div>
      </div>
    </aside>
  );
}

function MenuTree({ onNavigate }: { onNavigate?: () => void }) {
  const [favorites] = useLocalStorage<string[]>(FAV_KEY, []);
  const [open, setOpen] = useLocalStorage<Record<string, boolean>>('menu-open', {});
  const location = useLocation();

  const byCategory = useMemo(
    () =>
      CATEGORIES.map((cat) => ({
        cat,
        tools: ALL_TOOLS.filter((t) => t.category === cat.id).sort((a, b) => a.name.localeCompare(b.name)),
      })),
    [],
  );

  const favTools = favorites
    .map((p) => ALL_TOOLS.find((t) => t.path === p))
    .filter((t): t is ToolDef => Boolean(t));

  const isOpen = (id: string) => open[id] ?? true;
  const toggle = (id: string) => setOpen({ ...open, [id]: !isOpen(id) });

  return (
    <nav className="flex flex-col gap-2.5">
      {favTools.length > 0 && (
        <Group
          label="Favorites"
          open={isOpen('__fav')}
          onToggle={() => toggle('__fav')}
          tools={favTools}
          current={location.pathname}
          onNavigate={onNavigate}
          icon={<Bookmark size={11} />}
        />
      )}
      {byCategory.map(({ cat, tools }) =>
        tools.length === 0 ? null : (
          <Group
            key={cat.id}
            label={cat.title}
            open={isOpen(cat.id)}
            onToggle={() => toggle(cat.id)}
            tools={tools}
            current={location.pathname}
            onNavigate={onNavigate}
          />
        ),
      )}
    </nav>
  );
}

function Group({
  label,
  open,
  onToggle,
  tools,
  current,
  onNavigate,
  icon,
}: {
  label: string;
  open: boolean;
  onToggle: () => void;
  tools: ToolDef[];
  current: string;
  onNavigate?: () => void;
  icon?: ReactNode;
}) {
  return (
    <div>
      <button
        type="button"
        onClick={onToggle}
        className="mb-0.5 flex w-full items-center gap-1 rounded px-2 py-1 text-left text-[11.5px] font-semibold tracking-[0.04em] text-[var(--text-muted)] uppercase transition-colors hover:text-[var(--text)]"
      >
        {icon ?? (
          <ChevronDown
            size={11}
            className={`transition-transform duration-150 ${open ? '' : '-rotate-90'}`}
          />
        )}
        <span className="truncate">{label}</span>
        <span className="ml-auto shrink-0 text-[10px] font-normal opacity-50">{tools.length}</span>
      </button>

      {open && (
        <ul className="m-0 list-none space-y-px p-0">
          {tools.map((tool) => {
            const active = current === `/${tool.path}`;
            return (
              <li key={tool.path}>
                <Link
                  to={`/${tool.path}`}
                  onClick={onNavigate}
                  title={tool.description}
                  className={`flex items-center gap-2 rounded px-2 py-[5px] text-[13px] no-underline transition-colors ${
                    active
                      ? 'bg-[var(--accent-faded)] text-[var(--accent)]'
                      : 'text-[var(--text)] opacity-85 hover:bg-[var(--neutral-btn)] hover:text-[var(--accent)] hover:opacity-100'
                  }`}
                >
                  <span className="w-3.5 shrink-0 text-center text-[var(--text-muted)] opacity-70">
                    <ToolIcon path={tool.path} />
                  </span>
                  <span className="truncate">{tool.name}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

/* ── Navbar ──────────────────────────────────────────────────────────────── */

function Navbar({ onToggleMenu, onOpenSearch }: { onToggleMenu: () => void; onOpenSearch: () => void }) {
  const [theme, setTheme] = useTheme();
  const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);

  return (
    <div className="sticky top-0 z-30 flex h-[56px] items-center gap-1.5 bg-[var(--body)] px-[18px] max-[700px]:px-2.5 min-[701px]:h-[64px]">
      <NavIcon title="Toggle menu" onClick={onToggleMenu}>
        <Menu size={21} />
      </NavIcon>
      <NavIcon title="Home" to="/">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
          <polyline points="9 22 9 12 15 12 15 22" />
        </svg>
      </NavIcon>

      <button
        type="button"
        onClick={onOpenSearch}
        className="mx-1 flex h-9 w-full max-w-[620px] items-center gap-2 rounded border border-[var(--input-border)] bg-[var(--input)] px-3 text-[13px] text-[var(--text-muted)] transition-colors hover:border-[var(--accent)]"
      >
        <Search size={14} className="opacity-70" />
        <span>Search</span>
        <kbd className="rf-mono ml-auto rounded border border-[var(--input-border)] bg-[var(--card)] px-1.5 py-px text-[10px] text-[var(--text-faint)]">
          {isMac ? '⌘' : 'Ctrl'} + K
        </kbd>
      </button>

      <div className="ml-auto flex items-center gap-0.5">
        <NavIcon title="Source" href="https://github.com/redforge/toolkit">
          <GitBranch size={18} />
        </NavIcon>
        <NavIcon title="About" to="/about">
          <ExternalLink size={17} />
        </NavIcon>
        <NavIcon title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'} onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
          {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
        </NavIcon>
        <Link
          to="/about"
          className="ml-1.5 hidden h-9 items-center gap-1.5 rounded-full bg-[var(--accent)] px-4 text-[12.5px] font-semibold text-white no-underline transition-[padding] hover:px-5 min-[701px]:inline-flex"
        >
          OPSEC mode
        </Link>
      </div>
    </div>
  );
}

function useTheme() {
  const [theme, setTheme] = useLocalStorage<'light' | 'dark'>('theme', 'dark');
  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle('dark', theme === 'dark');
    root.style.colorScheme = theme;
  }, [theme]);
  return [theme, setTheme] as const;
}

function NavIcon({ title, to, href, onClick, children }: { title: string; to?: string; href?: string; onClick?: () => void; children: ReactNode }) {
  const cls =
    'inline-flex h-9 w-9 shrink-0 items-center justify-center rounded text-[var(--text-muted)] no-underline transition-colors hover:bg-[var(--neutral-btn)] hover:text-[var(--accent)]';
  if (to) {
    return (
      <Link to={to} title={title} aria-label={title} className={cls}>
        {children}
      </Link>
    );
  }
  if (href) {
    return (
      <a href={href} target="_blank" rel="noopener noreferrer" title={title} aria-label={title} className={cls}>
        {children}
      </a>
    );
  }
  return (
    <button type="button" title={title} aria-label={title} onClick={onClick} className={cls}>
      {children}
    </button>
  );
}

/* ── Command palette ─────────────────────────────────────────────────────── */

function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (open) {
      setQ('');
      setActive(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const results = useMemo(() => searchTools(q), [q]);

  useEffect(() => setActive(0), [q]);

  if (!open) return null;

  const go = (tool: ToolDef) => {
    onClose();
    navigate(`/${tool.path}`);
  };

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center bg-black/50 px-4 pt-[10vh] backdrop-blur-[2px]"
      onMouseDown={onClose}
    >
      <div
        className="rf-fade-up w-full max-w-[640px] overflow-hidden rounded-lg border border-[var(--card-border)] bg-[var(--card)] shadow-2xl"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 border-b border-[var(--card-border)] px-4">
          <Search size={15} className="text-[var(--text-faint)]" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') onClose();
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setActive((a) => Math.min(a + 1, results.length - 1));
              }
              if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActive((a) => Math.max(a - 1, 0));
              }
              if (e.key === 'Enter' && results[active]) go(results[active]);
            }}
            placeholder={`Search ${ALL_TOOLS.length} red-team tools…`}
            className="h-12 flex-1 bg-transparent text-[14px] text-[var(--text)] outline-none placeholder:text-[var(--text-faint)]"
          />
          <kbd className="rf-mono rounded border border-[var(--input-border)] px-1.5 py-px text-[10px] text-[var(--text-faint)]">esc</kbd>
        </div>

        <div className="max-h-[54vh] overflow-y-auto py-1">
          {results.length === 0 && (
            <div className="px-4 py-8 text-center text-[13px] text-[var(--text-muted)]">
              <Command size={18} className="mx-auto mb-2 opacity-40" />
              No tool matches “{q}”
            </div>
          )}
          {results.map((tool, i) => (
            <button
              key={tool.path}
              type="button"
              onMouseEnter={() => setActive(i)}
              onClick={() => go(tool)}
              className={`flex w-full items-center gap-3 px-4 py-2 text-left transition-colors ${
                i === active ? 'bg-[var(--accent-faded)]' : ''
              }`}
            >
              <span className="flex h-5 w-5 shrink-0 items-center justify-center text-[var(--text-muted)]">
                <ToolIcon path={tool.path} />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[13.5px] text-[var(--text)]">{tool.name}</span>
                <span className="block truncate text-[11.5px] text-[var(--text-muted)]">{tool.description}</span>
              </span>
              <span className="shrink-0 rounded bg-[var(--neutral-btn)] px-1.5 py-0.5 text-[10px] text-[var(--text-faint)]">
                {categoryTitle(tool.category)}
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

