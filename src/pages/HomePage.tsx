import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router';
import { ArrowRight, Clock, Heart } from 'lucide-react';
import { ALL_TOOLS, type ToolDef } from '@/tools';
import { useLocalStorage } from '@/lib/hooks';
import { categoryTitle } from '@/tools/types';
import { ToolIcon } from '@/components/ToolIcon';

/**
 * Home page — the it-tools rhythm: hero blurb, tool card grid in batches of 24,
 * a promo card at the end. Search lives in the navbar palette.
 */
const BATCH = 24;

export default function HomePage() {
  const [favorites, setFavorites] = useLocalStorage<string[]>('favorites', []);
  const [batched, setBatched] = useState(BATCH);

  useEffect(() => {
    document.title = 'RedForge - Offensive security toolkit';
  }, []);

  const favTools = useMemo(
    () => favorites.map((p) => ALL_TOOLS.find((t) => t.path === p)).filter((t): t is ToolDef => Boolean(t)),
    [favorites],
  );

  const visible = ALL_TOOLS.slice(0, batched);
  const remaining = ALL_TOOLS.length - visible.length;

  const toggleFav = (path: string) =>
    setFavorites(favorites.includes(path) ? favorites.filter((p) => p !== path) : [...favorites, path]);

  return (
    <div className="mx-auto box-border w-full max-w-[1200px] pb-10">
      <header className="pt-6 pb-2 min-[701px]:pt-[50px]">
        <h1 className="m-0 text-[28px] leading-tight font-normal text-[var(--text)] opacity-90 min-[701px]:text-[38px]">
          The offensive security toolkit
        </h1>
        <div className="my-2.5 h-[2px] w-full bg-[#a1a1a1] opacity-20" />
        <p className="m-0 max-w-[760px] text-[14.5px] leading-relaxed text-[var(--text)] opacity-70">
          {ALL_TOOLS.length} hand-built tools for reconnaissance, exploitation, credential work and reporting — the
          scribbly bits of an engagement that are easier to generate than to remember. Everything runs in this tab.
        </p>
      </header>

      {favTools.length > 0 && (
        <>
          <SectionHeading icon={<Heart size={15} />}>Favorites</SectionHeading>
          <Grid tools={favTools} favorites={favorites} onToggleFav={toggleFav} />
        </>
      )}

      <SectionHeading icon={<Clock size={15} />}>All the tools</SectionHeading>
      <Grid tools={visible} favorites={favorites} onToggleFav={toggleFav} />

      {remaining > 0 && (
        <div className="mt-6 flex justify-center">
          <button
            type="button"
            onClick={() => setBatched((b) => b + BATCH)}
            className="inline-flex items-center gap-2 rounded border border-[var(--card-border)] bg-[var(--card)] px-4 py-2 text-[13px] text-[var(--text-muted)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
          >
            Load {Math.min(BATCH, remaining)} more tools ({visible.length}/{ALL_TOOLS.length})
          </button>
        </div>
      )}

      <PromoCard />
    </div>
  );
}

function SectionHeading({ children, icon }: { children: React.ReactNode; icon: React.ReactNode }) {
  return (
    <h3 className="mt-[26px] mb-[10px] flex items-center gap-2 text-[15px] font-medium text-[var(--text-muted)]">
      <span className="opacity-70">{icon}</span>
      {children}
    </h3>
  );
}

function Grid({
  tools,
  favorites,
  onToggleFav,
}: {
  tools: ToolDef[];
  favorites: string[];
  onToggleFav: (path: string) => void;
}) {
  return (
    <div className="grid grid-cols-1 gap-[12px] sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4">
      {tools.map((tool) => (
        <ToolCard
          key={tool.path}
          tool={tool}
          favorite={favorites.includes(tool.path)}
          onToggleFav={() => onToggleFav(tool.path)}
        />
      ))}
    </div>
  );
}

function ToolCard({ tool, favorite, onToggleFav }: { tool: ToolDef; favorite: boolean; onToggleFav: () => void }) {
  return (
    <div className="group relative flex flex-col rounded border-2 border-[var(--card-border)] bg-[var(--card)] px-[18px] py-4 transition-colors duration-150 hover:border-[var(--accent)]">
      <Link to={`/${tool.path}`} className="min-w-0 flex-1 no-underline">
        <span className="inline-flex text-[var(--accent)] opacity-85 transition-opacity group-hover:opacity-100">
          <ToolIcon path={tool.path} size={40} />
        </span>
        <div className="mt-[10px] truncate text-[16px] font-medium text-[var(--text)] group-hover:text-[var(--accent)]">
          {tool.name}
        </div>
        <div className="mt-1 line-clamp-2 text-[12.5px] leading-snug text-[var(--text-muted)]">{tool.description}</div>
      </Link>

      <div className="mt-2 flex items-center justify-between gap-2">
        <span className="rounded bg-[var(--neutral-btn)] px-1.5 py-[1px] text-[10.5px] tracking-wide text-[var(--text-faint)] uppercase">
          {categoryTitle(tool.category)}
        </span>
      </div>

      <button
        type="button"
        onClick={(e) => {
          e.preventDefault();
          onToggleFav();
        }}
        aria-label={favorite ? 'Remove from favorites' : 'Add to favorites'}
        className={`absolute top-2.5 right-2.5 inline-flex h-6 w-6 items-center justify-center rounded transition-opacity ${
          favorite
            ? 'text-[var(--accent)] opacity-100'
            : 'text-[var(--text-faint)] opacity-0 group-hover:opacity-100 hover:text-[var(--accent)]'
        }`}
      >
        <Heart size={14} fill={favorite ? 'currentColor' : 'none'} />
      </button>
    </div>
  );
}

function PromoCard() {
  return (
    <div
      className="mt-8 flex flex-wrap items-center justify-between gap-4 rounded px-6 py-5 text-white"
      style={{ background: 'linear-gradient(48deg, #4a1013 0%, #8f1622 46%, #e11d2a 100%)' }}
    >
      <div>
        <div className="text-[17px] font-semibold">Keep the toolkit offline</div>
        <div className="mt-1 max-w-[620px] text-[13px] leading-relaxed opacity-85">
          Add RedForge to your dock and it keeps working with no network. Nothing you paste is transmitted, stored or
          logged — refresh and it is gone.
        </div>
      </div>
      <Link
        to="/about"
        className="inline-flex items-center gap-1.5 rounded bg-white/15 px-4 py-2 text-[13px] font-semibold text-white no-underline transition-colors hover:bg-white/25"
      >
        How it works
        <ArrowRight size={14} />
      </Link>
    </div>
  );
}
