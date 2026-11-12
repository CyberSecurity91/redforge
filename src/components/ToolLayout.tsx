import type { ReactNode } from 'react';
import { useEffect } from 'react';
import { Link } from 'react-router';
import { ChevronRight, Monitor } from 'lucide-react';
import type { ToolDef } from '@/tools/types';
import { categoryTitle } from '@/tools/types';

/**
 * Tool page shell — mirrors it-tools: max-width 1200px, 40px padding on the
 * header, oversized light h1, 2px separator at 20% opacity, muted description,
 * then the tool body as a centred column of cards.
 */
export function ToolLayout({
  tool,
  children,
  footer,
}: {
  tool: ToolDef;
  children: ReactNode;
  footer?: ReactNode;
}) {
  useEffect(() => {
    document.title = `${tool.name} - RedForge`;
  }, [tool]);

  return (
    <div className="mx-auto box-border w-full max-w-[1200px]">
      <div className="w-full pt-4 pb-6 min-[701px]:pt-10 min-[701px]:pb-10">
        <div className="mb-2 flex items-center gap-1 text-[11.5px] text-[var(--text-muted)]">
          <Link to="/" className="transition-colors hover:text-[var(--accent)]">
            Home
          </Link>
          <ChevronRight size={11} className="opacity-60" />
          <span>{categoryTitle(tool.category)}</span>
        </div>

        <div className="flex flex-nowrap items-center justify-between gap-4">
          <h1 className="m-0 inline-flex items-center gap-2 text-[30px] leading-none font-normal tracking-[-0.01em] text-[var(--text)] opacity-90 min-[701px]:text-[40px]">
            {tool.name}
            <span title="Runs entirely in your browser — no external requests" className="inline-flex">
              <Monitor size={15} className="opacity-50" />
            </span>
          </h1>
        </div>

        <div className="my-2.5 h-[2px] w-full bg-[#a1a1a1] opacity-20" />

        <p className="m-0 text-[14.5px] leading-relaxed text-[var(--text)] opacity-70">{tool.description}</p>
      </div>

      <div className="flex flex-col gap-4">{children}</div>

      {footer !== false && (
        <div className="pt-8 pb-10 text-center text-[12px] leading-relaxed text-[var(--text)] opacity-60">
          {footer ?? (
            <>
              Everything is computed in this tab — nothing is uploaded. Outputs are inert templates: run them only
              against systems covered by a signed scope document.
            </>
          )}
        </div>
      )}
    </div>
  );
}
