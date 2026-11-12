import { Link } from 'react-router';
import { ALL_TOOLS, CATEGORIES, toolsByCategory } from '@/tools';
import { Card, Callout } from '@/components/ui';
import { ToolIcon } from '@/components/ToolIcon';

/** Static about page — carries the "runs offline" pitch the promo card links to. */
export default function AboutPage() {
  return (
    <div className="mx-auto box-border w-full max-w-[900px] pb-16">
      <header className="pt-6 pb-2 min-[701px]:pt-10">
        <h1 className="m-0 text-[30px] leading-tight font-normal text-[var(--text)] opacity-90 min-[701px]:text-[40px]">
          About RedForge
        </h1>
        <div className="my-2.5 h-[2px] w-full bg-[#a1a1a1] opacity-20" />
        <p className="m-0 text-[14.5px] leading-relaxed text-[var(--text)] opacity-70">
          {ALL_TOOLS.length} small utilities that turn up on every engagement — payload scaffolding, hashes, header
          audits, reporting boilerplate — collected into one offline page.
        </p>
      </header>

      <div className="flex flex-col gap-4">
        <Card title="How it works">
          <ul className="m-0 list-disc space-y-1.5 pl-5 text-[13.5px] leading-relaxed text-[var(--text-muted)]">
            <li>Every tool is a static page. There is no backend, no account and no telemetry.</li>
            <li>Input is processed in the browser tab; reload and it is gone. Favourites and the theme persist locally.</li>
            <li>Generator outputs are templates with placeholder values — swap in your own host, domain and IDs.</li>
            <li>Nothing here contacts a target. Copy the output into your own tooling, under your own authorisation.</li>
          </ul>
        </Card>

        <Card title="Keyboard">
          <div className="grid grid-cols-1 gap-2 text-[13px] sm:grid-cols-2">
            {[
              ['⌘ / Ctrl + K', 'Open the command palette'],
              ['/', 'Open the command palette'],
              ['↑ / ↓', 'Move through results'],
              ['Enter', 'Open the highlighted tool'],
              ['Esc', 'Close the palette or drawer'],
            ].map(([keys, what]) => (
              <div key={keys} className="flex items-center gap-2">
                <kbd className="rf-mono shrink-0 rounded border border-[var(--input-border)] bg-[var(--input)] px-1.5 py-0.5 text-[11.5px] text-[var(--text)]">
                  {keys}
                </kbd>
                <span className="text-[var(--text-muted)]">{what}</span>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Categories">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {CATEGORIES.map((cat) => (
              <div key={cat.id} className="rounded border border-[var(--card-border)] px-3 py-2">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-[13.5px] font-medium text-[var(--text)]">{cat.title}</span>
                  <span className="text-[11px] text-[var(--text-faint)]">{toolsByCategory(cat.id).length} tools</span>
                </div>
                <p className="mt-0.5 mb-0 text-[12px] leading-snug text-[var(--text-muted)]">{cat.blurb}</p>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Scope check">
          <Callout tone="warn" title="Use on systems you are authorised to test">
            These tools generate strings; they do not validate targets. Phishing copy, payloads and scan profiles are
            templates for an engagement covered by a signed scope and rules of engagement.
          </Callout>
          <p className="mt-3 mb-0 text-[13.5px] text-[var(--text-muted)]">
            New here? Start with{' '}
            <Link to="/rules-of-engagement" className="text-[var(--accent)] no-underline hover:underline">
              rules of engagement builder
            </Link>{' '}
            and{' '}
            <Link to="/engagement-notes" className="text-[var(--accent)] no-underline hover:underline">
              engagement notes
            </Link>
            .
          </p>
        </Card>

      </div>
    </div>
  );
}
