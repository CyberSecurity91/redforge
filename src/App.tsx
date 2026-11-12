import { Routes, Route, useParams } from 'react-router';
import { Suspense, lazy, useEffect } from 'react';
import Layout from '@/components/Layout';
import { ToolLayout } from '@/components/ToolLayout';
import { TOOLS_BY_PATH } from '@/tools';
import HomePage from '@/pages/HomePage';

const AboutPage = lazy(() => import('@/pages/AboutPage'));

/** Thin wrapper: resolve the path, then mount the tool's own component. */
function ToolRoute() {
  const { toolPath } = useParams<{ toolPath: string }>();
  const tool = toolPath ? TOOLS_BY_PATH[toolPath] : undefined;

  useEffect(() => {
    if (toolPath && !tool) document.title = 'Not found - RedForge';
  }, [tool, toolPath]);

  if (!tool) return <NotFound />;
  const Body = tool.component;
  return (
    <ToolLayout tool={tool}>
      <Suspense fallback={<ToolSkeleton />}>
        <Body />
      </Suspense>
    </ToolLayout>
  );
}

function ToolSkeleton() {
  return (
    <div className="rounded border border-[var(--card-border)] bg-[var(--card)] px-6 py-10 text-center text-[13px] text-[var(--text-muted)]">
      Loading tool…
    </div>
  );
}

function NotFound() {
  return (
    <div className="mx-auto max-w-[1200px] pt-16 text-center">
      <div className="text-[64px] leading-none font-normal text-[var(--text)] opacity-20">404</div>
      <h1 className="mt-4 mb-2 text-[24px] font-normal text-[var(--text)] opacity-90">That tool does not exist</h1>
      <p className="m-0 text-[14px] text-[var(--text-muted)]">
        Check the sidebar, or press <kbd className="rf-mono rounded border border-[var(--input-border)] px-1.5">⌘K</kbd>{' '}
        to search.
      </p>
    </div>
  );
}

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/about" element={<Suspense fallback={null}><AboutPage /></Suspense>} />
        <Route path="/:toolPath" element={<ToolRoute />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Layout>
  );
}
