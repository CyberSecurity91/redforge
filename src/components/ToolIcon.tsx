import type { LucideIcon } from 'lucide-react';
import { TOOL_ICONS } from './tool-icons';

/** Renders the icon registered for a tool path, with a sensible fallback. */
export function ToolIcon({ path, size = 13 }: { path: string; size?: number }) {
  const Icon: LucideIcon = TOOL_ICONS[path] ?? TOOL_ICONS.__default;
  return <Icon size={size} strokeWidth={1.7} />;
}
