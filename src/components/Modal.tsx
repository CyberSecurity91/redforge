import { useEffect, useRef, useState, type ReactNode } from 'react';
import { X } from 'lucide-react';
import { IconButton } from './ui';

/**
 * Native <dialog> based modal. Gives us focus trapping, Escape handling and a
 * real backdrop with no extra dependency build-out.
 */
export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  width = 640,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  width?: number;
}) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (open && !el.open) el.showModal();
    if (!open && el.open) el.close();
  }, [open]);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const onCancel = (e: Event) => {
      e.preventDefault();
      onClose();
    };
    el.addEventListener('cancel', onCancel);
    return () => el.removeEventListener('cancel', onCancel);
  }, [onClose]);

  return (
    <dialog
      ref={ref}
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
      className="rf-dialog m-auto max-h-[85vh] w-[calc(100vw-2rem)] overflow-hidden rounded-lg border border-[var(--card-border)] bg-[var(--card)] p-0 text-[var(--text)] backdrop:bg-black/50 backdrop:backdrop-blur-sm"
      style={{ maxWidth: width }}
    >
      <div className="flex items-center justify-between gap-3 border-b border-[var(--card-border)] px-4 py-3">
        <div className="text-[14px] font-medium">{title}</div>
        <IconButton title="Close" onClick={onClose}>
          <X size={15} />
        </IconButton>
      </div>
      <div className="max-h-[70vh] overflow-y-auto px-4 py-4">{children}</div>
      {footer ? <div className="border-t border-[var(--card-border)] px-4 py-3">{footer}</div> : null}
    </dialog>
  );
}

/** Tiny delay helper for UI-side "simulate" affordances. */
export function useClipboardToast() {
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    if (!msg) return;
    const id = window.setTimeout(() => setMsg(null), 1800);
    return () => window.clearTimeout(id);
  }, [msg]);
  return { msg, set: setMsg };
}

/** Renders children only after mount — guards crypto.subtle & window usage. */
export function ClientOnly({ children, fallback = null }: { children: ReactNode; fallback?: ReactNode }) {
  const [ready, setReady] = useState(false);
  useEffect(() => setReady(true), []);
  return <>{ready ? children : fallback}</>;
}
