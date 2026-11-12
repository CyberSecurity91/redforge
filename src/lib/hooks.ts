import { useCallback, useEffect, useRef, useState } from 'react';

const PREFIX = 'redforge:';

export function useLocalStorage<T>(key: string, initial: T) {
  const fullKey = PREFIX + key;
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(fullKey);
      return raw === null ? initial : (JSON.parse(raw) as T);
    } catch {
      return initial;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(fullKey, JSON.stringify(value));
    } catch {
      /* storage blocked */
    }
  }, [fullKey, value]);
  return [value, setValue] as const;
}

/** Clipboard write with per-button "copied" feedback. */
export function useCopy(timeout = 1600) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copy = useCallback(
    async (text: string, key = 'default') => {
      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(text);
        } else {
          const ta = document.createElement('textarea');
          ta.value = text;
          ta.style.position = 'fixed';
          ta.style.opacity = '0';
          document.body.appendChild(ta);
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
        }
        setCopiedKey(key);
        window.setTimeout(() => setCopiedKey(null), timeout);
      } catch {
        /* clipboard denied */
      }
    },
    [timeout],
  );

  return { copy, copiedKey, isCopied: (key = 'default') => copiedKey === key };
}

/** Global hotkey listener. `mod` = Cmd on macOS, Ctrl elsewhere. */
export function useHotkey(key: string, handler: () => void, opts: { mod?: boolean; shift?: boolean } = {}) {
  const ref = useRef(handler);
  ref.current = handler;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (opts.mod && !(e.metaKey || e.ctrlKey)) return;
      if (e.key.toLowerCase() !== key.toLowerCase()) return;
      if (opts.shift && !e.shiftKey) return;
      e.preventDefault();
      ref.current();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [key, opts.mod, opts.shift]);
}

export function useMediaQuery(query: string) {
  const [matches, setMatches] = useState(() => (typeof window === 'undefined' ? false : window.matchMedia(query).matches));
  useEffect(() => {
    const mq = window.matchMedia(query);
    const onChange = () => setMatches(mq.matches);
    onChange();
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [query]);
  return matches;
}

export function useDebounced<T>(value: T, delay = 180): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const id = window.setTimeout(() => setDebounced(value), delay);
    return () => window.clearTimeout(id);
  }, [value, delay]);
  return debounced;
}
