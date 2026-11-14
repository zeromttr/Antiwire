import { Check, CircleAlert, Info, TriangleAlert, X } from 'lucide-react';
import { memo, useCallback, useLayoutEffect, useRef, useState, type CSSProperties } from 'react';
import { m } from '#lib/i18n/messages.ts';
import {
  EASING,
  MOTION,
  playMotion,
  prefersReducedMotion,
  toastIn,
  toastOut,
} from '#lib/motion.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { displayText } from '#lib/utils/index.ts';
import { tryMessage } from '#lib/utils/error.ts';
import type { Toast } from '#lib/types/index.ts';
import styles from './ToastHost.module.css';

interface Entry {
  toast: Toast;
  leaving: boolean;
}

function dismissLabel(): string {
  return tryMessage(() => m.alerts_dismiss(), 'Dismiss notification');
}

/** Toasts carry a CSS colour; pick the glyph that matches its meaning. */
function iconFor(color: string) {
  if (color.includes('--bad')) return <CircleAlert size={14} strokeWidth={2} />;
  if (color.includes('--warn')) return <TriangleAlert size={14} strokeWidth={2} />;
  if (color.includes('--ok') || color.includes('--acc')) return <Check size={14} strokeWidth={2} />;
  return <Info size={14} strokeWidth={2} />;
}

/**
 * Keeps removed toasts in the list, marked `leaving`, until their exit
 * animation ends; new toasts take their store position.
 */
function mergeEntries(previous: Entry[], toasts: readonly Toast[]): Entry[] {
  const live = new Map(toasts.map((toast) => [toast.id, toast]));
  const next: Entry[] = [];
  const seen = new Set<string>();
  for (const entry of previous) {
    const toast = live.get(entry.toast.id);
    if (toast) {
      next.push({ toast, leaving: false });
      seen.add(toast.id);
    } else {
      next.push(entry.leaving ? entry : { ...entry, leaving: true });
    }
  }
  for (const toast of toasts) {
    if (!seen.has(toast.id)) next.push({ toast, leaving: false });
  }
  return next;
}

export function ToastHost() {
  const toasts = useSelector(daemon, (d) => d.state.toasts);
  const [entries, setEntries] = useState<Entry[]>(() => mergeEntries([], toasts));
  const [source, setSource] = useState(toasts);
  if (source !== toasts) {
    setSource(toasts);
    setEntries((prev) => mergeEntries(prev, toasts));
  }

  const onExited = useCallback((id: string) => {
    setEntries((prev) => prev.filter((entry) => !(entry.leaving && entry.toast.id === id)));
  }, []);

  // FLIP: toasts that moved because another arrived or left glide to their new slot.
  const host = useRef<HTMLDivElement | null>(null);
  const positions = useRef(new Map<string, number>());
  useLayoutEffect(() => {
    const el = host.current;
    if (!el) return;
    const next = new Map<string, number>();
    for (const node of el.querySelectorAll<HTMLElement>('[data-toast-id]')) {
      if (node.dataset.leaving === 'true') continue;
      const id = node.dataset.toastId ?? '';
      const top = node.offsetTop;
      next.set(id, top);
      const before = positions.current.get(id);
      if (before !== undefined && before !== top && !prefersReducedMotion()) {
        node.animate(
          [{ transform: `translateY(${before - top}px)` }, { transform: 'translateY(0px)' }],
          { duration: MOTION.slow, easing: EASING.out, composite: 'add' },
        );
      }
    }
    positions.current = next;
  }, [entries]);

  return (
    <div className={styles.toastHost} ref={host} aria-live="polite" aria-atomic="false">
      {entries.map((entry) => (
        <ToastItem
          key={entry.toast.id}
          toast={entry.toast}
          leaving={entry.leaving}
          onExited={onExited}
        />
      ))}
    </div>
  );
}

interface ItemProps {
  toast: Toast;
  leaving: boolean;
  onExited: (id: string) => void;
}

const ToastItem = memo(function ToastItem({ toast, leaving, onExited }: ItemProps) {
  const ref = useRef<HTMLDivElement | null>(null);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const animation = playMotion(el, toastIn());
    return () => animation?.cancel();
  }, []);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!leaving || !el) return;
    // Leave the flow so the rest of the stack can close the gap while this one exits.
    const { offsetTop, offsetLeft, offsetWidth } = el;
    Object.assign(el.style, {
      position: 'absolute',
      top: `${offsetTop}px`,
      left: `${offsetLeft}px`,
      width: `${offsetWidth}px`,
    });
    const animation = playMotion(el, toastOut(), 'forwards');
    if (!animation) {
      onExited(toast.id);
      return;
    }
    animation.onfinish = () => onExited(toast.id);
    return () => {
      animation.onfinish = null;
    };
  }, [leaving, onExited, toast.id]);

  return (
    <div
      ref={ref}
      className={styles.toast}
      style={{ '--tone': toast.color } as CSSProperties}
      role="status"
      data-toast-id={String(toast.id)}
      data-leaving={leaving ? 'true' : undefined}
    >
      <span className={styles.icon} aria-hidden="true">
        {iconFor(toast.color)}
      </span>
      <div className={styles.copy}>
        <div className={styles.toastTitle}>{displayText(toast.title)}</div>
        {toast.body && <div className={styles.toastBody}>{displayText(toast.body)}</div>}
      </div>
      <button
        type="button"
        className={styles.dismiss}
        aria-label={dismissLabel()}
        title={dismissLabel()}
        disabled={leaving}
        onClick={() => daemon.dismissToast(toast.id)}
      >
        <X size={14} strokeWidth={2} />
      </button>
    </div>
  );
});

export default ToastHost;
