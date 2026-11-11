import { useLayoutEffect, useRef, useState, type RefObject } from 'react';
import { playMotion, type MotionSpec } from './motion';

/**
 * Keeps an element mounted while its exit animation plays, and plays an
 * enter animation when it mounts.
 *
 * ```tsx
 * const menu = usePresence<HTMLDivElement>(open, popoverIn(), popoverOut());
 * {menu.present && <div ref={menu.ref}>…</div>}
 * ```
 *
 * The entrance plays whenever `open` turns true (also on a reopen during
 * the exit); the element unmounts when the exit finishes. Reduced motion
 * skips both. Specs may change every render; the latest ones are used.
 */
export function usePresence<T extends Element>(
  open: boolean,
  enter?: MotionSpec | null,
  exit?: MotionSpec | null,
): { present: boolean; ref: RefObject<T | null> } {
  const ref = useRef<T | null>(null);
  const specs = useRef({ enter, exit });
  const [present, setPresent] = useState(open);
  const [wasOpen, setWasOpen] = useState(open);
  // Opening mounts in the same render; closing waits for the exit below.
  if (open !== wasOpen) {
    setWasOpen(open);
    if (open) setPresent(true);
  }

  useLayoutEffect(() => {
    specs.current = { enter, exit };
  });

  useLayoutEffect(() => {
    const element = ref.current;
    if (open) {
      const spec = specs.current.enter;
      if (!element || !spec) return;
      const animation = playMotion(element, spec);
      return () => animation?.cancel();
    }
    if (!present) return;
    const spec = specs.current.exit;
    const animation = element && spec ? playMotion(element, spec, 'forwards') : null;
    if (!animation) {
      let cancelled = false;
      queueMicrotask(() => {
        if (!cancelled) setPresent(false);
      });
      return () => {
        cancelled = true;
      };
    }
    animation.onfinish = () => setPresent(false);
    return () => {
      animation.onfinish = null;
      animation.cancel();
    };
  }, [open, present]);

  return { present: present || open, ref };
}

/**
 * Plays `spec` on the referenced element when it mounts and whenever `key`
 * changes.
 */
export function useEnterMotion<T extends Element>(
  spec: MotionSpec | null | undefined,
  key?: unknown,
): RefObject<T | null> {
  const ref = useRef<T | null>(null);
  const specRef = useRef(spec);
  useLayoutEffect(() => {
    specRef.current = spec;
  });
  useLayoutEffect(() => {
    const element = ref.current;
    const current = specRef.current;
    if (!element || !current) return;
    const animation = playMotion(element, current);
    return () => animation?.cancel();
  }, [key]);
  return ref;
}
