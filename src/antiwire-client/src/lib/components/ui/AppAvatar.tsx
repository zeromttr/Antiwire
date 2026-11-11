import clsx from 'clsx';
import { memo, useEffect, useRef, useState, type CSSProperties } from 'react';
import { shallowEqual, useSelector } from '#lib/state/reactive.ts';
import { appIcons, appIconCacheKey } from '#lib/stores/app-icons.ts';
import { appTint, displayText, initials } from '#lib/utils/index.ts';
import styles from './AppAvatar.module.css';

interface Props {
  name: string;
  path?: string;
  size?: number;
  /** The "all applications" avatar: neutral outline instead of the app's tint. */
  all?: boolean;
  className?: string;
}

function closestScrollRoot(node: Element): Element | null {
  let current = node.parentElement;
  while (current) {
    const overflowY = getComputedStyle(current).overflowY;
    if (overflowY === 'auto' || overflowY === 'scroll') {
      return current;
    }
    current = current.parentElement;
  }
  return null;
}

/** An application's icon, or its tinted initials until (or unless) the icon loads. */
export const AppAvatar = memo(function AppAvatar({
  name,
  path = '',
  size = 24,
  all = false,
  className = '',
}: Props) {
  const cacheKey = appIconCacheKey(path, name);
  const icon = useSelector(
    appIcons,
    (store) => {
      const entry = store.get(cacheKey);
      return { status: entry.status, src: entry.src };
    },
    shallowEqual,
  );
  const label = initials(displayText(name));
  const showIcon = icon.status === 'ready' && Boolean(icon.src);

  const root = useRef<HTMLDivElement | null>(null);
  const [inView, setInView] = useState(false);

  useEffect(() => {
    const node = root.current;
    if (!node || inView) return;
    const markVisible = () => setInView(true);

    if (typeof IntersectionObserver !== 'function') {
      queueMicrotask(markVisible);
      return;
    }

    // Observe the nearest scroller. Viewport-rooted IO misses rows inside
    // `contain: strict` virtual lists (firewall / records).
    const scrollRoot = closestScrollRoot(node);
    const rect = node.getBoundingClientRect();
    const bounds = scrollRoot?.getBoundingClientRect();
    const top = bounds?.top ?? 0;
    const bottom = bounds?.bottom ?? window.innerHeight;
    if (rect.height > 0 && rect.bottom >= top - 120 && rect.top <= bottom + 120) {
      queueMicrotask(markVisible);
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          markVisible();
          observer.disconnect();
        }
      },
      { root: scrollRoot, rootMargin: '120px 0px' },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [inView]);

  useEffect(() => {
    if (!inView) return;
    appIcons.ensure(path, name);
  }, [inView, path, name, icon.status]);

  const style = {
    width: `${size}px`,
    height: `${size}px`,
    fontSize: `${Math.max(9, Math.round(size * 0.4))}px`,
    borderRadius: `${Math.round(size * 0.28)}px`,
    '--app-tint': all ? undefined : appTint(name),
  } as CSSProperties;

  return (
    <div
      ref={root}
      className={clsx(styles.appAvatar, className, all && styles.all, showIcon && styles.hasIcon)}
      style={style}
      aria-hidden="true"
    >
      {showIcon && icon.src ? (
        <img
          src={icon.src}
          alt=""
          draggable={false}
          decoding="async"
          onError={() => appIcons.markBroken(cacheKey)}
        />
      ) : (
        label
      )}
    </div>
  );
});

export default AppAvatar;
