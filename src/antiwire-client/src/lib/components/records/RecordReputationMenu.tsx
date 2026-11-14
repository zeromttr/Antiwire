import clsx from 'clsx';
import { ChevronDown, ExternalLink, ShieldCheck } from 'lucide-react';
import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react';
import { createPortal } from 'react-dom';
import { api } from '#lib/api/daemon.ts';
import Button from '#lib/components/ui/Button.tsx';
import { m } from '#lib/i18n/messages.ts';
import { popoverIn, popoverOut } from '#lib/motion.ts';
import { usePresence } from '#lib/use-presence.ts';
import { REPUTATION_SERVICES, type ReputationService } from '#lib/models/reputation.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { displayText } from '#lib/utils/index.ts';
import styles from './RecordReputationMenu.module.css';

interface Props {
  /** A validated public hostname (see `lookupHostname`). */
  domain: string;
}

const GAP = 6;
const EDGE = 12;
/** Roughly the full menu; below this much room, it opens upward instead. */
const PREFERRED_HEIGHT = 380;

type Placement = { up: boolean; offset: number; right: number; maxHeight: number };

export function RecordReputationMenu({ domain }: Props) {
  const menuId = useId();
  const [open, setOpen] = useState(false);
  const [placement, setPlacement] = useState<Placement>({
    up: false,
    offset: 0,
    right: 0,
    maxHeight: 0,
  });
  const wrapEl = useRef<HTMLDivElement>(null);
  const triggerEl = useRef<HTMLButtonElement>(null);
  const { present: menuPresent, ref: menuRef } = usePresence<HTMLDivElement>(
    open,
    popoverIn({ from: placement.up ? 'bottom' : 'top' }),
    popoverOut({ from: placement.up ? 'bottom' : 'top' }),
  );

  function items(): HTMLButtonElement[] {
    return [...(menuRef.current?.querySelectorAll<HTMLButtonElement>('button') ?? [])];
  }

  function close(focusTrigger = false) {
    setOpen(false);
    if (focusTrigger) queueMicrotask(() => triggerEl.current?.focus());
  }

  // Anchored to the viewport. The node is portaled to `document.body`: the
  // inspector is `contain: layout` and the page is `contain: paint`, so a
  // fixed menu left in the tree stays trapped in the scroller and paints
  // under the records table.
  function place() {
    const rect = wrapEl.current?.getBoundingClientRect();
    if (!rect) return;
    const below = window.innerHeight - rect.bottom - GAP - EDGE;
    const above = rect.top - GAP - EDGE;
    const up = below < PREFERRED_HEIGHT && above > below;
    setPlacement({
      up,
      offset: up ? window.innerHeight - rect.top + GAP : rect.bottom + GAP,
      right: Math.max(EDGE, window.innerWidth - rect.right),
      maxHeight: up ? above : below,
    });
  }

  function toggle() {
    if (!open) place();
    const next = !open;
    setOpen(next);
    if (next) requestAnimationFrame(() => items()[0]?.focus());
  }

  // The report opens natively in the default browser; this needs no daemon.
  async function pick(service: ReputationService) {
    close(true);
    try {
      await api.openDomainReputation(service.id, domain);
    } catch (error) {
      daemon.addToast(
        m.records_reputation_failed({ service: service.name }),
        error instanceof Error ? error.message : String(error),
        'var(--bad)',
      );
    }
  }

  function onMenuKeydown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Escape' || event.key === 'Tab') {
      // Close only the menu: the inspector also closes on Escape.
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
      }
      close(event.key === 'Escape');
      return;
    }
    if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
    const buttons = items();
    if (!buttons.length) return;
    event.preventDefault();
    const index = buttons.indexOf(document.activeElement as HTMLButtonElement);
    const next =
      event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? buttons.length - 1
          : (index + (event.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length;
    buttons[next]?.focus();
  }

  useEffect(() => {
    if (!open) return;
    const closeOutside = (event: PointerEvent) => {
      const target = event.target as Node;
      if (wrapEl.current?.contains(target) || menuRef.current?.contains(target)) return;
      setOpen(false);
    };
    // A fixed menu would drift from its trigger, so moving anything closes it.
    const closeOnScroll = (event: Event) => {
      if (!menuRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const closeOnResize = () => setOpen(false);
    window.addEventListener('pointerdown', closeOutside);
    window.addEventListener('scroll', closeOnScroll, true);
    window.addEventListener('resize', closeOnResize);
    return () => {
      window.removeEventListener('pointerdown', closeOutside);
      window.removeEventListener('scroll', closeOnScroll, true);
      window.removeEventListener('resize', closeOnResize);
    };
  }, [open, menuRef]);

  return (
    <div className={styles.wrap} ref={wrapEl}>
      <span className={styles.trigger}>
        <Button
          ref={triggerEl}
          variant="ghost"
          size="sm"
          aria-haspopup="menu"
          aria-expanded={open}
          aria-controls={open ? menuId : undefined}
          onClick={toggle}
        >
          <ShieldCheck size={13} strokeWidth={2} />
          {m.records_reputation_button()}
          <ChevronDown
            size={12}
            strokeWidth={2}
            className={clsx(styles.chevron, open && styles.open)}
          />
        </Button>
      </span>
      {menuPresent &&
        createPortal(
          <div
            ref={menuRef}
            id={menuId}
            className={styles.menu}
            role="menu"
            aria-label={m.records_reputation_menu({ domain: displayText(domain) })}
            style={{
              top: placement.up ? undefined : `${placement.offset}px`,
              bottom: placement.up ? `${placement.offset}px` : undefined,
              right: `${placement.right}px`,
              maxHeight: `${placement.maxHeight}px`,
            }}
            onKeyDown={onMenuKeydown}
          >
            <p className={styles.caption} aria-hidden="true">
              {m.records_reputation_caption({ domain: displayText(domain) })}
            </p>
            {REPUTATION_SERVICES.map((service) => (
              <button
                key={service.id}
                type="button"
                role="menuitem"
                className={styles.item}
                aria-label={m.records_reputation_item_aria({
                  domain: displayText(domain),
                  service: service.name,
                })}
                onClick={() => void pick(service)}
              >
                <span className={styles.text}>
                  <span className={styles.name}>{service.name}</span>
                  <span className={styles.desc}>{service.description()}</span>
                </span>
                <ExternalLink size={12} strokeWidth={2} aria-hidden="true" />
              </button>
            ))}
          </div>,
          document.body,
        )}
    </div>
  );
}

export default RecordReputationMenu;
