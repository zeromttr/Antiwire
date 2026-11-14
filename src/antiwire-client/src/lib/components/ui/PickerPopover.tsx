import clsx from 'clsx';
import { ChevronDown } from 'lucide-react';
import {
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
  type ComponentType,
  type KeyboardEvent,
  type ReactNode,
  type Ref,
} from 'react';
import styles from './PickerPopover.module.css';

/** Imperative API (was `bind:this` + exported functions). */
export interface PickerPopoverHandle {
  openPanel: () => void;
  closePanel: (returnFocus?: boolean) => void;
}

export type PickerIcon = ComponentType<{
  className?: string;
  size?: number;
  strokeWidth?: number;
  'aria-hidden'?: 'true' | 'false' | boolean;
}>;

interface Props {
  ref?: Ref<PickerPopoverHandle>;
  /** Controlled open state (was `bind:open`). */
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  className?: string;
  /** Borderless transparent trigger for embedding inside a joined control group. */
  bare?: boolean;
  icon: PickerIcon;
  panelId: string;
  triggerLabel: string;
  panelLabel: string;
  /** Text shown in the trigger; a change replays the value animation. */
  valueText: string;
  /** Replays the value animation when it changes; defaults to `valueText`. */
  valueKey?: unknown;
  panelWidth: number;
  /** Runs right after the panel opens so the picker can set up its state and focus. */
  onOpen?: () => void;
  /** Keys the shell does not handle itself (it owns Escape). */
  onTriggerKeyDown?: (event: KeyboardEvent<HTMLButtonElement>) => void;
  onPanelKeyDown?: (event: KeyboardEvent<HTMLDivElement>) => void;
  children?: ReactNode;
}

/** The trigger-plus-panel shell shared by DateInput and TimeInput. The panel stays mounted. */
export function PickerPopover({
  ref,
  open = false,
  onOpenChange,
  className = '',
  bare = false,
  icon: Icon,
  panelId,
  triggerLabel,
  panelLabel,
  valueText,
  valueKey = valueText,
  panelWidth,
  onOpen,
  onTriggerKeyDown,
  onPanelKeyDown,
  children,
}: Props) {
  const root = useRef<HTMLDivElement | null>(null);
  const trigger = useRef<HTMLButtonElement | null>(null);
  const panel = useRef<HTMLDivElement | null>(null);
  const [placement, setPlacement] = useState<'above' | 'below'>('above');

  function measurePlacement() {
    if (!trigger.current || !panel.current) return;
    setPlacement(
      trigger.current.getBoundingClientRect().top > panel.current.offsetHeight + 12
        ? 'above'
        : 'below',
    );
  }

  function openPanel() {
    measurePlacement();
    onOpenChange?.(true);
    onOpen?.();
  }

  function closePanel(returnFocus = false) {
    onOpenChange?.(false);
    if (returnFocus) trigger.current?.focus();
  }

  useImperativeHandle(ref, () => ({ openPanel, closePanel }));

  function toggle() {
    if (open) closePanel();
    else openPanel();
  }

  /** Closes on Escape; returns whether the key was consumed. */
  function handleEscape(event: KeyboardEvent): boolean {
    if (event.key !== 'Escape') return false;
    event.preventDefault();
    event.stopPropagation();
    closePanel(true);
    return true;
  }

  function handleTriggerKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    if (open && handleEscape(event)) return;
    onTriggerKeyDown?.(event);
  }

  function handlePanelKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (handleEscape(event)) return;
    onPanelKeyDown?.(event);
  }

  const closeRef = useRef(onOpenChange);
  useEffect(() => {
    closeRef.current = onOpenChange;
  });

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (root.current && !root.current.contains(event.target as Node)) {
        closeRef.current?.(false);
      }
    };
    const onResize = () => {
      if (!trigger.current || !panel.current) return;
      setPlacement(
        trigger.current.getBoundingClientRect().top > panel.current.offsetHeight + 12
          ? 'above'
          : 'below',
      );
    };
    window.addEventListener('pointerdown', onPointerDown);
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('pointerdown', onPointerDown);
      window.removeEventListener('resize', onResize);
    };
  }, [open]);

  return (
    <div
      className={clsx(styles.picker, className, open && styles.open, bare && styles.bare)}
      ref={root}
    >
      <button
        type="button"
        className={clsx(styles.field, 'mono')}
        ref={trigger}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={panelId}
        aria-label={triggerLabel}
        onClick={toggle}
        onKeyDown={handleTriggerKeyDown}
      >
        <Icon className="glyph" size={13} strokeWidth={1.9} aria-hidden="true" />
        <span className={styles.value}>
          {/* Re-keyed so the CSS `valueIn` animation replays on each change. */}
          <span key={String(valueKey)} className={styles.valueText}>
            {valueText}
          </span>
        </span>
        <ChevronDown className="chevron" size={13} strokeWidth={2.2} aria-hidden="true" />
      </button>

      <div
        className={clsx(styles.panel, 'panel', placement === 'below' && styles.below)}
        style={{ width: `${panelWidth}px` }}
        ref={panel}
        id={panelId}
        role="dialog"
        tabIndex={-1}
        aria-label={panelLabel}
        onKeyDown={handlePanelKeyDown}
      >
        {children}
      </div>
    </div>
  );
}

export default PickerPopover;
