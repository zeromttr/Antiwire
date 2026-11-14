import clsx from 'clsx';
import { Clock3 } from 'lucide-react';
import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react';
import { m } from '#lib/i18n/messages.ts';
import { PickerPopover, type PickerPopoverHandle } from './PickerPopover.tsx';
import { clampTime, parseTimeKey, toTimeKey } from './time-input';
import styles from './TimeInput.module.css';

interface Props {
  /** `HH:MM`. Controlled (was `bind:value`). */
  value?: string;
  ariaLabel?: string;
  /** Latest selectable time, `HH:MM`; later hours and minutes are disabled. */
  max?: string;
  className?: string;
  /** `bind:value`: a time was picked. */
  onValueChange?: (value: string) => void;
  /** Same moment as `onValueChange`. */
  onChange?: (value: string) => void;
}

const FORMAT = (() => {
  const hourFormatter = new Intl.DateTimeFormat(undefined, { hour: 'numeric' });
  return {
    valueFormatter: new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' }),
    hourLabels: Array.from({ length: 24 }, (_, hour) =>
      hourFormatter.format(new Date(2000, 0, 1, hour, 0)),
    ),
    minuteLabels: Array.from({ length: 60 }, (_, minute) => String(minute).padStart(2, '0')),
  };
})();

type Column = 'hours' | 'minutes';

function centerRow(list: HTMLDivElement | null, index: number, smooth = true) {
  if (!list) return;
  const row = list.children[index] as HTMLElement | undefined;
  if (!row) return;
  const top = row.offsetTop - (list.clientHeight - row.offsetHeight) / 2;
  if (smooth) list.scrollTo({ top, behavior: 'smooth' });
  else list.scrollTop = top;
}

export function TimeInput({
  value = '',
  ariaLabel,
  max,
  className = '',
  onValueChange,
  onChange,
}: Props) {
  const uid = useId();
  const panelId = `${uid}-panel`;
  const { valueFormatter, hourLabels, minuteLabels } = FORMAT;

  const popover = useRef<PickerPopoverHandle | null>(null);
  const hoursList = useRef<HTMLDivElement | null>(null);
  const minutesList = useRef<HTMLDivElement | null>(null);
  const [open, setOpen] = useState(false);
  const [now, setNow] = useState(() => new Date());
  /** Column to focus after the next render, with whether to snap the lists first. */
  const [focusRequest, setFocusRequest] = useState<{
    column: Column;
    snap: boolean;
    tick: number;
  } | null>(null);
  const requestFocus = (column: Column, snap = false) =>
    setFocusRequest((prev) => ({ column, snap, tick: (prev?.tick ?? 0) + 1 }));

  const selected = parseTimeKey(value) ?? { hours: 0, minutes: 0 };
  const bound = max ? parseTimeKey(max) : null;
  const focusParts = clampTime(selected, bound);
  const nowParts = { hours: now.getHours(), minutes: now.getMinutes() };
  const displayValue = valueFormatter.format(
    new Date(2000, 0, 1, selected.hours, selected.minutes),
  );
  const triggerLabel = ariaLabel ? `${ariaLabel}: ${displayValue}` : displayValue;
  const maxHour = bound ? bound.hours : 23;

  function focusRow(column: Column) {
    const list = column === 'hours' ? hoursList.current : minutesList.current;
    const index = column === 'hours' ? focusParts.hours : focusParts.minutes;
    const attr = column === 'hours' ? 'data-hour' : 'data-minute';
    list?.querySelector<HTMLButtonElement>(`[${attr}="${index}"]`)?.focus({ preventScroll: true });
    centerRow(list, index);
  }

  const focusRowRef = useRef(focusRow);
  const partsRef = useRef(focusParts);
  useEffect(() => {
    focusRowRef.current = focusRow;
    partsRef.current = focusParts;
  });
  useEffect(() => {
    if (!focusRequest) return;
    if (focusRequest.snap) {
      centerRow(hoursList.current, partsRef.current.hours, false);
      centerRow(minutesList.current, partsRef.current.minutes, false);
    }
    focusRowRef.current(focusRequest.column);
  }, [focusRequest]);

  function onOpen() {
    setNow(new Date());
    requestFocus('hours', true);
  }

  function futureHour(hour: number): boolean {
    return bound ? hour > bound.hours : false;
  }

  function maxMinuteFor(hour: number): number {
    if (!bound || hour < bound.hours) return 59;
    return hour === bound.hours ? bound.minutes : -1;
  }

  function futureMinute(minute: number): boolean {
    return minute > maxMinuteFor(focusParts.hours);
  }

  function commit(hours: number, minutes: number) {
    const next = toTimeKey(hours, minutes);
    if (next !== value) {
      onValueChange?.(next);
      onChange?.(next);
    }
  }

  function selectHour(hour: number) {
    if (futureHour(hour)) return;
    commit(hour, Math.min(selected.minutes, maxMinuteFor(hour)));
  }

  function selectMinute(minute: number) {
    if (futureMinute(minute)) return;
    commit(focusParts.hours, minute);
  }

  function selectNow() {
    const target = clampTime(nowParts, bound);
    commit(target.hours, target.minutes);
  }

  function onTriggerKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (open) focusRow('hours');
      else popover.current?.openPanel();
    }
  }

  function moveHour(hour: number) {
    const next = Math.min(Math.max(hour, 0), maxHour);
    if (futureHour(next)) return;
    selectHour(next);
    requestFocus('hours');
  }

  function moveMinute(minute: number) {
    const next = Math.min(Math.max(minute, 0), maxMinuteFor(focusParts.hours));
    if (futureMinute(next)) return;
    selectMinute(next);
    requestFocus('minutes');
  }

  function onHourKeyDown(event: KeyboardEvent, target: HTMLElement) {
    const hour = Number(target.dataset.hour);
    let handled = true;
    switch (event.key) {
      case 'ArrowUp':
        moveHour(hour - 1);
        break;
      case 'ArrowDown':
        moveHour(hour + 1);
        break;
      case 'PageUp':
        moveHour(hour - 6);
        break;
      case 'PageDown':
        moveHour(hour + 6);
        break;
      case 'Home':
        moveHour(0);
        break;
      case 'End':
        moveHour(maxHour);
        break;
      case 'ArrowRight':
      case 'Enter':
        requestFocus('minutes');
        break;
      default:
        handled = false;
    }
    if (handled) event.preventDefault();
  }

  function onMinuteKeyDown(event: KeyboardEvent, target: HTMLElement) {
    const minute = Number(target.dataset.minute);
    let handled = true;
    switch (event.key) {
      case 'ArrowUp':
        moveMinute(minute - 1);
        break;
      case 'ArrowDown':
        moveMinute(minute + 1);
        break;
      case 'PageUp':
        moveMinute(minute - 5);
        break;
      case 'PageDown':
        moveMinute(minute + 5);
        break;
      case 'Home':
        moveMinute(0);
        break;
      case 'End':
        moveMinute(maxMinuteFor(focusParts.hours));
        break;
      case 'ArrowLeft':
        requestFocus('hours');
        break;
      case 'Enter':
        popover.current?.closePanel(true);
        break;
      default:
        handled = false;
    }
    if (handled) event.preventDefault();
  }

  function onPanelKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const target = event.target as HTMLElement;
    if (target.hasAttribute('data-hour')) onHourKeyDown(event, target);
    else if (target.hasAttribute('data-minute')) onMinuteKeyDown(event, target);
  }

  return (
    <PickerPopover
      ref={popover}
      open={open}
      onOpenChange={setOpen}
      className={className}
      icon={Clock3}
      panelId={panelId}
      triggerLabel={triggerLabel}
      panelLabel={ariaLabel ?? displayValue}
      valueText={displayValue}
      valueKey={value}
      panelWidth={224}
      onOpen={onOpen}
      onTriggerKeyDown={onTriggerKeyDown}
      onPanelKeyDown={onPanelKeyDown}
    >
      <div className={clsx(styles.columns, open && styles.open)}>
        <section className={styles.columnWrap}>
          <span className={styles.columnTitle} id={`${panelId}-hours`}>
            {m.common_time_hours()}
          </span>
          <div
            className={styles.column}
            role="listbox"
            aria-labelledby={`${panelId}-hours`}
            ref={hoursList}
          >
            {hourLabels.map((hourLabel, hour) => (
              <button
                key={hour}
                type="button"
                role="option"
                className={clsx(
                  styles.option,
                  'mono',
                  hour === selected.hours && !futureHour(hour) && styles.selected,
                  hour === nowParts.hours && styles.isNow,
                )}
                data-hour={hour}
                tabIndex={hour === focusParts.hours ? 0 : -1}
                aria-selected={hour === selected.hours}
                disabled={futureHour(hour)}
                onClick={() => selectHour(hour)}
              >
                {hourLabel}
              </button>
            ))}
          </div>
        </section>

        <section className={styles.columnWrap}>
          <span className={styles.columnTitle} id={`${panelId}-minutes`}>
            {m.common_time_minutes()}
          </span>
          <div
            className={styles.column}
            role="listbox"
            aria-labelledby={`${panelId}-minutes`}
            ref={minutesList}
          >
            {minuteLabels.map((minuteLabel, minute) => (
              <button
                key={minute}
                type="button"
                role="option"
                className={clsx(
                  styles.option,
                  'mono',
                  minute === selected.minutes && !futureMinute(minute) && styles.selected,
                  minute === nowParts.minutes && styles.isNow,
                )}
                data-minute={minute}
                tabIndex={minute === focusParts.minutes ? 0 : -1}
                aria-selected={minute === selected.minutes}
                disabled={futureMinute(minute)}
                onClick={() => selectMinute(minute)}
              >
                {minuteLabel}
              </button>
            ))}
          </div>
        </section>
      </div>

      <footer className={styles.panelFoot}>
        <button type="button" className={styles.now} onClick={selectNow}>
          {m.common_time_now()}
        </button>
        <button
          type="button"
          className={styles.done}
          onClick={() => popover.current?.closePanel(true)}
        >
          {m.common_time_done()}
        </button>
      </footer>
    </PickerPopover>
  );
}

export default TimeInput;
