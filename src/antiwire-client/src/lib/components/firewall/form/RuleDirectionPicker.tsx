import clsx from 'clsx';
import { ArrowDown, ArrowUp, ArrowUpDown, type LucideIcon } from 'lucide-react';
import { createPortal } from 'react-dom';
import { useFloatingTip } from '#lib/utils/floating-tip.ts';
import { m } from '#lib/i18n/messages.ts';
import type { RuleDirection } from '#lib/types/index.ts';
import {
  ruleDirectionDescription,
  ruleDirectionLabel,
  ruleDirections,
} from '#lib/components/firewall/form/rule-form.ts';
import styles from './RuleDirectionPicker.module.css';

interface Props {
  value: RuleDirection;
  disabled?: boolean;
  onChange?: (value: RuleDirection) => void;
}

const ICONS: Record<RuleDirection, LucideIcon> = {
  OUTBOUND: ArrowUp,
  INBOUND: ArrowDown,
  BOTH: ArrowUpDown,
};

export function RuleDirectionPicker({ value, disabled = false, onChange }: Props) {
  const { hover, placement, tipRef, show, hide } = useFloatingTip<RuleDirection>({
    estimatedTipHeight: 48,
  });

  return (
    <>
      <div
        className={styles['direction-picker']}
        role="group"
        aria-label={m.firewall_direction_aria()}
      >
        {ruleDirections.map((option) => {
          const Icon = ICONS[option];
          const active = value === option;
          return (
            <button
              key={option}
              type="button"
              className={clsx(styles['dir-chip'], active && styles.active)}
              data-direction={option}
              disabled={disabled}
              aria-label={ruleDirectionLabel(option)}
              aria-pressed={active}
              onMouseEnter={(event) => show(option, event)}
              onMouseLeave={hide}
              onFocus={(event) => show(option, event)}
              onBlur={hide}
              onClick={() => onChange?.(option)}
            >
              <span className={styles['dir-glyph']} aria-hidden="true">
                <Icon size={14} strokeWidth={2} />
              </span>
            </button>
          );
        })}
      </div>

      {hover &&
        createPortal(
          <div
            ref={tipRef}
            className={clsx(styles.tip, 'mono', placement === 'bottom' && styles.below)}
            role="tooltip"
          >
            <span className={styles['tip-label']}>{ruleDirectionLabel(hover)}</span>
            <span className={styles['tip-text']}>{ruleDirectionDescription(hover)}</span>
          </div>,
          document.body,
        )}
    </>
  );
}

export default RuleDirectionPicker;
