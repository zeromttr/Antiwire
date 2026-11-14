import clsx from 'clsx';
import { Ban, CircleCheck, type LucideIcon } from 'lucide-react';
import { createPortal } from 'react-dom';
import { useFloatingTip } from '#lib/utils/floating-tip.ts';
import { m } from '#lib/i18n/messages.ts';
import {
  ruleActionDescription,
  ruleActionLabel,
  ruleActions,
  type RuleFormAction,
} from '#lib/components/firewall/form/rule-form.ts';
import styles from './RuleActionPicker.module.css';

interface Props {
  value: RuleFormAction;
  disabled?: boolean;
  onChange?: (value: RuleFormAction) => void;
}

const ICONS: Record<RuleFormAction, LucideIcon> = {
  BLOCK: Ban,
  ALLOW: CircleCheck,
};

export function RuleActionPicker({ value, disabled = false, onChange }: Props) {
  const { hover, placement, tipRef, show, hide } = useFloatingTip<RuleFormAction>({
    estimatedTipHeight: 48,
  });

  return (
    <>
      <div className={styles['action-picker']} role="group" aria-label={m.firewall_action_aria()}>
        {ruleActions.map((option) => {
          const Icon = ICONS[option];
          const active = value === option;
          return (
            <button
              key={option}
              type="button"
              className={clsx(
                styles['action-chip'],
                active && styles.active,
                option === 'BLOCK' && styles.block,
                option === 'ALLOW' && styles.allow,
              )}
              data-action={option}
              disabled={disabled}
              aria-label={ruleActionLabel(option)}
              aria-pressed={active}
              onMouseEnter={(event) => show(option, event)}
              onMouseLeave={hide}
              onFocus={(event) => show(option, event)}
              onBlur={hide}
              onClick={() => onChange?.(option)}
            >
              <span className={styles['action-glyph']} aria-hidden="true">
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
            className={clsx(
              styles.tip,
              'mono',
              placement === 'bottom' && styles.below,
              hover === 'BLOCK' && styles['block-tip'],
              hover === 'ALLOW' && styles['allow-tip'],
            )}
            role="tooltip"
          >
            <span className={styles['tip-label']}>{ruleActionLabel(hover)}</span>
            <span className={styles['tip-text']}>{ruleActionDescription(hover)}</span>
          </div>,
          document.body,
        )}
    </>
  );
}

export default RuleActionPicker;
