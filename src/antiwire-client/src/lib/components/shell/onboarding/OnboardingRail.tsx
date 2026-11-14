import clsx from 'clsx';
import { Check } from 'lucide-react';
import { m } from '#lib/i18n/messages.ts';
import applicationIcon from '../../../../../resources/icons/128x128.png?inline';
import { steps } from './onboarding-steps';
import styles from './OnboardingRail.module.css';

interface Props {
  step: number;
  reached: number;
  disabled?: boolean;
  onselect: (index: number) => void;
}

export function OnboardingRail({ step, reached, disabled = false, onselect }: Props) {
  return (
    <nav
      className={styles.rail}
      aria-label={m.onboarding_step_progress_aria({ step: step + 1, total: steps.length })}
    >
      <div className={styles.railBrand}>
        <img src={applicationIcon} alt="" width="22" height="22" draggable={false} />
        <span>{m.shell_setup()}</span>
      </div>
      <ol className={styles.railSteps}>
        {steps.map((item, index) => {
          const Icon = item.icon;
          const done = index < reached && index !== step;
          const active = index === step;
          return (
            <li key={index}>
              <button
                type="button"
                className={clsx(styles.railStep, active && styles.active, done && styles.done)}
                disabled={index > reached || disabled}
                aria-current={active ? 'step' : undefined}
                onClick={() => onselect(index)}
              >
                <span className={styles.railIcon} aria-hidden="true">
                  {done ? (
                    <span className={styles.railCheck}>
                      <Check size={11} strokeWidth={3} />
                    </span>
                  ) : (
                    <Icon size={15} strokeWidth={1.7} />
                  )}
                </span>
                <span className={styles.railLabel}>{item.name()}</span>
              </button>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

export default OnboardingRail;
