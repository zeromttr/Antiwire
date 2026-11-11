import { ChoiceCard } from '#lib/components/ui/ChoiceCard.tsx';
import { m } from '#lib/i18n/messages.ts';
import { RETENTION_OPTIONS, type RetentionChoice } from '#lib/models/onboarding-settings.ts';
import type { StepProps } from './onboarding-steps';

// Styles: onboarding-steps.css (global, under `.step-body`).
export function RetentionStep({ choices, patch }: StepProps) {
  return (
    <>
      <div className="retention" role="radiogroup" aria-label={m.onboarding_step_retention_title()}>
        {RETENTION_OPTIONS.map((option) => (
          <ChoiceCard
            key={option}
            role="radio"
            className="retention-option"
            selected={choices.retention === option}
            onClick={() => patch('retention', option as RetentionChoice)}
          >
            <span className="retention-value">{option === 'unlimited' ? '∞' : option}</span>
            <span className="retention-unit">
              {option === 'unlimited'
                ? m.onboarding_retention_unlimited()
                : m.onboarding_retention_days()}
            </span>
          </ChoiceCard>
        ))}
      </div>
      <p className="note">{m.onboarding_retention_note()}</p>
    </>
  );
}

export default RetentionStep;
