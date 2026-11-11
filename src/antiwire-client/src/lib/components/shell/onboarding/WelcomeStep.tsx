import { LanguagePicker } from '#lib/components/settings/form/LanguagePicker.tsx';
import { m } from '#lib/i18n/messages.ts';
import { highlights } from './onboarding-steps';

// Styles: onboarding-steps.css (global, under `.step-body`).
export function WelcomeStep() {
  return (
    <>
      <ul className="highlights">
        {highlights.map((item) => {
          const Icon = item.icon;
          return (
            <li key={item.title()}>
              <span className="highlight-icon">
                <Icon size={16} strokeWidth={1.7} />
              </span>
              <span className="row-copy">
                <strong>{item.title()}</strong>
                <small>{item.body()}</small>
              </span>
            </li>
          );
        })}
      </ul>
      <div className="card language">
        <LanguagePicker embedded id="onboarding-language" />
      </div>
      <p className="note">{m.onboarding_welcome_note()}</p>
    </>
  );
}

export default WelcomeStep;
