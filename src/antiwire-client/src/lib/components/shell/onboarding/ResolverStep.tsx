import { Checkbox } from '#lib/components/ui/Checkbox.tsx';
import { ChoiceCard } from '#lib/components/ui/ChoiceCard.tsx';
import { Toggle } from '#lib/components/ui/Toggle.tsx';
import { m } from '#lib/i18n/messages.ts';
import { protocols, type StepProps } from './onboarding-steps';

// Styles: onboarding-steps.css (global, under `.step-body`).
export function ResolverStep({ choices, patch }: StepProps) {
  return (
    <>
      <div className="card">
        <div className="row">
          <span className="row-copy">
            <strong>{m.onboarding_resolver_title()}</strong>
          </span>
          <Toggle
            checked={choices.resolverEnabled}
            onCheckedChange={(value) => patch('resolverEnabled', value)}
            ariaLabel={m.onboarding_resolver_aria()}
          />
        </div>
      </div>
      <div className="options" role="radiogroup" aria-label={m.onboarding_step_dns_title()}>
        {protocols.map((protocol) => {
          const selected = choices.resolverProtocol === protocol.id;
          return (
            <ChoiceCard
              key={protocol.id}
              role="radio"
              className="option"
              selected={selected}
              disabled={!choices.resolverEnabled}
              onClick={() => patch('resolverProtocol', protocol.id)}
            >
              <span className="mark">
                <Checkbox decorative round checked={selected} />
              </span>
              <span className="row-copy">
                <span className="option-title">
                  {protocol.name()}
                  <span className="option-summary">{protocol.summary()}</span>
                  {protocol.recommended && (
                    <span className="tag">{m.onboarding_recommended()}</span>
                  )}
                </span>
                <small>{protocol.detail()}</small>
              </span>
            </ChoiceCard>
          );
        })}
      </div>
    </>
  );
}

export default ResolverStep;
