import { Toggle } from '#lib/components/ui/Toggle.tsx';
import { m } from '#lib/i18n/messages.ts';
import type { StepProps } from './onboarding-steps';

// Styles: onboarding-steps.css (global, under `.step-body`).
export function GeoIpStep({ choices, patch }: StepProps) {
  return (
    <div className="card">
      <div className="row">
        <span className="row-copy">
          <strong>{m.onboarding_geoip_title()}</strong>
          <small>{m.onboarding_geoip_privacy_note()}</small>
        </span>
        <Toggle
          checked={choices.geoIpEnabled}
          onCheckedChange={(value) => patch('geoIpEnabled', value)}
          ariaLabel={m.onboarding_geoip_aria()}
        />
      </div>
    </div>
  );
}

export default GeoIpStep;
