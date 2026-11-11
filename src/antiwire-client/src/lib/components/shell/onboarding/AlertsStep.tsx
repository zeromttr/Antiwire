import { Toggle } from '#lib/components/ui/Toggle.tsx';
import { m } from '#lib/i18n/messages.ts';
import type { StepProps } from './onboarding-steps';

// Styles: onboarding-steps.css (global, under `.step-body`).
export function AlertsStep({ choices, patch }: StepProps) {
  return (
    <>
      <div className="card">
        <div className="row">
          <span className="row-copy">
            <strong>{m.onboarding_desktop_notifications_title()}</strong>
            <small>{m.onboarding_desktop_notifications_note()}</small>
          </span>
          <Toggle
            checked={choices.desktopNotifications}
            onCheckedChange={(value) => patch('desktopNotifications', value)}
            ariaLabel={m.onboarding_desktop_notifications_aria()}
          />
        </div>
      </div>
      <div className="card">
        <div className="row">
          <span className="row-copy">
            <strong>{m.onboarding_alert_new_connections_title()}</strong>
            <small>{m.onboarding_alert_new_connections_body()}</small>
          </span>
          <Toggle
            checked={choices.newConnectionAlerts}
            onCheckedChange={(value) => patch('newConnectionAlerts', value)}
            ariaLabel={m.onboarding_alert_new_connections_aria()}
          />
        </div>
        <div className="row">
          <span className="row-copy">
            <strong>{m.onboarding_alert_new_apps_title()}</strong>
            <small>{m.onboarding_alert_new_apps_body()}</small>
          </span>
          <Toggle
            checked={choices.newApplicationAlerts}
            onCheckedChange={(value) => patch('newApplicationAlerts', value)}
            ariaLabel={m.onboarding_alert_new_apps_aria()}
          />
        </div>
        <div className="row">
          <span className="row-copy">
            <strong>{m.onboarding_alert_threats_title()}</strong>
            <small>{m.onboarding_alert_threats_body()}</small>
          </span>
          <Toggle
            checked={choices.threatAlerts}
            onCheckedChange={(value) => patch('threatAlerts', value)}
            ariaLabel={m.onboarding_alert_threats_aria()}
          />
        </div>
      </div>
    </>
  );
}

export default AlertsStep;
