import * as AlertDialog from '@radix-ui/react-alert-dialog';
import clsx from 'clsx';
import { useEffect, useRef, useState } from 'react';
import { api, type SettingsDto } from '#lib/api/daemon.ts';
import { Button } from '#lib/components/ui/Button.tsx';
import { Spinner } from '#lib/components/ui/Spinner.tsx';
import { m } from '#lib/i18n/messages.ts';
import {
  applyOnboardingChoices,
  onboardingChoicesFromSettings,
  type OnboardingChoices,
} from '#lib/models/onboarding-settings.ts';
import { stepIn } from '#lib/motion.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { useEnterMotion } from '#lib/use-presence.ts';
import { AlertsStep } from './onboarding/AlertsStep.tsx';
import { BlocklistsStep } from './onboarding/BlocklistsStep.tsx';
import { GeoIpStep } from './onboarding/GeoIpStep.tsx';
import { OnboardingRail } from './onboarding/OnboardingRail.tsx';
import { ResolverStep } from './onboarding/ResolverStep.tsx';
import { RetentionStep } from './onboarding/RetentionStep.tsx';
import { WelcomeStep } from './onboarding/WelcomeStep.tsx';
import { steps } from './onboarding/onboarding-steps';
import './onboarding/onboarding-steps.css';
import styles from './OnboardingModal.module.css';

export interface OnboardingModalProps {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  preferRecommendedDefaults?: boolean;
  onComplete?: () => void | Promise<void>;
}

const lastStep = steps.length - 1;

function errorText(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

export default function OnboardingModal({
  open = false,
  onOpenChange,
  preferRecommendedDefaults = false,
  onComplete,
}: OnboardingModalProps) {
  const [step, setStep] = useState(0);
  /** Furthest step visited; the rail lets people jump back to anything up to here. */
  const [reached, setReached] = useState(0);
  const [direction, setDirection] = useState(1);
  const [settings, setSettings] = useState<SettingsDto | null>(null);
  const [choices, setChoices] = useState<OnboardingChoices | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const preferRecommended = useRef(preferRecommendedDefaults);
  useEffect(() => {
    preferRecommended.current = preferRecommendedDefaults;
  });

  const connected = useSelector(daemon, (d) => d.state.connected);
  const current = steps[step];

  // Every opening starts the wizard over.
  const [wasOpen, setWasOpen] = useState(false);
  if (open !== wasOpen) {
    setWasOpen(open);
    if (open) {
      setStep(0);
      setReached(0);
      setDirection(1);
      setSettings(null);
      setChoices(null);
      setError('');
    }
  }

  // Loads the daemon's settings once the dialog is open and connected. The
  // cleanup drops a load still in flight (closing, disconnecting, unmount);
  // a StrictMode remount simply starts it again.
  // Until it lands, the steps after Welcome show the loading state (`!choices`).
  const needsSettings = open && connected && !settings;
  useEffect(() => {
    if (!needsSettings) return;
    let cancelled = false;
    void (async () => {
      try {
        const loaded = await api.getSettings();
        if (cancelled) return;
        setSettings(loaded);
        setChoices(onboardingChoicesFromSettings(loaded, preferRecommended.current));
        setError('');
      } catch (cause) {
        if (!cancelled) setError(errorText(cause));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [needsSettings]);

  const stepRef = useEnterMotion<HTMLDivElement>(stepIn({ direction }), step);

  function patchChoice<K extends keyof OnboardingChoices>(key: K, value: OnboardingChoices[K]) {
    setChoices((prev) => (prev ? { ...prev, [key]: value } : prev));
  }

  function goTo(index: number, furthest = reached) {
    if (index === step || index < 0 || index > furthest || saving) return;
    setDirection(index > step ? 1 : -1);
    setStep(index);
    setError('');
  }

  async function skipSetup() {
    if (saving) return;
    setSaving(true);
    setError('');
    try {
      await onComplete?.();
      onOpenChange?.(false);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setSaving(false);
    }
  }

  async function next() {
    if (step < lastStep) {
      const furthest = Math.max(reached, step + 1);
      setReached(furthest);
      goTo(step + 1, furthest);
      return;
    }
    if (!settings || !choices || saving) return;
    setSaving(true);
    setError('');
    try {
      const updated = applyOnboardingChoices(settings, choices);
      const result = await api.updateSettings(updated);
      if (!result.success) throw new Error(m.onboarding_error_daemon_rejected());
      await onComplete?.();
      daemon.addToast(
        m.onboarding_toast_complete_title(),
        m.onboarding_toast_complete_body(),
        'var(--ok)',
      );
      if (result.notApplied.length > 0) {
        daemon.addToast(
          m.settings_toast_not_applied_title(),
          result.notApplied.join('\n'),
          'var(--warn)',
        );
      }
      onOpenChange?.(false);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setSaving(false);
    }
  }

  function renderStep() {
    if (step === 0) return <WelcomeStep />;
    if (!connected) {
      return (
        <div className={styles.state}>
          <span className={styles.stateDot}></span>
          <strong>{m.onboarding_waiting_daemon_title()}</strong>
          <p>{m.onboarding_waiting_daemon_body()}</p>
        </div>
      );
    }
    if (!choices) {
      return (
        <div className={styles.state}>
          <Spinner />
          <strong>{m.onboarding_loading_settings()}</strong>
        </div>
      );
    }
    if (step === 1) return <ResolverStep choices={choices} patch={patchChoice} />;
    if (step === 2) return <BlocklistsStep choices={choices} patch={patchChoice} />;
    if (step === 3) return <GeoIpStep choices={choices} patch={patchChoice} />;
    if (step === 4) return <AlertsStep choices={choices} patch={patchChoice} />;
    return <RetentionStep choices={choices} patch={patchChoice} />;
  }

  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className={styles.setupOverlay} />
        <AlertDialog.Content
          className={styles.setupModal}
          onEscapeKeyDown={(event) => event.preventDefault()}
        >
          <OnboardingRail step={step} reached={reached} disabled={saving} onselect={goTo} />

          <section className={styles.main}>
            <div key={step} ref={stepRef} className={styles.step}>
              <header className={styles.stepHead}>
                <AlertDialog.Title className={styles.setupTitle}>
                  {current.title()}
                </AlertDialog.Title>
                <AlertDialog.Description className={styles.lead} id="setup-description">
                  {current.lead()}
                </AlertDialog.Description>
              </header>

              {/* `step-body` (plain) anchors the shared onboarding-steps.css. */}
              <div className={clsx(styles.stepBody, 'step-body')}>
                {renderStep()}
                {error && (
                  <div className={styles.error} role="alert">
                    {error}
                  </div>
                )}
              </div>
            </div>

            <footer className={styles.foot}>
              <span className={styles.progress}>
                {m.onboarding_step_progress_aria({ step: step + 1, total: steps.length })}
              </span>
              <div className={styles.actions}>
                {step > 0 ? (
                  <Button variant="ghost" onClick={() => goTo(step - 1)} disabled={saving}>
                    {m.onboarding_back()}
                  </Button>
                ) : (
                  <Button variant="ghost" onClick={() => void skipSetup()} disabled={saving}>
                    {m.onboarding_skip()}
                  </Button>
                )}
                <Button
                  variant="primary"
                  onClick={() => void next()}
                  disabled={(!choices && step > 0) || saving || !connected}
                >
                  {saving
                    ? m.onboarding_saving()
                    : step === lastStep
                      ? m.onboarding_apply()
                      : m.onboarding_continue()}
                </Button>
              </div>
            </footer>
          </section>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}
