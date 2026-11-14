import { Button } from '#lib/components/ui/Button.tsx';
import { SettingsInput } from '#lib/components/ui/SettingsInput.tsx';
import { m } from '#lib/i18n/messages.ts';
import styles from './SecretInput.module.css';

/**
 * Input for a write-only daemon secret. The daemon never returns the stored
 * value, only whether one exists, so an empty field keeps it and Remove asks
 * the daemon to delete it on the next save.
 */
interface Props {
  id: string;
  value: string;
  stored: boolean;
  cleared: boolean;
  describedBy?: string;
  oninput: (value: string) => void;
  onclear: () => void;
}

export function SecretInput({ id, value, stored, cleared, describedBy, oninput, onclear }: Props) {
  const kept = stored && !cleared;
  const placeholder = kept
    ? m.settings_secret_saved_placeholder()
    : stored && cleared
      ? m.settings_secret_cleared_placeholder()
      : '';
  return (
    <div className={styles.secretRow}>
      <SettingsInput
        id={id}
        type="password"
        autoComplete="off"
        aria-describedby={describedBy}
        value={value}
        placeholder={placeholder}
        onInput={(event) => oninput(event.currentTarget.value)}
      />
      {kept && value === '' && (
        <span className={styles.secretAction}>
          <Button variant="secondary" size="sm" onClick={onclear}>
            {m.settings_secret_remove()}
          </Button>
        </span>
      )}
    </div>
  );
}

export default SecretInput;
