import styles from './SettingsFieldLabel.module.css';

interface Props {
  /** Id of the control; renders a `<label for>`. Without it the label is a plain span. */
  htmlFor?: string;
  label: string;
}

export function SettingsFieldLabel({ htmlFor, label }: Props) {
  return htmlFor ? (
    <label className={styles.settingsFieldLabel} htmlFor={htmlFor}>
      {label}
    </label>
  ) : (
    <span className={styles.settingsFieldLabel}>{label}</span>
  );
}

export default SettingsFieldLabel;
