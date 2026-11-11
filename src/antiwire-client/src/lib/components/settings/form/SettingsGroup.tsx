import { useId, type ReactNode } from 'react';
import styles from './SettingsGroup.module.css';

/**
 * One titled group of settings: a heading and one-line description above a
 * card of rows, the same pattern as the Appearance sections. A section is a
 * stack of these (see `.settings-groups` in settings-form.css).
 */
interface Props {
  title?: string;
  description?: string;
  children?: ReactNode;
}

export function SettingsGroup({ title, description, children }: Props) {
  const headingId = useId();
  return (
    <section className={styles.settingsGroup} aria-labelledby={title ? headingId : undefined}>
      {title && (
        <header className={styles.groupHead}>
          <h3 id={headingId}>{title}</h3>
          {description && <p>{description}</p>}
        </header>
      )}
      <div className="form-panel panel">{children}</div>
    </section>
  );
}

export default SettingsGroup;
