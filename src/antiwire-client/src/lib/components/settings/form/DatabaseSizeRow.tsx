import { m } from '#lib/i18n/messages.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { formatBytes } from '#lib/utils/format.ts';
import styles from './DatabaseSizeRow.module.css';

/** Read-only row showing how much disk the daemon's history database takes. */
export function DatabaseSizeRow() {
  const size = useSelector(daemon, (d) => d.state.stats.databaseSizeBytes);
  return (
    <div className={styles.row}>
      <div className={styles.text}>
        <div className={styles.label}>{m.settings_database_size_label()}</div>
        <div className={styles.desc}>{m.settings_database_size_desc()}</div>
      </div>
      <span className={styles.value}>
        {size == null ? m.settings_database_size_unavailable() : formatBytes(size)}
      </span>
    </div>
  );
}

export default DatabaseSizeRow;
