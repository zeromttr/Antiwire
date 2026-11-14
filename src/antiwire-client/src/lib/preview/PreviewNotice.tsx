import { browserPreviewMode } from './runtime';
import styles from './PreviewNotice.module.css';

/** Banner shown only in the browser preview (no Electron), with links to switch scenario. */
export function PreviewNotice() {
  if (!browserPreviewMode) return null;
  return (
    <aside
      className={styles.previewNotice}
      aria-label="Browser preview"
      data-testid="browser-preview"
    >
      <span>
        <strong>Browser preview</strong> ·{' '}
        {browserPreviewMode === 'sample'
          ? 'Synthetic data · sample changes reset on reload'
          : 'Offline scenario'}
      </span>
      <span className={styles.actions}>
        {/* Plain links: a full document load re-seeds the preview scenario. */}
        <a href="?preview=sample">Reset sample data</a>
        <a href="?preview=offline">Test offline</a>
      </span>
    </aside>
  );
}

export default PreviewNotice;
