import clsx from 'clsx';
import { AlertTriangle } from 'lucide-react';
import { m } from '#lib/i18n/messages.ts';
import { navigate } from '#lib/navigation.ts';
import { formatErrorMessage, tryMessage } from '#lib/utils/error.ts';
import { Button } from './Button.tsx';
import styles from './ErrorFallback.module.css';

export type ErrorFallbackVariant = 'fatal' | 'page' | 'inspector' | 'inline';

export interface ErrorFallbackProps {
  error?: unknown;
  /** Shown as the primary "retry" action when set. */
  reset?: () => void;
  variant?: ErrorFallbackVariant;
  title?: string;
  retryLabel?: string;
  status?: number;
  showHome?: boolean;
  showReload?: boolean;
  onHome?: () => void;
  onReload?: () => void;
}

export function ErrorFallback({
  error,
  reset,
  variant = 'page',
  title = '',
  retryLabel = '',
  status,
  showHome = false,
  showReload = false,
  onHome,
  onReload,
}: ErrorFallbackProps) {
  const compact = variant === 'inline' || variant === 'inspector';

  const heading =
    title ||
    (variant === 'inspector'
      ? tryMessage(() => m.error_inspector_title(), 'Failed to render packet inspector')
      : variant === 'fatal'
        ? tryMessage(() => m.error_fatal_title(), 'Antiwire hit an unexpected error')
        : tryMessage(() => m.error_page_title(), 'Something went wrong'));

  const body =
    variant === 'inline' || variant === 'inspector'
      ? ''
      : variant === 'fatal'
        ? tryMessage(
            () => m.error_fatal_body(),
            'The current view could not be shown. You can retry, go back to the dashboard, or reload the app.',
          )
        : tryMessage(
            () => m.error_page_body(),
            'This view failed to render. Navigation and the Antiwire service are still running.',
          );

  const detail = formatErrorMessage(
    error,
    tryMessage(() => m.error_generic_detail(), 'An unexpected error occurred.'),
  );

  const retryText =
    retryLabel ||
    (variant === 'inspector'
      ? tryMessage(() => m.error_inspector_retry(), 'Retry Inspector')
      : variant === 'page'
        ? tryMessage(() => m.error_recover_view(), 'Recover View')
        : tryMessage(() => m.error_retry(), 'Try again'));

  const homeText = tryMessage(() => m.error_go_home(), 'Go to Dashboard');
  const reloadText = tryMessage(() => m.error_reload(), 'Reload Antiwire');
  const kicker =
    typeof status === 'number' && status > 0
      ? tryMessage(() => m.error_status({ status }), `Error ${status}`)
      : tryMessage(() => m.error_kicker(), 'RECOVERY');

  function goHome() {
    if (onHome) {
      onHome();
      return;
    }
    try {
      navigate('/');
    } catch {
      location.assign('/');
    }
  }

  function reload() {
    if (onReload) {
      onReload();
      return;
    }
    location.reload();
  }

  const size = compact ? 'sm' : 'md';

  return (
    <div
      className={clsx(
        styles.errorFallback,
        compact && styles.compact,
        (variant === 'page' || variant === 'fatal') && styles.page,
        variant === 'inspector' && styles.inspector,
        variant === 'inline' && styles.inline,
      )}
      role="alert"
      data-testid="error-fallback"
    >
      <div className={clsx(styles.card, 'panel', compact && styles.compact)}>
        {!compact && <div className={styles.kicker}>{kicker}</div>}
        <div className={styles.head}>
          <div className={clsx(styles.icon, compact && styles.compact)}>
            <AlertTriangle size={compact ? 16 : 18} strokeWidth={1.75} />
          </div>
          <h3 className={styles.title}>{heading}</h3>
        </div>
        {body && <p className={styles.body}>{body}</p>}
        <p className={clsx(styles.detail, 'mono')}>{detail}</p>
        <div className={styles.actions}>
          {reset && (
            <Button variant="primary" size={size} data-testid="error-retry" onClick={() => reset()}>
              {retryText}
            </Button>
          )}
          {showHome && (
            <Button variant="secondary" size={size} data-testid="error-home" onClick={goHome}>
              {homeText}
            </Button>
          )}
          {showReload && (
            <Button variant="secondary" size={size} data-testid="error-reload" onClick={reload}>
              {reloadText}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

export default ErrorFallback;
