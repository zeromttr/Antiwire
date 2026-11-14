import clsx from 'clsx';
import { shallowEqual, useSelector } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { m } from '#lib/i18n/messages.ts';
import styles from './CollectorNotice.module.css';

/**
 * Explains a degraded collector wherever byte figures are shown.
 *
 * Without this the sent/received columns simply read zero, which is
 * indistinguishable from an idle network.
 */
export function CollectorNotice() {
  const { show, statusDetail } = useSelector(
    daemon,
    (d) => ({
      show: d.state.connected && d.state.stats.byteAccountingAvailable === false,
      statusDetail: d.state.stats.collectorStatusDetail,
    }),
    shallowEqual,
  );
  if (!show) return null;
  const detail = statusDetail || m.dashboard_collector_fallback();
  return (
    <div className={styles.notice} role="status" data-testid="collector-notice">
      <span className={clsx(styles.dot, 'dot')} aria-hidden="true"></span>
      <div className={styles.body}>
        <div className={styles.title}>{m.dashboard_collector_title()}</div>
        <div className={styles.detail}>{detail}</div>
      </div>
    </div>
  );
}

export default CollectorNotice;
