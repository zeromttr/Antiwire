import { ExternalLink, Trash2 } from 'lucide-react';
import { memo, type CSSProperties } from 'react';
import { useNavigate } from 'react-router';
import { Button } from '#lib/components/ui/Button.tsx';
import { Status } from '#lib/components/ui/Status.tsx';
import { statusToneFromColor } from '#lib/components/ui/status-tone.ts';
import { m } from '#lib/i18n/messages.ts';
import {
  alertCategory,
  alertRecordsWindow,
  alertSeverityLabel,
  alertTypeLabel,
  formatAlertTime,
  type AlertCategory,
} from '#lib/models/alerts.ts';
import type { NotificationEvent } from '#lib/types/index.ts';
import { displayText } from '#lib/utils/index.ts';
import { recordsTimeWindowUrl } from '#lib/utils/records-url.ts';
import { alertIcon, alertTone } from './alert-visuals';
import styles from './AlertDetail.module.css';

interface Props {
  alert: NotificationEvent;
  dismissing?: boolean;
  onDismiss?: (id: string) => void;
}

const CATEGORY_LABELS: Record<AlertCategory, () => string> = {
  threats: () => m.alerts_tab_threats(),
  activity: () => m.alerts_tab_activity(),
  system: () => m.alerts_tab_system(),
};

export const AlertDetail = memo(function AlertDetail({
  alert,
  dismissing = false,
  onDismiss,
}: Props) {
  const navigate = useNavigate();
  const Icon = alertIcon(alert);
  const tone = alertTone(alert.severity);
  const recordsWindow = alertRecordsWindow(alert.timestamp);
  const recordsUrl = recordsWindow
    ? recordsTimeWindowUrl(recordsWindow.from, recordsWindow.to)
    : null;

  return (
    <article className={styles.detail} aria-labelledby="alert-detail-title">
      <header className={styles.head}>
        <span
          className={styles.glyph}
          style={{ '--tone': tone } as CSSProperties}
          aria-hidden="true"
        >
          <Icon size={20} strokeWidth={1.8} />
        </span>
        <div className={styles.titleBlock}>
          <h2 id="alert-detail-title">{displayText(alert.title)}</h2>
          <div className={styles.meta}>
            <Status tone={statusToneFromColor(tone)}>{alertSeverityLabel(alert.severity)}</Status>
            <span className={styles.sep} aria-hidden="true">
              ·
            </span>
            <span>{CATEGORY_LABELS[alertCategory(alert.tag)]()}</span>
          </div>
        </div>
      </header>

      {alert.body && <p className={styles.body}>{displayText(alert.body)}</p>}

      <dl className={styles.facts}>
        <div>
          <dt>{m.alerts_detail_type()}</dt>
          <dd>{alertTypeLabel(alert.tag)}</dd>
        </div>
        <div>
          <dt>{m.alerts_detail_received()}</dt>
          <dd className={styles.num}>{formatAlertTime(alert.timestamp)}</dd>
        </div>
      </dl>

      <div className={styles.actions}>
        {recordsUrl && (
          <Button
            variant="secondary"
            href={recordsUrl}
            onClick={(event) => {
              event.preventDefault();
              void navigate(recordsUrl);
            }}
          >
            {m.alerts_view_connections()}
            <ExternalLink size={13} />
          </Button>
        )}
        <Button variant="ghost" disabled={dismissing} onClick={() => onDismiss?.(alert.id)}>
          <Trash2 size={14} />
          {m.alerts_dismiss()}
        </Button>
      </div>
    </article>
  );
});

export default AlertDetail;
