import clsx from 'clsx';
import { BellRing, Clock3, Trash2 } from 'lucide-react';
import ChoiceCard from '#lib/components/ui/ChoiceCard.tsx';
import Button from '#lib/components/ui/Button.tsx';
import DialogModal from '#lib/components/ui/DialogModal.tsx';
import {
  formatWatchInterval,
  watchIntervalDescription,
  WATCH_INTERVALS,
  type DeviceWatch,
  type WatchInterval,
} from '#lib/models/network-watch.ts';
import { m } from '#lib/i18n/messages.ts';
import styles from './DeviceWatchDialog.module.css';

interface WatchableDevice {
  ipAddress: string;
  macAddress: string;
  mdnsName: string;
  manufacturer: string;
}

interface Props {
  /** Controlled open state (was `bind:open`). */
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  mode?: 'configure' | 'remove';
  device?: WatchableDevice | null;
  watch?: DeviceWatch | null;
  /** Controlled interval (was `bind:interval`). */
  interval?: WatchInterval;
  onIntervalChange?: (interval: WatchInterval) => void;
  submitting?: boolean;
  onConfirm?: (interval: WatchInterval) => void | Promise<void>;
  onCancel?: () => void;
}

export function DeviceWatchDialog({
  open = false,
  onOpenChange,
  mode = 'configure',
  device = null,
  watch = null,
  interval = 5,
  onIntervalChange,
  submitting = false,
  onConfirm,
  onCancel,
}: Props) {
  const isRemoving = mode === 'remove';
  const deviceLabel = device?.mdnsName || device?.ipAddress || m.network_watch_dialog_this_device();

  function close() {
    if (submitting) return;
    onOpenChange?.(false);
    onCancel?.();
  }

  function confirm() {
    if (!device || submitting) return;
    void onConfirm?.(interval);
  }

  return (
    <DialogModal
      open={open}
      onOpenChange={onOpenChange}
      title={
        isRemoving
          ? m.network_watch_dialog_title_remove({ device: deviceLabel })
          : m.network_watch_dialog_title_configure({ device: deviceLabel })
      }
      kicker={
        isRemoving
          ? m.network_watch_dialog_kicker_remove()
          : m.network_watch_dialog_kicker_configure()
      }
      icon={isRemoving ? Trash2 : BellRing}
      iconVariant={isRemoving ? 'bad' : 'accent'}
      describedBy="network-watch-dialog-description"
      maxWidth="520px"
      submitting={submitting}
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" disabled={submitting} onClick={close}>
            {m.common_cancel()}
          </Button>
          <Button
            variant={isRemoving ? 'destructive' : 'primary'}
            disabled={submitting || !device}
            onClick={confirm}
          >
            {submitting
              ? isRemoving
                ? m.network_watch_removing()
                : m.network_watch_saving()
              : isRemoving
                ? m.network_watch_remove()
                : m.network_watch_start()}
          </Button>
        </>
      }
    >
      <div className={styles.body}>
        <p id="network-watch-dialog-description" className={styles.intro}>
          {isRemoving
            ? m.network_watch_dialog_intro_remove()
            : m.network_watch_dialog_intro_configure()}
        </p>

        {device && (
          <dl className={clsx(styles['device-details'], 'mono')}>
            <div>
              <dt>{m.network_watch_dialog_ip()}</dt>
              <dd>{device.ipAddress}</dd>
            </div>
            <div>
              <dt>{m.network_watch_dialog_mac()}</dt>
              <dd>{device.macAddress}</dd>
            </div>
            {device.manufacturer && (
              <div>
                <dt>{m.network_watch_dialog_vendor()}</dt>
                <dd>{device.manufacturer}</dd>
              </div>
            )}
            {isRemoving && watch && (
              <div>
                <dt>{m.network_watch_dialog_check_interval()}</dt>
                <dd>
                  {m.network_watch_dialog_every_interval({
                    interval: formatWatchInterval(watch.intervalMinutes),
                  })}
                </dd>
              </div>
            )}
          </dl>
        )}

        {!isRemoving && (
          <fieldset className={styles['interval-fieldset']} disabled={submitting}>
            <legend>
              <Clock3 size={14} strokeWidth={1.75} />
              {m.network_watch_dialog_interval_legend()}
            </legend>
            <div className={styles['interval-grid']}>
              {WATCH_INTERVALS.map((option) => (
                <ChoiceCard
                  key={option}
                  className={styles['interval-option']}
                  selected={interval === option}
                  onClick={() => onIntervalChange?.(option)}
                >
                  <span>
                    {m.network_watch_dialog_every_interval({
                      interval: formatWatchInterval(option),
                    })}
                  </span>
                  <small>{watchIntervalDescription(option)}</small>
                </ChoiceCard>
              ))}
            </div>
          </fieldset>
        )}
      </div>
    </DialogModal>
  );
}

export default DeviceWatchDialog;
