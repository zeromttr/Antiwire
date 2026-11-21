import clsx from 'clsx';
import { ArrowDown, ArrowUp, Download, SlidersHorizontal } from 'lucide-react';
import { useEffect, useState } from 'react';
import { invoke, isNative } from '#lib/bridge.ts';
import { AnimatedText } from '#lib/components/ui/AnimatedText.tsx';
import { Button } from '#lib/components/ui/Button.tsx';
import { DialogModal } from '#lib/components/ui/DialogModal.tsx';
import { m } from '#lib/i18n/messages.ts';
import {
  UPDATE_CHECK_MS,
  UPDATE_INSTALL_POLL_MS,
  updateFooterView,
} from '#lib/models/update-status.ts';
import { shallowEqual, useSelector } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { updates } from '#lib/stores/updates.ts';
import { formatBytes, formatThroughput } from '#lib/utils/index.ts';
import styles from './StatusBar.module.css';

interface Props {
  /** Re-opens the setup wizard; the button only shows in debug builds. */
  onShowSetup?: () => void;
}

export function StatusBar({ onShowSetup }: Props) {
  const update = useSelector(
    updates,
    (u) => ({
      status: u.status,
      dialogOpen: u.installDialogOpen,
      submitting: u.installSubmitting,
      error: u.installError,
    }),
    shallowEqual,
  );
  const updateStatus = update.status;
  const updateView = updateFooterView(updateStatus);
  const availableVersion = updateStatus?.availableVersion ?? '';
  const installing = updateStatus?.state === 'installing';
  const [debugBuild, setDebugBuild] = useState<boolean>(import.meta.env.DEV);

  const live = useSelector(
    daemon,
    (d) => ({
      downloadRate: d.state.downloadRate,
      uploadRate: d.state.uploadRate,
      socketsAvailable: d.state.stats.activeConnectionsAvailable,
      socketsStale: d.state.stats.activeConnectionsStale,
      activeConnections: d.state.stats.activeConnections,
      bytesToday: d.state.bytesToday,
    }),
    shallowEqual,
  );
  const download = formatThroughput(live.downloadRate).label;
  const upload = formatThroughput(live.uploadRate).label;
  const socketsLabel = !live.socketsAvailable
    ? m.shell_sockets({ count: m.common_em_dash() })
    : live.socketsStale
      ? m.shell_sockets_stale({ count: live.activeConnections })
      : m.shell_sockets({ count: live.activeConnections });
  const today = formatBytes(live.bytesToday);

  useEffect(() => {
    if (!isNative()) return;
    let cancelled = false;
    invoke<boolean>('is_debug_build').then(
      (value) => {
        if (!cancelled) setDebugBuild(value);
      },
      () => {
        if (!cancelled) setDebugBuild(import.meta.env.DEV);
      },
    );
    return () => {
      cancelled = true;
    };
  }, []);

  const openInstallDialog = () => updates.setInstallDialogOpen(true);

  // The status comes from the daemon, which the shell connects to only after the footer
  // mounts. A reconnect can also be to a daemon that restarted as another version.
  const connected = useSelector(daemon, (d) => d.state.connected);
  useEffect(() => {
    if (connected) void updates.refresh();
  }, [connected]);

  useEffect(() => {
    const onVisibilityChange = () => {
      if (!document.hidden) void updates.refresh();
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    const timer = setInterval(() => void updates.refresh(), UPDATE_CHECK_MS);
    return () => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, []);

  useEffect(() => {
    if (!installing) return;
    const timer = setInterval(() => void updates.refresh(), UPDATE_INSTALL_POLL_MS);
    return () => clearInterval(timer);
  }, [installing]);

  return (
    <>
      <footer className={styles.statusbar}>
        <div className={styles.left}>
          <span
            className={clsx(
              live.socketsStale && styles.stale,
              !live.socketsAvailable && styles.unavailable,
            )}
          >
            {socketsLabel}
          </span>
          <span className={styles.separator} aria-hidden="true"></span>
          <span className={clsx(styles.metric, styles.down)}>
            <ArrowDown size={10} />
            {m.shell_down()} <AnimatedText text={download} />
          </span>
          <span className={clsx(styles.metric, styles.up)}>
            <ArrowUp size={10} />
            {m.shell_up()} <AnimatedText text={upload} />
          </span>
        </div>
        <div className={styles.right}>
          {debugBuild && (
            <button
              type="button"
              className={styles.setupButton}
              onClick={onShowSetup}
              aria-label={m.shell_setup_aria()}
            >
              <SlidersHorizontal size={10} />
              {m.shell_setup()}
            </button>
          )}
          {updateView.kind === 'installing' ? (
            <span>{m.shell_update_installing()}</span>
          ) : updateView.kind === 'reopen' ? (
            <span>{m.shell_update_reopen({ version: updateView.version })}</span>
          ) : updateView.kind === 'unsupported' ? (
            <span>{m.shell_update_unsupported({ version: updateView.version })}</span>
          ) : updateView.kind === 'available' ? (
            <button type="button" className={styles.updateButton} onClick={openInstallDialog}>
              <Download size={10} />
              {m.shell_update_available({ version: updateView.version })}
            </button>
          ) : updateView.kind === 'failed' ? (
            <button
              type="button"
              className={clsx(styles.updateButton, styles.failed)}
              onClick={openInstallDialog}
            >
              {m.shell_update_retry()}
            </button>
          ) : null}
          <span>{m.shell_today({ bytes: today })}</span>
        </div>
      </footer>

      <DialogModal
        open={update.dialogOpen}
        onOpenChange={updates.setInstallDialogOpen}
        title={m.shell_update_dialog_title({ version: availableVersion })}
        icon={Download}
        describedBy="update-dialog-desc"
        maxWidth="440px"
        submitting={update.submitting}
        footer={
          <>
            <Button
              variant="secondary"
              disabled={update.submitting}
              onClick={() => updates.setInstallDialogOpen(false)}
            >
              {m.shell_update_dialog_later()}
            </Button>
            {/* A failure the daemon reports before it knows of a newer release has nothing to retry. */}
            <Button
              variant="primary"
              disabled={update.submitting || !availableVersion}
              onClick={() => void updates.install()}
            >
              {m.shell_update_dialog_install()}
            </Button>
          </>
        }
      >
        <div id="update-dialog-desc" className={styles.updateDialog}>
          {updateStatus?.notes && (
            <>
              <span className={styles.updateLabel}>{m.shell_update_dialog_notes()}</span>
              <p className={styles.updateNotes}>{updateStatus.notes}</p>
            </>
          )}
          {update.error ? (
            <p className={styles.updateFailure}>
              {m.shell_update_dialog_failed({ detail: update.error })}
            </p>
          ) : updateStatus?.state === 'failed' ? (
            <p className={styles.updateFailure}>
              {m.shell_update_dialog_failed({ detail: updateStatus.detail })}
            </p>
          ) : null}
          <p>{m.shell_update_dialog_body()}</p>
        </div>
      </DialogModal>
    </>
  );
}

export default StatusBar;
