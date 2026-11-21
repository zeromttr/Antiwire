// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import {
  AlertTriangle,
  Ban,
  Clock,
  Download,
  ExternalLink,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  type LucideIcon,
} from 'lucide-react';
import { releaseUrl } from '#shared/project.ts';
import { useEffect, useId } from 'react';
import type { SettingsDto } from '#lib/api/daemon.ts';
import { SettingsGroup } from '#lib/components/settings/form/SettingsGroup.tsx';
import { Button } from '#lib/components/ui/Button.tsx';
import { ChoiceCard } from '#lib/components/ui/ChoiceCard.tsx';
import { m } from '#lib/i18n/messages.ts';
import {
  channelSwitchNote,
  normalizeUpdateChannel,
  updatesPanelStatus,
  type UpdatesPanelStatus,
} from '#lib/models/update-status.ts';
import { shallowEqual, useSelector } from '#lib/state/reactive.ts';
import { updates } from '#lib/stores/updates.ts';
import { UPDATE_CHANNELS, type UpdateChannel, type UpdateStatus } from '#lib/types/index.ts';
import { formatDateTime } from '#lib/utils/format.ts';
import type { SettingsWorkspace } from './settings-workspace.ts';
import styles from './SettingsUpdatesPanel.module.css';

interface Props {
  set: SettingsWorkspace;
  settings: SettingsDto;
}

const CHANNEL_TEXT: Record<
  UpdateChannel,
  { label: () => string; description: () => string; stability: number }
> = {
  stable: {
    label: m.settings_updates_channel_stable,
    description: m.settings_updates_channel_stable_desc,
    stability: 3,
  },
  beta: {
    label: m.settings_updates_channel_beta,
    description: m.settings_updates_channel_beta_desc,
    stability: 2,
  },
  nightly: {
    label: m.settings_updates_channel_nightly,
    description: m.settings_updates_channel_nightly_desc,
    stability: 1,
  },
};

type Tone = 'ok' | 'busy' | 'bad' | 'new' | 'muted';

interface Hero {
  tone: Tone;
  icon: LucideIcon;
  spin?: boolean;
  eyebrow?: string;
  title: string;
  body: string;
  /** A machine-written reason, shown in monospace under the body. */
  detail?: string;
}

function channelLabel(channel: string): string {
  return CHANNEL_TEXT[normalizeUpdateChannel(channel)].label();
}

/** What the status card says. Leads with the state, then one line on what it means. */
function hero(view: UpdatesPanelStatus, status: UpdateStatus | null): Hero {
  const current = status?.currentVersion || m.common_em_dash();
  switch (view.kind) {
    case 'checking':
      return {
        tone: 'busy',
        icon: RefreshCw,
        spin: true,
        title: m.settings_updates_checking(),
        body: m.settings_updates_checking_body(),
      };
    case 'unreachable':
    case 'check_error':
      return {
        tone: 'bad',
        icon: AlertTriangle,
        title: m.settings_updates_check_error(),
        body: '',
        detail: view.detail,
      };
    case 'installing':
      return {
        tone: 'busy',
        icon: RefreshCw,
        spin: true,
        title: m.settings_updates_installing(),
        body: m.shell_update_dialog_body(),
      };
    case 'reopen':
      return {
        tone: 'ok',
        icon: ShieldCheck,
        title: m.shell_update_reopen({ version: view.version }),
        body: '',
      };
    case 'failed':
      return {
        tone: 'bad',
        icon: RotateCcw,
        title: m.settings_updates_failed(),
        body: '',
        detail: view.detail,
      };
    case 'available':
      return {
        tone: 'new',
        icon: Download,
        eyebrow: m.settings_updates_available_label(),
        title: m.settings_updates_available({ version: view.version }),
        body: m.settings_updates_available_body({ current }),
      };
    case 'unsupported':
      return {
        tone: 'muted',
        icon: Ban,
        title: m.settings_updates_unsupported(),
        body: view.detail,
      };
    case 'up_to_date':
      return {
        tone: 'ok',
        icon: ShieldCheck,
        title: m.settings_updates_up_to_date(),
        body: m.settings_updates_up_to_date_body({ version: current }),
      };
    case 'unknown':
      return {
        tone: 'muted',
        icon: Clock,
        title: m.settings_updates_never_checked(),
        body: m.settings_updates_never_checked_body(),
      };
  }
}

export function SettingsUpdatesPanel({ set, settings }: Props) {
  const state = useSelector(
    updates,
    (u) => ({ status: u.status, checking: u.checking, checkFailure: u.checkFailure }),
    shallowEqual,
  );
  const headingId = useId();
  const status = state.status;
  const chosen = normalizeUpdateChannel(settings.updateChannel);
  // The daemon checks the saved channel; an unsaved choice is not checked yet.
  const saved = status ? normalizeUpdateChannel(status.channel) : chosen;
  const note = status
    ? channelSwitchNote(status.currentVersion, saved, chosen)
    : ({ kind: 'none' } as const);
  const view = updatesPanelStatus(status, state.checking, state.checkFailure);
  const card = hero(view, status);
  const Icon = card.icon;
  const notesUrl =
    view.kind === 'available' || view.kind === 'unsupported'
      ? releaseUrl(status?.availableVersion ?? '')
      : '';
  const notes = view.kind === 'available' ? (status?.notes.trim() ?? '') : '';
  const canInstall =
    view.kind === 'available' || (view.kind === 'failed' && !!status?.availableVersion);
  const canCheck = !state.checking && note.kind === 'none' && view.kind !== 'installing';

  useEffect(() => {
    void updates.refresh();
  }, []);

  return (
    <div className="settings-groups">
      <section className={clsx('panel', styles.hero)} aria-labelledby={headingId}>
        <div className={clsx(styles.heroMain, card.tone === 'new' && styles.heroNew)}>
          <div className={clsx(styles.heroIcon, styles[card.tone])} aria-hidden="true">
            <Icon size={24} strokeWidth={2} className={clsx(card.spin && styles.spinning)} />
          </div>
          <div className={styles.heroText} role="status" aria-live="polite">
            {card.eyebrow && <p className={styles.eyebrow}>{card.eyebrow}</p>}
            <h3 id={headingId} className={styles.heroTitle}>
              {card.title}
            </h3>
            {card.body && <p className={styles.heroBody}>{card.body}</p>}
            {card.detail && <p className={clsx(styles.heroDetail, 'mono')}>{card.detail}</p>}
          </div>
          <div className={styles.actions}>
            {canInstall && (
              <Button
                variant="primary"
                size="sm"
                onClick={() => updates.setInstallDialogOpen(true)}
              >
                <Download size={14} />
                {m.settings_updates_install_button()}
              </Button>
            )}
            {view.kind !== 'installing' && (
              <Button
                variant="secondary"
                size="sm"
                disabled={!canCheck}
                onClick={() => void updates.check()}
              >
                <RefreshCw size={14} className={clsx(state.checking && styles.spinning)} />
                {m.settings_updates_check_button()}
              </Button>
            )}
          </div>
        </div>

        {(notes || notesUrl) && (
          <div className={styles.notes}>
            <div className={styles.notesHead}>
              {notes && <h4>{m.settings_updates_whats_new()}</h4>}
              {notesUrl && (
                // The main process sends new-window links to the system browser.
                <a
                  className={styles.link}
                  href={notesUrl}
                  target="_blank"
                  rel="noreferrer noopener"
                >
                  {m.settings_updates_release_notes()}
                  <ExternalLink size={11} strokeWidth={2} aria-hidden="true" />
                </a>
              )}
            </div>
            {notes && <p className={styles.notesBody}>{notes}</p>}
          </div>
        )}

        <p className={styles.meta}>
          <span>
            {m.settings_updates_installed_label()}{' '}
            <span className={clsx(styles.metaValue, 'mono')}>
              {status?.currentVersion || m.common_em_dash()}
            </span>
          </span>
          <span>
            {m.settings_updates_channel_label()}{' '}
            <span className={styles.metaValue}>
              {status ? channelLabel(status.channel) : m.common_em_dash()}
            </span>
          </span>
          {status && status.lastCheckedAt > 0 && (
            <span>
              {m.settings_updates_last_checked({ when: formatDateTime(status.lastCheckedAt) })}
            </span>
          )}
        </p>
      </section>

      <SettingsGroup
        title={m.settings_updates_channel_title()}
        description={m.settings_updates_channel_desc()}
      >
        <div
          className={styles.channels}
          role="radiogroup"
          aria-label={m.settings_updates_channel_title()}
        >
          {UPDATE_CHANNELS.map((channel) => (
            <ChoiceCard
              key={channel}
              role="radio"
              className={styles.channel}
              selected={chosen === channel}
              onClick={() => set.patch('updateChannel', channel)}
            >
              <span className={styles.stability} aria-hidden="true">
                {[1, 2, 3].map((bar) => (
                  <span
                    key={bar}
                    className={clsx(bar <= CHANNEL_TEXT[channel].stability && styles.on)}
                  />
                ))}
              </span>
              <strong>{CHANNEL_TEXT[channel].label()}</strong>
              <span>{CHANNEL_TEXT[channel].description()}</span>
            </ChoiceCard>
          ))}
        </div>

        {note.kind !== 'none' && (
          <div className={styles.switchNote} role="status">
            {note.kind === 'stay' ? (
              <>
                <p className={styles.switchTitle}>
                  {m.settings_updates_switch_stay({ version: note.version })}
                </p>
                <p>{m.settings_updates_switch_stay_body()}</p>
              </>
            ) : (
              <p className={styles.switchTitle}>{m.settings_updates_switch_now()}</p>
            )}
            <div className={styles.switchActions}>
              <Button
                variant="primary"
                size="sm"
                disabled={set.saving || !set.settingsFieldsValid || !set.connected}
                onClick={() => void set.saveSettings()}
              >
                {m.settings_updates_switch_button()}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={set.saving}
                onClick={() => set.revertField('updateChannel')}
              >
                {m.common_cancel()}
              </Button>
            </div>
          </div>
        )}
      </SettingsGroup>
    </div>
  );
}

export default SettingsUpdatesPanel;
