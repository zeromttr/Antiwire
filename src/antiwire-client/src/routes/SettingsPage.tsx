// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import { Check } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from '#lib/api/daemon.ts';
import '#lib/components/settings/form/settings-form.css';
import { AboutSettingsTab } from '#lib/components/settings/AboutSettingsTab.tsx';
import { PowerUserWarningDialog } from '#lib/components/settings/dialogs/PowerUserWarningDialog.tsx';
import type { SettingsSection } from '#lib/components/settings/form/settings-form';
import { SettingsAiPanel } from '#lib/components/settings/SettingsAiPanel.tsx';
import { SettingsDnsPanel } from '#lib/components/settings/SettingsDnsPanel.tsx';
import { SettingsForwardingPanel } from '#lib/components/settings/SettingsForwardingPanel.tsx';
import { SettingsGeneralPanel } from '#lib/components/settings/SettingsGeneralPanel.tsx';
import { SettingsNetworkPanel } from '#lib/components/settings/SettingsNetworkPanel.tsx';
import { SettingsSideNav } from '#lib/components/settings/SettingsSideNav.tsx';
import { SettingsUpdatesPanel } from '#lib/components/settings/SettingsUpdatesPanel.tsx';
import {
  SettingsWorkspace,
  type SettingsHost,
} from '#lib/components/settings/settings-workspace.ts';
import { Button } from '#lib/components/ui/Button.tsx';
import { EmptyState } from '#lib/components/ui/EmptyState.tsx';
import DaemonOffline from '#lib/components/shell/DaemonOffline.tsx';
import { m } from '#lib/i18n/messages.ts';
import { useReactive, useSelector } from '#lib/state/reactive.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { updates } from '#lib/stores/updates.ts';
import styles from './SettingsPage.module.css';

const SECTIONS: Record<SettingsSection, { title: () => string; description: () => string }> = {
  General: { title: m.settings_appearance_title, description: m.settings_appearance_intro },
  Notifications: {
    title: m.settings_notifications_title,
    description: m.settings_notifications_intro,
  },
  Activity: { title: m.settings_activity_title, description: m.settings_activity_intro },
  DNS: { title: m.settings_nav_dns, description: m.settings_dns_intro },
  AI: { title: m.settings_ai_title, description: m.settings_ai_intro },
  'Network Mapping': {
    title: m.settings_nav_network_mapping,
    description: m.settings_network_intro,
  },
  'Event Forwarding': {
    title: m.settings_nav_event_forwarding,
    description: m.settings_forwarding_intro,
  },
  Updates: { title: m.settings_nav_updates, description: m.settings_updates_intro },
  About: { title: m.settings_nav_about, description: m.settings_about_intro },
};

// One host for the page's lifetime: it reads the store when asked, so the
// workspace never sees a stale connection state.
const HOST: SettingsHost = {
  get connected() {
    return daemon.state.connected;
  },
  toast: (title, body, color) => daemon.addToast(title, body, color),
  // A new channel has its own releases, so check it at once rather than at the next timer.
  saved: (before, after) => {
    if (before?.updateChannel !== after.updateChannel) void updates.check();
  },
};

export default function SettingsPage() {
  const connected = useSelector(daemon, (d) => d.state.connected);
  const [set] = useState(() => new SettingsWorkspace(api, HOST));
  useReactive(set);

  // Load on every (re)connect. The cleanup drops a load still in flight on
  // disconnect or unmount; a StrictMode remount simply loads again.
  useEffect(() => {
    if (!connected) return;
    void set.loadSettings();
    return () => set.dispose();
  }, [connected, set]);

  const section = SECTIONS[set.section];

  function renderSection() {
    if (set.section === 'About') return <AboutSettingsTab />;
    if (set.section === 'General') return <SettingsGeneralPanel set={set} />;
    if (!connected) return <DaemonOffline text={m.settings_empty_daemon_cannot_load()} />;
    if (set.loadFailed) {
      return (
        <div className={clsx(styles.loadError, 'panel')} role="alert">
          <p>{m.settings_load_failed()}</p>
          <Button variant="secondary" onClick={() => void set.loadSettings()}>
            {m.settings_retry()}
          </Button>
        </div>
      );
    }
    if (set.loading || !set.settings) {
      return <EmptyState text={m.settings_empty_loading()} panel />;
    }
    const settings = set.settings;
    switch (set.section) {
      case 'Notifications':
      case 'Activity':
        return <SettingsGeneralPanel set={set} />;
      case 'DNS':
        return <SettingsDnsPanel set={set} settings={settings} />;
      case 'AI':
        return <SettingsAiPanel set={set} settings={settings} />;
      case 'Network Mapping':
        return <SettingsNetworkPanel set={set} settings={settings} />;
      case 'Event Forwarding':
        return <SettingsForwardingPanel set={set} settings={settings} />;
      case 'Updates':
        return <SettingsUpdatesPanel set={set} settings={settings} />;
      default:
        return null;
    }
  }

  return (
    <div className={styles.page} data-testid="page-settings" data-page-motion="settings">
      <div className={styles.layout}>
        <aside className={clsx(styles.subnavWrap, 'scroll')} data-motion-stage="1">
          <SettingsSideNav section={set.section} onselect={set.setSection} />
        </aside>

        <div className={clsx(styles.content, 'scroll')} data-motion-stage="2">
          <div className={styles.contentInner}>
            <section
              key={set.section}
              className={styles.sectionEnter}
              aria-labelledby="settings-section-title"
            >
              <header className={styles.sectionHeading}>
                <h2 id="settings-section-title">{section.title()}</h2>
                <p>{section.description()}</p>
              </header>
              {renderSection()}
            </section>
          </div>
        </div>
      </div>
      {set.isDirty && (
        <footer className={styles.saveBar}>
          <div className={styles.saveStatus} role="status">
            <span className={styles.statusDot}></span>
            <div>
              <strong>{m.settings_pending()}</strong>
              <p>
                {!connected
                  ? m.settings_empty_daemon_cannot_load()
                  : !set.settingsFieldsValid
                    ? m.settings_invalid_desc()
                    : m.settings_pending_desc()}
              </p>
            </div>
          </div>
          <div className={styles.saveActions}>
            <Button
              variant="secondary"
              onClick={set.discardChanges}
              disabled={set.saving || set.loading}
            >
              {m.settings_discard()}
            </Button>
            <Button
              variant="primary"
              onClick={() => void set.saveSettings()}
              disabled={!connected || !set.settingsFieldsValid || set.saving || set.loading}
            >
              <Check size={15} />
              {set.saving ? m.settings_saving() : m.settings_save_changes()}
            </Button>
          </div>
        </footer>
      )}

      {set.settings && (
        <PowerUserWarningDialog
          open={set.powerUserDialogOpen}
          onOpenChange={set.setPowerUserDialogOpen}
          onconfirm={set.confirmPowerUser}
        />
      )}
    </div>
  );
}
