// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import { AccentColorPicker } from '#lib/components/settings/form/AccentColorPicker.tsx';
import { AppearancePreview } from '#lib/components/settings/form/AppearancePreview.tsx';
import { DatabaseSizeRow } from '#lib/components/settings/form/DatabaseSizeRow.tsx';
import { HistoryDeletionGroup } from '#lib/components/settings/form/HistoryDeletionGroup.tsx';
import { InlineNumber } from '#lib/components/settings/form/InlineNumber.tsx';
import { LanguagePicker } from '#lib/components/settings/form/LanguagePicker.tsx';
import { SettingsGroup } from '#lib/components/settings/form/SettingsGroup.tsx';
import { SettingsToggleRow as ToggleRow } from '#lib/components/settings/form/SettingsToggleRow.tsx';
import { ThemePicker } from '#lib/components/settings/form/ThemePicker.tsx';
import { m } from '#lib/i18n/messages.ts';
import type { SettingsWorkspace } from './settings-workspace.ts';
import styles from './SettingsGeneralPanel.module.css';

interface Props {
  set: SettingsWorkspace;
}

export function SettingsGeneralPanel({ set }: Props) {
  if (set.section === 'General') {
    return (
      <div className={styles.appearance}>
        <ThemePicker />
        <AccentColorPicker appearance />
        <AppearancePreview />
        <LanguagePicker appearance />
      </div>
    );
  }

  const settings = set.settings;
  if (!settings) return null;
  const retentionInvalid =
    !Number.isInteger(settings.logRetentionDays) || settings.logRetentionDays < 1;

  return (
    <div className="settings-groups">
      {set.section === 'Notifications' ? (
        <>
          <SettingsGroup
            title={m.settings_group_delivery_title()}
            description={m.settings_group_delivery_desc()}
          >
            <ToggleRow
              label={m.settings_desktop_notifications_label()}
              description={m.settings_desktop_notifications_desc()}
              checked={settings.notifyEveryConnection}
              onCheckedChange={(v) => set.patch('notifyEveryConnection', v)}
            />
          </SettingsGroup>
          <SettingsGroup
            title={m.settings_group_alerts_title()}
            description={m.settings_group_alerts_desc()}
          >
            <ToggleRow
              label={m.settings_new_connection_alerts_label()}
              description={m.settings_new_connection_alerts_desc()}
              checked={settings.notifyNewConnection}
              onCheckedChange={(v) => set.patch('notifyNewConnection', v)}
            />
            <ToggleRow
              label={m.settings_new_application_alerts_label()}
              description={m.settings_new_application_alerts_desc()}
              checked={settings.notifyNewApp}
              onCheckedChange={(v) => set.patch('notifyNewApp', v)}
            />
            <ToggleRow
              label={m.settings_threat_alerts_label()}
              description={m.settings_threat_alerts_desc()}
              checked={settings.notifyThreatDetected}
              onCheckedChange={(v) => set.patch('notifyThreatDetected', v)}
            />
          </SettingsGroup>
        </>
      ) : (
        <>
          <SettingsGroup
            title={m.settings_group_details_title()}
            description={m.settings_group_details_desc()}
          >
            <ToggleRow
              label={m.settings_geoip_label()}
              description={m.settings_geoip_desc()}
              checked={settings.geoIpEnabled}
              onCheckedChange={(v) => set.patch('geoIpEnabled', v)}
            />
            <ToggleRow
              label={m.settings_save_lookups_label()}
              description={m.settings_save_lookups_desc()}
              checked={settings.saveDomainLookups}
              onCheckedChange={(v) => set.patch('saveDomainLookups', v)}
            />
          </SettingsGroup>
          <SettingsGroup
            title={m.settings_group_rules_title()}
            description={m.settings_group_rules_desc()}
          >
            <ToggleRow
              label={m.settings_persist_rules_label()}
              description={m.settings_persist_rules_desc()}
              checked={settings.persistRulesOffline}
              onCheckedChange={(v) => set.patch('persistRulesOffline', v)}
            />
          </SettingsGroup>
          <SettingsGroup
            title={m.settings_group_history_title()}
            description={m.settings_group_history_desc()}
          >
            <ToggleRow
              label={m.settings_log_retention_label()}
              description={m.settings_log_retention_desc()}
              checked={settings.logRetentionEnabled}
              onCheckedChange={(v) => set.patch('logRetentionEnabled', v)}
              details={
                retentionInvalid ? (
                  <p id="retention-error" className={clsx('field-hint', styles.error)} role="alert">
                    {m.settings_invalid_desc()}
                  </p>
                ) : undefined
              }
              actions={
                <InlineNumber
                  id="retention"
                  value={settings.logRetentionDays}
                  unit={m.settings_unit_days()}
                  label={m.settings_retention_days_label()}
                  min={1}
                  invalid={retentionInvalid}
                  describedBy={retentionInvalid ? 'retention-error' : undefined}
                  onchange={(v) => set.patch('logRetentionDays', v)}
                />
              }
            />
            <DatabaseSizeRow />
          </SettingsGroup>
          <HistoryDeletionGroup />
        </>
      )}
    </div>
  );
}

export default SettingsGeneralPanel;
