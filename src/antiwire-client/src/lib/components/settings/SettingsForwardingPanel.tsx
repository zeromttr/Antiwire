// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import type { SettingsDto } from '#lib/api/daemon.ts';
import { SecretInput } from '#lib/components/settings/form/SecretInput.tsx';
import { SettingsGroup } from '#lib/components/settings/form/SettingsGroup.tsx';
import { SettingsToggleRow as ToggleRow } from '#lib/components/settings/form/SettingsToggleRow.tsx';
import { SegmentedControl } from '#lib/components/ui/SegmentedControl.tsx';
import { SettingsFieldLabel } from '#lib/components/ui/SettingsFieldLabel.tsx';
import { SettingsInput } from '#lib/components/ui/SettingsInput.tsx';
import { m } from '#lib/i18n/messages.ts';
import type { SettingsWorkspace } from './settings-workspace.ts';
import styles from './SettingsForwardingPanel.module.css';

interface Props {
  set: SettingsWorkspace;
  settings: SettingsDto;
}

type EventKey =
  | 'siemSendAllowed'
  | 'siemSendBlocked'
  | 'siemSendNewApp'
  | 'siemSendNewDomain'
  | 'siemSendThreats';

const EVENTS: { key: EventKey; label: () => string }[] = [
  { key: 'siemSendBlocked', label: m.settings_siem_send_blocked },
  { key: 'siemSendThreats', label: m.settings_siem_send_threats },
  { key: 'siemSendNewApp', label: m.settings_siem_send_new_app },
  { key: 'siemSendNewDomain', label: m.settings_siem_send_new_domain },
  { key: 'siemSendAllowed', label: m.settings_siem_send_allowed },
];

export function SettingsForwardingPanel({ set, settings }: Props) {
  return (
    <div className="settings-groups">
      <SettingsGroup>
        <ToggleRow
          label={m.settings_siem_enable_label()}
          description={m.settings_siem_enable_desc()}
          checked={settings.siemEnabled}
          onCheckedChange={(v) => set.patch('siemEnabled', v)}
        />
      </SettingsGroup>

      {/* Each destination's fields appear only while it is on. */}
      <SettingsGroup
        title={m.settings_group_destinations_title()}
        description={m.settings_group_destinations_desc()}
      >
        <ToggleRow
          label={m.settings_siem_file_label()}
          description={m.settings_siem_file_desc()}
          checked={settings.siemFileEnabled}
          onCheckedChange={(v) => set.patch('siemFileEnabled', v)}
          details={
            <div className={styles.sinkFields}>
              <div className={styles.fieldBlock}>
                <SettingsFieldLabel
                  htmlFor="wazuh-file"
                  label={m.settings_siem_log_file_path_label()}
                />
                <SettingsInput
                  id="wazuh-file"
                  value={settings.wazuhFilePath}
                  onInput={(e) => set.patch('wazuhFilePath', e.currentTarget.value)}
                />
              </div>
            </div>
          }
        />

        <ToggleRow
          label={m.settings_siem_syslog_label()}
          description={m.settings_siem_syslog_desc()}
          checked={settings.siemSyslogEnabled}
          onCheckedChange={(v) => set.patch('siemSyslogEnabled', v)}
          details={
            <div className={styles.sinkFields}>
              <div className={styles.pair}>
                <div className={styles.fieldBlock}>
                  <SettingsFieldLabel
                    htmlFor="wazuh-host"
                    label={m.settings_siem_manager_host_label()}
                  />
                  <SettingsInput
                    id="wazuh-host"
                    value={settings.wazuhManagerHost}
                    invalid={set.siemHostInvalid}
                    onInput={(e) => set.patch('wazuhManagerHost', e.currentTarget.value)}
                  />
                </div>
                <div className={styles.fieldBlock}>
                  <SettingsFieldLabel
                    htmlFor="wazuh-port"
                    label={m.settings_siem_manager_port_label()}
                  />
                  <SettingsInput
                    id="wazuh-port"
                    type="number"
                    min={1}
                    max={65535}
                    value={settings.wazuhManagerPort}
                    invalid={set.siemPortInvalid}
                    onInput={(e) => set.patch('wazuhManagerPort', Number(e.currentTarget.value))}
                  />
                </div>
              </div>
              <div className={clsx(styles.fieldBlock, styles.segmentedBlock)}>
                <SettingsFieldLabel label={m.settings_siem_syslog_protocol_label()} />
                <SegmentedControl
                  options={set.siemProtocolOptions}
                  value={set.siemProtocol}
                  ariaLabel={m.settings_siem_syslog_protocol_label()}
                  onChange={(v) => set.patch('wazuhProtocol', v)}
                />
              </div>
            </div>
          }
        />

        <ToggleRow
          label={m.settings_siem_webhook_label()}
          description={m.settings_siem_webhook_desc()}
          checked={settings.siemWebhookEnabled}
          onCheckedChange={(v) => set.patch('siemWebhookEnabled', v)}
          details={
            <div className={styles.sinkFields}>
              <div className={styles.fieldBlock}>
                <SettingsFieldLabel
                  htmlFor="siem-url"
                  label={m.settings_siem_webhook_url_label()}
                />
                <SettingsInput
                  id="siem-url"
                  value={settings.siemUrl}
                  invalid={set.siemUrlInvalid}
                  onInput={(e) => set.patch('siemUrl', e.currentTarget.value)}
                />
              </div>
              <div className={clsx(styles.pair, styles.even)}>
                <div className={styles.fieldBlock}>
                  <SettingsFieldLabel
                    htmlFor="siem-auth-header"
                    label={m.settings_siem_auth_header_label()}
                  />
                  <SettingsInput
                    id="siem-auth-header"
                    value={settings.siemAuthHeader}
                    placeholder={m.settings_siem_auth_header_placeholder()}
                    onInput={(e) => set.patch('siemAuthHeader', e.currentTarget.value)}
                  />
                </div>
                <div className={styles.fieldBlock}>
                  <SettingsFieldLabel
                    htmlFor="siem-auth-token"
                    label={m.settings_siem_auth_token_label()}
                  />
                  <SecretInput
                    id="siem-auth-token"
                    value={settings.siemAuthToken}
                    stored={settings.siemAuthTokenSet}
                    cleared={settings.clearSiemAuthToken}
                    oninput={(value) =>
                      set.patchSecret('siemAuthToken', 'clearSiemAuthToken', value)
                    }
                    onclear={() => set.clearSecret('siemAuthToken', 'clearSiemAuthToken')}
                  />
                </div>
              </div>
            </div>
          }
        />
      </SettingsGroup>

      <SettingsGroup
        title={m.settings_group_event_types_title()}
        description={m.settings_group_event_types_desc()}
      >
        {EVENTS.map((event) => (
          <ToggleRow
            key={event.key}
            label={event.label()}
            checked={settings[event.key]}
            onCheckedChange={(v) => set.patch(event.key, v)}
          />
        ))}
      </SettingsGroup>
    </div>
  );
}

export default SettingsForwardingPanel;
