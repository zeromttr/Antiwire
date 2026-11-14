// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import type { SettingsDto } from '#lib/api/daemon.ts';
import { SecretInput } from '#lib/components/settings/form/SecretInput.tsx';
import { SettingsGroup } from '#lib/components/settings/form/SettingsGroup.tsx';
import { SettingsToggleRow as ToggleRow } from '#lib/components/settings/form/SettingsToggleRow.tsx';
import { Dropdown } from '#lib/components/ui/Dropdown.tsx';
import { SegmentedControl } from '#lib/components/ui/SegmentedControl.tsx';
import { SettingsFieldLabel } from '#lib/components/ui/SettingsFieldLabel.tsx';
import { Toggle } from '#lib/components/ui/Toggle.tsx';
import { ValueSlider } from '#lib/components/ui/ValueSlider.tsx';
import { m } from '#lib/i18n/messages.ts';
import type { SettingsWorkspace } from './settings-workspace.ts';
import styles from './SettingsAiPanel.module.css';

interface Props {
  set: SettingsWorkspace;
  settings: SettingsDto;
}

interface TypeRow {
  enabledKey:
    | 'aiAdvertisingEnabled'
    | 'aiTrackingEnabled'
    | 'aiTelemetryEnabled'
    | 'aiAnalyticsEnabled'
    | 'aiMaliciousEnabled'
    | 'aiFraudEnabled'
    | 'aiCryptominingEnabled'
    | 'aiTunnelEnabled';
  actionKey:
    | 'aiAdvertisingAction'
    | 'aiTrackingAction'
    | 'aiTelemetryAction'
    | 'aiAnalyticsAction'
    | 'aiMaliciousAction'
    | 'aiFraudAction'
    | 'aiCryptominingAction'
    | 'aiTunnelAction';
  confidenceKey:
    | 'aiConfidenceAdvertising'
    | 'aiConfidenceTracking'
    | 'aiConfidenceTelemetry'
    | 'aiConfidenceAnalytics'
    | 'aiConfidenceMalicious'
    | 'aiConfidenceFraud'
    | 'aiConfidenceCryptomining'
    | 'aiConfidenceTunnel';
  label: () => string;
}

const TYPES: TypeRow[] = [
  {
    enabledKey: 'aiAdvertisingEnabled',
    actionKey: 'aiAdvertisingAction',
    confidenceKey: 'aiConfidenceAdvertising',
    label: m.settings_ai_advertising,
  },
  {
    enabledKey: 'aiTrackingEnabled',
    actionKey: 'aiTrackingAction',
    confidenceKey: 'aiConfidenceTracking',
    label: m.settings_ai_tracking,
  },
  {
    enabledKey: 'aiTelemetryEnabled',
    actionKey: 'aiTelemetryAction',
    confidenceKey: 'aiConfidenceTelemetry',
    label: m.settings_ai_telemetry,
  },
  {
    enabledKey: 'aiAnalyticsEnabled',
    actionKey: 'aiAnalyticsAction',
    confidenceKey: 'aiConfidenceAnalytics',
    label: m.settings_ai_analytics,
  },
  {
    enabledKey: 'aiMaliciousEnabled',
    actionKey: 'aiMaliciousAction',
    confidenceKey: 'aiConfidenceMalicious',
    label: m.settings_ai_malicious,
  },
  {
    enabledKey: 'aiFraudEnabled',
    actionKey: 'aiFraudAction',
    confidenceKey: 'aiConfidenceFraud',
    label: m.settings_ai_fraud,
  },
  {
    enabledKey: 'aiCryptominingEnabled',
    actionKey: 'aiCryptominingAction',
    confidenceKey: 'aiConfidenceCryptomining',
    label: m.settings_ai_cryptomining,
  },
  {
    enabledKey: 'aiTunnelEnabled',
    actionKey: 'aiTunnelAction',
    confidenceKey: 'aiConfidenceTunnel',
    label: m.settings_ai_tunnel,
  },
];

export function SettingsAiPanel({ set, settings }: Props) {
  const proactive = settings.aiDecisionMode === 'proactive';
  return (
    <div className="settings-groups">
      <SettingsGroup
        title={m.settings_group_classification_title()}
        description={m.settings_group_classification_desc()}
      >
        <ToggleRow
          label={m.settings_ai_enable_label()}
          description={m.settings_ai_enable_desc()}
          checked={settings.aiEnabled}
          onCheckedChange={(value) => set.patch('aiEnabled', value)}
        />
        <div className="field">
          <SettingsFieldLabel htmlFor="ai-api-key" label={m.settings_ai_key_label()} />
          <SecretInput
            id="ai-api-key"
            describedBy="ai-api-key-hint"
            value={settings.aiApiKey}
            stored={settings.aiApiKeySet}
            cleared={settings.clearAiApiKey}
            oninput={(value) => set.patchSecret('aiApiKey', 'clearAiApiKey', value)}
            onclear={() => set.clearSecret('aiApiKey', 'clearAiApiKey')}
          />
          <p id="ai-api-key-hint" className="field-hint">
            {m.settings_ai_key_desc()}
          </p>
        </div>
        <div className="field">
          <SettingsFieldLabel htmlFor="ai-decision-mode" label={m.settings_ai_mode_label()} />
          <Dropdown
            id="ai-decision-mode"
            options={[
              { value: 'retroactive', label: m.settings_ai_mode_retroactive() },
              { value: 'proactive', label: m.settings_ai_mode_proactive() },
            ]}
            value={proactive ? 'proactive' : 'retroactive'}
            onChange={(value) => set.patch('aiDecisionMode', value)}
          />
          <div className={styles.modeNotes}>
            <p className={clsx('field-hint', !proactive && styles.selected)}>
              <span className={styles.modeName}>{m.settings_ai_mode_retroactive()}</span>
              {m.settings_ai_mode_retroactive_desc()}
            </p>
            <p className={clsx('field-hint', proactive && styles.selected)}>
              <span className={styles.modeName}>{m.settings_ai_mode_proactive()}</span>
              {m.settings_ai_mode_proactive_desc()}
            </p>
          </div>
        </div>
      </SettingsGroup>

      <SettingsGroup title={m.settings_ai_types_label()} description={m.settings_ai_types_desc()}>
        <div className={styles.typeHead} aria-hidden="true">
          <span>{m.settings_ai_col_category()}</span>
          <span>{m.settings_ai_col_action()}</span>
          <span>{m.settings_ai_col_score()}</span>
          <span></span>
        </div>
        {TYPES.map((row) => {
          const enabled = settings[row.enabledKey];
          return (
            <div
              key={row.enabledKey}
              className={clsx('type-row', styles.typeRow, !enabled && styles.off)}
            >
              <span className={styles.typeName}>{row.label()}</span>
              <SegmentedControl
                options={[
                  { value: 'block', label: m.settings_ai_action_block() },
                  { value: 'record', label: m.settings_ai_action_record() },
                ]}
                value={settings[row.actionKey] === 'block' ? 'block' : 'record'}
                ariaLabel={`${row.label()}: ${m.settings_ai_col_action()}`}
                disabled={!enabled}
                onChange={(value) => set.patch(row.actionKey, value)}
              />
              <ValueSlider
                value={settings[row.confidenceKey]}
                label={row.label()}
                min={60}
                disabled={!enabled}
                onInput={(value) => set.patch(row.confidenceKey, value)}
              />
              <Toggle
                checked={enabled}
                onCheckedChange={(value) => set.patch(row.enabledKey, value)}
                ariaLabel={row.label()}
              />
            </div>
          );
        })}
        <p className={clsx('field-hint', styles.footnote)}>{m.settings_ai_confidence_desc()}</p>
      </SettingsGroup>
    </div>
  );
}

export default SettingsAiPanel;
