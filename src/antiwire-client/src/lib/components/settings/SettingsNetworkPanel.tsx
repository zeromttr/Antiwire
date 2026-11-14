// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import type { SettingsDto } from '#lib/api/daemon.ts';
import { InlineNumber } from '#lib/components/settings/form/InlineNumber.tsx';
import { SettingsGroup } from '#lib/components/settings/form/SettingsGroup.tsx';
import { SettingsToggleRow as ToggleRow } from '#lib/components/settings/form/SettingsToggleRow.tsx';
import { m } from '#lib/i18n/messages.ts';
import type { SettingsWorkspace } from './settings-workspace.ts';

interface Props {
  set: SettingsWorkspace;
  settings: SettingsDto;
}

export function SettingsNetworkPanel({ set, settings }: Props) {
  return (
    <div className="settings-groups">
      <SettingsGroup
        title={m.settings_group_discovery_title()}
        description={m.settings_group_discovery_desc()}
      >
        <ToggleRow
          label={m.settings_network_auto_scan_label()}
          description={m.settings_network_auto_scan_desc()}
          checked={settings.networkMappingAutoEnabled}
          onCheckedChange={(v) => set.patch('networkMappingAutoEnabled', v)}
          actions={
            <InlineNumber
              id="scan-interval"
              value={settings.networkMappingIntervalMinutes}
              unit={m.settings_unit_minutes()}
              label={m.settings_scan_interval_label()}
              min={5}
              onchange={(v) => set.patch('networkMappingIntervalMinutes', v)}
            />
          }
        />
      </SettingsGroup>
    </div>
  );
}

export default SettingsNetworkPanel;
