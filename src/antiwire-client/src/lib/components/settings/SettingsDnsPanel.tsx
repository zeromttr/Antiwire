// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import type { SettingsDto } from '#lib/api/daemon.ts';
import { BlocklistSettingsRow } from '#lib/components/settings/form/BlocklistSettingsRow.tsx';
import { SettingsGroup } from '#lib/components/settings/form/SettingsGroup.tsx';
import { SettingsToggleRow as ToggleRow } from '#lib/components/settings/form/SettingsToggleRow.tsx';
import { Dropdown } from '#lib/components/ui/Dropdown.tsx';
import { SegmentedControl } from '#lib/components/ui/SegmentedControl.tsx';
import { SettingsFieldLabel } from '#lib/components/ui/SettingsFieldLabel.tsx';
import { SettingsInput } from '#lib/components/ui/SettingsInput.tsx';
import { Toggle } from '#lib/components/ui/Toggle.tsx';
import { m } from '#lib/i18n/messages.ts';
import { dnsProtocolOptions } from '#lib/models/dns-providers.ts';
import { newDomainMaxAgeOptions, normalizeNewDomainMaxAge } from '#lib/models/new-domain-age.ts';
import { windowPlatform } from '#lib/utils/window-platform.ts';
import type { SettingsWorkspace } from './settings-workspace.ts';

interface Props {
  set: SettingsWorkspace;
  settings: SettingsDto;
}

/** iCloud Private Relay exists on macOS only, and so does the setting that makes room for it. */
const offersPrivateRelayCompatibility = windowPlatform() === 'macos';
/**
 * Only Windows has to choose: without a driver it can block DNS that apps send past the
 * resolver, but not redirect it, and a block can leave such an app without the internet.
 * Linux and macOS redirect it.
 */
const offersDnsBypassBlocking = windowPlatform() === 'windows';

export function SettingsDnsPanel({ set, settings }: Props) {
  return (
    <div className="settings-groups">
      <SettingsGroup
        title={m.settings_group_resolver_title()}
        description={m.settings_group_resolver_desc()}
      >
        <div className="resolver-row">
          <div className="resolver-text">
            <div className="resolver-label">{m.settings_resolver_label()}</div>
            <div className="resolver-desc">{m.settings_resolver_desc()}</div>
          </div>
          <div className="resolver-controls">
            <SegmentedControl
              options={dnsProtocolOptions()}
              value={set.dnsProtocol}
              onChange={set.setDnsProtocol}
            />
            <Toggle
              checked={settings.dnsResolverEnabled}
              onCheckedChange={(v) => set.patch('dnsResolverEnabled', v)}
              ariaLabel={m.settings_resolver_aria()}
            />
          </div>
        </div>
        {settings.dnsResolverEnabled && (
          <>
            <div className="field">
              <SettingsFieldLabel
                htmlFor="doh-provider"
                label={m.settings_remote_dns_provider_label()}
              />
              <Dropdown
                id="doh-provider"
                options={set.dnsProviderOptionList}
                value={set.safeDnsProvider}
                menuTitle={m.settings_remote_dns_provider_menu()}
                onChange={(v) => set.patch('dohProvider', v)}
              />
              <p className="field-hint">
                {set.dnsProtocol === 'doq'
                  ? m.settings_dns_provider_hint_doq()
                  : m.settings_dns_provider_hint_default()}
              </p>
            </div>
            {settings.dohProvider === 'custom' && (
              <div className="field">
                <SettingsFieldLabel
                  htmlFor="doh-custom-url"
                  label={m.settings_custom_resolver_url_label()}
                />
                <SettingsInput
                  id="doh-custom-url"
                  value={settings.dohCustomUrl}
                  invalid={set.customResolverInvalid}
                  onInput={(e) => set.patch('dohCustomUrl', e.currentTarget.value)}
                  placeholder={m.settings_custom_resolver_url_placeholder()}
                />
              </div>
            )}
          </>
        )}
        <ToggleRow
          label={m.settings_doh_blocking_label()}
          description={m.settings_doh_blocking_desc()}
          checked={settings.dohBlockingEnabled && !settings.privateRelayCompatibility}
          disabled={settings.privateRelayCompatibility}
          onCheckedChange={(v) => set.patch('dohBlockingEnabled', v)}
        />
      </SettingsGroup>

      {offersPrivateRelayCompatibility && (
        <SettingsGroup
          title={m.settings_group_private_relay_title()}
          description={m.settings_group_private_relay_desc()}
        >
          <ToggleRow
            label={m.settings_private_relay_label()}
            tag={m.settings_experimental_tag()}
            description={m.settings_private_relay_desc()}
            warning={m.settings_private_relay_warning()}
            checked={settings.privateRelayCompatibility}
            onCheckedChange={(v) => set.patch('privateRelayCompatibility', v)}
          />
        </SettingsGroup>
      )}

      {/* The daemon says whether it can use the driver: only its Windows x64 build can. */}
      {settings.windivertSupported && (
        <SettingsGroup
          title={m.settings_group_windivert_title()}
          description={m.settings_group_windivert_desc()}
        >
          <ToggleRow
            label={m.settings_windivert_label()}
            description={m.settings_windivert_desc()}
            warning={m.settings_windivert_warning()}
            checked={settings.windivertEnabled}
            onCheckedChange={(v) => set.patch('windivertEnabled', v)}
          />
        </SettingsGroup>
      )}

      {offersDnsBypassBlocking && (
        <SettingsGroup
          title={m.settings_group_dns_bypass_title()}
          description={m.settings_group_dns_bypass_desc()}
        >
          <ToggleRow
            label={m.settings_dns_bypass_block_label()}
            description={
              settings.windivertSupported
                ? `${m.settings_dns_bypass_block_desc()} ${m.settings_dns_bypass_block_windivert_note()}`
                : m.settings_dns_bypass_block_desc()
            }
            warning={m.settings_dns_bypass_block_warning()}
            checked={settings.dnsBypassBlockingEnabled}
            // WinDivert redirects these lookups, so there is nothing left to block.
            disabled={settings.windivertEnabled}
            onCheckedChange={(v) => set.patch('dnsBypassBlockingEnabled', v)}
          />
        </SettingsGroup>
      )}

      <SettingsGroup
        title={m.settings_group_blocklists_title()}
        description={m.settings_group_blocklists_desc()}
      >
        <BlocklistSettingsRow
          enabled={settings.hostsBlocklistEnabled}
          selectedLists={settings.hostsBlocklistSelectedLists}
          customUrls={settings.hostsBlocklistCustomUrls}
          updateFrequency={settings.hostsBlocklistUpdateFrequency}
          lastUpdated={settings.hostsBlocklistLastUpdated}
          onEnabledChange={(v) => set.patch('hostsBlocklistEnabled', v)}
          onUpdateFrequencyChange={(v) => set.patch('hostsBlocklistUpdateFrequency', v)}
          onSelectedListsChange={(v) => set.patch('hostsBlocklistSelectedLists', v)}
          onCustomUrlsChange={(v) => set.patch('hostsBlocklistCustomUrls', v)}
          onSettingsRefresh={set.loadSettings}
        />
      </SettingsGroup>

      <SettingsGroup
        title={m.settings_group_new_domains_title()}
        description={m.settings_group_new_domains_desc()}
      >
        <ToggleRow
          label={m.settings_new_domains_label()}
          description={m.settings_new_domains_desc()}
          checked={settings.dnsNewDomainBlockingEnabled}
          onCheckedChange={(v) => set.patch('dnsNewDomainBlockingEnabled', v)}
        />
        {settings.dnsNewDomainBlockingEnabled && (
          <div className="resolver-row">
            <div className="resolver-text">
              <div className="resolver-label">{m.settings_new_domains_age_label()}</div>
            </div>
            <div className="resolver-controls">
              <SegmentedControl
                ariaLabel={m.settings_new_domains_age_label()}
                options={newDomainMaxAgeOptions()}
                value={String(normalizeNewDomainMaxAge(settings.dnsNewDomainMaxAgeDays))}
                onChange={(v) => set.patch('dnsNewDomainMaxAgeDays', Number(v))}
              />
            </div>
          </div>
        )}
      </SettingsGroup>

      <SettingsGroup title={m.settings_power_users_section()}>
        <ToggleRow
          label={m.settings_power_user_enable_label()}
          description={m.settings_power_user_enable_desc()}
          checked={settings.powerUserSettingsEnabled}
          onCheckedChange={set.onPowerUserToggle}
        />
        {settings.powerUserSettingsEnabled && (
          <>
            <ToggleRow
              label={m.settings_dns_rebinding_label()}
              description={m.settings_dns_rebinding_desc()}
              checked={settings.dnsRebindingProtectionEnabled}
              onCheckedChange={(v) => set.patch('dnsRebindingProtectionEnabled', v)}
            />
            <ToggleRow
              label={m.settings_dns_local_names_label()}
              description={m.settings_dns_local_names_desc()}
              checked={settings.dnsAnswerLocalNamesEnabled}
              onCheckedChange={(v) => set.patch('dnsAnswerLocalNamesEnabled', v)}
            />
          </>
        )}
      </SettingsGroup>
    </div>
  );
}

export default SettingsDnsPanel;
