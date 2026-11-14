import type { SettingsDto } from '#lib/api/daemon.ts';
import { m } from '#lib/i18n/messages.ts';
import { providerOptionsForProtocol } from '#lib/models/dns-providers.ts';
import {
  isValidOptionalHostname,
  isValidOptionalHttpUrl,
  isValidPort,
} from '#lib/models/settings-validation.ts';

export type SettingsSection =
  | 'General'
  | 'Notifications'
  | 'Activity'
  | 'DNS'
  | 'Network Mapping'
  | 'Event Forwarding'
  | 'AI'
  | 'Updates'
  | 'About';

export const DEFAULT_DNS_PROTOCOL = 'doh';
export const DEFAULT_DNS_PROVIDER = 'cloudflare';
export const DOQ_FALLBACK_PROVIDER = 'quad9';

export function dnsProtocol(settings: SettingsDto): string {
  return settings.dnsProtocol || DEFAULT_DNS_PROTOCOL;
}

export function dnsProviderOptions(settings: SettingsDto): Record<string, string> {
  return providerOptionsForProtocol(dnsProtocol(settings));
}

export function dnsProviderOptionList(settings: SettingsDto): { value: string; label: string }[] {
  return Object.entries(dnsProviderOptions(settings)).map(([value, label]) => ({
    value,
    label,
  }));
}

export function safeDnsProvider(settings: SettingsDto): string {
  const options = dnsProviderOptions(settings);
  const current = (settings.dohProvider || DEFAULT_DNS_PROVIDER).trim();
  return current in options ? current : (Object.keys(options)[0] ?? DEFAULT_DNS_PROVIDER);
}

export function applyDnsProtocol(settings: SettingsDto, protocol: string): SettingsDto {
  const next = { ...settings, dnsProtocol: protocol };
  const provider = (next.dohProvider || DEFAULT_DNS_PROVIDER).trim();
  const options = providerOptionsForProtocol(protocol);
  if (!(provider in options)) {
    next.dohProvider = protocol === 'doq' ? DOQ_FALLBACK_PROVIDER : DEFAULT_DNS_PROVIDER;
  }
  return next;
}

export function customResolverInvalid(settings: SettingsDto | null): boolean {
  return (
    settings != null &&
    settings.dohProvider === 'custom' &&
    !isValidOptionalHttpUrl(settings.dohCustomUrl)
  );
}

/*
 * A sink's fields are only checked while that sink is on: the form hides a
 * disabled sink's fields, and a value nobody can see must not block saving.
 * The daemon only reads a sink's fields when the sink is enabled.
 */
export function siemHostInvalid(settings: SettingsDto | null): boolean {
  return (
    settings != null &&
    settings.siemSyslogEnabled &&
    !isValidOptionalHostname(settings.wazuhManagerHost)
  );
}

export function siemPortInvalid(settings: SettingsDto | null): boolean {
  return settings != null && settings.siemSyslogEnabled && !isValidPort(settings.wazuhManagerPort);
}

export function siemUrlInvalid(settings: SettingsDto | null): boolean {
  return (
    settings != null && settings.siemWebhookEnabled && !isValidOptionalHttpUrl(settings.siemUrl)
  );
}

export function settingsFieldsValid(settings: SettingsDto | null): boolean {
  return (
    (settings === null ||
      !settings.logRetentionEnabled ||
      (Number.isInteger(settings.logRetentionDays) && settings.logRetentionDays >= 1)) &&
    !customResolverInvalid(settings) &&
    !siemHostInvalid(settings) &&
    !siemPortInvalid(settings) &&
    !siemUrlInvalid(settings)
  );
}

export function showSave(input: {
  connected: boolean;
  settings: SettingsDto | null;
  section: string;
  isDirty: boolean;
  fieldsValid: boolean;
}): boolean {
  return (
    input.connected &&
    input.settings !== null &&
    input.section !== 'About' &&
    input.isDirty &&
    input.fieldsValid
  );
}

export function siemProtocolOptions(): { value: string; label: string }[] {
  return [
    { value: 'udp', label: m.settings_siem_protocol_udp() },
    { value: 'tcp', label: m.settings_siem_protocol_tcp() },
    { value: 'tls', label: m.settings_siem_protocol_tls() },
  ];
}

/** The daemon reads the protocol case-insensitively and treats anything else as UDP. */
export function siemProtocolValue(protocol: string): 'tcp' | 'tls' | 'udp' {
  const normalized = protocol.trim().toLowerCase();
  return normalized === 'tcp' || normalized === 'tls' ? normalized : 'udp';
}
