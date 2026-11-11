import { m } from '#lib/i18n/messages.ts';

const DNS_PROVIDER_IDS = [
  'cloudflare',
  'cloudflare-fam',
  'cloudflare-sec',
  'quad9',
  'quad9-ecs',
  'quad9-unfiltered',
  'adguard',
  'adguard-fam',
  'adguard-unfiltered',
  'google',
  'opendns',
  'opendns-fam',
  'cleanbrowsing',
  'cleanbrowsing-fam',
  'cleanbrowsing-adult',
  'custom',
] as const;

export const DOQ_CAPABLE_PROVIDER_IDS = [
  'quad9',
  'quad9-ecs',
  'adguard',
  'adguard-fam',
  'custom',
] as const;

const PROVIDER_LABEL_FNS: Record<string, () => string> = {
  cloudflare: m.settings_dns_provider_cloudflare,
  'cloudflare-fam': m.settings_dns_provider_cloudflare_fam,
  'cloudflare-sec': m.settings_dns_provider_cloudflare_sec,
  quad9: m.settings_dns_provider_quad9,
  'quad9-ecs': m.settings_dns_provider_quad9_ecs,
  'quad9-unfiltered': m.settings_dns_provider_quad9_unfiltered,
  adguard: m.settings_dns_provider_adguard,
  'adguard-fam': m.settings_dns_provider_adguard_fam,
  'adguard-unfiltered': m.settings_dns_provider_adguard_unfiltered,
  google: m.settings_dns_provider_google,
  opendns: m.settings_dns_provider_opendns,
  'opendns-fam': m.settings_dns_provider_opendns_fam,
  cleanbrowsing: m.settings_dns_provider_cleanbrowsing,
  'cleanbrowsing-fam': m.settings_dns_provider_cleanbrowsing_fam,
  'cleanbrowsing-adult': m.settings_dns_provider_cleanbrowsing_adult,
  custom: m.settings_dns_provider_custom,
};

/** Returns the localized label for a DNS provider id. */
export function dnsProviderLabel(id: string): string {
  return (PROVIDER_LABEL_FNS[id] ?? PROVIDER_LABEL_FNS.cloudflare)();
}

function localizedProviderOptions(ids: readonly string[]): Record<string, string> {
  const options: Record<string, string> = {};
  for (const id of ids) options[id] = dnsProviderLabel(id);
  return options;
}

export function providerOptionsForProtocol(protocol: string): Record<string, string> {
  return localizedProviderOptions(protocol === 'doq' ? DOQ_CAPABLE_PROVIDER_IDS : DNS_PROVIDER_IDS);
}

export const DNS_PROTOCOLS = ['doh', 'dot', 'doq'] as const;
export type DnsProtocol = (typeof DNS_PROTOCOLS)[number];

const PROTOCOL_LABEL_FNS: Record<DnsProtocol, () => string> = {
  doh: m.settings_dns_protocol_doh,
  dot: m.settings_dns_protocol_dot,
  doq: m.settings_dns_protocol_doq,
};

/** Returns the localized display label for a DNS protocol id (falls back to DoH). */
export function dnsProtocolLabel(protocol: string): string {
  return (PROTOCOL_LABEL_FNS[protocol as DnsProtocol] ?? PROTOCOL_LABEL_FNS.doh)();
}

export function dnsProtocolOptions(): { value: string; label: string }[] {
  return DNS_PROTOCOLS.map((protocol) => ({ value: protocol, label: dnsProtocolLabel(protocol) }));
}
