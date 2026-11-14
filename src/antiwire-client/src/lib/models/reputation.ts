import { m } from '#lib/i18n/messages.ts';

/**
 * Well-known sites that report on a domain's reputation. The native command
 * `open_domain_reputation` owns each report URL; keep the ids in step with
 * `REPUTATION_SERVICES` in `electron/main/reputation.ts`.
 */
export type ReputationServiceId =
  'virustotal' | 'alienvault' | 'talos' | 'urlscan' | 'urlhaus' | 'xforce' | 'google';

export interface ReputationService {
  id: ReputationServiceId;
  /** Brand name, shown untranslated. */
  name: string;
  description: () => string;
  /** Only for the browser preview, which cannot run the native command. */
  previewUrl: (domain: string) => string;
}

const q = encodeURIComponent;

export const REPUTATION_SERVICES: readonly ReputationService[] = [
  {
    id: 'virustotal',
    name: 'VirusTotal',
    description: m.records_reputation_virustotal_desc,
    previewUrl: (d) => `https://www.virustotal.com/gui/domain/${q(d)}`,
  },
  {
    id: 'alienvault',
    name: 'AlienVault OTX',
    description: m.records_reputation_alienvault_desc,
    previewUrl: (d) => `https://otx.alienvault.com/indicator/domain/${q(d)}`,
  },
  {
    id: 'talos',
    name: 'Cisco Talos',
    description: m.records_reputation_talos_desc,
    previewUrl: (d) => `https://talosintelligence.com/reputation_center/lookup?search=${q(d)}`,
  },
  {
    id: 'urlscan',
    name: 'urlscan.io',
    description: m.records_reputation_urlscan_desc,
    previewUrl: (d) => `https://urlscan.io/domain/${q(d)}`,
  },
  {
    id: 'urlhaus',
    name: 'URLhaus',
    description: m.records_reputation_urlhaus_desc,
    previewUrl: (d) => `https://urlhaus.abuse.ch/browse.php?search=${q(d)}`,
  },
  {
    id: 'xforce',
    name: 'IBM X-Force',
    description: m.records_reputation_xforce_desc,
    previewUrl: (d) => `https://exchange.xforce.ibmcloud.com/url/${q(d)}`,
  },
  {
    id: 'google',
    name: 'Google Safe Browsing',
    description: m.records_reputation_google_desc,
    previewUrl: (d) => `https://transparencyreport.google.com/safe-browsing/search?url=${q(d)}`,
  },
];

export function reputationService(id: string): ReputationService | undefined {
  return REPUTATION_SERVICES.find((service) => service.id === id);
}
