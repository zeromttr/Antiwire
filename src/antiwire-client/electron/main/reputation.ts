/**
 * Third-party reputation pages for a domain.
 *
 * The renderer never supplies a URL: it names a service from a fixed list and
 * passes a domain, which is validated here and placed into that service's
 * template, so this cannot be used to open arbitrary links or programs.
 */

/**
 * Report URL for each service; the domain is appended to the prefix.
 * Keep the ids in step with `REPUTATION_SERVICES` in `src/lib/models/reputation.ts`.
 */
export const REPUTATION_SERVICES: ReadonlyArray<readonly [id: string, prefix: string]> = [
  ['virustotal', 'https://www.virustotal.com/gui/domain/'],
  ['alienvault', 'https://otx.alienvault.com/indicator/domain/'],
  ['talos', 'https://talosintelligence.com/reputation_center/lookup?search='],
  ['urlscan', 'https://urlscan.io/domain/'],
  ['urlhaus', 'https://urlhaus.abuse.ch/browse.php?search='],
  ['xforce', 'https://exchange.xforce.ibmcloud.com/url/'],
  ['google', 'https://transparencyreport.google.com/safe-browsing/search?url='],
];

export function isReputationService(service: string): boolean {
  return REPUTATION_SERVICES.some(([id]) => id === service);
}

const LABEL = /^[a-z0-9-]{1,63}$/;

/** A lower-case public hostname: 2+ dot-separated LDH labels, 253 chars at most. */
export function normalizeDomain(domain: string): string | null {
  const host = domain.trim().replace(/\.+$/, '').toLowerCase();
  if (!host || host.length > 253) return null;
  const labels = host.split('.');
  const labelOk = (label: string) =>
    LABEL.test(label) && !label.startsWith('-') && !label.endsWith('-');
  if (labels.length < 2 || !labels.every(labelOk)) return null;
  // An all-numeric last label means an IPv4 address, not a domain.
  if (/^\d+$/.test(labels[labels.length - 1])) return null;
  return host;
}

export function reputationUrl(service: string, domain: string): string | null {
  const entry = REPUTATION_SERVICES.find(([id]) => id === service);
  if (!entry) return null;
  const host = normalizeDomain(domain);
  return host ? entry[1] + host : null;
}
