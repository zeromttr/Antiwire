const IPV4_OCTET = '(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)';

const IPV4_RE = new RegExp(`^${IPV4_OCTET}\\.${IPV4_OCTET}\\.${IPV4_OCTET}\\.${IPV4_OCTET}$`);
const CIDR_RE = new RegExp(
  `^${IPV4_OCTET}\\.${IPV4_OCTET}\\.${IPV4_OCTET}\\.${IPV4_OCTET}/(?:[0-9]|[1-2]\\d|3[0-2])$`,
);
const DOMAIN_LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const DOMAIN_RE = new RegExp(`^(?:\\*\\.)?${DOMAIN_LABEL}(?:\\.${DOMAIN_LABEL})*$`, 'i');

export function isValidIpv4(value: string): boolean {
  return IPV4_RE.test(value.trim());
}

const IPV6_HEXTET = /^[0-9a-f]{1,4}$/i;

function isIpv6Hextet(part: string): boolean {
  return IPV6_HEXTET.test(part);
}

/** Accepts the same textual IPv6 forms `std::net::IpAddr` parses, minus zone IDs. */
export function isValidIpv6(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed || trimmed.includes('/') || trimmed.includes('%') || !trimmed.includes(':')) {
    return false;
  }

  const lastColon = trimmed.lastIndexOf(':');
  const maybeIpv4 = trimmed.slice(lastColon + 1);
  let head = trimmed;
  let ipv4Groups = 0;
  if (maybeIpv4.includes('.')) {
    if (!isValidIpv4(maybeIpv4)) return false;
    head = trimmed.slice(0, lastColon);
    ipv4Groups = 2;
  }

  if ((head.match(/::/g) ?? []).length > 1) return false;

  const compressed = head.includes('::');
  const [leftRaw, rightRaw] = compressed ? head.split('::') : [head, ''];
  const left = leftRaw === '' ? [] : leftRaw.split(':');
  const right = rightRaw === '' ? [] : rightRaw.split(':');
  if (left.some((part) => part === '' || !isIpv6Hextet(part))) return false;
  if (right.some((part) => part === '' || !isIpv6Hextet(part))) return false;

  const groupCount = left.length + right.length + ipv4Groups;
  if (compressed) return groupCount < 8;
  return groupCount === 8;
}

export function isValidIp(value: string): boolean {
  return isValidIpv4(value) || isValidIpv6(value);
}

export function isValidCidr(value: string): boolean {
  return CIDR_RE.test(value.trim());
}

export function isValidDomain(value: string): boolean {
  const canonical = canonicalizeDomainInput(value);
  return canonical !== null && DOMAIN_RE.test(canonical);
}

function canonicalizeDomainInput(value: string): string | null {
  const trimmed = value.trim();
  const wildcard = trimmed.startsWith('*.');
  const host = (wildcard ? trimmed.slice(2) : trimmed).replace(/\.+$/u, '').replace(/^\.+/u, '');
  if (!host || host.includes('*')) {
    return null;
  }
  const ascii = toAsciiHostname(host);
  if (ascii === null) {
    return null;
  }
  return wildcard ? `*.${ascii}` : ascii;
}

function isAscii(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) > 0x7f) return false;
  }
  return value.length > 0;
}

function toAsciiHostname(host: string): string | null {
  if (isAscii(host)) {
    return host.toLowerCase();
  }
  try {
    return new URL(`http://${host}`).hostname || null;
  } catch {
    return null;
  }
}
