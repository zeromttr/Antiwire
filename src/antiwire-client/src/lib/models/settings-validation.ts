import { isValidBlocklistUrl } from './blocklists';

/** Absolute http(s) URL, or empty (optional field). */
export function isValidOptionalHttpUrl(value: string): boolean {
  return isValidBlocklistUrl(value);
}

/** Hostname, IPv4, or bracketed IPv6 — empty is valid for an optional field. */
export function isValidOptionalHostname(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return true;
  if (trimmed.includes('://') || trimmed.includes('/') || trimmed.includes(' ')) {
    return false;
  }
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    return isIpv6(trimmed.slice(1, -1));
  }
  if (isIpv4(trimmed)) return true;
  return isDnsHostname(trimmed);
}

export function isValidPort(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

function isIpv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

function isIpv6(value: string): boolean {
  return /^[0-9a-f:]+$/i.test(value) && value.includes(':');
}

function isDnsHostname(value: string): boolean {
  if (value.length > 253) return false;
  return value.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}
