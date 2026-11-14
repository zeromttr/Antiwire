export type PrivateNetworkClass = 'A' | 'B' | 'C';

export interface NetworkScanRange {
  id: number;
  adapterId: string;
  cidr: string;
}

export interface NetworkScanSuggestion extends NetworkScanRange {
  networkClass: PrivateNetworkClass | null;
  interfaceLabel: string;
}

/**
 * Returns the familiar classful label for a private IPv4 range. The label is
 * only explanatory; scanning still uses the range's precise CIDR prefix.
 */
export function privateNetworkClass(cidr: string): PrivateNetworkClass | null {
  const address = cidr.trim().split('/')[0];
  const octets = address.split('.').map(Number);
  if (
    octets.length !== 4 ||
    octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
  ) {
    return null;
  }

  const [first, second] = octets;
  if (first === 10) return 'A';
  if (first === 172 && second >= 16 && second <= 31) return 'B';
  if (first === 192 && second === 168) return 'C';
  return null;
}

export function scanSuggestions(ranges: NetworkScanRange[]): NetworkScanSuggestion[] {
  return ranges.map((range, index) => ({
    ...range,
    networkClass: privateNetworkClass(range.cidr),
    interfaceLabel: range.adapterId.trim() || `Network interface ${index + 1}`,
  }));
}
