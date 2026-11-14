export type NetworkDeviceSortKey = 'device' | 'identity' | 'status' | 'lastSeen';

export function compareNetworkDevices(
  left: {
    ipAddress: string;
    macAddress: string;
    mdnsName: string;
    manufacturer: string;
    isPresent: boolean;
    lastSeen: string;
  },
  right: {
    ipAddress: string;
    macAddress: string;
    mdnsName: string;
    manufacturer: string;
    isPresent: boolean;
    lastSeen: string;
  },
  key: NetworkDeviceSortKey,
  lastSeenTimestamp: (lastSeen: string) => number,
): number {
  switch (key) {
    case 'device':
      return (
        left.ipAddress.localeCompare(right.ipAddress, undefined, { numeric: true }) ||
        left.macAddress.localeCompare(right.macAddress, undefined, { numeric: true })
      );
    case 'identity': {
      const leftLabel = (left.mdnsName || left.manufacturer || left.ipAddress).toLowerCase();
      const rightLabel = (right.mdnsName || right.manufacturer || right.ipAddress).toLowerCase();
      return leftLabel.localeCompare(rightLabel);
    }
    case 'status':
      return Number(left.isPresent) - Number(right.isPresent);
    case 'lastSeen':
      return lastSeenTimestamp(left.lastSeen) - lastSeenTimestamp(right.lastSeen);
  }
}

export function sortNetworkDevices<
  T extends {
    ipAddress: string;
    macAddress: string;
    mdnsName: string;
    manufacturer: string;
    isPresent: boolean;
    lastSeen: string;
  },
>(
  devices: T[],
  sortKey: NetworkDeviceSortKey | null,
  sortDir: 1 | -1,
  lastSeenTimestamp: (lastSeen: string) => number,
): T[] {
  const key = sortKey ?? 'lastSeen';
  const dir = sortKey ? sortDir : -1;
  return [...devices].sort(
    (left, right) => compareNetworkDevices(left, right, key, lastSeenTimestamp) * dir,
  );
}
