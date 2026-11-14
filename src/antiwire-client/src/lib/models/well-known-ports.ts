/** Transport a well-known name applies to. Omitted means both TCP and UDP. */
type PortTransport = 'tcp' | 'udp';

type WellKnownPort = {
  name: string;
  transport?: PortTransport;
};

/**
 * Common assigned ports that show up in a desktop connection log.
 * Names are IANA/service acronyms, not localized.
 */
const WELL_KNOWN_PORTS: Record<number, WellKnownPort> = {
  20: { name: 'FTP', transport: 'tcp' },
  21: { name: 'FTP', transport: 'tcp' },
  22: { name: 'SSH', transport: 'tcp' },
  23: { name: 'TELNET', transport: 'tcp' },
  25: { name: 'SMTP', transport: 'tcp' },
  53: { name: 'DNS' },
  67: { name: 'DHCP', transport: 'udp' },
  68: { name: 'DHCP', transport: 'udp' },
  69: { name: 'TFTP', transport: 'udp' },
  80: { name: 'HTTP' },
  88: { name: 'KERBEROS' },
  110: { name: 'POP3', transport: 'tcp' },
  123: { name: 'NTP', transport: 'udp' },
  135: { name: 'RPC', transport: 'tcp' },
  137: { name: 'NETBIOS', transport: 'udp' },
  138: { name: 'NETBIOS', transport: 'udp' },
  139: { name: 'NETBIOS', transport: 'tcp' },
  143: { name: 'IMAP', transport: 'tcp' },
  161: { name: 'SNMP', transport: 'udp' },
  162: { name: 'SNMP', transport: 'udp' },
  389: { name: 'LDAP' },
  443: { name: 'HTTPS' },
  445: { name: 'SMB', transport: 'tcp' },
  465: { name: 'SMTPS', transport: 'tcp' },
  500: { name: 'IKE', transport: 'udp' },
  514: { name: 'SYSLOG', transport: 'udp' },
  515: { name: 'LPD', transport: 'tcp' },
  548: { name: 'AFP', transport: 'tcp' },
  554: { name: 'RTSP' },
  587: { name: 'SMTP', transport: 'tcp' },
  631: { name: 'IPP' },
  636: { name: 'LDAPS', transport: 'tcp' },
  853: { name: 'DOT' },
  993: { name: 'IMAPS', transport: 'tcp' },
  995: { name: 'POP3S', transport: 'tcp' },
  1194: { name: 'OPENVPN' },
  1433: { name: 'MSSQL', transport: 'tcp' },
  1701: { name: 'L2TP', transport: 'udp' },
  1723: { name: 'PPTP', transport: 'tcp' },
  1812: { name: 'RADIUS', transport: 'udp' },
  1813: { name: 'RADIUS', transport: 'udp' },
  1883: { name: 'MQTT' },
  1900: { name: 'SSDP', transport: 'udp' },
  1935: { name: 'RTMP', transport: 'tcp' },
  2049: { name: 'NFS' },
  3074: { name: 'XBOX' },
  3306: { name: 'MYSQL', transport: 'tcp' },
  3389: { name: 'RDP', transport: 'tcp' },
  3478: { name: 'STUN' },
  4070: { name: 'SPOTIFY', transport: 'tcp' },
  4500: { name: 'NAT-T', transport: 'udp' },
  5060: { name: 'SIP' },
  5061: { name: 'SIPS', transport: 'tcp' },
  5222: { name: 'XMPP', transport: 'tcp' },
  5228: { name: 'GCM', transport: 'tcp' },
  5353: { name: 'MDNS', transport: 'udp' },
  5355: { name: 'LLMNR' },
  5432: { name: 'POSTGRES', transport: 'tcp' },
  5672: { name: 'AMQP', transport: 'tcp' },
  5900: { name: 'VNC', transport: 'tcp' },
  6379: { name: 'REDIS', transport: 'tcp' },
  7680: { name: 'DO', transport: 'tcp' },
  8080: { name: 'HTTP' },
  8443: { name: 'HTTPS' },
  8883: { name: 'MQTTS', transport: 'tcp' },
  9418: { name: 'GIT', transport: 'tcp' },
  27017: { name: 'MONGODB', transport: 'tcp' },
  27036: { name: 'STEAM' },
};

function normalizeTransport(protocol: string): PortTransport | undefined {
  const normalized = protocol.trim().toLowerCase();
  if (normalized === 'tcp' || normalized === 'udp') return normalized;
  return undefined;
}

/** Service name for a known TCP/UDP port, or undefined when the pair is not assigned. */
export function wellKnownPortName(port: number, protocol: string): string | undefined {
  if (!Number.isInteger(port) || port <= 0) return undefined;
  const entry = WELL_KNOWN_PORTS[port];
  if (!entry) return undefined;
  if (!entry.transport) return entry.name;
  const transport = normalizeTransport(protocol);
  if (!transport) return entry.name;
  return entry.transport === transport ? entry.name : undefined;
}

/** Protocol column label: known service name, otherwise the transport (TCP/UDP). */
export function recordProtocolLabel(protocol: string, port: number): string {
  return wellKnownPortName(port, protocol) || protocol.trim() || '';
}

const WELL_KNOWN_PROTOCOL_NAMES = [
  ...new Set(Object.values(WELL_KNOWN_PORTS).map((entry) => entry.name)),
].sort();

const WELL_KNOWN_PROTOCOL_NAME_SET = new Set(WELL_KNOWN_PROTOCOL_NAMES);

/** Sorted unique service names from the well-known port table. */
export function wellKnownProtocolNames(): readonly string[] {
  return WELL_KNOWN_PROTOCOL_NAMES;
}

export function isWellKnownProtocolName(label: string): boolean {
  return WELL_KNOWN_PROTOCOL_NAME_SET.has(label.trim().toUpperCase());
}
