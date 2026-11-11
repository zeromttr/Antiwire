export type NavRoute =
  | 'dashboard'
  | 'records'
  | 'firewall'
  | 'analytics'
  | 'alerts'
  | 'ai'
  | 'capture'
  | 'network'
  | 'settings';

export interface NavItem {
  id: NavRoute;
  href: string;
}

export const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', href: '/' },
  { id: 'records', href: '/records' },
  { id: 'firewall', href: '/firewall' },
  { id: 'analytics', href: '/analytics' },
  { id: 'alerts', href: '/alerts' },
  { id: 'ai', href: '/ai' },
  { id: 'capture', href: '/capture' },
  { id: 'network', href: '/network' },
  { id: 'settings', href: '/settings' },
];

export interface Stats {
  bytesSent: number;
  bytesReceived: number;
  activeConnections: number;
  blockedConnections: number;
  /** False when the collector cannot observe traffic volume, so every byte figure is zero. */
  byteAccountingAvailable: boolean;
  /** User-facing explanation of the degradation, empty while the collector is healthy. */
  collectorStatusDetail: string;
  /** False when the socket count could not be acquired. Do not treat `activeConnections` as a confirmed zero. */
  activeConnectionsAvailable: boolean;
  /** True when `activeConnections` is last-known after a failed refresh. */
  activeConnectionsStale: boolean;
  /** Distinct applications owning live connections; `null` when the daemon cannot say. */
  activeApplications: number | null;
  /** Bytes the history database occupies on disk; `null` when the daemon cannot say. */
  databaseSizeBytes: number | null;
}

export type UpdateState =
  'unknown' | 'up_to_date' | 'available' | 'installing' | 'failed' | 'unsupported';

/** What the daemon last learned about updates, plus this client's own version. */
/** The release channels a user can follow, most stable first. */
export const UPDATE_CHANNELS = ['stable', 'beta', 'nightly'] as const;
export type UpdateChannel = (typeof UPDATE_CHANNELS)[number];

export interface UpdateStatus {
  state: UpdateState;
  /** Version of the running daemon. */
  currentVersion: string;
  /** Newer release the daemon knows about; empty when there is none. */
  availableVersion: string;
  notes: string;
  /** Reason for `failed` or `unsupported`; empty otherwise. */
  detail: string;
  /** The channel the status describes. */
  channel: string;
  /** Unix seconds of the last check; 0 before the first. */
  lastCheckedAt: number;
  /** Why the last check could not read the release feeds; empty when it could. */
  checkError: string;
  clientVersion: string;
}

export const AI_CATEGORIES = [
  'advertising',
  'tracking',
  'telemetry',
  'analytics',
  'malicious',
  'fraud',
  'cryptomining',
  'tunnel',
] as const;

export type AiCategory = (typeof AI_CATEGORIES)[number];

/** `block` was enforced, `record` was flagged only, `''` means no category met its threshold. */
export type AiVerdict = 'block' | 'record' | '';

export interface AiSignals {
  newlyRegistered: number;
  registryHold: number;
  hiddenRegistrant: number;
  abusiveRegistrar: number;
}

export interface AiDecision {
  domain: string;
  model: string;
  verdict: AiVerdict;
  /** Category that drove the verdict; empty when `verdict` is `''`. */
  topCategory: string;
  /** 0-1 probability of `topCategory` (or the highest enabled score when clean). */
  topScore: number;
  /** Raw 0-1 probability per category. */
  ratings: Record<AiCategory, number>;
  /** Registration judgments from an advanced check. Zero until one has run. */
  signals: AiSignals;
  scanTier: string;
  /** Unix seconds. */
  firstSeen: number;
  /** Unix seconds of the most recent classification. */
  updatedAt: number;
}

export interface ConnectionLog {
  /** Database row id. 0 for realtime events that have not been persisted yet. */
  id: number;
  /** Unix seconds when the connection ended. 0 means no close was observed; liveness is unknown. */
  closedAt: number;
  /** Confirmed active by the daemon; absent on older versions. */
  isActive?: boolean;
  applicationName: string;
  applicationPath: string;
  domain: string;
  sourceIp: string;
  /** The local port the connection left from. 0 when unknown. */
  sourcePort: number;
  destinationIp: string;
  /** The destination port. */
  port: number;
  protocol: string;
  action: string;
  bytesSent: number;
  bytesReceived: number;
  timestamp: number;
  lastSeen: number;
  countryCode: string;
  /** Catalog ids / custom list names that produced a hosts-blocklist block. */
  blocklistNames: string[];
}

export interface AppSummary {
  /** Database row id of the application; selects exactly one install path. */
  applicationId: number;
  applicationName: string;
  applicationPath: string;
  connectionCount: number;
  blockedCount: number;
  totalBytes: number;
  bytesSent: number;
  bytesReceived: number;
}

export type RuleDirection = 'INBOUND' | 'OUTBOUND' | 'BOTH';

export interface Rule {
  id: number;
  targetType: string;
  targetValue: string;
  action: string;
  direction: RuleDirection;
}

/** A country block: one logical rule covering many networks. */
export interface CountryRule {
  id: number;
  countryCode: string;
  action: string;
  direction: RuleDirection;
  cidrCount: number;
}

export interface NotificationEvent {
  id: string;
  title: string;
  body: string;
  severity: 'bad' | 'warn' | 'ok' | 'info';
  timestamp: string;
  tag: string;
}

export interface Toast {
  id: string;
  title: string;
  body: string;
  color: string;
}
