/**
 * TypeScript views of the daemon's proto messages, as `@grpc/proto-loader`
 * decodes them with `PROTO_LOADER_OPTIONS`: camelCase fields, 64-bit integers
 * as numbers, enums as their names, and every scalar defaulted. Proto3
 * `optional` fields stay `undefined` when the daemon leaves them unset.
 *
 * The proto (`antiwire-proto/proto/antiwire.proto`) is the source of truth and
 * is loaded at runtime; these interfaces only type the fields this client
 * uses, so a field added to the proto needs no change here until it is read.
 */

export type Empty = Record<string, never>;

export interface ActionResponse {
  success: boolean;
  message: string;
}

export interface StatsResponse {
  totalBytesSent: number;
  totalBytesReceived: number;
  activeConnectionsCount: number;
  blockedConnectionsCount: number;
  byteAccountingAvailable: boolean;
  collectorStatusDetail: string;
  activeConnectionsAvailable?: boolean;
  activeConnectionsStale: boolean;
  activeApplicationsCount?: number;
  daemonVersion: string;
  databaseSizeBytes?: number;
}

export interface ActiveApplication {
  appName: string;
  appPath: string;
  connectionCount: number;
  downloadRate: number;
  uploadRate: number;
  topDestinations: string[];
  destinationCount: number;
  newestOpenedAt: number;
}

export interface ActiveApplicationsResponse {
  applications: ActiveApplication[];
  available: boolean;
}

export interface TrafficEvent {
  timestamp: number;
  appName: string;
  appPath: string;
  protocol: string;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  dstDomain: string;
  bytesSent: number;
  bytesReceived: number;
  action: string;
  lastSeen: number;
  countryCode: string;
  isp: string;
  blocklistNames: string[];
  id: number;
  closedAt: number;
  isActive: boolean;
}

export interface CountryStatisticsResponse {
  countryCounts: Record<string, number>;
  totalCount: number;
  unknownCount: number;
}

export interface LogRequest {
  limit: number;
  offset: number;
  searchQuery: string;
  orderBy: string;
  appName: string;
  actionFilter: string;
  timeFilterSeconds: number;
  sortDescending: boolean;
  protocolFilter: string;
  timeWindowStart: number;
  timeWindowEnd: number;
  countryFilter: string;
  appId: number;
  portFilter: number;
  hostFilter: string;
}

export interface LogResponse {
  logs: TrafficEvent[];
  totalCount: number;
  blockedCount: number;
}

export interface ApplicationLogSummaryRequest {
  searchQuery: string;
  actionFilter: string;
  timeFilterSeconds: number;
  timeWindowStart: number;
  timeWindowEnd: number;
}

export interface ApplicationLogSummary {
  appName: string;
  appPath: string;
  totalCount: number;
  blockedCount: number;
  totalBytes: number;
  bytesSent: number;
  bytesReceived: number;
  appId: number;
}

export interface ApplicationLogSummaryResponse {
  applications: ApplicationLogSummary[];
  totalCount: number;
  blockedCount: number;
}

export interface ActivityBucketsRequest {
  days: number;
  since: number;
  until: number;
}

export interface ActivityBucket {
  bucketStart: number;
  eventCount: number;
  bytesSent: number;
  bytesReceived: number;
  blockedCount: number;
}

export interface DeleteHistoryRequest {
  all: boolean;
  since: number;
}

export interface Rule {
  id: number;
  targetType: string;
  targetValue: string;
  action: string;
  direction: string;
}

export interface CountryRule {
  id: number;
  countryCode: string;
  action: string;
  direction: string;
  cidrs: string[];
}

export interface CountryRuleSummary {
  id: number;
  countryCode: string;
  action: string;
  direction: string;
  cidrCount: number;
}

export interface RulesResponse {
  rules: Rule[];
  countryRules: CountryRuleSummary[];
}

export interface AiDecisionsRequest {
  limit: number;
  offset: number;
  verdictFilter: string;
  searchQuery: string;
}

export interface AiDecision {
  domain: string;
  model: string;
  verdict: string;
  topCategory: string;
  topScore: number;
  ratingAdvertising: number;
  ratingTracking: number;
  ratingTelemetry: number;
  ratingAnalytics: number;
  ratingMalicious: number;
  ratingFraud: number;
  ratingCryptomining: number;
  ratingTunnel: number;
  scanTier: string;
  firstSeen: number;
  updatedAt: number;
  ratingNewlyRegistered: number;
  ratingRegistryHold: number;
  ratingHiddenRegistrant: number;
  ratingAbusiveRegistrar: number;
}

export interface AiDecisionsResponse {
  decisions: AiDecision[];
  totalCount: number;
  blockCount: number;
  recordCount: number;
  cleanCount: number;
}

export interface DomainRequest {
  domain: string;
}

/** `LookupOutcome` by name; a number when the daemon sends a value this proto does not know. */
export type LookupOutcome = string | number;

export interface DelegationSigner {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: string;
}

export interface NameserverGlue {
  name: string;
  addresses: string[];
}

export interface DomainRegistration {
  domain: string;
  source: string;
  registrar: string;
  registrarId: string;
  statuses: string[];
  nameservers: string[];
  registeredAt: number;
  expiresAt: number;
  updatedAt: number;
  registrantName: string;
  registrantOrganization: string;
  redacted: boolean;
  dnssec: string;
  fetchedAt: number;
  dsRecords: DelegationSigner[];
  nameserverAddresses: NameserverGlue[];
  handle: string;
  unicodeName: string;
  registrarUrl: string;
  registrarCountry: string;
  whoisServer: string;
  abuseEmail: string;
  abusePhone: string;
  abuseUrl: string;
  registrantCountry: string;
  registrantRegion: string;
  registrantContactUrl: string;
  registrarExpiresAt: number;
  transferredAt: number;
  databaseUpdatedAt: number;
  registrySource: string;
  registrarSource: string;
}

export interface LookupDomainResponse {
  outcome: LookupOutcome;
  registration: DomainRegistration | null;
  detail: string;
}

export interface DnsRecordsRequest {
  host: string;
  domain: string;
  address: string;
}

export interface DnsAnswer {
  name: string;
  recordType: string;
  ttl: number;
  data: string;
}

export interface DnsRecordSet {
  purpose: string;
  name: string;
  recordType: string;
  status: string;
  authenticated: boolean;
  answers: DnsAnswer[];
}

export interface DnsRecordsResponse {
  upstream: string;
  domain: string;
  sets: DnsRecordSet[];
}

export interface HostDomainRequest {
  host: string;
  domain: string;
}

export interface SeenSubdomain {
  name: string;
  connections: number;
  blocked: number;
  firstSeen: number;
  lastSeen: number;
}

export interface SeenSubdomainsResponse {
  names: SeenSubdomain[];
  truncated: boolean;
  domain: string;
}

export interface CertificateHostname {
  name: string;
  certificates: number;
  firstIssued: number;
  latestExpiry: number;
  issuer: string;
}

export interface CertificateSearchResponse {
  outcome: LookupOutcome;
  domain: string;
  certificates: number;
  names: CertificateHostname[];
  truncated: boolean;
  detail: string;
}

/** Settings fields; see `SETTINGS_FIELDS` in `dto/settings.ts` for the list. */
export type SettingsRequest = Record<string, string | number | boolean>;
export type SettingsResponse = Record<string, string | number | boolean>;

export interface UpdateSettingsResponse {
  success: boolean;
  message: string;
  notApplied: string[];
}

export interface NotificationEvent {
  type: string;
  title: string;
  message: string;
  timestamp: number;
  severity: string;
  id: number;
}

export interface AlertsResponse {
  alerts: NotificationEvent[];
}

export interface CaptureDevice {
  name: string;
  description: string;
  addresses: string[];
  loopback: boolean;
}

export interface CaptureDevicesResponse {
  devices: CaptureDevice[];
  available: boolean;
  message: string;
}

export interface StartCaptureRequest {
  deviceName: string;
  captureFilter: string;
  snapLength: number;
  promiscuous: boolean;
  readTimeoutMs: number;
  maxSeconds: number;
  maxBytes: number;
  appPath: string;
  appName: string;
}

export interface CaptureControl {
  captureId: string;
}

export interface CaptureSessionResponse {
  captureId: string;
  started: boolean;
  message: string;
}

export interface CaptureStatus {
  captureId: string;
  state: string;
  active: boolean;
  packets: number;
  bytes: number;
  droppedPackets: number;
  elapsedSeconds: number;
  deviceName: string;
  message: string;
  filteredPackets: number;
  appName: string;
}

export interface CaptureChunk {
  data: Buffer;
  last: boolean;
}

export interface CapturedPacket {
  sequence: number;
  timestampUs: number;
  capturedLength: number;
  originalLength: number;
  linkLayer: number;
  protocol: string;
  source: string;
  destination: string;
  sourcePort: number;
  destinationPort: number;
  info: string;
  data: Buffer;
}

export interface NetworkDevice {
  macAddress: string;
  ipAddress: string;
  manufacturer: string;
  mdnsName: string;
  present: boolean;
  watched: boolean;
  lastSeen: string;
}

export interface NetworkScanRange {
  id: number;
  adapterId: string;
  cidr: string;
}

export interface NetworkDeviceWatch {
  id: number;
  macAddress: string;
  adapterId: string;
  cidr: string;
  intervalMinutes: number;
  enabled: boolean;
  present: boolean;
  lastChecked: string;
  ipAddress: string;
}

export interface NetworkMappingState {
  supported: boolean;
  message: string;
  devices: NetworkDevice[];
  scanRanges: NetworkScanRange[];
  deviceWatches: NetworkDeviceWatch[];
  isScanning: boolean;
}

export interface NetworkMapRequest {
  cidrRanges: string[];
}

export interface UpdateStatus {
  /** `UpdateStatus.State` by name, or a number the proto does not know. */
  state: string | number;
  currentVersion: string;
  availableVersion: string;
  notes: string;
  detail: string;
  /** "stable", "beta", or "nightly"; empty from a daemon that predates channels. */
  channel: string;
  /** Unix seconds of the last check; 0 before the first. */
  lastCheckedAt: number;
  checkError: string;
}

/** Unary RPCs this client calls: request and response per method. */
export interface UnaryRpcs {
  GetStats: [Empty, StatsResponse];
  GetActiveApplications: [Empty, ActiveApplicationsResponse];
  GetConnectionLogs: [LogRequest, LogResponse];
  GetCountryStatistics: [Empty, CountryStatisticsResponse];
  GetApplicationLogSummaries: [ApplicationLogSummaryRequest, ApplicationLogSummaryResponse];
  GetActivityBuckets: [ActivityBucketsRequest, { buckets: ActivityBucket[] }];
  DeleteHistory: [
    DeleteHistoryRequest,
    { success: boolean; message: string; deletedCount: number },
  ];
  GetRules: [Empty, RulesResponse];
  AddRule: [Rule, ActionResponse];
  RemoveRule: [Rule, ActionResponse];
  AddCountryRule: [CountryRule, ActionResponse];
  RemoveCountryRule: [CountryRule, ActionResponse];
  GetAiDecisions: [AiDecisionsRequest, AiDecisionsResponse];
  DeleteAiDecision: [DomainRequest, ActionResponse];
  RefreshAiDecision: [DomainRequest, AiDecision];
  AdvancedAiDecision: [DomainRequest, AiDecision];
  LookupDomain: [DomainRequest, LookupDomainResponse];
  LookupDnsRecords: [DnsRecordsRequest, DnsRecordsResponse];
  GetSeenSubdomains: [HostDomainRequest, SeenSubdomainsResponse];
  SearchCertificates: [HostDomainRequest, CertificateSearchResponse];
  GetSettings: [Empty, SettingsResponse];
  UpdateSettings: [SettingsRequest, UpdateSettingsResponse];
  SyncHostsBlocklist: [Empty, ActionResponse];
  RefreshGeoDatabase: [Empty, ActionResponse];
  GetAlerts: [Empty, AlertsResponse];
  DismissAlert: [{ id: number }, ActionResponse];
  ClearAlerts: [Empty, ActionResponse];
  ListCaptureDevices: [Empty, CaptureDevicesResponse];
  StartCapture: [StartCaptureRequest, CaptureSessionResponse];
  StopCapture: [CaptureControl, ActionResponse];
  GetCaptureStatus: [CaptureControl, CaptureStatus];
  GetNetworkMappingState: [Empty, NetworkMappingState];
  ScanNetwork: [NetworkMapRequest, ActionResponse];
  StopNetworkScan: [Empty, ActionResponse];
  ClearNetworkDevices: [Empty, ActionResponse];
  SaveNetworkScanRange: [NetworkScanRange, ActionResponse];
  RemoveNetworkScanRange: [NetworkScanRange, ActionResponse];
  SaveNetworkDeviceWatch: [NetworkDeviceWatch, ActionResponse];
  RemoveNetworkDeviceWatch: [NetworkDeviceWatch, ActionResponse];
  UpdateOuiDatabase: [Empty, ActionResponse];
  GetUpdateStatus: [Empty, UpdateStatus];
  InstallUpdate: [{ version: string }, ActionResponse];
  CheckForUpdates: [Empty, UpdateStatus];
}

/** Server-streaming RPCs this client calls. */
export interface StreamRpcs {
  StreamRealtimeTraffic: [Empty, TrafficEvent];
  StreamNotifications: [Empty, NotificationEvent];
  StreamCapturedPackets: [CaptureControl, CapturedPacket];
  DownloadCapture: [CaptureControl, CaptureChunk];
}
