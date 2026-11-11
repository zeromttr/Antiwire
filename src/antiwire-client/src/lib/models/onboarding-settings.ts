import type { SettingsDto } from '../api/daemon';
import { DOQ_CAPABLE_PROVIDER_IDS } from './dns-providers';
import {
  RECOMMENDED_BLOCKLIST_IDS,
  parseBlocklistSelection,
  serializeBlocklistSelection,
} from './blocklists';

export const RETENTION_OPTIONS = [15, 30, 90, 180, 365, 'unlimited'] as const;

export type ResolverProtocol = 'doh' | 'dot' | 'doq';
export type RetentionChoice = (typeof RETENTION_OPTIONS)[number];

export interface OnboardingChoices {
  resolverEnabled: boolean;
  resolverProtocol: ResolverProtocol;
  blocklistIds: string[];
  geoIpEnabled: boolean;
  desktopNotifications: boolean;
  newConnectionAlerts: boolean;
  newApplicationAlerts: boolean;
  threatAlerts: boolean;
  retention: RetentionChoice;
}

function retentionChoice(settings: SettingsDto): RetentionChoice {
  if (!settings.logRetentionEnabled) return 'unlimited';
  return RETENTION_OPTIONS.includes(settings.logRetentionDays as RetentionChoice)
    ? (settings.logRetentionDays as RetentionChoice)
    : 30;
}

export function onboardingChoicesFromSettings(
  settings: SettingsDto,
  recommendBlocklists = false,
): OnboardingChoices {
  const selected = settings.hostsBlocklistEnabled
    ? [...parseBlocklistSelection(settings.hostsBlocklistSelectedLists)]
    : recommendBlocklists
      ? [...RECOMMENDED_BLOCKLIST_IDS]
      : [];

  return {
    resolverEnabled: settings.dnsResolverEnabled,
    resolverProtocol: ['doh', 'dot', 'doq'].includes(settings.dnsProtocol)
      ? (settings.dnsProtocol as ResolverProtocol)
      : 'doh',
    blocklistIds: selected,
    geoIpEnabled: settings.geoIpEnabled,
    desktopNotifications: settings.notifyEveryConnection,
    newConnectionAlerts: settings.notifyNewConnection,
    newApplicationAlerts: settings.notifyNewApp,
    threatAlerts: settings.notifyThreatDetected,
    retention: retentionChoice(settings),
  };
}

export function applyOnboardingChoices(
  settings: SettingsDto,
  choices: OnboardingChoices,
): SettingsDto {
  const blocklistIds = new Set(choices.blocklistIds);
  const provider =
    choices.resolverProtocol === 'doq' &&
    !(DOQ_CAPABLE_PROVIDER_IDS as readonly string[]).includes(settings.dohProvider)
      ? 'quad9'
      : settings.dohProvider;

  return {
    ...settings,
    dnsResolverEnabled: choices.resolverEnabled,
    dnsProtocol: choices.resolverProtocol,
    dohProvider: provider,
    hostsBlocklistEnabled: blocklistIds.size > 0,
    hostsBlocklistSelectedLists: serializeBlocklistSelection(blocklistIds),
    geoIpEnabled: choices.geoIpEnabled,
    notifyEveryConnection: choices.desktopNotifications,
    notifyNewConnection: choices.newConnectionAlerts,
    notifyNewApp: choices.newApplicationAlerts,
    notifyThreatDetected: choices.threatAlerts,
    logRetentionEnabled: choices.retention !== 'unlimited',
    logRetentionDays:
      choices.retention === 'unlimited' ? settings.logRetentionDays : choices.retention,
  };
}
