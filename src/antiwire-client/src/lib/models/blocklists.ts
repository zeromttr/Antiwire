import { m } from '#lib/i18n/messages.ts';

export const HAGEZI_ABUSED_TLDS_LIST_ID = 'hagezi_abused_tlds';

/** Matches `antiwire_policy::FIREWALL_RULE_LABEL` stored on connection logs. */
export const FIREWALL_RULE_LABEL = 'Firewall Rule';
export const AI_BLOCK_LABEL = 'AI';
export const LOADING_BLOCKLISTS_LABEL = 'Loading Block Lists';
export const DNS_PROVIDER_BLOCK_LABEL = 'DNS Provider';
/** Matches `antiwire_dns`'s label for a block by registration age. */
export const NEW_DOMAIN_BLOCK_LABEL = 'Newly Registered Domain';

/** What a list is for; the selector groups lists by it. */
export type BlocklistGroup = 'hagezi' | 'security' | 'community';

export interface BlocklistOption {
  id: string;
  name: string;
  description: string;
  group: BlocklistGroup;
  /**
   * HaGeZi multi-purpose level, 1 (Light) to 5 (Ultimate). Higher blocks more
   * and is more likely to break sites; a Mini variant shares its level.
   */
  strength?: number;
  /** Suggested by default in first-run setup. */
  recommended?: boolean;
}

/**
 * The blocklist catalog. This is the one place a list is added: every picker
 * (Settings, first-run setup) and every label for a list id reads from here.
 */
interface BlocklistMessages {
  id: string;
  group: BlocklistGroup;
  strength?: number;
  recommended?: boolean;
  name: () => string;
  description: () => string;
}

const BLOCKLIST_MESSAGES: BlocklistMessages[] = [
  {
    id: 'hagezi_light',
    group: 'hagezi',
    strength: 1,
    name: m.settings_blocklist_hagezi_light_name,
    description: m.settings_blocklist_hagezi_light_desc,
  },
  {
    id: 'hagezi_multi',
    group: 'hagezi',
    strength: 2,
    recommended: true,
    name: m.settings_blocklist_hagezi_multi_name,
    description: m.settings_blocklist_hagezi_multi_desc,
  },
  {
    id: 'hagezi_pro',
    group: 'hagezi',
    strength: 3,
    name: m.settings_blocklist_hagezi_pro_name,
    description: m.settings_blocklist_hagezi_pro_desc,
  },
  {
    id: 'hagezi_pro_mini',
    group: 'hagezi',
    strength: 3,
    name: m.settings_blocklist_hagezi_pro_mini_name,
    description: m.settings_blocklist_hagezi_pro_mini_desc,
  },
  {
    id: 'hagezi_pro_plus_plus',
    group: 'hagezi',
    strength: 4,
    name: m.settings_blocklist_hagezi_pro_plus_plus_name,
    description: m.settings_blocklist_hagezi_pro_plus_plus_desc,
  },
  {
    id: 'hagezi_pro_plus_plus_mini',
    group: 'hagezi',
    strength: 4,
    name: m.settings_blocklist_hagezi_pro_plus_plus_mini_name,
    description: m.settings_blocklist_hagezi_pro_plus_plus_mini_desc,
  },
  {
    id: 'hagezi_ultimate',
    group: 'hagezi',
    strength: 5,
    name: m.settings_blocklist_hagezi_ultimate_name,
    description: m.settings_blocklist_hagezi_ultimate_desc,
  },
  {
    id: 'hagezi_ultimate_mini',
    group: 'hagezi',
    strength: 5,
    name: m.settings_blocklist_hagezi_ultimate_mini_name,
    description: m.settings_blocklist_hagezi_ultimate_mini_desc,
  },
  {
    id: 'hagezi_tif',
    group: 'security',
    recommended: true,
    name: m.settings_blocklist_hagezi_tif_name,
    description: m.settings_blocklist_hagezi_tif_desc,
  },
  {
    id: 'hagezi_bypass',
    group: 'security',
    name: m.settings_blocklist_hagezi_bypass_name,
    description: m.settings_blocklist_hagezi_bypass_desc,
  },
  {
    id: 'hagezi_dyn',
    group: 'security',
    name: m.settings_blocklist_hagezi_dyn_name,
    description: m.settings_blocklist_hagezi_dyn_desc,
  },
  {
    id: 'urlhaus',
    group: 'security',
    name: m.settings_blocklist_urlhaus_name,
    description: m.settings_blocklist_urlhaus_desc,
  },
  {
    id: 'phishing_army',
    group: 'security',
    name: m.settings_blocklist_phishing_army_name,
    description: m.settings_blocklist_phishing_army_desc,
  },
  {
    id: 'stevenblack-uni',
    group: 'community',
    name: m.settings_blocklist_stevenblack_name,
    description: m.settings_blocklist_stevenblack_desc,
  },
  {
    id: '1hosts_lite',
    group: 'community',
    name: m.settings_blocklist_1hosts_lite_name,
    description: m.settings_blocklist_1hosts_lite_desc,
  },
  {
    id: '1host_xtra',
    group: 'community',
    name: m.settings_blocklist_1hosts_xtra_name,
    description: m.settings_blocklist_1hosts_xtra_desc,
  },
  {
    id: 'someonewhocares',
    group: 'community',
    name: m.settings_blocklist_someonewhocares_name,
    description: m.settings_blocklist_someonewhocares_desc,
  },
  {
    id: HAGEZI_ABUSED_TLDS_LIST_ID,
    group: 'security',
    name: m.settings_blocklist_hagezi_tlds_name,
    description: m.settings_blocklist_hagezi_tlds_desc,
  },
];

/** Localized blocklist options; re-evaluated on each access so the active locale is reflected. */
export function blocklistOptions(): BlocklistOption[] {
  return BLOCKLIST_MESSAGES.map(({ id, group, strength, recommended, name, description }) => ({
    id,
    group,
    strength,
    recommended,
    name: name(),
    description: description(),
  }));
}

/** Lists first-run setup selects by default: a balanced list plus threat intelligence. */
export const RECOMMENDED_BLOCKLIST_IDS: readonly string[] = BLOCKLIST_MESSAGES.filter(
  (list) => list.recommended,
).map((list) => list.id);

/** Selector sections, in display order. */
export const BLOCKLIST_GROUPS: readonly BlocklistGroup[] = ['hagezi', 'security', 'community'];

/** Options in one group, in catalog order. */
export function blocklistsInGroup(
  options: readonly BlocklistOption[],
  group: BlocklistGroup,
): BlocklistOption[] {
  return options.filter((option) => option.group === group);
}

/** Highest HaGeZi multi-purpose level. */
export const BLOCKLIST_MAX_STRENGTH = 5;

/**
 * A list's name inside its HaGeZi section, which already says HaGeZi:
 * "HaGeZi - Pro Mini" reads "Pro Mini". List names are brand names and the
 * same in every locale; a name without the prefix is returned unchanged.
 */
export function shortBlocklistName(name: string): string {
  return name.replace(/^HaGeZi\s*-\s*/i, '');
}

/**
 * Catalog lists that are selected, in catalog order; ids no longer in the
 * catalog are left out.
 */
export function selectedBlocklistOptions(
  options: readonly BlocklistOption[],
  selection: string,
): BlocklistOption[] {
  const selected = parseBlocklistSelection(selection);
  return options.filter((option) => selected.has(option.id));
}

/** Localized label for a catalog id, firewall rule, or custom list name. */
export function blocklistDisplayName(id: string): string {
  const trimmed = id.trim();
  if (!trimmed) return '';
  if (trimmed === FIREWALL_RULE_LABEL) return m.records_blocklist_firewall_rule();
  if (trimmed === AI_BLOCK_LABEL) return m.records_blocklist_ai();
  if (trimmed === LOADING_BLOCKLISTS_LABEL) return m.records_blocklist_loading();
  if (trimmed === DNS_PROVIDER_BLOCK_LABEL) return m.records_blocklist_dns_provider();
  if (trimmed === NEW_DOMAIN_BLOCK_LABEL) return m.records_blocklist_new_domain();
  const match = BLOCKLIST_MESSAGES.find((option) => option.id === trimmed);
  return match ? match.name() : trimmed;
}

/** Joins matching list names for record details and the blocked-dot tooltip. */
export function formatBlocklistNames(names: readonly string[] | undefined): string {
  if (!names?.length) return '';
  return names.map(blocklistDisplayName).filter(Boolean).join(', ');
}

export function parseBlocklistSelection(value: string): Set<string> {
  return new Set(
    value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean),
  );
}

export function serializeBlocklistSelection(selected: Set<string> | Iterable<string>): string {
  return [...selected].join(',');
}

export function setSelectedBlocklist(selection: string, id: string, enabled: boolean): string {
  const next = parseBlocklistSelection(selection);
  if (enabled) {
    next.add(id);
  } else {
    next.delete(id);
  }
  return serializeBlocklistSelection(next);
}

/** Parses daemon custom URL storage (`;`-separated) into editable single-URL fields. */
export function parseCustomBlocklistUrls(value: string): string[] {
  const urls = value
    .split(';')
    .map((entry) => entry.trim())
    .filter(Boolean);
  return urls.length > 0 ? urls : [''];
}

/** Serializes single-URL fields back to daemon storage (`;`-separated). */
export function serializeCustomBlocklistUrls(urls: Iterable<string>): string {
  return [...urls]
    .map((entry) => entry.trim())
    .filter(Boolean)
    .join(';');
}

export function isValidBlocklistUrl(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return true;
  try {
    const url = new URL(trimmed);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Automatic sync intervals, as the daemon names them
 * (`antiwire_policy::blocklist_sync_interval_hours`), with their hours.
 * `manual` turns automatic syncing off.
 */
export const BLOCKLIST_UPDATE_FREQUENCIES = [
  { value: 'manual', hours: 0 },
  { value: '1hour', hours: 1 },
  { value: '3hours', hours: 3 },
  { value: '6hours', hours: 6 },
  { value: '12hours', hours: 12 },
  { value: '24hours', hours: 24 },
  { value: '48hours', hours: 48 },
  { value: '5days', hours: 120 },
  { value: 'weekly', hours: 168 },
] as const;

/** The daemon's default when nothing is saved. */
export const DEFAULT_BLOCKLIST_UPDATE_FREQUENCY = '24hours';

/** Older and shorthand spellings the daemon still accepts, mapped to the listed values. */
const FREQUENCY_ALIASES: Record<string, string> = {
  '1h': '1hour',
  '3h': '3hours',
  '6h': '6hours',
  '12h': '12hours',
  '24h': '24hours',
  daily: '24hours',
  '48h': '48hours',
  '5d': '5days',
};

/**
 * The listed value for a saved frequency. `monthly` stays as it is (the daemon
 * reads it as 30 days); anything the daemon does not recognise reads as
 * `weekly`, which is what the daemon falls back to.
 */
export function normalizeBlocklistFrequency(value: string): string {
  const key = value.trim().toLowerCase();
  if (!key) return DEFAULT_BLOCKLIST_UPDATE_FREQUENCY;
  if (key === 'monthly') return key;
  if (BLOCKLIST_UPDATE_FREQUENCIES.some((option) => option.value === key)) return key;
  return FREQUENCY_ALIASES[key] ?? 'weekly';
}

/** Localized label for a (normalized) frequency. */
export function blocklistFrequencyLabel(value: string): string {
  if (value === 'manual') return m.settings_blocklists_frequency_manual();
  if (value === 'monthly') return m.settings_blocklists_frequency_days({ count: 30 });
  if (value === 'weekly') return m.settings_blocklists_frequency_week();
  const hours = BLOCKLIST_UPDATE_FREQUENCIES.find((option) => option.value === value)?.hours ?? 0;
  if (hours === 1) return m.settings_blocklists_frequency_hour();
  if (hours % 24 === 0 && hours > 48)
    return m.settings_blocklists_frequency_days({ count: hours / 24 });
  return m.settings_blocklists_frequency_hours({ count: hours });
}

/** Dropdown options; a saved `monthly` is kept as its own choice rather than rewritten. */
export function blocklistFrequencyOptions(current: string): { value: string; label: string }[] {
  const values: string[] = BLOCKLIST_UPDATE_FREQUENCIES.map((option) => option.value);
  if (normalizeBlocklistFrequency(current) === 'monthly') values.push('monthly');
  return values.map((value) => ({ value, label: blocklistFrequencyLabel(value) }));
}

/**
 * When the lists last synced, in epoch milliseconds, or `0` when they never
 * have: the daemon sends the Unix epoch until the first sync.
 */
export function blocklistLastSyncedAt(value: string): number {
  const ms = Date.parse(value.trim());
  // Anything before 2000 is the never-synced placeholder, not a real sync.
  return Number.isFinite(ms) && ms > Date.UTC(2000, 0, 1) ? ms : 0;
}
