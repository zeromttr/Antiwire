import { beforeAll, describe, expect, test } from 'bun:test';
import { loadMessages, m } from '#lib/i18n/messages.ts';
import {
  AI_BLOCK_LABEL,
  DNS_PROVIDER_BLOCK_LABEL,
  FIREWALL_RULE_LABEL,
  LOADING_BLOCKLISTS_LABEL,
  NEW_DOMAIN_BLOCK_LABEL,
  HAGEZI_ABUSED_TLDS_LIST_ID,
  BLOCKLIST_GROUPS,
  BLOCKLIST_MAX_STRENGTH,
  RECOMMENDED_BLOCKLIST_IDS,
  blocklistDisplayName,
  blocklistFrequencyLabel,
  blocklistFrequencyOptions,
  blocklistLastSyncedAt,
  blocklistOptions,
  normalizeBlocklistFrequency,
  blocklistsInGroup,
  selectedBlocklistOptions,
  shortBlocklistName,
  formatBlocklistNames,
  parseBlocklistSelection,
  setSelectedBlocklist,
} from './blocklists';

beforeAll(async () => {
  await loadMessages('en');
});

describe('blocklists', () => {
  test('includes the abused TLD list', () => {
    expect(blocklistOptions().some((option) => option.id === HAGEZI_ABUSED_TLDS_LIST_ID)).toBe(
      true,
    );
  });

  test('puts every list in exactly one selector group', () => {
    const options = blocklistOptions();
    const grouped = BLOCKLIST_GROUPS.flatMap((group) => blocklistsInGroup(options, group));
    expect(grouped).toHaveLength(options.length);
    expect(new Set(grouped.map((option) => option.id)).size).toBe(options.length);
    expect(blocklistsInGroup(options, 'security').map((option) => option.id)).toContain(
      HAGEZI_ABUSED_TLDS_LIST_ID,
    );
  });

  test('rates the HaGeZi levels from Light to Ultimate, Mini sharing its level', () => {
    const strength = Object.fromEntries(
      blocklistOptions().map((option) => [option.id, option.strength]),
    );
    expect(strength.hagezi_light).toBe(1);
    expect(strength.hagezi_multi).toBe(2);
    expect(strength.hagezi_pro).toBe(strength.hagezi_pro_mini);
    expect(strength.hagezi_ultimate).toBe(BLOCKLIST_MAX_STRENGTH);
    expect(strength['stevenblack-uni']).toBeUndefined();
    for (const option of blocklistsInGroup(blocklistOptions(), 'hagezi')) {
      expect(option.strength).toBeGreaterThan(0);
    }
  });

  test('recommends the balanced HaGeZi list and threat intelligence', () => {
    expect([...RECOMMENDED_BLOCKLIST_IDS]).toEqual(['hagezi_multi', 'hagezi_tif']);
    const catalog = new Set(blocklistOptions().map((option) => option.id));
    for (const id of RECOMMENDED_BLOCKLIST_IDS) expect(catalog.has(id)).toBe(true);
  });

  test('shortens a name inside its HaGeZi section only', () => {
    expect(shortBlocklistName('HaGeZi - Pro Mini')).toBe('Pro Mini');
    expect(shortBlocklistName('StevenBlack')).toBe('StevenBlack');
  });

  test('lists the selected catalog lists in catalog order, skipping unknown ids', () => {
    const selected = selectedBlocklistOptions(
      blocklistOptions(),
      'stevenblack-uni, retired_list, hagezi_multi',
    );
    expect(selected.map((option) => option.id)).toEqual(['hagezi_multi', 'stevenblack-uni']);
  });

  test('reads saved update frequencies the way the daemon does', () => {
    expect(normalizeBlocklistFrequency('24hours')).toBe('24hours');
    expect(normalizeBlocklistFrequency(' Daily ')).toBe('24hours');
    expect(normalizeBlocklistFrequency('6h')).toBe('6hours');
    expect(normalizeBlocklistFrequency('manual')).toBe('manual');
    expect(normalizeBlocklistFrequency('monthly')).toBe('monthly');
    expect(normalizeBlocklistFrequency('')).toBe('24hours');
    expect(normalizeBlocklistFrequency('fortnightly')).toBe('weekly');
  });

  test('labels frequencies and keeps a saved monthly choice', () => {
    expect(blocklistFrequencyLabel('1hour')).toBe(m.settings_blocklists_frequency_hour());
    expect(blocklistFrequencyLabel('12hours')).toBe(
      m.settings_blocklists_frequency_hours({ count: 12 }),
    );
    expect(blocklistFrequencyLabel('48hours')).toBe(
      m.settings_blocklists_frequency_hours({ count: 48 }),
    );
    expect(blocklistFrequencyLabel('5days')).toBe(
      m.settings_blocklists_frequency_days({ count: 5 }),
    );
    expect(blocklistFrequencyOptions('24hours').map((option) => option.value)).not.toContain(
      'monthly',
    );
    expect(blocklistFrequencyOptions('monthly').map((option) => option.value)).toContain('monthly');
  });

  test('treats the epoch placeholder as never synced', () => {
    expect(blocklistLastSyncedAt('1970-01-01T00:00:00Z')).toBe(0);
    expect(blocklistLastSyncedAt('')).toBe(0);
    expect(blocklistLastSyncedAt('not a date')).toBe(0);
    expect(blocklistLastSyncedAt('2026-09-29T10:00:00Z')).toBe(Date.UTC(2026, 8, 29, 10));
  });

  test('toggles a list id in the stored selection', () => {
    const enabled = setSelectedBlocklist('hagezi_multi', HAGEZI_ABUSED_TLDS_LIST_ID, true);
    expect(parseBlocklistSelection(enabled).has(HAGEZI_ABUSED_TLDS_LIST_ID)).toBe(true);
    expect(parseBlocklistSelection(enabled).has('hagezi_multi')).toBe(true);

    const disabled = setSelectedBlocklist(enabled, HAGEZI_ABUSED_TLDS_LIST_ID, false);
    expect(parseBlocklistSelection(disabled).has(HAGEZI_ABUSED_TLDS_LIST_ID)).toBe(false);
    expect(disabled).toBe('hagezi_multi');
  });

  test('maps catalog ids and the firewall label, and passes custom names through', () => {
    expect(blocklistDisplayName('hagezi_light')).toBe(m.settings_blocklist_hagezi_light_name());
    expect(blocklistDisplayName(FIREWALL_RULE_LABEL)).toBe(m.records_blocklist_firewall_rule());
    expect(blocklistDisplayName(AI_BLOCK_LABEL)).toBe(m.records_blocklist_ai());
    expect(blocklistDisplayName(LOADING_BLOCKLISTS_LABEL)).toBe(m.records_blocklist_loading());
    expect(blocklistDisplayName(DNS_PROVIDER_BLOCK_LABEL)).toBe(m.records_blocklist_dns_provider());
    expect(blocklistDisplayName(NEW_DOMAIN_BLOCK_LABEL)).toBe(m.records_blocklist_new_domain());
    expect(blocklistDisplayName('Custom List - 1')).toBe('Custom List - 1');
    expect(blocklistDisplayName('  ')).toBe('');
  });

  test('joins display names for the records UI', () => {
    expect(formatBlocklistNames(undefined)).toBe('');
    expect(formatBlocklistNames([])).toBe('');
    expect(formatBlocklistNames(['hagezi_light', 'hagezi_tif'])).toBe(
      `${m.settings_blocklist_hagezi_light_name()}, ${m.settings_blocklist_hagezi_tif_name()}`,
    );
  });
});
