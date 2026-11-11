#!/usr/bin/env bun
/**
 * Merge a translation map over en.json, preserving key order and locked strings.
 * Usage: bun scripts/i18n/build-locale.mjs <fi|cs|sk>
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "../..");
const locale = process.argv[2];
if (!locale) {
  console.error("Usage: bun scripts/i18n/build-locale.mjs <locale>");
  process.exit(1);
}

const en = JSON.parse(fs.readFileSync(path.join(root, "messages/en.json"), "utf8"));
const mapPath = path.join(__dirname, `${locale}.json`);
const map = JSON.parse(fs.readFileSync(mapPath, "utf8"));

const lockedPrefixes = ["locale_", "common_unit_", "common_format_"];
const lockedExact = new Set([
  "settings_about_mit_license_text",
  "settings_about_copyright",
]);
// Brand names, protocol codes, placeholders, and unit/example strings kept in English.
const keepEnglish = new Set([
  "nav_alerts_badge_overflow",
  "onboarding_resolver_title",
  "onboarding_blocklist_hagezi_normal_title",
  "onboarding_blocklist_hagezi_tif_title",
  "settings_resolver_label",
  "settings_resolver_aria",
  "settings_dns_protocol_doh",
  "settings_dns_protocol_dot",
  "settings_dns_protocol_doq",
  "settings_custom_resolver_url_placeholder",
  "settings_dns_provider_cloudflare",
  "settings_dns_provider_cloudflare_fam",
  "settings_dns_provider_cloudflare_sec",
  "settings_dns_provider_quad9",
  "settings_dns_provider_quad9_ecs",
  "settings_dns_provider_quad9_unfiltered",
  "settings_dns_provider_adguard",
  "settings_dns_provider_adguard_fam",
  "settings_dns_provider_adguard_unfiltered",
  "settings_dns_provider_google",
  "settings_dns_provider_opendns",
  "settings_dns_provider_opendns_fam",
  "settings_dns_provider_cleanbrowsing",
  "settings_dns_provider_cleanbrowsing_fam",
  "settings_dns_provider_cleanbrowsing_adult",
  "settings_blocklist_hagezi_light_name",
  "settings_blocklist_hagezi_multi_name",
  "settings_blocklist_hagezi_pro_name",
  "settings_blocklist_hagezi_pro_mini_name",
  "settings_blocklist_hagezi_pro_plus_plus_name",
  "settings_blocklist_hagezi_pro_plus_plus_mini_name",
  "settings_blocklist_hagezi_ultimate_name",
  "settings_blocklist_hagezi_ultimate_mini_name",
  "settings_blocklist_hagezi_tif_name",
  "settings_blocklist_hagezi_bypass_name",
  "settings_blocklist_hagezi_dyn_name",
  "settings_blocklist_stevenblack_name",
  "settings_blocklist_1hosts_lite_name",
  "settings_blocklist_1hosts_xtra_name",
  "settings_blocklist_someonewhocares_name",
  "settings_custom_blocklist_url_placeholder",
  "settings_siem_protocol_udp",
  "settings_siem_protocol_tcp",
  "settings_siem_auth_header_placeholder",
  "settings_about_version",
  "settings_about_license_name",
  "firewall_rule_type_ip",
  "firewall_kind_ip",
  "firewall_kind_cidr",
  "firewall_placeholder_domain",
  "firewall_placeholder_ip",
  "firewall_placeholder_cidr",
  "firewall_add_app_path_placeholder",
  "records_protocol_tcp",
  "records_protocol_udp",
  "records_packet_verb_dns",
  "records_packet_verb_block",
  "records_packet_verb_open",
  "records_packet_verb_xfer",
  "records_packet_dns_text",
  "capture_filter_help",
  "capture_preset_dns",
  "capture_preset_tcp",
  "capture_preset_udp",
  "capture_preset_icmp",
  "capture_snap_headers_desc",
  "capture_snap_standard_desc",
  "capture_snap_full_desc",
  "capture_size_10mb",
  "capture_size_50mb",
  "capture_size_100mb",
  "capture_size_250mb",
  "capture_size_500mb",
  "network_custom_cidr_placeholder",
  "network_watch_interval_compact_minutes",
  "network_watch_interval_compact_hour",
  "analytics_dns_query_count",
  "dashboard_activity_axis",
  "common_em_dash",
]);

const keys = Object.keys(en);
const out = {};
const missing = [];
const unexpected = Object.keys(map).filter((k) => !(k in en));

for (const key of keys) {
  const enVal = en[key];
  const isLocked =
    lockedExact.has(key) ||
    lockedPrefixes.some((p) => key.startsWith(p)) ||
    keepEnglish.has(key);
  if (isLocked) {
    out[key] = enVal;
    continue;
  }
  if (!(key in map)) {
    missing.push(key);
    out[key] = enVal;
    continue;
  }
  out[key] = map[key];
}

const dest = path.join(root, `messages/${locale}.json`);
const json = JSON.stringify(out, null, 2) + "\n";
fs.writeFileSync(dest, json);

const outKeys = Object.keys(out);
const keysMatch =
  outKeys.length === keys.length && outKeys.every((k, i) => k === keys[i]);

console.log(
  JSON.stringify(
    {
      locale,
      keyCount: outKeys.length,
      keysMatch,
      missing: missing.length,
      unexpected: unexpected.length,
      missingSample: missing.slice(0, 10),
      unexpectedSample: unexpected.slice(0, 10),
      written: dest,
    },
    null,
    2,
  ),
);

if (!keysMatch || missing.length || unexpected.length) {
  process.exit(2);
}
