import clsx from 'clsx';
import { Copy, ExternalLink, Shield } from 'lucide-react';
import { useState } from 'react';
import { SettingsGroup } from '#lib/components/settings/form/SettingsGroup.tsx';
import { Button } from '#lib/components/ui/Button.tsx';
import { m } from '#lib/i18n/messages.ts';
import {
  ABOUT_PRODUCT,
  DATA_CREDITS,
  FONT_CREDITS,
  FRAMEWORK_CREDITS,
  MIT_LICENSE_TEXT,
  PACKAGE_CREDITS,
  RUNTIME_CREDITS,
  type CreditEntry,
} from '#lib/models/about-credits.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { REPOSITORY_URL } from '#shared/project.ts';
import { copyText } from '#lib/utils/clipboard.ts';
import styles from './AboutSettingsTab.module.css';

async function copyLicense() {
  try {
    const ok = await copyText(MIT_LICENSE_TEXT.trim());
    if (!ok) throw new Error('Copy failed');
    daemon.addToast(
      m.settings_about_toast_copied_title(),
      m.settings_about_toast_copied_body(),
      'var(--acc)',
    );
  } catch {
    daemon.addToast(
      m.settings_about_toast_copy_failed_title(),
      m.settings_about_toast_copy_failed_body(),
      'var(--bad)',
    );
  }
}

interface CreditSection {
  title: string;
  intro: string;
  entries: CreditEntry[];
}

/** Roles with a translation; any other role is shown as written in about-credits.ts. */
const ROLE_LABEL_FNS: Record<string, () => string> = {
  'UI framework': m.settings_about_role_ui_framework,
  'Desktop shell and native bridge': m.settings_about_role_desktop_shell,
  'Frontend build tooling': m.settings_about_role_build_tooling,
  'Navigation and UI icons': m.settings_about_role_icons,
  'Icon components': m.settings_about_role_icon_components,
  'Virtualized tables': m.settings_about_role_virtualized_tables,
  'Self-hosted sans-serif font assets': m.settings_about_role_sans_font_assets,
  'Self-hosted monospace font assets': m.settings_about_role_mono_font_assets,
  'Primary sans-serif typeface (via @fontsource)': m.settings_about_role_primary_sans,
  'Primary monospace typeface (via @fontsource)': m.settings_about_role_primary_mono,
  'Preferred system monospace on Windows when installed': m.settings_about_role_system_mono,
  'GeoIP / ASN resolution data (daemon)': m.settings_about_role_geoip_data,
  'Optional community hosts blocklists': m.settings_about_role_community_blocklists,
  'Optional unified hosts blocklist': m.settings_about_role_unified_hosts,
  'Optional hosts blocklist': m.settings_about_role_optional_hosts,
  'Windows packet capture driver (optional runtime)': m.settings_about_role_npcap,
  'Windows flow ownership and DNS packet diversion (runtime)': m.settings_about_role_windivert,
  'Packet capture on macOS / Linux (planned platforms)': m.settings_about_role_libpcap,
};

function roleLabel(role: string): string {
  return ROLE_LABEL_FNS[role]?.() ?? role;
}

/** `https://www.npmjs.com/package/x` reads as `npmjs.com/package/x`. */
function shortUrl(url: string): string {
  return url
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\/$/, '');
}

export function AboutSettingsTab() {
  const [logoFailed, setLogoFailed] = useState(false);

  const creditSections: CreditSection[] = [
    {
      title: m.settings_about_frameworks_title(),
      intro: m.settings_about_frameworks_intro(),
      entries: FRAMEWORK_CREDITS,
    },
    {
      title: m.settings_about_packages_title(),
      intro: m.settings_about_packages_intro(),
      entries: PACKAGE_CREDITS,
    },
    {
      title: m.settings_about_fonts_title(),
      intro: m.settings_about_fonts_intro(),
      entries: FONT_CREDITS,
    },
    {
      title: m.settings_about_data_title(),
      intro: m.settings_about_data_intro(),
      entries: DATA_CREDITS,
    },
    {
      title: m.settings_about_runtime_title(),
      intro: m.settings_about_runtime_intro(),
      entries: RUNTIME_CREDITS,
    },
  ];

  return (
    <div className={clsx(styles.aboutTab, 'settings-groups')} data-testid="settings-about">
      <section
        className={clsx(styles.hero, 'panel')}
        aria-label={m.settings_about_product_section()}
      >
        <div className={styles.heroTop}>
          {!logoFailed ? (
            <img
              className={styles.heroLogo}
              src="/icon.svg"
              alt=""
              decoding="async"
              onError={() => setLogoFailed(true)}
            />
          ) : (
            <span className={styles.heroFallback}>
              <Shield size={40} strokeWidth={1.5} />
            </span>
          )}
          <div className={styles.heroTitle}>
            <h3 className={styles.productName}>{ABOUT_PRODUCT.name}</h3>
            <p className={clsx(styles.productVersion, 'mono')}>
              {m.settings_about_version({
                client: ABOUT_PRODUCT.clientLabel,
                version: ABOUT_PRODUCT.version,
              })}
            </p>
            <p className={styles.productTagline}>{m.settings_about_tagline()}</p>
          </div>
        </div>
        <p className={styles.productDescription}>{m.settings_about_description()}</p>
        <p className={styles.productMeta}>
          {m.settings_about_copyright()} ·{' '}
          {m.settings_about_licensed_under({ license: m.settings_about_license_name() })}
          {REPOSITORY_URL && (
            <>
              {' · '}
              <a
                className={styles.creditLink}
                href={REPOSITORY_URL}
                target="_blank"
                rel="noreferrer noopener"
              >
                {m.settings_about_source_code()}
                <ExternalLink size={11} strokeWidth={2} aria-hidden="true" />
              </a>
            </>
          )}
        </p>
      </section>

      <SettingsGroup
        title={m.settings_about_license_section()}
        description={m.settings_about_license_intro()}
      >
        <div className={styles.license}>
          <div className={styles.licenseHead}>
            <span className={clsx(styles.tag, 'mono')}>{m.settings_about_license_name()}</span>
            <Button variant="secondary" size="sm" onClick={() => void copyLicense()}>
              <Copy size={14} />
              {m.settings_about_license_copy()}
            </Button>
          </div>
          <pre className={clsx(styles.licenseText, 'mono')}>{MIT_LICENSE_TEXT.trim()}</pre>
        </div>
      </SettingsGroup>

      {creditSections.map((sec) => (
        <SettingsGroup key={sec.title} title={sec.title} description={sec.intro}>
          <ul className={styles.credits}>
            {sec.entries.map((entry) => (
              <li key={entry.name} className={styles.credit}>
                <div className={styles.creditMain}>
                  <span className={styles.creditName}>{entry.name}</span>
                  <span className={styles.creditRole}>{roleLabel(entry.role)}</span>
                  {entry.url && (
                    // The main process sends new-window links to the system browser.
                    <a
                      className={styles.creditLink}
                      href={entry.url}
                      target="_blank"
                      rel="noreferrer noopener"
                    >
                      {shortUrl(entry.url)}
                      <ExternalLink size={11} strokeWidth={2} aria-hidden="true" />
                    </a>
                  )}
                  {entry.note && <p className={styles.creditNote}>{entry.note}</p>}
                </div>
                <span className={clsx(styles.tag, 'mono')}>{entry.license}</span>
              </li>
            ))}
          </ul>
        </SettingsGroup>
      ))}

      <p className={styles.legal}>
        <strong>{m.settings_about_legal_section()}.</strong> {m.settings_about_legal_footer()}
      </p>
    </div>
  );
}

export default AboutSettingsTab;
