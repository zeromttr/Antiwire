import { memo, useMemo, type CSSProperties } from 'react';
import { m } from '#lib/i18n/messages.ts';
import { getLocale } from '#lib/paraglide/runtime.js';
import type { AnalyticsCountryShare } from '#lib/utils/analytics-aggregates.ts';
import styles from './DestinationCountries.module.css';

interface Props {
  countryCounts: Record<string, number>;
  unknownCount: number;
  totalCount: number;
  unknownPct: number;
  /** Every known country across retained connection history, ranked by count. */
  countries?: AnalyticsCountryShare[];
}

const NO_COUNTRIES: AnalyticsCountryShare[] = [];

export const DestinationCountries = memo(function DestinationCountries({
  countryCounts,
  unknownCount,
  totalCount,
  unknownPct,
  countries = NO_COUNTRIES,
}: Props) {
  const locale = getLocale();
  const regionNames = useMemo(
    () =>
      typeof Intl.DisplayNames === 'function'
        ? new Intl.DisplayNames([locale], { type: 'region' })
        : null,
    [locale],
  );
  const shareFormatter = useMemo(
    () => new Intl.NumberFormat(locale, { style: 'percent', maximumFractionDigits: 2 }),
    [locale],
  );

  /** Bars scale against the busiest country so small spreads stay readable. */
  const topShare = countries.reduce((max, country) => Math.max(max, country.share), 0) || 1;

  function countryShare(share: number): string {
    return share > 0 && share < 0.01
      ? '<' + shareFormatter.format(0.0001)
      : shareFormatter.format(share / 100);
  }

  function countryName(code: string): string {
    try {
      return regionNames?.of(code) ?? code;
    } catch {
      return code;
    }
  }

  const knownCount = totalCount - unknownCount;
  const countryCount = Object.keys(countryCounts).length;
  const geoMissing = totalCount > 0 && knownCount === 0;

  return (
    <div className={styles.countriesCard}>
      <div className={styles.head}>
        <h2>{m.analytics_region_title()}</h2>
        <span className={styles.dim}>
          {m.analytics_region_meta({ known: knownCount, countries: countryCount })}
        </span>
      </div>

      {geoMissing && <p className={styles.geoHint}>{m.analytics_geo_missing_hint()}</p>}

      {countries.length > 0 && (
        <ol className={styles.countries}>
          {countries.map((country) => (
            <li key={country.code}>
              <span className={styles.code}>{country.code}</span>
              <span className={styles.name}>{countryName(country.code)}</span>
              <span className={styles.bar}>
                <span style={{ '--pct': country.share / topShare } as CSSProperties}></span>
              </span>
              <span className={styles.share}>{countryShare(country.share)}</span>
            </li>
          ))}
        </ol>
      )}

      <div className={styles.unknownRow}>
        <div className={styles.unknownLabel}>
          <span>{m.analytics_unknown_label()}</span>
          <span className={styles.dim}>
            {m.analytics_unknown_meta({ count: unknownCount, pct: unknownPct })}
          </span>
        </div>
        <div className={styles.unknownBar}>
          <div
            className={styles.unknownFill}
            style={{ '--pct': unknownPct / 100 } as CSSProperties}
          ></div>
        </div>
      </div>
    </div>
  );
});

export default DestinationCountries;
