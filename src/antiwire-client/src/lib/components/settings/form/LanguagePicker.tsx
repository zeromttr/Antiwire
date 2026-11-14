import clsx from 'clsx';
import { Dropdown } from '#lib/components/ui/Dropdown.tsx';
import { m } from '#lib/i18n/messages.ts';
import { SUPPORTED_LOCALES, type AppLocale } from '#lib/models/locales.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { client } from '#lib/stores/client.ts';
import { daemon } from '#lib/stores/daemon.ts';
import styles from './LanguagePicker.module.css';

interface Props {
  /** Drop the settings-row border for use inside onboarding / panels. */
  embedded?: boolean;
  /** Settings > Appearance styling: a flat section with a bolder label. */
  appearance?: boolean;
  id?: string;
}

const LOCALE_LABELS: Record<AppLocale, () => string> = {
  bg: () => m.locale_bg(),
  cs: () => m.locale_cs(),
  da: () => m.locale_da(),
  de: () => m.locale_de(),
  el: () => m.locale_el(),
  en: () => m.locale_en(),
  es: () => m.locale_es(),
  et: () => m.locale_et(),
  fi: () => m.locale_fi(),
  fr: () => m.locale_fr(),
  hr: () => m.locale_hr(),
  hu: () => m.locale_hu(),
  it: () => m.locale_it(),
  lt: () => m.locale_lt(),
  lv: () => m.locale_lv(),
  nb: () => m.locale_nb(),
  nl: () => m.locale_nl(),
  pl: () => m.locale_pl(),
  pt: () => m.locale_pt(),
  ro: () => m.locale_ro(),
  sk: () => m.locale_sk(),
  sl: () => m.locale_sl(),
  sv: () => m.locale_sv(),
  uk: () => m.locale_uk(),
};

async function onchange(value: string) {
  if (value === client.state.locale) return;
  await client.setAppLocale(value);
}

function reportLocaleError(message: string) {
  daemon.addToast(m.settings_toast_save_failed_title(), message, 'var(--bad)');
}

export function LanguagePicker({
  embedded = false,
  appearance = false,
  id = 'settings-language',
}: Props) {
  const locale = useSelector(client, (c) => c.state.locale);
  const options = SUPPORTED_LOCALES.map((value) => ({
    value,
    label: LOCALE_LABELS[value](),
  }));
  return (
    <div
      className={clsx(
        styles.languagePicker,
        embedded && styles.embedded,
        appearance && styles.appearance,
      )}
    >
      <div>
        <div className={styles.label}>{m.settings_language_label()}</div>
        <div className={styles.desc}>{m.settings_language_desc()}</div>
      </div>
      <Dropdown
        options={options}
        value={locale}
        onChange={onchange}
        onError={reportLocaleError}
        hint={m.common_select_ellipsis()}
        menuTitle={m.settings_language_menu()}
        id={id}
      />
    </div>
  );
}

export default LanguagePicker;
