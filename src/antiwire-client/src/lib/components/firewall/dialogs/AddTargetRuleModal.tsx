import clsx from 'clsx';
import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import Button from '#lib/components/ui/Button.tsx';
import SettingsInput from '#lib/components/ui/SettingsInput.tsx';
import SegmentedControl from '#lib/components/ui/SegmentedControl.tsx';
import FirewallDialog from '#lib/components/firewall/dialogs/FirewallDialog.tsx';
import RuleActionPicker from '#lib/components/firewall/form/RuleActionPicker.tsx';
import RuleDirectionPicker from '#lib/components/firewall/form/RuleDirectionPicker.tsx';
import {
  networkRuleKindLabel,
  networkRulePlaceholder,
  pageRuleTypeToNetworkKind,
  type NetworkRuleKind,
  type RuleFormAction,
  type RuleFormPayload,
  type RuleFormType,
} from '#lib/components/firewall/form/rule-form.ts';
import type { RuleDirection } from '#lib/types/index.ts';
import { COUNTRY_ENTRIES, getCountryCidrs, type CountryEntry } from '#lib/models/country-cidrs.ts';
import { isValidCidr, isValidDomain, isValidIpv4 } from '#lib/utils/network-target.ts';
import { m } from '#lib/i18n/messages.ts';
import styles from './AddTargetRuleModal.module.css';

interface Props {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  initialRuleType?: RuleFormType;
  submitting?: boolean;
  onSubmit?: (payload: RuleFormPayload) => void | Promise<void>;
}

const KIND_OPTIONS: NetworkRuleKind[] = ['Domain', 'IP', 'CIDR', 'Country'];
const NO_CIDRS: string[] = [];

export function AddTargetRuleModal({
  open = false,
  onOpenChange,
  initialRuleType = 'Domain',
  submitting = false,
  onSubmit,
}: Props) {
  const [kind, setKind] = useState<NetworkRuleKind>(() =>
    pageRuleTypeToNetworkKind(initialRuleType),
  );
  const [targetValue, setTargetValue] = useState('');
  const [action, setAction] = useState<RuleFormAction>('BLOCK');
  const [direction, setDirection] = useState<RuleDirection>('OUTBOUND');
  const [countryQuery, setCountryQuery] = useState('');
  const [selectedCountry, setSelectedCountry] = useState<CountryEntry | null>(null);
  const [selectedCountryCidrs, setSelectedCountryCidrs] = useState<string[]>(NO_CIDRS);
  const [countryLoading, setCountryLoading] = useState(false);
  const [countryError, setCountryError] = useState('');
  /** Bumped whenever the selection is reset, so late CIDR loads are ignored. */
  const countrySelectGeneration = useRef(0);

  // Every opening starts from a clean form.
  const [wasOpen, setWasOpen] = useState(open);
  if (open !== wasOpen) {
    setWasOpen(open);
    if (open) {
      setKind(pageRuleTypeToNetworkKind(initialRuleType));
      setTargetValue('');
      setAction('BLOCK');
      setDirection('OUTBOUND');
      setCountryQuery('');
      setSelectedCountry(null);
      setSelectedCountryCidrs(NO_CIDRS);
      setCountryError('');
      setCountryLoading(false);
    }
  }
  useEffect(() => {
    if (open) countrySelectGeneration.current += 1;
  }, [open]);

  const title = m.firewall_add_target_title({ kind: networkRuleKindLabel(kind).toLowerCase() });

  const kindOptions = KIND_OPTIONS.map((option) => ({
    value: option,
    label: networkRuleKindLabel(option),
  }));

  const filteredCountries = useMemo(() => {
    const q = countryQuery.trim().toLowerCase();
    if (!q) return COUNTRY_ENTRIES;
    return COUNTRY_ENTRIES.filter((country) => {
      return country.code.toLowerCase().includes(q) || country.name.toLowerCase().includes(q);
    });
  }, [countryQuery]);

  const canSubmit = (() => {
    if (submitting || countryLoading) return false;
    if (kind === 'Domain') return isValidDomain(targetValue);
    if (kind === 'IP') return isValidIpv4(targetValue);
    if (kind === 'CIDR') return isValidCidr(targetValue);
    // Country CIDRs load lazily: allow submit with just a selection so the
    // submit path can (re)fetch them, e.g. retrying after a failed chunk
    // load. Stale selections are guarded by countrySelectGeneration.
    return selectedCountry !== null;
  })();

  const submitLabel = (() => {
    if (submitting) return m.firewall_add_target_submit_adding();
    // A country is one rule covering many networks, not many rules.
    if (kind === 'Country' && selectedCountryCidrs.length > 0) {
      return m.firewall_add_target_submit_block_networks({
        count: selectedCountryCidrs.length.toLocaleString(),
      });
    }
    return m.firewall_add_target_submit();
  })();

  function changeKind(value: string) {
    const next = KIND_OPTIONS.find((option) => option === value);
    if (!next || next === kind) return;
    countrySelectGeneration.current += 1;
    setKind(next);
    setTargetValue('');
    setSelectedCountry(null);
    setSelectedCountryCidrs(NO_CIDRS);
    setCountryError('');
    setCountryLoading(false);
  }

  async function selectCountry(country: CountryEntry) {
    if (submitting) return;
    const generation = ++countrySelectGeneration.current;
    setSelectedCountry(country);
    setSelectedCountryCidrs(NO_CIDRS);
    setCountryError('');
    setCountryLoading(true);
    try {
      const cidrs = await getCountryCidrs(country.code);
      if (generation !== countrySelectGeneration.current) return;
      setSelectedCountryCidrs(cidrs);
      if (cidrs.length === 0) {
        setCountryError(m.firewall_add_target_no_cidrs({ code: country.code }));
      }
    } catch {
      if (generation !== countrySelectGeneration.current) return;
      setCountryError(m.firewall_add_target_load_cidrs_failed({ code: country.code }));
    } finally {
      if (generation === countrySelectGeneration.current) {
        setCountryLoading(false);
      }
    }
  }

  async function submit() {
    if (!canSubmit) return;

    if (kind === 'Country' && selectedCountry) {
      const country = selectedCountry;
      const generationAtSubmit = countrySelectGeneration.current;
      let cidrs: string[];
      try {
        cidrs =
          selectedCountryCidrs.length > 0
            ? selectedCountryCidrs
            : await getCountryCidrs(country.code);
      } catch {
        if (generationAtSubmit !== countrySelectGeneration.current) return;
        setCountryError(m.firewall_add_target_load_cidrs_failed({ code: country.code }));
        return;
      }
      if (generationAtSubmit !== countrySelectGeneration.current) return;
      if (cidrs.length === 0) {
        setCountryError(m.firewall_add_target_no_cidrs({ code: country.code }));
        return;
      }
      await onSubmit?.({
        kind: 'country',
        countryCode: country.code,
        countryName: country.name,
        cidrs,
        action,
        direction,
      });
      return;
    }

    await onSubmit?.({
      kind: 'target',
      targetType: kind === 'Domain' ? 'DNS' : 'IP',
      targetValue: targetValue.trim(),
      action,
      direction,
    });
  }

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Enter' && canSubmit) {
      event.preventDefault();
      void submit();
    }
  }

  return (
    <FirewallDialog
      open={open}
      onOpenChange={onOpenChange}
      kicker={m.firewall_add_target_kicker()}
      title={title}
      describedBy="target-rule-dialog-desc"
      onKeyDown={handleKeyDown}
    >
      {({ close }) => (
        <div className={styles['form-shell']}>
          <p id="target-rule-dialog-desc" className={styles.body}>
            {m.firewall_add_target_body()}
          </p>

          <div className={styles['kind-picker']}>
            <SegmentedControl options={kindOptions} value={kind} onChange={changeKind} />
          </div>

          <div className={styles['form-scroll']}>
            {kind === 'Country' ? (
              <div className={styles['country-panel']}>
                <div className={styles.field}>
                  <label className={styles['field-label']} htmlFor="country-rule-search">
                    {m.firewall_add_target_country_label()}
                  </label>
                  <SettingsInput
                    id="country-rule-search"
                    placeholder={m.firewall_add_target_country_search_placeholder()}
                    value={countryQuery}
                    onValueChange={(next) => setCountryQuery(String(next ?? ''))}
                    disabled={submitting}
                  />
                </div>

                <div
                  className={styles['country-list']}
                  role="listbox"
                  aria-label={m.firewall_add_target_countries_aria()}
                >
                  {filteredCountries.length > 0 ? (
                    filteredCountries.map((country) => {
                      const selected = selectedCountry?.code === country.code;
                      return (
                        <button
                          key={country.code}
                          type="button"
                          role="option"
                          aria-selected={selected}
                          className={clsx(styles['country-item'], selected && styles.selected)}
                          disabled={submitting}
                          onClick={() => void selectCountry(country)}
                        >
                          <span className={styles['country-meta']}>
                            <span className={clsx('mono', styles['country-code'])}>
                              {country.code}
                            </span>
                            <span className={styles['country-name']}>{country.name}</span>
                          </span>
                        </button>
                      );
                    })
                  ) : (
                    <div className={styles.empty}>{m.firewall_add_target_no_country_match()}</div>
                  )}
                </div>

                {countryLoading ? (
                  <p className={styles.hint}>{m.firewall_add_target_loading_cidrs()}</p>
                ) : countryError ? (
                  <p className={clsx(styles.hint, styles.error)}>{countryError}</p>
                ) : selectedCountry && selectedCountryCidrs.length > 0 ? (
                  <p className={styles.hint}>
                    {m.firewall_add_target_cidrs_hint({
                      count: selectedCountryCidrs.length.toLocaleString(),
                      blockWord:
                        selectedCountryCidrs.length === 1
                          ? m.firewall_add_target_cidr_block_one()
                          : m.firewall_add_target_cidr_block_other(),
                      country: selectedCountry.name,
                    })}
                  </p>
                ) : null}
              </div>
            ) : (
              <div className={styles.field}>
                <label className={styles['field-label']} htmlFor="target-rule-value">
                  {kind === 'Domain'
                    ? m.firewall_add_target_field_domain()
                    : kind === 'IP'
                      ? m.firewall_add_target_field_ip()
                      : m.firewall_add_target_field_cidr()}
                </label>
                <SettingsInput
                  id="target-rule-value"
                  className="mono"
                  placeholder={networkRulePlaceholder(kind)}
                  value={targetValue}
                  onValueChange={(next) => setTargetValue(String(next ?? ''))}
                  disabled={submitting}
                />
              </div>
            )}

            <div className={styles['policy-row']}>
              <div className={styles.field}>
                <span className={styles['field-label']}>
                  {m.firewall_add_target_field_action()}
                </span>
                <RuleActionPicker value={action} disabled={submitting} onChange={setAction} />
              </div>

              <div className={styles.field}>
                <span className={styles['field-label']}>
                  {m.firewall_add_target_field_direction()}
                </span>
                <RuleDirectionPicker
                  value={direction}
                  disabled={submitting}
                  onChange={setDirection}
                />
              </div>
            </div>
          </div>

          <div className={styles.actions}>
            <Button variant="secondary" disabled={submitting} onClick={close}>
              {m.common_cancel()}
            </Button>
            <Button variant="primary" disabled={!canSubmit} onClick={() => void submit()}>
              {submitLabel}
            </Button>
          </div>
        </div>
      )}
    </FirewallDialog>
  );
}

export default AddTargetRuleModal;
