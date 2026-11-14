import clsx from 'clsx';
import Button from '#lib/components/ui/Button.tsx';
import FirewallDialog from '#lib/components/firewall/dialogs/FirewallDialog.tsx';
import { ruleDirectionLabel } from '#lib/components/firewall/form/rule-form.ts';
import type { CountryRule, Rule } from '#lib/types/index.ts';
import { m } from '#lib/i18n/messages.ts';
import { displayText } from '#lib/utils/index.ts';
import styles from './RemoveRuleDialog.module.css';

interface Props {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  rule?: Rule | null;
  countryRule?: CountryRule | null;
  countryDisplay?: string;
  submitting?: boolean;
  onConfirm?: () => void | Promise<void>;
  onCancel?: () => void;
}

export function RemoveRuleDialog({
  open = false,
  onOpenChange,
  rule = null,
  countryRule = null,
  countryDisplay = '',
  submitting = false,
  onConfirm,
  onCancel,
}: Props) {
  const isCountry = countryRule !== null;
  const canConfirm = Boolean(rule || countryRule);

  const actionLabel = ((isCountry ? countryRule?.action : rule?.action) ?? '').toUpperCase();
  const isBlock = actionLabel.includes('BLOCK');

  const dialogKicker = isCountry
    ? m.firewall_remove_country_kicker()
    : m.firewall_remove_rule_kicker();
  const dialogTitle = isCountry
    ? m.firewall_remove_country_title()
    : m.firewall_remove_rule_title();
  const confirmLabel = submitting
    ? m.firewall_remove_removing()
    : isCountry
      ? m.firewall_remove_confirm_country()
      : m.firewall_remove_confirm_rule();

  const direction = isCountry ? countryRule?.direction : rule?.direction;
  const directionLabel = direction ? ruleDirectionLabel(direction) : m.common_em_dash();

  const actionCell = (
    <dd className={clsx(isBlock && styles.bad, !isBlock && styles.ok)}>
      {actionLabel || m.common_em_dash()}
    </dd>
  );

  return (
    <FirewallDialog
      open={open}
      onOpenChange={onOpenChange}
      kicker={dialogKicker}
      title={dialogTitle}
      describedBy="remove-rule-dialog-desc"
    >
      {({ close }) => (
        <>
          {isCountry && countryRule ? (
            <>
              <p id="remove-rule-dialog-desc" className={styles.body}>
                {m.firewall_remove_country_body({
                  label: countryDisplay || countryRule.countryCode,
                })}{' '}
                {countryRule.cidrCount > 0
                  ? m.firewall_remove_country_networks_affected({
                      count: countryRule.cidrCount.toLocaleString(),
                    })
                  : m.firewall_remove_country_matching_affected()}
              </p>

              <dl className={clsx(styles.details, 'mono')}>
                <div className={styles['detail-row']}>
                  <dt>{m.firewall_remove_detail_country()}</dt>
                  <dd>{countryDisplay || countryRule.countryCode}</dd>
                </div>
                <div className={styles['detail-row']}>
                  <dt>{m.firewall_remove_detail_action()}</dt>
                  {actionCell}
                </div>
                <div className={styles['detail-row']}>
                  <dt>{m.firewall_remove_detail_direction()}</dt>
                  <dd>{directionLabel}</dd>
                </div>
                <div className={styles['detail-row']}>
                  <dt>{m.firewall_remove_detail_networks()}</dt>
                  <dd>{countryRule.cidrCount.toLocaleString()}</dd>
                </div>
              </dl>
            </>
          ) : rule ? (
            <>
              <p id="remove-rule-dialog-desc" className={styles.body}>
                {m.firewall_remove_rule_body({ target: displayText(rule.targetValue) })}
              </p>

              <dl className={clsx(styles.details, 'mono')}>
                <div className={styles['detail-row']}>
                  <dt>{m.firewall_remove_detail_target()}</dt>
                  <dd>{displayText(rule.targetValue)}</dd>
                </div>
                <div className={styles['detail-row']}>
                  <dt>{m.firewall_remove_detail_action()}</dt>
                  {actionCell}
                </div>
                <div className={styles['detail-row']}>
                  <dt>{m.firewall_remove_detail_type()}</dt>
                  <dd>{rule.targetType}</dd>
                </div>
                <div className={styles['detail-row']}>
                  <dt>{m.firewall_remove_detail_direction()}</dt>
                  <dd>{directionLabel}</dd>
                </div>
              </dl>
            </>
          ) : null}

          <div className={styles.actions}>
            <Button
              variant="secondary"
              disabled={submitting}
              onClick={() => {
                close();
                onCancel?.();
              }}
            >
              {m.common_cancel()}
            </Button>
            <Button
              variant="destructive"
              disabled={submitting || !canConfirm}
              onClick={() => void onConfirm?.()}
            >
              {confirmLabel}
            </Button>
          </div>
        </>
      )}
    </FirewallDialog>
  );
}

export default RemoveRuleDialog;
