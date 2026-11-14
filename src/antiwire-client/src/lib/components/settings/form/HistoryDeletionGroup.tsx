import clsx from 'clsx';
import { Trash2 } from 'lucide-react';
import { useState } from 'react';
import { DeleteHistoryDialog } from '#lib/components/settings/dialogs/DeleteHistoryDialog.tsx';
import { Button } from '#lib/components/ui/Button.tsx';
import { Dropdown } from '#lib/components/ui/Dropdown.tsx';
import { SettingsInput } from '#lib/components/ui/SettingsInput.tsx';
import { m } from '#lib/i18n/messages.ts';
import { getLocale } from '#lib/paraglide/runtime.js';
import { daemon } from '#lib/stores/daemon.ts';
import {
  HISTORY_DELETION_UNITS,
  historyDeletionStart,
  historyDeletionUnitLabel,
  isValidHistoryDeletionAmount,
  MAX_HISTORY_DELETION_AMOUNT,
  type HistoryDeletionRange,
  type HistoryDeletionUnit,
} from '#lib/utils/history-deletion.ts';
import { SettingsGroup } from './SettingsGroup.tsx';
import styles from './HistoryDeletionGroup.module.css';

export function HistoryDeletionGroup() {
  const [amount, setAmount] = useState(1);
  const [unit, setUnit] = useState<HistoryDeletionUnit>('hours');
  const [dialogOpen, setDialogOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [range, setRange] = useState<HistoryDeletionRange>({ all: true });

  const amountValid = isValidHistoryDeletionAmount(amount);
  const unitOptions = HISTORY_DELETION_UNITS.map((value) => ({
    value,
    label: historyDeletionUnitLabel(value, amountValid ? amount : 2, getLocale()),
  }));

  /** Fixes the range when the dialog opens, so it shows exactly what will go. */
  function confirmDeletion(next: HistoryDeletionRange) {
    setRange(next);
    setDialogOpen(true);
  }

  async function deleteHistory() {
    if (deleting) return;
    setDeleting(true);
    try {
      const deleted = await daemon.deleteHistory(range);
      setDialogOpen(false);
      daemon.addToast(
        m.settings_delete_history_done_title(),
        m.settings_delete_history_done_body({ count: deleted }),
        'var(--ok)',
      );
    } catch (error) {
      daemon.addToast(
        m.settings_delete_history_failed_title(),
        error instanceof Error ? error.message : String(error),
        'var(--bad)',
      );
    } finally {
      setDeleting(false);
    }
  }

  return (
    <>
      <SettingsGroup
        title={m.settings_group_delete_history_title()}
        description={m.settings_group_delete_history_desc()}
      >
        <div className={clsx(styles.row, !amountValid && styles.invalid)}>
          <div className={styles.text}>
            <div className={styles.label}>{m.settings_delete_recent_label()}</div>
            <div className={styles.desc}>{m.settings_delete_recent_desc()}</div>
            {!amountValid && (
              <p id="delete-history-amount-error" className={styles.error} role="alert">
                {m.settings_delete_history_amount_invalid({ max: MAX_HISTORY_DELETION_AMOUNT })}
              </p>
            )}
          </div>
          <div className={styles.controls}>
            <span className={styles.amount}>
              <SettingsInput
                id="delete-history-amount"
                type="number"
                min={1}
                max={MAX_HISTORY_DELETION_AMOUNT}
                value={amount}
                invalid={!amountValid}
                aria-invalid={!amountValid}
                aria-describedby={amountValid ? undefined : 'delete-history-amount-error'}
                aria-label={m.settings_delete_recent_amount_label()}
                onInput={(event) => setAmount(Number(event.currentTarget.value))}
              />
            </span>
            <span className={styles.unit}>
              <Dropdown
                id="delete-history-unit"
                options={unitOptions}
                value={unit}
                menuTitle={m.settings_delete_recent_unit_label()}
                onChange={(value) => setUnit(value as HistoryDeletionUnit)}
              />
            </span>
            <Button
              variant="danger"
              size="sm"
              disabled={!amountValid || deleting}
              onClick={() =>
                confirmDeletion({ all: false, since: historyDeletionStart(amount, unit) })
              }
            >
              <Trash2 size={14} />
              {m.settings_delete_recent_button()}
            </Button>
          </div>
        </div>
        <div className={styles.row}>
          <div className={styles.text}>
            <div className={styles.label}>{m.settings_delete_all_label()}</div>
            <div className={styles.desc}>{m.settings_delete_all_desc()}</div>
          </div>
          <div className={styles.controls}>
            <Button
              variant="danger"
              size="sm"
              disabled={deleting}
              onClick={() => confirmDeletion({ all: true })}
            >
              <Trash2 size={14} />
              {m.settings_delete_all_button()}
            </Button>
          </div>
        </div>
      </SettingsGroup>

      <DeleteHistoryDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        range={range}
        submitting={deleting}
        onconfirm={deleteHistory}
      />
    </>
  );
}

export default HistoryDeletionGroup;
