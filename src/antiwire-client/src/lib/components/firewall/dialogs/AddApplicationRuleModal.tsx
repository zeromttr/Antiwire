import clsx from 'clsx';
import { FolderOpen } from 'lucide-react';
import { useMemo, useState, type KeyboardEvent } from 'react';
import Button from '#lib/components/ui/Button.tsx';
import SettingsInput from '#lib/components/ui/SettingsInput.tsx';
import AppAvatar from '#lib/components/ui/AppAvatar.tsx';
import FirewallDialog from '#lib/components/firewall/dialogs/FirewallDialog.tsx';
import RuleActionPicker from '#lib/components/firewall/form/RuleActionPicker.tsx';
import RuleDirectionPicker from '#lib/components/firewall/form/RuleDirectionPicker.tsx';
import type { RuleFormAction, RuleFormPayload } from '#lib/components/firewall/form/rule-form.ts';
import type { RuleDirection } from '#lib/types/index.ts';
import { isNative } from '#lib/bridge.ts';
import { pickExecutable } from '#lib/utils/file-dialog.ts';
import { displayText } from '#lib/utils/index.ts';
import { formatErrorMessage } from '#lib/utils/error.ts';
import { m } from '#lib/i18n/messages.ts';
import styles from './AddApplicationRuleModal.module.css';

type AppOption = {
  name: string;
  path: string;
};

interface Props {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  applications?: AppOption[];
  /** Apps already shown on the Applications tab, hidden from the picker list. */
  excludedKeys?: ReadonlySet<string>;
  submitting?: boolean;
  onSubmit?: (payload: RuleFormPayload) => void | Promise<void>;
  onError?: (message: string, error: unknown) => void;
}

const NO_APPS: AppOption[] = [];
const NO_KEYS: ReadonlySet<string> = new Set<string>();

function appKey(app: AppOption) {
  return `${app.name}::${app.path}`;
}

export function AddApplicationRuleModal({
  open = false,
  onOpenChange,
  applications = NO_APPS,
  excludedKeys = NO_KEYS,
  submitting = false,
  onSubmit,
  onError,
}: Props) {
  const [query, setQuery] = useState('');
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [executablePath, setExecutablePath] = useState('');
  const [action, setAction] = useState<RuleFormAction>('BLOCK');
  const [direction, setDirection] = useState<RuleDirection>('OUTBOUND');
  const [browsing, setBrowsing] = useState(false);
  const [browseError, setBrowseError] = useState('');
  const [submitError, setSubmitError] = useState('');

  // Every opening starts from a clean form.
  const [wasOpen, setWasOpen] = useState(open);
  if (open !== wasOpen) {
    setWasOpen(open);
    if (open) {
      setQuery('');
      setSelectedKey(null);
      setExecutablePath('');
      setAction('BLOCK');
      setDirection('OUTBOUND');
      setBrowsing(false);
      setBrowseError('');
      setSubmitError('');
    }
  }

  const pickerApps = useMemo(
    () =>
      applications
        .filter((app) => !excludedKeys.has(appKey(app)))
        .sort((a, b) => a.name.localeCompare(b.name)),
    [applications, excludedKeys],
  );

  const filteredApps = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return pickerApps;
    return pickerApps.filter((app) => {
      const name = app.name.toLowerCase();
      const path = app.path.toLowerCase();
      return name.includes(q) || path.includes(q);
    });
  }, [pickerApps, query]);

  const targetValue = executablePath.trim();
  const canSubmit = targetValue.length > 0 && !submitting && !browsing;
  const canBrowse = isNative() && !submitting && !browsing;

  function reportError(message: string, error: unknown) {
    try {
      onError?.(message, error);
    } catch {
      // Error reporting must never break the dialog.
    }
  }

  function selectApp(app: AppOption) {
    setSelectedKey(appKey(app));
    setExecutablePath(app.path || app.name);
  }

  async function browseExecutable() {
    if (!canBrowse) return;
    setBrowsing(true);
    setBrowseError('');
    try {
      const path = await pickExecutable(executablePath || undefined);
      if (!path) return;
      setSelectedKey(null);
      setExecutablePath(path);
    } catch (error) {
      const message = formatErrorMessage(error);
      setBrowseError(message);
      reportError(message, error);
    } finally {
      setBrowsing(false);
    }
  }

  async function submit() {
    if (!canSubmit) return;
    setSubmitError('');
    try {
      await onSubmit?.({
        kind: 'target',
        targetType: 'APPLICATION',
        targetValue,
        action,
        direction,
      });
    } catch (error) {
      const message = formatErrorMessage(error);
      setSubmitError(message);
      reportError(message, error);
    }
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
      kicker={m.firewall_add_app_kicker()}
      title={m.firewall_add_app_title()}
      describedBy="app-rule-dialog-desc"
      onKeyDown={handleKeyDown}
    >
      {({ close }) => (
        <>
          <p id="app-rule-dialog-desc" className={styles.body}>
            {m.firewall_add_app_body()}
          </p>

          <div className={styles.field}>
            <label className={styles['field-label']} htmlFor="app-rule-path">
              {m.firewall_add_app_executable_label()}
            </label>
            <div className={styles['path-row']}>
              <SettingsInput
                id="app-rule-path"
                className={clsx('mono', styles['path-input'])}
                placeholder={m.firewall_add_app_path_placeholder()}
                value={executablePath}
                onValueChange={(next) => setExecutablePath(String(next ?? ''))}
                disabled={submitting || browsing}
                onInput={() => setSelectedKey(null)}
              />
              <Button
                variant="secondary"
                disabled={!canBrowse}
                title={
                  canBrowse
                    ? m.firewall_add_app_browse_title()
                    : m.firewall_add_app_browse_unavailable_title()
                }
                onClick={() => void browseExecutable()}
              >
                <FolderOpen size={14} strokeWidth={2} />
                {browsing ? m.firewall_add_app_opening() : m.firewall_add_app_browse()}
              </Button>
            </div>
            {browseError && (
              <p className={styles.error} role="alert">
                {browseError}
              </p>
            )}
          </div>

          {pickerApps.length > 0 ? (
            <>
              <div className={styles.field}>
                <label className={styles['field-label']} htmlFor="app-rule-search">
                  {m.firewall_add_app_other_label()}
                </label>
                <SettingsInput
                  id="app-rule-search"
                  placeholder={m.firewall_add_app_search_placeholder()}
                  value={query}
                  onValueChange={(next) => setQuery(String(next ?? ''))}
                  disabled={submitting}
                />
              </div>

              <div
                className={styles['app-list']}
                role="listbox"
                aria-label={m.firewall_add_app_other_aria()}
              >
                {filteredApps.length > 0 ? (
                  filteredApps.map((app) => {
                    const key = appKey(app);
                    const selected = selectedKey === key;
                    return (
                      <button
                        key={key}
                        type="button"
                        role="option"
                        aria-selected={selected}
                        className={clsx(styles['app-item'], selected && styles.selected)}
                        disabled={submitting}
                        onClick={() => selectApp(app)}
                      >
                        <span className={styles['app-avatar-wrap']}>
                          <AppAvatar name={app.name} path={app.path} size={28} />
                        </span>
                        <span className={styles['app-meta']}>
                          <span className={styles['app-name']}>{displayText(app.name)}</span>
                          {app.path && (
                            <span className={clsx('mono', styles['app-path'])}>
                              {displayText(app.path)}
                            </span>
                          )}
                        </span>
                      </button>
                    );
                  })
                ) : (
                  <div className={styles.empty}>{m.firewall_add_app_no_match()}</div>
                )}
              </div>
            </>
          ) : (
            <p className={styles.hint}>{m.firewall_add_app_already_listed_hint()}</p>
          )}

          <div className={styles['policy-row']}>
            <div className={styles.field}>
              <span className={styles['field-label']}>{m.firewall_add_target_field_action()}</span>
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

          <div className={styles.actions}>
            {submitError && (
              <p className={styles.error} role="alert">
                {submitError}
              </p>
            )}
            <Button variant="secondary" disabled={submitting} onClick={close}>
              {m.common_cancel()}
            </Button>
            <Button variant="primary" disabled={!canSubmit} onClick={() => void submit()}>
              {submitting ? m.firewall_add_app_adding() : m.firewall_add_app_submit()}
            </Button>
          </div>
        </>
      )}
    </FirewallDialog>
  );
}

export default AddApplicationRuleModal;
