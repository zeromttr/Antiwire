import clsx from 'clsx';
import { AppWindow, ArrowDown, ArrowUp, Ban, Check, Copy, Globe, Network, X } from 'lucide-react';
import { useEffect, useState, type KeyboardEvent } from 'react';
import Button from '#lib/components/ui/Button.tsx';
import Status from '#lib/components/ui/Status.tsx';
import AppAvatar from '#lib/components/ui/AppAvatar.tsx';
import { api } from '#lib/api/daemon.ts';
import { canMutateFirewallRule } from '#lib/components/firewall/rules/app-toggle.ts';
import { getLocale } from '#lib/paraglide/runtime.js';
import { m } from '#lib/i18n/messages.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { recordProtocolColorVar } from '#lib/models/protocol-colors.ts';
import { recordProtocolLabel } from '#lib/models/well-known-ports.ts';
import type { ConnectionLog } from '#lib/types/index.ts';
import { copyText } from '#lib/utils/clipboard.ts';
import { displayText, formatBytes, formatDateTime } from '#lib/utils/index.ts';
import {
  recordBlockedByText,
  recordConnectionStatus,
  recordCountryLabel,
  recordDetailTitle,
  recordExecutableName,
  recordStateTone,
} from './detail/record-detail';
import { recordActionLabel } from './list/records-list';
import RecordDnsRecords from './RecordDnsRecords';
import RecordDomainLookup from './RecordDomainLookup';
import RecordSubdomains from './RecordSubdomains';
import {
  canTargetRecordRule,
  findRecordRule,
  isBlockingRule,
  planRecordRuleToggle,
  recordRuleTarget,
  type RecordRuleKind,
} from './rules/record-rules';
import styles from './RecordInspector.module.css';

interface Props {
  record: ConnectionLog;
  onclose: () => void;
  onmutated?: () => void;
}

const RULE_KINDS: RecordRuleKind[] = ['application', 'domain', 'ip'];
const KIND_ICONS = { application: AppWindow, domain: Globe, ip: Network };
/** How long the copy button shows its tick. */
const COPIED_MS = 1400;

function display(value: string | number): string {
  if (typeof value === 'number') return String(value);
  return displayText(value.trim()) || m.common_em_dash();
}

function kindName(kind: RecordRuleKind): string {
  if (kind === 'application') return m.records_detail_kind_application();
  if (kind === 'domain') return m.records_detail_kind_domain();
  return m.records_detail_kind_ip();
}

export function RecordInspector({ record, onclose, onmutated }: Props) {
  const [inFlight, setInFlight] = useState<RecordRuleKind | null>(null);
  const [copied, setCopied] = useState(false);
  const rules = useSelector(daemon, (d) => d.state.rules);
  const connected = useSelector(daemon, (d) => d.state.connected);
  const applicationRules = useSelector(daemon, (d) => d.state.applicationRulesSupported);

  const tone = recordStateTone(record.action);
  const statusTone = tone === 'blocked' ? 'bad' : tone === 'listen' ? 'warn' : 'ok';
  const country = recordCountryLabel(record.countryCode, getLocale());
  const protoLabel = recordProtocolLabel(record.protocol, record.port);
  // The transport under a named protocol, e.g. TCP under HTTPS.
  const transport = record.protocol.trim().toUpperCase();
  const connectionStatus = recordConnectionStatus(record);
  const connectionText =
    connectionStatus === 'closed'
      ? m.records_detail_connection_closed()
      : connectionStatus === 'active'
        ? m.records_detail_connection_open()
        : '';
  const blockedBy = tone === 'blocked' ? recordBlockedByText(record) : '';
  const exeName = recordExecutableName(record);
  const title = recordDetailTitle(record);

  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), COPIED_MS);
    return () => clearTimeout(timer);
  }, [copied]);

  function kindLabel(kind: RecordRuleKind, blocked: boolean): string {
    if (inFlight === kind) return m.records_detail_updating();
    if (kind === 'application') {
      return blocked
        ? m.records_detail_unblock_application()
        : m.records_detail_block_application();
    }
    if (kind === 'domain') {
      return blocked ? m.records_detail_unblock_domain() : m.records_detail_block_domain();
    }
    return blocked ? m.records_detail_unblock_ip() : m.records_detail_block_ip();
  }

  /**
   * One button per rule target; a blocked target's button unblocks it. The application has
   * none where the daemon cannot enforce a rule on one.
   */
  const blockOptions = RULE_KINDS.filter((kind) => applicationRules || kind !== 'application').map(
    (kind) => {
      const blocked = isBlockingRule(findRecordRule(kind, record, rules));
      const action = kindLabel(kind, blocked);
      return {
        kind,
        label: kindName(kind),
        icon: blocked ? Ban : KIND_ICONS[kind],
        blocked,
        enabled: canTargetRecordRule(kind, record) && canMutateFirewallRule(connected, inFlight),
        action,
        ariaLabel: m.records_detail_action_aria({
          action,
          target: displayText(recordRuleTarget(kind, record) || m.common_em_dash()),
        }),
      };
    },
  );

  async function toggleKind(kind: RecordRuleKind) {
    if (!canMutateFirewallRule(connected, inFlight)) return;
    const plan = planRecordRuleToggle(kind, record, rules);
    if (!plan) return;

    setInFlight(kind);
    try {
      if (plan.op === 'add') {
        const ok = await api.addRule(
          plan.targetType,
          plan.targetValue,
          plan.action,
          plan.direction,
        );
        if (!ok) throw new Error('daemon rejected rule');
        daemon.addToast(m.records_detail_toast_blocked_title(), plan.targetValue, 'var(--bad)');
      } else {
        await api.removeRule(
          plan.rule.id,
          plan.rule.targetType,
          plan.rule.targetValue,
          plan.rule.action,
        );
        daemon.addToast(
          m.records_detail_toast_unblocked_title(),
          plan.rule.targetValue,
          'var(--ok)',
        );
      }
      await daemon.refreshAll();
      onmutated?.();
    } catch (error) {
      daemon.addToast(
        m.records_detail_toast_failed_title(),
        error instanceof Error ? error.message : String(error),
        'var(--bad)',
      );
    } finally {
      setInFlight(null);
    }
  }

  async function copyTitle() {
    if (await copyText(title)) setCopied(true);
  }

  function onKeydown(event: KeyboardEvent<HTMLElement>) {
    if (event.key === 'Escape') onclose();
  }

  return (
    <aside
      className={styles.inspector}
      aria-labelledby="record-inspector-title"
      onKeyDown={onKeydown}
    >
      <header className={styles.band}>
        <Status tone={statusTone}>{recordActionLabel(record.action)}</Status>
        <span className={styles.bandNote}>{displayText(blockedBy) || connectionText}</span>
        <Button
          className={styles.close}
          variant="ghost"
          size="sm"
          iconOnly
          aria-label={m.common_close_aria()}
          title={m.common_close_aria()}
          onClick={onclose}
        >
          <X size={14} strokeWidth={2} />
        </Button>
      </header>

      <div className={styles.body}>
        <div className={styles.intro}>
          {/* The whole name, wrapped: the band above is too short to hold it. */}
          <div className={styles.titleRow}>
            <h2 className={styles.title} id="record-inspector-title">
              {displayText(title) || m.records_detail_title_fallback()}
            </h2>
            {title && (
              <Button
                variant="ghost"
                size="sm"
                iconOnly
                aria-label={m.common_copy_aria({ label: m.records_col_remote_host() })}
                title={m.common_copy_aria({ label: m.records_col_remote_host() })}
                onClick={() => void copyTitle()}
              >
                {copied ? (
                  <Check size={13} strokeWidth={2.4} />
                ) : (
                  <Copy size={13} strokeWidth={2} />
                )}
              </Button>
            )}
          </div>
          <div className={styles.app}>
            <AppAvatar name={record.applicationName} path={record.applicationPath} size={20} />
            <span className={styles.appName}>{displayText(record.applicationName)}</span>
            {exeName && exeName !== record.applicationName && (
              <>
                <span className={styles.sep} aria-hidden="true">
                  ·
                </span>
                <span className={styles.exe}>{displayText(exeName)}</span>
              </>
            )}
          </div>
        </div>

        <div className={styles.traffic}>
          <div className={styles.tile}>
            <span className={clsx(styles.tileLabel, styles.up)}>
              <ArrowUp size={11} strokeWidth={2.6} aria-hidden="true" />
              {m.records_detail_field_sent()}
            </span>
            <span className={clsx('mono', styles.tileValue)}>
              {record.bytesSent ? formatBytes(record.bytesSent) : m.common_em_dash()}
            </span>
          </div>
          <div className={styles.tile}>
            <span className={clsx(styles.tileLabel, styles.down)}>
              <ArrowDown size={11} strokeWidth={2.6} aria-hidden="true" />
              {m.records_detail_field_received()}
            </span>
            <span className={clsx('mono', styles.tileValue)}>
              {record.bytesReceived ? formatBytes(record.bytesReceived) : m.common_em_dash()}
            </span>
          </div>
        </div>

        <dl className={styles.facts}>
          <div>
            <dt>{m.records_detail_field_destination()}</dt>
            <dd className={styles.endpoint}>
              <span className="mono">{display(record.destinationIp)}</span>
              {record.port > 0 && (
                <span className={clsx('mono', styles.port)}>
                  <span className={styles.portLabel}>{m.records_col_port()}</span>
                  {record.port}
                </span>
              )}
            </dd>
          </div>
          <div>
            <dt>{m.records_detail_field_source()}</dt>
            <dd className={styles.endpoint}>
              <span className="mono">{display(record.sourceIp)}</span>
              {record.sourcePort > 0 && (
                <span className={clsx('mono', styles.port, styles.source)}>
                  <span className={styles.portLabel}>{m.records_col_port()}</span>
                  {record.sourcePort}
                </span>
              )}
            </dd>
          </div>
          <div>
            <dt>{m.records_detail_field_protocol()}</dt>
            {/* The colour the records table gives this protocol. */}
            <dd className={styles.proto} style={{ color: recordProtocolColorVar(protoLabel) }}>
              {display(protoLabel)}
              {transport && transport !== protoLabel.trim().toUpperCase() && (
                <>
                  <span className={styles.protoSep} aria-hidden="true"></span>
                  {transport}
                </>
              )}
            </dd>
          </div>
          <div>
            <dt>{m.records_detail_field_country()}</dt>
            <dd>{country || m.common_em_dash()}</dd>
          </div>
          <div>
            <dt>{m.records_detail_field_first_seen()}</dt>
            <dd>{formatDateTime(record.timestamp) || m.common_em_dash()}</dd>
          </div>
          <div>
            <dt>{m.records_detail_field_last_seen()}</dt>
            <dd>{formatDateTime(record.lastSeen) || m.common_em_dash()}</dd>
          </div>
          <div className={styles.wide}>
            <dt>{m.records_detail_field_path()}</dt>
            <dd className={clsx('mono', styles.path)}>{display(record.applicationPath)}</dd>
          </div>
        </dl>

        <RecordDomainLookup domain={record.domain} connected={connected} />
        <RecordDnsRecords
          domain={record.domain}
          address={record.destinationIp}
          connected={connected}
        />
        <RecordSubdomains domain={record.domain} connected={connected} />
      </div>

      <div className={styles.actions} role="group" aria-label={m.records_detail_actions_label()}>
        <span className={styles.actionsLabel}>
          {inFlight ? m.records_detail_updating() : m.records_detail_block_menu()}
        </span>
        <div className={styles.kinds}>
          {blockOptions.map((option) => {
            const Icon = option.icon;
            return (
              <Button
                key={option.kind}
                variant={option.blocked ? 'danger' : 'secondary'}
                size="sm"
                aria-pressed={option.blocked}
                aria-label={option.ariaLabel}
                title={option.action}
                disabled={!option.enabled}
                onClick={() => void toggleKind(option.kind)}
              >
                <Icon size={13} strokeWidth={2} />
                {option.label}
              </Button>
            );
          })}
        </div>
      </div>
    </aside>
  );
}

export default RecordInspector;
