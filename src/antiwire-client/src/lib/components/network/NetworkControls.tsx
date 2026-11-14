// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import { Plus, RefreshCw, Square } from 'lucide-react';
import ChoiceCard from '#lib/components/ui/ChoiceCard.tsx';
import Button from '#lib/components/ui/Button.tsx';
import Status from '#lib/components/ui/Status.tsx';
import { m } from '#lib/i18n/messages.ts';
import { rangeHelpText } from './list/network-list';
import type { NetworkWorkspace } from './network-workspace';
import styles from './NetworkControls.module.css';

/** Writes a tracked workspace field (the former `bind:` target). */
function setField<T extends object, K extends keyof T>(target: T, key: K, value: T[K]): void {
  target[key] = value;
}

interface Props {
  /** The page re-renders on every workspace change, so this one is not memoized. */
  net: NetworkWorkspace;
}

export function NetworkControls({ net }: Props) {
  return (
    <>
      <header className={styles['scan-head']}>
        <h1>{m.nav_network()}</h1>
        <Status tone={net.isScanning ? 'ok' : 'idle'} className={net.isScanning ? styles.live : ''}>
          {net.isScanning ? m.network_status_scanning() : m.network_status_idle()}
        </Status>
        <p className={styles.copy}>{m.network_scan_controls_copy()}</p>
        <div className={styles.actions}>
          <Button variant="ghost" onClick={() => void net.clearDevices()}>
            {m.network_clear()}
          </Button>
          {net.isScanning ? (
            <Button variant="danger" onClick={() => void net.stopScan()}>
              <Square size={13} />
              {m.network_stop_scan()}
            </Button>
          ) : (
            <Button variant="primary" onClick={() => void net.startScan()}>
              <RefreshCw size={14} />
              {m.network_start_scan()}
            </Button>
          )}
        </div>
      </header>

      <section className={clsx(styles.networks, 'panel')} aria-labelledby="scan-networks-title">
        <div className={styles['networks-head']}>
          <h2 id="scan-networks-title">{m.network_networks_title()}</h2>
          <span className={styles.hint}>{m.network_ranges_hint()}</span>
        </div>
        <div className={styles['range-grid']}>
          {net.suggestedRanges.map((range) => (
            <ChoiceCard
              key={range.id}
              className={styles.range}
              selected={net.customCidr === range.cidr}
              title={m.network_range_use_title({
                cidr: range.cidr,
                interface: range.interfaceLabel,
              })}
              onClick={() => net.chooseScanRange(range.cidr)}
            >
              <span className={styles['class-tag']}>
                {range.networkClass
                  ? m.network_range_class({ class: range.networkClass })
                  : m.network_range_local()}
              </span>
              <span className={styles['range-copy']}>
                <span className={styles['range-name']}>{range.interfaceLabel}</span>
                <span className={styles['range-cidr']}>{range.cidr}</span>
              </span>
              <span className={styles['range-help']}>{rangeHelpText(range.networkClass)}</span>
            </ChoiceCard>
          ))}
          <label className={clsx(styles.custom, Boolean(net.customCidr) && styles.filled)}>
            <Plus size={14} aria-hidden="true" />
            <input
              aria-label={m.network_custom_cidr_aria()}
              placeholder={m.network_custom_cidr_placeholder()}
              value={net.customCidr}
              onChange={(event) => setField(net, 'customCidr', event.currentTarget.value)}
              spellCheck={false}
              autoComplete="off"
            />
          </label>
        </div>
        {net.message && <p className={styles.message}>{net.message}</p>}
      </section>
    </>
  );
}

export default NetworkControls;
