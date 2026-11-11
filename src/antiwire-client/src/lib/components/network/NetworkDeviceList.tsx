// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import { Bell } from 'lucide-react';
import { memo, useCallback } from 'react';
import Status from '#lib/components/ui/Status.tsx';
import AppAvatar from '#lib/components/ui/AppAvatar.tsx';
import Button from '#lib/components/ui/Button.tsx';
import Tooltip from '#lib/components/ui/Tooltip.tsx';
import VirtualScrollList from '#lib/components/ui/VirtualScrollList.tsx';
import EmptyState from '#lib/components/ui/EmptyState.tsx';
import {
  formatWatchInterval,
  matchingDeviceWatch,
  type DeviceWatch,
  type NetworkDeviceRow,
} from '#lib/models/network-watch.ts';
import { m } from '#lib/i18n/messages.ts';
import { DEVICE_ROW_HEIGHT, networkDeviceKey } from './list/network-list';
import type { NetworkWorkspace } from './network-workspace';
import styles from './NetworkDeviceList.module.css';

interface Props {
  /** The page re-renders on every workspace change, so this one is not memoized. */
  net: NetworkWorkspace;
}

const DeviceRow = memo(function DeviceRow({
  dev,
  watch,
  lastSeenLabel,
  lastSeenTitle,
  onOpenRemoveWatch,
  onOpenWatchSettings,
}: {
  dev: NetworkDeviceRow;
  watch: DeviceWatch | null | undefined;
  lastSeenLabel: string;
  lastSeenTitle: string;
  onOpenRemoveWatch: (dev: NetworkDeviceRow, watch: DeviceWatch) => void;
  onOpenWatchSettings: (dev: NetworkDeviceRow) => void;
}) {
  const label = dev.mdnsName || m.network_unnamed_device();
  return (
    <div className={clsx(styles.row, styles['device-grid'], watch && styles.watched)}>
      <div className={styles.identity}>
        <AppAvatar name={dev.mdnsName || dev.manufacturer || dev.ipAddress} size={30} />
        <div className={styles['identity-copy']}>
          <Tooltip text={dev.mdnsName} label={m.network_tooltip_mdns()}>
            <span className={clsx(styles.name, !dev.mdnsName && styles.unnamed)}>{label}</span>
          </Tooltip>
          <Tooltip text={dev.manufacturer} label={m.network_tooltip_vendor()}>
            <span className={styles.vendor}>{dev.manufacturer || m.network_vendor_unknown()}</span>
          </Tooltip>
        </div>
      </div>
      <Tooltip text={dev.ipAddress} label={m.network_tooltip_ip()}>
        <span className={clsx('mono', styles.ip)}>{dev.ipAddress}</span>
      </Tooltip>
      <Tooltip text={dev.macAddress} label={m.network_tooltip_mac()}>
        <span className={clsx('mono', styles.mac)}>{dev.macAddress}</span>
      </Tooltip>
      <span>
        <Status tone={dev.isPresent ? 'ok' : 'idle'}>
          {dev.isPresent ? m.network_status_present() : m.network_status_away()}
        </Status>
      </span>
      <time className={styles['last-seen']} dateTime={dev.lastSeen} title={lastSeenTitle}>
        {lastSeenLabel}
      </time>
      <span className={styles.action}>
        <Button
          variant={watch ? 'secondary' : 'ghost'}
          size="sm"
          aria-label={
            watch
              ? m.network_unwatch_aria({ device: dev.mdnsName || dev.ipAddress })
              : m.network_watch_aria({ device: dev.mdnsName || dev.ipAddress })
          }
          onClick={() => (watch ? onOpenRemoveWatch(dev, watch) : onOpenWatchSettings(dev))}
        >
          {watch ? (
            <>
              <Bell size={13} />
              {m.network_watched_badge({
                interval: formatWatchInterval(watch.intervalMinutes, true),
              })}
            </>
          ) : (
            m.network_watch()
          )}
        </Button>
      </span>
    </div>
  );
});

export function NetworkDeviceList({ net }: Props) {
  const { deviceWatches, lastSeenLabel, lastSeenTitle, openRemoveWatch, openWatchSettings } = net;

  const deviceRow = useCallback(
    ({ item }: { item: NetworkDeviceRow }) => (
      <DeviceRow
        dev={item}
        watch={matchingDeviceWatch(deviceWatches, item)}
        lastSeenLabel={lastSeenLabel(item.lastSeen)}
        lastSeenTitle={lastSeenTitle(item.lastSeen)}
        onOpenRemoveWatch={openRemoveWatch}
        onOpenWatchSettings={openWatchSettings}
      />
    ),
    [deviceWatches, lastSeenLabel, lastSeenTitle, openRemoveWatch, openWatchSettings],
  );

  return (
    <section className={clsx(styles.devices, 'panel')} aria-labelledby="scan-devices-title">
      <div className={styles['devices-head']}>
        <h2 id="scan-devices-title">{m.network_discovered_title()}</h2>
        <span className={styles.counts}>
          {net.deviceCountText}
          {net.deviceWatches.length > 0 &&
            ` · ${m.network_watched_count({ count: net.deviceWatches.length })}`}
        </span>
      </div>
      <div className={clsx(styles.thead, styles['device-grid'])}>
        {net.colDefs.map((col, index) => (
          <ColumnHeader
            key={col.key}
            label={col.label}
            active={net.activeSortKey === col.key}
            arrow={net.activeSortKey === col.key ? (net.activeSortDir === 1 ? '↑' : '↓') : ''}
            onClick={() => net.toggleSort(col.key)}
            withMacAfter={index === 1}
          />
        ))}
        <span aria-hidden="true"></span>
      </div>
      <div className={styles.tbody}>
        <VirtualScrollList
          items={net.sortedDevices}
          estimateSize={DEVICE_ROW_HEIGHT}
          getItemKey={networkDeviceKey}
          row={deviceRow}
          empty={<EmptyState text={m.network_empty_no_devices()} compact />}
        />
      </div>
    </section>
  );
}

function ColumnHeader({
  label,
  active,
  arrow,
  onClick,
  withMacAfter,
}: {
  label: string;
  active: boolean;
  arrow: string;
  onClick: () => void;
  withMacAfter: boolean;
}) {
  return (
    <>
      <button type="button" className={clsx(styles.th, active && styles.active)} onClick={onClick}>
        {label}
        <span className={styles.arrow} aria-hidden="true">
          {arrow}
        </span>
      </button>
      {withMacAfter && (
        <span className={clsx(styles.th, styles.static)}>{m.network_col_mac()}</span>
      )}
    </>
  );
}

export default NetworkDeviceList;
