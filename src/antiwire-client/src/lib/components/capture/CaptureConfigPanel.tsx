// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import { RefreshCw, RotateCcw } from 'lucide-react';
import { memo, useCallback, useEffect, useMemo, type CSSProperties } from 'react';
import { Button } from '#lib/components/ui/Button.tsx';
import { ChoiceCard } from '#lib/components/ui/ChoiceCard.tsx';
import { Dropdown } from '#lib/components/ui/Dropdown.tsx';
import { SettingsInput } from '#lib/components/ui/SettingsInput.tsx';
import { ToggleRow } from '#lib/components/ui/ToggleRow.tsx';
import {
  BPF_PRESETS,
  SNAP_LENGTH_OPTIONS,
  bpfPresetLabel,
  capturePresetId,
  snapLengthDescription,
  snapLengthLabel,
} from '#lib/models/capture.ts';
import { activeApps } from '#lib/stores/active-apps.ts';
import { m } from '#lib/i18n/messages.ts';
import { shallowEqual, useSelector } from '#lib/state/reactive.ts';
import type { CaptureWorkspace } from './capture-workspace';
import {
  applicationDropdownOptions,
  deviceDropdownOptions,
  durationDropdownOptions,
  sizeDropdownOptions,
} from './view/capture-view';
import styles from './CaptureConfigPanel.module.css';

interface Props {
  cap: CaptureWorkspace;
}

export const CaptureConfigPanel = memo(function CaptureConfigPanel({ cap }: Props) {
  const s = useSelector(
    cap,
    (c) => ({
      configuration: c.configuration,
      capturing: c.capturing,
      loadingDevices: c.loadingDevices,
      devices: c.devices,
      devicesAvailable: c.devicesAvailable,
      selectedDevice: c.selectedDevice,
      limitProgress: c.limitProgress,
    }),
    shallowEqual,
  );
  const { configuration, capturing } = s;
  const appsPage = useSelector(activeApps, (a) => a.page);

  // The shared poll runs while the configuration is on screen.
  useEffect(() => activeApps.retain(), []);

  const appsAvailable = appsPage?.available !== false;
  const appOptions = useMemo(
    () =>
      applicationDropdownOptions(
        appsPage?.applications ?? [],
        { path: configuration.appPath, name: configuration.appName },
        m.capture_app_all(),
      ),
    [appsPage, configuration.appPath, configuration.appName],
  );
  const deviceOptions = useMemo(
    () => deviceDropdownOptions(s.devices, m.capture_interface_none()),
    [s.devices],
  );
  const durationOptions = useMemo(() => durationDropdownOptions(), []);
  const sizeOptions = useMemo(() => sizeDropdownOptions(), []);
  const activeDevice = s.devices.find((device) => device.name === s.selectedDevice);
  const activePreset = capturePresetId(configuration.captureFilter);

  const chooseApplication = useCallback(
    (path: string) => {
      cap.chooseApplication(path, appOptions.find((option) => option.value === path)?.label ?? '');
    },
    [cap, appOptions],
  );
  const setFilter = useCallback(
    (value: string | number | undefined) => {
      // Replaced, not mutated: the page persists the configuration when its reference changes.
      cap.session.configuration = { ...cap.configuration, captureFilter: String(value ?? '') };
    },
    [cap],
  );
  const setMaxSeconds = useCallback((value: string) => cap.setMaxSeconds(Number(value)), [cap]);
  const setMaxBytes = useCallback((value: string) => cap.setMaxBytes(Number(value)), [cap]);

  return (
    <aside className={clsx(styles.configuration, 'panel')}>
      <div className={styles['panel-heading']}>
        <h2>{m.capture_setup_title()}</h2>
        <Button
          variant="ghost"
          size="sm"
          iconOnly
          aria-label={m.capture_reset_aria()}
          title={m.capture_reset_aria()}
          onClick={cap.resetConfiguration}
          disabled={capturing}
        >
          <RotateCcw size={14} />
        </Button>
      </div>

      <div className={styles['form-section']}>
        <div className={styles['field-heading']}>
          <label htmlFor="capture-device">{m.capture_interface_label()}</label>
          <Button
            variant="ghost"
            size="sm"
            onClick={cap.loadDevices}
            disabled={s.loadingDevices || capturing}
          >
            <span className={clsx(s.loadingDevices && styles.spin)}>
              <RefreshCw size={12} />
            </span>
            {m.capture_interface_refresh()}
          </Button>
        </div>
        <Dropdown
          id="capture-device"
          options={deviceOptions}
          value={s.selectedDevice}
          disabled={!s.devicesAvailable || capturing}
          hint={m.capture_interface_hint()}
          menuTitle={m.capture_interface_menu()}
          onChange={cap.selectDevice}
        />
        {activeDevice && (
          <div className={clsx(styles['field-meta'], 'mono')}>
            <span>
              {activeDevice.loopback
                ? m.capture_interface_loopback()
                : m.capture_interface_network()}
            </span>
            <span title={activeDevice.name}>{activeDevice.addresses[0] || activeDevice.name}</span>
          </div>
        )}
      </div>

      <div className={styles['form-section']}>
        <label htmlFor="capture-app">{m.capture_app_label()}</label>
        <Dropdown
          id="capture-app"
          options={appOptions}
          value={configuration.appPath}
          disabled={capturing || (!appsAvailable && !configuration.appPath)}
          menuTitle={m.capture_app_menu()}
          onChange={chooseApplication}
        />
        <p className={styles.help}>{m.capture_app_help()}</p>
        {!appsAvailable && <p className={styles.help}>{m.capture_app_unavailable()}</p>}
      </div>

      <div className={styles['form-section']}>
        <label htmlFor="capture-filter">{m.capture_filter_label()}</label>
        <div className={styles['preset-grid']}>
          {BPF_PRESETS.map((preset) => (
            <ChoiceCard
              key={preset.id}
              className={styles.preset}
              selected={activePreset === preset.id}
              disabled={capturing}
              onClick={() => cap.choosePreset(preset.filter)}
            >
              {bpfPresetLabel(preset.id)}
            </ChoiceCard>
          ))}
        </div>
        <SettingsInput
          id="capture-filter"
          className="mono"
          placeholder={m.capture_filter_placeholder()}
          value={configuration.captureFilter}
          onValueChange={setFilter}
          disabled={capturing}
          spellCheck={false}
        />
        <p className={styles.help}>{m.capture_filter_help()}</p>
      </div>

      <div className={styles['form-section']}>
        <div className={styles['field-label']}>{m.capture_packet_detail_label()}</div>
        <div className={styles['snap-grid']}>
          {SNAP_LENGTH_OPTIONS.map((option) => (
            <ChoiceCard
              key={option}
              className={styles.snap}
              selected={configuration.snapLength === option}
              disabled={capturing}
              onClick={() => cap.chooseSnapLength(option)}
            >
              <strong>{snapLengthLabel(option)}</strong>
              <span className="mono">{snapLengthDescription(option)}</span>
            </ChoiceCard>
          ))}
        </div>
      </div>

      <div className={clsx(styles['form-section'], styles['limit-fields'])}>
        <div>
          <label htmlFor="duration-limit">{m.capture_time_limit_label()}</label>
          <Dropdown
            id="duration-limit"
            options={durationOptions}
            value={String(configuration.maxSeconds)}
            disabled={capturing}
            menuTitle={m.capture_time_limit_menu()}
            onChange={setMaxSeconds}
          />
        </div>
        <div>
          <label htmlFor="size-limit">{m.capture_size_limit_label()}</label>
          <Dropdown
            id="size-limit"
            options={sizeOptions}
            value={String(configuration.maxBytes)}
            disabled={capturing}
            menuTitle={m.capture_size_limit_menu()}
            onChange={setMaxBytes}
          />
        </div>
      </div>
      <p className={styles.help}>{m.capture_storage_help()}</p>

      <div className={styles['toggle-wrap']}>
        <ToggleRow
          label={m.capture_promiscuous_label()}
          description={m.capture_promiscuous_desc()}
          checked={configuration.promiscuous}
          disabled={capturing}
          onCheckedChange={cap.setPromiscuous}
        />
      </div>

      <div className={styles.limit}>
        <div className={styles['limit-head']}>
          <span>{m.capture_limit_label()}</span>
          <span className={styles['limit-value']}>{s.limitProgress.toFixed(0)}%</span>
        </div>
        <div
          className={styles['limit-track']}
          role="progressbar"
          aria-label={m.capture_limit_progress_aria()}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.round(s.limitProgress)}
        >
          <span style={{ '--pct': s.limitProgress / 100 } as CSSProperties}></span>
        </div>
      </div>
    </aside>
  );
});

export default CaptureConfigPanel;
