import clsx from 'clsx';
import { Plus } from 'lucide-react';
import { useState } from 'react';
import { Button } from '#lib/components/ui/Button.tsx';
import { StatCell } from '#lib/components/ui/StatCell.tsx';
import { Status } from '#lib/components/ui/Status.tsx';
import { Toggle } from '#lib/components/ui/Toggle.tsx';
import { m } from '#lib/i18n/messages.ts';
import styles from './AppearancePreview.module.css';

// A fixed, pleasant-looking series: this is a swatch, not live data.
const BARS = [3, 4, 3, 5, 6, 5, 7, 6, 8, 7, 9, 8, 10, 9, 11, 10, 12, 11, 13, 12, 14, 12, 15, 16];

export function AppearancePreview() {
  const [demoToggle, setDemoToggle] = useState(true);
  return (
    <div className={styles.previewBlock}>
      <div>
        <div className={styles.label}>{m.settings_appearance_preview()}</div>
      </div>
      <div className={clsx(styles.preview, 'panel')} aria-hidden="true" inert>
        <div className={styles.stat}>
          <StatCell
            label={m.dashboard_stat_download()}
            value="2.48"
            unit="MB/s"
            color="var(--acc)"
            bars={BARS}
          />
        </div>
        <div className={styles.controls}>
          <div className={styles.row}>
            <Button variant="primary" size="sm">
              <Plus size={14} />
              {m.firewall_add_rule()}
            </Button>
            <Button variant="secondary" size="sm">
              {m.alerts_dismiss()}
            </Button>
            <span className={styles.status}>
              <Status tone="ok">{m.firewall_action_allow()}</Status>
            </span>
          </div>
          <div className={styles.row}>
            <Toggle checked={demoToggle} onCheckedChange={setDemoToggle} />
            <span className={styles.toggleLabel}>{m.settings_new_application_alerts_label()}</span>
          </div>
          <div className={styles.focusDemo}>
            <span className={styles.caret}></span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default AppearancePreview;
