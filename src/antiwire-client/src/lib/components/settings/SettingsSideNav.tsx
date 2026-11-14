import clsx from 'clsx';
import {
  Bell,
  Database,
  Info,
  Radar,
  RefreshCw,
  Satellite,
  Settings,
  ShieldCheck,
  Sparkles,
  type LucideIcon,
} from 'lucide-react';
import { Fragment, memo } from 'react';
import { m } from '#lib/i18n/messages.ts';
import type { SettingsSection } from './form/settings-form';
import styles from './SettingsSideNav.module.css';

interface NavItem {
  id: SettingsSection;
  label: () => string;
  icon: LucideIcon;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'General', label: m.settings_appearance_title, icon: Settings },
  { id: 'Notifications', label: m.settings_notifications_title, icon: Bell },
  { id: 'Activity', label: m.settings_activity_title, icon: Database },
  { id: 'DNS', label: m.settings_nav_dns, icon: ShieldCheck },
  { id: 'AI', label: m.settings_nav_ai, icon: Sparkles },
  { id: 'Network Mapping', label: m.settings_nav_network_mapping, icon: Radar },
  { id: 'Event Forwarding', label: m.settings_nav_event_forwarding, icon: Satellite },
  { id: 'Updates', label: m.settings_nav_updates, icon: RefreshCw },
  { id: 'About', label: m.settings_nav_about, icon: Info },
];

interface Props {
  section: SettingsSection;
  onselect: (section: SettingsSection) => void;
}

export const SettingsSideNav = memo(function SettingsSideNav({ section, onselect }: Props) {
  return (
    <nav className={styles.subnav} aria-label={m.settings_sections_aria()}>
      {NAV_ITEMS.map((item) => {
        const Icon = item.icon;
        const active = section === item.id;
        return (
          <Fragment key={item.id}>
            {(item.id === 'General' || item.id === 'DNS') && (
              <div className={styles.groupLabel}>
                {item.id === 'General' ? m.settings_local_group() : m.settings_security_group()}
              </div>
            )}
            <button
              type="button"
              className={clsx(styles.subnavItem, active && styles.active)}
              aria-current={active ? 'page' : undefined}
              onClick={() => onselect(item.id)}
            >
              <span className={styles.iconWrap}>
                <Icon size={16} strokeWidth={1.75} />
              </span>
              <span className={styles.label}>{item.label()}</span>
            </button>
          </Fragment>
        );
      })}
    </nav>
  );
});

export default SettingsSideNav;
