// Reads a mutable workspace while rendering, so React Compiler must not
// cache it (see src/lib/state/compiler-opt-out.test.ts).
'use no memo';

import clsx from 'clsx';
import {
  BarChart3,
  Bell,
  Database,
  LayoutDashboard,
  Network,
  Radio,
  Settings,
  Shield,
  Sparkles,
  type LucideIcon,
} from 'lucide-react';
import { useLayoutEffect, useRef, useState, type MouseEvent } from 'react';
import { useLocation } from 'react-router';
import { m } from '#lib/i18n/messages.ts';
import { navigate } from '#lib/navigation.ts';
import { useReactive, useSelector } from '#lib/state/reactive.ts';
import { alertReads } from '#lib/stores/alert-reads.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { NAV_ITEMS, type NavRoute } from '#lib/types/index.ts';
import styles from './TopNav.module.css';

const ICONS: Record<NavRoute, LucideIcon> = {
  dashboard: LayoutDashboard,
  records: Database,
  firewall: Shield,
  analytics: BarChart3,
  alerts: Bell,
  ai: Sparkles,
  capture: Radio,
  network: Network,
  settings: Settings,
};

const NAV_LABELS: Record<NavRoute, () => string> = {
  dashboard: () => m.nav_dashboard(),
  records: () => m.nav_records(),
  firewall: () => m.nav_firewall(),
  analytics: () => m.nav_analytics(),
  alerts: () => m.nav_alerts(),
  ai: () => m.nav_ai(),
  capture: () => m.nav_capture(),
  network: () => m.nav_network(),
  settings: () => m.nav_settings(),
};

function alertBadgeLabel(count: number): string {
  return count > 9 ? m.nav_alerts_badge_overflow() : String(count);
}

/** Plain left clicks route in-app (with the page transition); modified clicks keep link behaviour. */
function onNavClick(event: MouseEvent<HTMLAnchorElement>, href: string) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
    return;
  }
  event.preventDefault();
  if (window.location.pathname === href && !window.location.search) return;
  navigate(href);
}

export function TopNav() {
  const { pathname } = useLocation();
  const notifications = useSelector(daemon, (d) => d.state.notifications);
  useReactive(alertReads);
  // Unread warnings and threats: reading them on the Alerts page clears the badge.
  const alertCount = notifications.filter(
    (alert) => (alert.severity === 'bad' || alert.severity === 'warn') && !alertReads.has(alert.id),
  ).length;

  const navElement = useRef<HTMLElement | null>(null);
  const [indicator, setIndicator] = useState({ left: 0, width: 0 });
  // The underline appears in place on first paint and only glides afterwards.
  const [settled, setSettled] = useState(false);

  const items = NAV_ITEMS.map((item) => ({
    ...item,
    label: NAV_LABELS[item.id](),
    active: pathname === item.href,
    Icon: ICONS[item.id],
  }));
  const labelsKey = items.map((item) => item.label).join('\u0000');

  useLayoutEffect(() => {
    // Re-measure for route changes, localization, and compact navigation.
    const nav = navElement.current;
    if (!nav) return;
    let settleFrame = 0;
    const update = () => {
      const active = nav.querySelector<HTMLElement>('[aria-current="page"]');
      if (!active) return;
      const next = { left: active.offsetLeft, width: active.offsetWidth };
      setIndicator((prev) => (prev.left === next.left && prev.width === next.width ? prev : next));
      if (!settleFrame) settleFrame = requestAnimationFrame(() => setSettled(true));
    };
    const observer = new ResizeObserver(update);
    observer.observe(nav);
    const frame = requestAnimationFrame(update);
    return () => {
      observer.disconnect();
      cancelAnimationFrame(frame);
      cancelAnimationFrame(settleFrame);
    };
  }, [pathname, labelsKey, alertCount]);

  return (
    <nav className={styles.topnav} ref={navElement} aria-label={m.nav_main_aria()}>
      <span
        className={clsx(styles.selection, settled && styles.settled)}
        aria-hidden="true"
        style={{ width: `${indicator.width}px`, transform: `translateX(${indicator.left}px)` }}
      ></span>
      {items.map((item) => (
        <a
          key={item.id}
          className={clsx(styles.navItem, item.active && styles.active)}
          href={item.href}
          aria-current={item.active ? 'page' : undefined}
          aria-label={
            item.id === 'alerts' && alertCount > 0
              ? item.label + ', ' + m.nav_alerts_badge_aria({ count: alertCount })
              : item.label
          }
          data-testid={`nav-${item.id}`}
          onClick={(event) => onNavClick(event, item.href)}
        >
          <item.Icon className="nav-icon" size={16} strokeWidth={1.6} />
          <span className={styles.label}>{item.label}</span>
          {item.id === 'alerts' && alertCount > 0 && (
            <span className={styles.alertBadge} aria-hidden="true">
              {alertBadgeLabel(alertCount)}
            </span>
          )}
        </a>
      ))}
    </nav>
  );
}

export default TopNav;
