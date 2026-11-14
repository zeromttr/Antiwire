import {
  Component,
  lazy,
  Suspense,
  type ReactNode,
  useEffect,
  useLayoutEffect,
  useState,
  type ComponentType,
} from 'react';
import { Outlet, useNavigate } from 'react-router';
import { api } from '#lib/api/daemon.ts';
import { invoke, isNative, listen } from '#lib/bridge.ts';
import { StatusBar } from '#lib/components/shell/StatusBar.tsx';
import { TitleBar } from '#lib/components/shell/TitleBar.tsx';
import { ToastHost } from '#lib/components/shell/ToastHost.tsx';
import { TopNav } from '#lib/components/shell/TopNav.tsx';
import { ErrorBoundary } from '#lib/components/ui/ErrorBoundary.tsx';
import { ErrorFallback } from '#lib/components/ui/ErrorFallback.tsx';
import { m } from '#lib/i18n/messages.ts';
import {
  applyThemeSnapshot,
  persistThemeSnapshot,
  readPersistedThemeSnapshot,
} from '#lib/models/theme-snapshot.ts';
import { setNavigator } from '#lib/navigation.ts';
import { PreviewNotice } from '#lib/preview/PreviewNotice.tsx';
import { browserPreviewMode } from '#lib/preview/runtime.ts';
import { useSelector } from '#lib/state/reactive.ts';
import { client } from '#lib/stores/client.ts';
import { daemon } from '#lib/stores/daemon.ts';
import { windowActivity } from '#lib/stores/window-activity.ts';
import type { NotificationEvent } from '#lib/types/index.ts';
import { debugError, debugLog, isDebugEnabled } from '#lib/utils/debug.ts';
import { buildDebugBridge, publishDebugBridge } from '#lib/utils/debug-bridge.ts';
import { KeepAliveOutlet } from './KeepAliveOutlet.tsx';
import { supportsViewTransitions, withViewTransition } from './view-transition.ts';
import styles from './AppShell.module.css';

if (supportsViewTransitions) document.documentElement.classList.add('has-view-transitions');

interface OnboardingModalProps {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  preferRecommendedDefaults?: boolean;
  onComplete?: () => void | Promise<void>;
}

// Lazy: onboarding shows once (first run / re-open from StatusBar) but pulls
// AlertDialog and its icons into the shell chunk paid by every route.
const OnboardingModal = lazy(
  () =>
    import('#lib/components/shell/OnboardingModal.tsx') as Promise<{
      default: ComponentType<OnboardingModalProps>;
    }>,
);

/** Theme boot shared by both windows; must not block the shell. */
function bootTheme() {
  try {
    applyThemeSnapshot(
      (window as Window & { __antiwireTheme?: unknown }).__antiwireTheme ??
        readPersistedThemeSnapshot(),
    );
  } catch {
    /* Theme boot must not block the shell. */
  }
}

/** Blocks the browser context menu everywhere, and image/link dragging outside the inspector. */
function useChromeGuards(allowDrag: boolean) {
  useEffect(() => {
    const blockContextMenu = (event: Event) => event.preventDefault();
    const blockDragStart = (event: Event) => {
      if (allowDrag) return;
      event.preventDefault();
    };
    document.addEventListener('contextmenu', blockContextMenu, true);
    document.addEventListener('dragstart', blockDragStart, true);
    return () => {
      document.removeEventListener('contextmenu', blockContextMenu, true);
      document.removeEventListener('dragstart', blockDragStart, true);
    };
  }, [allowDrag]);
}

/** Installs react-router's navigate (with page transitions) for code outside React. */
function useInstalledNavigator(animated: boolean) {
  const routerNavigate = useNavigate();
  useLayoutEffect(() => {
    const plain = (to: string, options?: { replace?: boolean }) =>
      void routerNavigate(to, { replace: options?.replace });
    setNavigator(animated ? withViewTransition(plain) : plain);
    return () => setNavigator(null);
  }, [routerNavigate, animated]);
}

/**
 * Last-resort boundary around the whole shell: replacing the old route error page,
 * which had to bring its own styles because the root layout may have failed.
 */
class FatalBoundary extends ErrorBoundary {
  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className={styles.kitError}>
        <ErrorFallback
          variant="fatal"
          error={this.state.error}
          reset={this.reset}
          showHome
          showReload
        />
      </div>
    );
  }
}

/** The main window: title bar with tabs, the routed page, status bar, toasts, onboarding. */
export function AppShell() {
  const [showOnboarding, setShowOnboarding] = useState(false);
  const onboardingDone = useSelector(client, (c) => c.state.onboardingDone);

  useInstalledNavigator(true);
  useChromeGuards(false);

  useEffect(() => {
    bootTheme();
  }, []);

  // Background mode: an unfocused window pauses decorative motion and slows live data.
  useEffect(() => windowActivity.start(), []);

  useEffect(() => {
    if (!isNative()) return;
    const syncVisibility = () => daemon.setWindowVisible(document.visibilityState === 'visible');
    document.addEventListener('visibilitychange', syncVisibility);
    syncVisibility();
    const stopVisibility = listen('window://visibility', (visible) => {
      daemon.setWindowVisible(Boolean(visible));
    });
    return () => {
      document.removeEventListener('visibilitychange', syncVisibility);
      stopVisibility();
    };
  }, []);

  useEffect(() => {
    if (!isNative()) return;
    return listen('daemon-notification', (raw) => {
      const payload = raw as NotificationEvent;
      daemon.addNotification(payload);
      daemon.addToast(
        payload.title,
        payload.body,
        payload.severity === 'warn' || payload.severity === 'bad' ? 'var(--warn)' : 'var(--ok)',
      );
    });
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        await client.init();
      } catch (e) {
        console.error('[antiwire] client settings failed to load', e);
      }
      if (cancelled) return;
      void daemon.connect();
      if (!client.state.onboardingDone && !browserPreviewMode) {
        setShowOnboarding(true);
      }

      const debugWindow = window as Window & { __antiwireDebug?: Record<string, unknown> };
      // The full bridge (redacted daemon counts + openDevtools) is only
      // published in dev builds or when debug mode is enabled. Otherwise only
      // the enable/disable toggles exist, so page scripts cannot harvest
      // daemon telemetry or open devtools in production.
      publishDebugBridge(
        debugWindow as unknown as Record<string, unknown>,
        buildDebugBridge(
          // Read lazily so every `daemon()` call reports current store state
          // instead of the mount-time values.
          () => ({
            connected: daemon.state.connected,
            connecting: daemon.state.connecting,
            error: daemon.state.error,
            rulesCount: daemon.state.rules.length,
            countryRulesCount: daemon.state.countryRules.length,
            notificationsCount: daemon.state.notifications.length,
            toastsCount: daemon.state.toasts.length,
            socketCount: daemon.state.socketCount,
          }),
          { openDevtools: () => invoke<void>('open_devtools') },
          { dev: import.meta.env.DEV, debugEnabled: isDebugEnabled() },
        ),
      );

      if (isDebugEnabled()) {
        debugLog('app', 'debug mode active — helpers on window.__antiwireDebug');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function completeOnboarding() {
    if (!client.state.onboardingDone) {
      await client.completeOnboarding();
    }
  }

  return (
    <FatalBoundary>
      <div className={styles.appShell}>
        <TitleBar nav={<TopNav />} />
        <PreviewNotice />
        <main className={styles.main}>
          {/* Keeps visited tabs mounted while hidden; each has its own error boundary. */}
          <KeepAliveOutlet />
        </main>
        <StatusBar onShowSetup={() => queueMicrotask(() => setShowOnboarding(true))} />
        <ToastHost />
        {showOnboarding && (
          <OnboardingErrorGuard onFail={() => setShowOnboarding(false)}>
            <Suspense fallback={null}>
              <OnboardingModal
                open={showOnboarding}
                onOpenChange={setShowOnboarding}
                preferRecommendedDefaults={!onboardingDone}
                onComplete={completeOnboarding}
              />
            </Suspense>
          </OnboardingErrorGuard>
        )}
      </div>
    </FatalBoundary>
  );
}

/**
 * The onboarding chunk failed to load (or render): close it so a later open
 * retries instead of leaving the shell stuck on a modal that can never render.
 */
class OnboardingErrorGuard extends Component<
  { onFail: () => void; children?: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(error: unknown) {
    debugError('app', 'onboarding-load-failed', error);
    this.props.onFail();
  }

  render() {
    return this.state.failed ? null : this.props.children;
  }
}

/** The packet inspector window: its own title bar, no tabs, status bar or daemon connection. */
export function InspectorShell() {
  useInstalledNavigator(false);
  useChromeGuards(true);

  useEffect(() => {
    bootTheme();
    if (!isNative()) return;
    const applyInspectedTheme = (value: unknown) => {
      persistThemeSnapshot(applyThemeSnapshot(value));
    };
    void api
      .getPacketInspectorTheme()
      .then(applyInspectedTheme)
      .catch(() => {});
    return listen('packet-inspector://theme', applyInspectedTheme);
  }, []);

  // Background mode applies to the inspector too.
  useEffect(() => windowActivity.start(), []);

  return (
    <FatalBoundary>
      <div className={styles.appShell}>
        <TitleBar label={m.inspector_header()} maximizable={false} />
        <PreviewNotice />
        <main className={styles.main}>
          <ErrorBoundary kind="inspector">
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </FatalBoundary>
  );
}
