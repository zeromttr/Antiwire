import { lazy, Suspense, type ComponentType } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router';
import { AppShell, InspectorShell } from './shell/AppShell.tsx';

/**
 * Routes. Every page is its own chunk: the dashboard is the default route, so
 * nothing else should cost first paint.
 */
const page = (load: () => Promise<{ default: ComponentType }>) => {
  const Page = lazy(load);
  return (
    <Suspense fallback={null}>
      <Page />
    </Suspense>
  );
};

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/inspector" element={<InspectorShell />}>
          <Route index element={page(() => import('./routes/InspectorPage.tsx'))} />
        </Route>
        <Route element={<AppShell />}>
          <Route index element={page(() => import('./routes/DashboardPage.tsx'))} />
          <Route path="ai" element={page(() => import('./routes/AiPage.tsx'))} />
          <Route path="alerts" element={page(() => import('./routes/AlertsPage.tsx'))} />
          <Route path="analytics" element={page(() => import('./routes/AnalyticsPage.tsx'))} />
          <Route path="capture" element={page(() => import('./routes/CapturePage.tsx'))} />
          <Route path="firewall" element={page(() => import('./routes/FirewallPage.tsx'))} />
          <Route path="network" element={page(() => import('./routes/NetworkPage.tsx'))} />
          <Route path="records" element={page(() => import('./routes/RecordsPage.tsx'))} />
          <Route path="settings" element={page(() => import('./routes/SettingsPage.tsx'))} />
          <Route path="hosts" element={<Navigate to="/analytics" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
