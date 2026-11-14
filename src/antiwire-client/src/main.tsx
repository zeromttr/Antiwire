import './app.css';
import './lib/page-motion.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { isNative } from '#lib/bridge.ts';
import { installCspNonce } from '#lib/csp-nonce.ts';
import { loadMessages } from '#lib/i18n/messages.ts';
import { App } from './App.tsx';

installCspNonce();

// The operating system draws the edge of a native window itself (shared/window-frame.ts);
// only the browser preview rounds its own corners.
if (isNative()) {
  document.documentElement.dataset.windowFrame = 'native';
}

// The first locale chunk loads before the first render so no string flashes in English.
void loadMessages()
  .catch((error) => console.error('[antiwire] failed to load messages', error))
  .finally(() => {
    createRoot(document.getElementById('root')!).render(
      <StrictMode>
        <App />
      </StrictMode>,
    );
  });

window.addEventListener('unhandledrejection', (event) => {
  console.error('[antiwire] unhandled rejection', event.reason);
});
