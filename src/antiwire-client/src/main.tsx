import './app.css';
import './lib/page-motion.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { usesNativeWindowFrame } from '#shared/window-frame';
import { hostPlatform, isNative } from '#lib/bridge.ts';
import { installCspNonce } from '#lib/csp-nonce.ts';
import { loadMessages } from '#lib/i18n/messages.ts';
import { App } from './App.tsx';

installCspNonce();

// The operating system rounds and shadows a native frame itself (shared/window-frame.ts).
if (isNative() && usesNativeWindowFrame(hostPlatform())) {
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
