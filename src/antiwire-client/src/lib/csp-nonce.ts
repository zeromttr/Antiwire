/**
 * Hands the document's CSP nonce to libraries that inject `<style>` elements.
 *
 * Packaged builds refuse inline styles without the nonce the main process
 * stamps on each document (`withStyleNonce` in electron/main/app-url.ts).
 * Radix's scroll lock (react-style-singleton) reads `__webpack_nonce__` when it
 * creates its `<style>`, so the nonce is published there. Chromium hides the
 * `nonce` attribute once the page has loaded; the `nonce` property keeps it.
 */

declare global {
  var __webpack_nonce__: string | undefined;
}

export function installCspNonce(): void {
  const meta = document.querySelector<HTMLMetaElement>('meta[property="csp-nonce"]');
  const nonce = meta?.nonce || meta?.getAttribute('nonce');
  if (nonce) globalThis.__webpack_nonce__ = nonce;
}
