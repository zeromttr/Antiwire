/**
 * Router-agnostic navigation for code outside React components (stores,
 * workspaces, the preview runtime). The app shell installs the router's own
 * navigate function on mount; before that, a full-document navigation is the
 * fallback.
 */
export interface NavigateOptions {
  replace?: boolean;
}

type Navigator = (to: string, options?: NavigateOptions) => void;

let navigator: Navigator | null = null;

export function setNavigator(next: Navigator | null): void {
  navigator = next;
}

export function navigate(to: string, options?: NavigateOptions): void {
  if (navigator) {
    navigator(to, options);
    return;
  }
  if (typeof window === 'undefined') return;
  if (options?.replace) window.location.replace(to);
  else window.location.assign(to);
}
