export type PreviewMode = 'sample' | 'offline' | null;

export function resolvePreviewMode(
  dev: boolean,
  browser: boolean,
  native: boolean,
  search: string,
): PreviewMode {
  if (!dev || !browser || native) return null;
  return new URLSearchParams(search).get('preview') === 'offline' ? 'offline' : 'sample';
}
