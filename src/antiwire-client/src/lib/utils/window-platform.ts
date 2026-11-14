export type WindowPlatform = 'macos' | 'windows' | 'linux';

/** The main process supplies the platform; navigator is only a browser-preview fallback. */
export function resolveWindowPlatform(target: string, host: string): WindowPlatform {
  const platform = (target || host).toLowerCase();
  if (/darwin|mac/.test(platform)) return 'macos';
  if (/win/.test(platform)) return 'windows';
  return 'linux';
}
