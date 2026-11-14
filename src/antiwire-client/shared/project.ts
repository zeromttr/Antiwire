/**
 * Facts about the project that the main process and the renderer share.
 *
 * The repository comes from `[workspace.package] repository` in src/antiwire-rs/Cargo.toml,
 * the one place it is named; the build defines it (vite.shared.ts). Moving the project means
 * changing that line only.
 */

declare const __ANTIWIRE_REPOSITORY__: string | undefined;

/**
 * `https://github.com/{owner}/{name}`. Empty where nothing defined it (unit tests), so a
 * link built from it is left out rather than pointing somewhere wrong.
 */
export const REPOSITORY_URL: string =
  typeof __ANTIWIRE_REPOSITORY__ === 'string' ? __ANTIWIRE_REPOSITORY__ : '';

/** The GitHub release page of `version`, or empty when the repository is unknown. */
export function releaseUrl(version: string, repository: string = REPOSITORY_URL): string {
  if (!repository || !version) return '';
  return `${repository}/releases/tag/v${encodeURIComponent(version)}`;
}
