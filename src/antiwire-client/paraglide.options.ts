/**
 * Paraglide compiler options, shared by the Vite plugin (vite.shared.ts) and
 * `bun run paraglide` (scripts/paraglide.ts) so both write the same output.
 *
 * No .d.ts files: generating them took about 25 of 33 seconds per compile. TypeScript
 * reads the message types from the generated JSDoc instead (`allowJs` in
 * tsconfig.web.json), so a wrong key or parameter is still a type error.
 */
export const PARAGLIDE_OPTIONS = {
  project: './project.inlang',
  outdir: './src/lib/paraglide',
  emitTsDeclarations: false,
  outputStructure: 'locale-modules',
  strategy: ['localStorage', 'preferredLanguage', 'baseLocale'],
} as const;
