import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import ts from 'typescript-eslint';

export default ts.config(
  js.configs.recommended,
  ...ts.configs.recommended,
  {
    ignores: ['out/**', 'dist/**', 'src/lib/paraglide/**', 'node_modules/**', 'test-results/**'],
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    plugins: { 'react-hooks': reactHooks },
    languageOptions: { globals: { ...globals.browser } },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // The renderer must reach the main process only through `#lib/bridge.ts`.
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'electron',
              message: 'The renderer has no Electron access; use #lib/bridge.ts.',
            },
          ],
          patterns: ['node:*'],
        },
      ],
    },
  },
  {
    // Plain scripts served to the renderer as-is (see index.html).
    files: ['static/**/*.js'],
    languageOptions: { globals: { ...globals.browser } },
  },
  {
    files: ['electron/**/*.ts', 'shared/**/*.ts', '*.{js,ts}', 'scripts/**/*.{js,mjs,ts}'],
    languageOptions: { globals: { ...globals.node } },
  },
  {
    files: ['**/*.test.{ts,tsx}', 'tests/**/*.ts'],
    rules: { 'no-restricted-imports': 'off' },
  },
  {
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/no-unused-expressions': 'off',
    },
  },
);
