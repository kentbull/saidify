import tsEslintPlugin from '@typescript-eslint/eslint-plugin'
import tsEslintParser from '@typescript-eslint/parser'
import tsdoc from 'eslint-plugin-tsdoc'
// @ts-expect-error
import onlyWarn from 'eslint-plugin-only-warn'

export default [
  {
    files: ['**/*.ts'],
    ignores: ['build/**/*', 'eslint.config.js', 'vitest.config.ts'],
    plugins: { tsdoc: tsdoc, 'only-warn': onlyWarn, '@typescript-eslint': tsEslintPlugin },
    rules: {
      // '@typescript-eslint/consistent-type-imports': 'warn',
      // Note you must disable the base rule as it can report incorrect errors.
      'quotes': 'off',
      // '@typescript-eslint/quotes': ['warn', 'double'],
      'tsdoc/syntax': 'warn',
      // TODO enable this rule once https://github.com/gund/eslint-plugin-deprecation/issues/78
      // TypeScript makes these safe & effective
      'no-case-declarations': 'off',
      // Same approach used by TypeScript noUnusedLocals
      '@typescript-eslint/no-unused-vars': ['warn', { varsIgnorePattern: '^_', argsIgnorePattern: '^_' }],
      // Needed when working with .mts/.cts where a lone e.g. <T> is not allowed
      '@typescript-eslint/no-unnecessary-type-constraint': 'off',
      // Useful for organizing Types
      '@typescript-eslint/no-namespace': 'off',
      // Turn training wheels off. When we want these we want these.
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/ban-ts-comment': ['warn', { 'ts-expect-error': false }],
    },
    languageOptions: {
      parser: tsEslintParser,
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
]
