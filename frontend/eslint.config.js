import js from '@eslint/js';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {ignores:['dist','playwright-report','test-results']},
  js.configs.recommended,
  ...tseslint.configs.recommended,
  reactHooks.configs.flat['recommended-latest'],
  {rules:{
    '@typescript-eslint/no-explicit-any':'error',
    // API-loading effects intentionally reset local state before asynchronous fetches.
    'react-hooks/set-state-in-effect':'off',
  }}
);
