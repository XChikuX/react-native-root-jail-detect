// ESLint flat config for `@psync/anti-jailbreak`.
// Uses native flat config syntax (no FlatCompat) for ESLint 10 compatibility.

import prettier from 'eslint-plugin-prettier';
import { defineConfig } from 'eslint/config';

export default defineConfig([
  {
    plugins: { prettier },
    rules: {
      'prettier/prettier': 'error',
    },
  },
  {
    ignores: ['node_modules/', 'lib/'],
  },
]);
