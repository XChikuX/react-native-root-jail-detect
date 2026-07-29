// Smoke test for the Expo config plugin entry.
//
// `app.plugin.js` is loaded exclusively by `expo prebuild`. The package must
// still be installable and requireable in a bare React Native project that has
// never installed `@expo/config-plugins`. This test pins that contract so a
// future refactor that hoists `require('@expo/config-plugins')` back to the
// top of the file (or otherwise introduces a top-level side effect on a
// bare-RN consumer) fails CI instead of silently breaking bare projects.
//
// Two assertions:
//   1. `require('../app.plugin')` must not throw even when
//      `@expo/config-plugins` is completely absent from the resolver.
//   2. Calling the exported function without `@expo/config-plugins` must
//      throw a clear module-not-found error so the failure is debuggable in
//      Expo prebuild (rather than, say, a vague "Cannot read property of
//      undefined").
//
// We use `{ virtual: true }` to tell Jest the module is not on disk; this
// is the supported way to simulate "the consumer never installed this
// package" without touching the host's dependency tree.

import { describe, expect, it, jest } from '@jest/globals';

describe('app.plugin.js', () => {
  it('does not require @expo/config-plugins at module load', () => {
    jest.isolateModules(() => {
      jest.resetModules();
      jest.mock(
        '@expo/config-plugins',
        () => {
          throw new Error("Cannot find module '@expo/config-plugins'");
        },
        { virtual: true }
      );

      // Top-level load: must succeed because the inner require lives inside
      // the exported function, not at module scope.
      expect(() => {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        require('../../app.plugin');
      }).not.toThrow();
    });
  });

  it('throws a clear error when invoked without @expo/config-plugins', () => {
    jest.isolateModules(() => {
      jest.resetModules();
      jest.mock(
        '@expo/config-plugins',
        () => {
          throw new Error("Cannot find module '@expo/config-plugins'");
        },
        { virtual: true }
      );

      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const plugin = require('../../app.plugin') as (config: unknown) => unknown;
      expect(() => plugin({})).toThrow(/@expo\/config-plugins/);
    });
  });
});
