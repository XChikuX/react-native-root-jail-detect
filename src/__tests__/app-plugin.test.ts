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

  describe('when @expo/config-plugins is available', () => {
    it('modifies AndroidManifest queries with root management package names', () => {
      jest.isolateModules(() => {
        jest.resetModules();

        let androidModCallback: (mod: any) => any = (mod) => mod;
        let infoPlistModCallback: (mod: any) => any = (mod) => mod;

        jest.mock(
          '@expo/config-plugins',
          () => ({
            withAndroidManifest: (config: any, cb: (mod: any) => any) => {
              androidModCallback = cb;
              return config;
            },
            withInfoPlist: (config: any, cb: (mod: any) => any) => {
              infoPlistModCallback = cb;
              return config;
            },
          }),
          { virtual: true }
        );

        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const plugin = require('../../app.plugin');
        const initialConfig = {};
        plugin(initialConfig);

        // Test AndroidManifest transformation
        const mockManifestMod = {
          modResults: {
            manifest: {},
          },
        };
        const updatedManifestMod = androidModCallback(mockManifestMod);
        const queries = updatedManifestMod.modResults.manifest.queries;
        expect(queries).toBeDefined();
        expect(queries.length).toBeGreaterThan(0);

        const addedPackages = queries[0].package.map(
          (p: any) => p.$['android:name']
        );
        expect(addedPackages).toContain('com.topjohnwu.magisk');
        expect(addedPackages).toContain('me.weishu.kernelsu');
        expect(addedPackages).toContain('me.bmax.apatch');
        expect(addedPackages).toContain('org.lsposed.manager');

        // Test Info.plist transformation with defaults
        const mockInfoPlistMod = {
          modResults: {
            LSApplicationQueriesSchemes: ['existing-scheme'],
          },
        };
        const updatedInfoPlistMod = infoPlistModCallback(mockInfoPlistMod);
        const schemes =
          updatedInfoPlistMod.modResults.LSApplicationQueriesSchemes;
        expect(schemes).toContain('existing-scheme');
        expect(schemes).toContain('cydia');
        expect(schemes).toContain('sileo');
        expect(schemes).toContain('zbra');
        expect(schemes).toContain('filza');
      });
    });

    it('prevents duplicate package entries in AndroidManifest', () => {
      jest.isolateModules(() => {
        jest.resetModules();

        let androidModCallback: (mod: any) => any = (mod) => mod;

        jest.mock(
          '@expo/config-plugins',
          () => ({
            withAndroidManifest: (config: any, cb: (mod: any) => any) => {
              androidModCallback = cb;
              return config;
            },
            withInfoPlist: (config: any) => config,
          }),
          { virtual: true }
        );

        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const plugin = require('../../app.plugin');
        plugin({});

        const mockManifestMod = {
          modResults: {
            manifest: {
              queries: [
                {
                  package: [
                    { $: { 'android:name': 'com.topjohnwu.magisk' } },
                  ],
                },
              ],
            },
          },
        };
        const updatedManifestMod = androidModCallback(mockManifestMod);
        const queries = updatedManifestMod.modResults.manifest.queries;

        // Magisk was already in queries, so missing packages should exclude magisk
        const lastPackageQuery = queries[queries.length - 1];
        const addedPackages = lastPackageQuery.package.map(
          (p: any) => p.$['android:name']
        );
        expect(addedPackages).not.toContain('com.topjohnwu.magisk');
        expect(addedPackages).toContain('me.weishu.kernelsu');
      });
    });

    it('respects custom urlSchemes and caps at 50 with warning', () => {
      jest.isolateModules(() => {
        jest.resetModules();

        let infoPlistModCallback: (mod: any) => any = (mod) => mod;
        const warnSpy = jest
          .spyOn(console, 'warn')
          .mockImplementation(() => {});

        jest.mock(
          '@expo/config-plugins',
          () => ({
            withAndroidManifest: (config: any) => config,
            withInfoPlist: (config: any, cb: (mod: any) => any) => {
              infoPlistModCallback = cb;
              return config;
            },
          }),
          { virtual: true }
        );

        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const plugin = require('../../app.plugin');

        // Generate 55 custom schemes
        const customSchemes = Array.from(
          { length: 55 },
          (_, i) => `scheme${i}`
        );
        plugin({}, { urlSchemes: customSchemes });

        const mockInfoPlistMod = {
          modResults: {
            LSApplicationQueriesSchemes: [],
          },
        };
        const updatedInfoPlistMod = infoPlistModCallback(mockInfoPlistMod);
        const schemes =
          updatedInfoPlistMod.modResults.LSApplicationQueriesSchemes;

        expect(schemes.length).toBe(50);
        expect(warnSpy).toHaveBeenCalledWith(
          expect.stringContaining(
            'LSApplicationQueriesSchemes would exceed the iOS 15+ 50-entry cap'
          )
        );

        warnSpy.mockRestore();
      });
    });
  });
});
