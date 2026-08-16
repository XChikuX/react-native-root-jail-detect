// Consistency test for the Android package-visibility contract.
//
// On Android 11+ (API 30+), `PackageManager.getPackageInfo()` only sees
// packages declared in the app's merged `<queries>` manifest (or via other
// visibility grants). The Kotlin probe (`HybridPackageManagerProbe`) queries a
// fixed list of package ids, and that list must stay in sync with:
//   1. the library manifest `android/src/main/AndroidManifest.xml` (merged
//      into bare-RN apps by the Gradle manifest merger), and
//   2. the Expo config plugin `app.plugin.js` (writes `<queries>` into the
//      prebuilt app manifest for Expo apps).
//
// A package queried by the probe but missing from a manifest silently throws
// `NameNotFoundException` even when installed — a detection that can never
// fire. A package declared in the manifests but never queried is dead weight
// that widens the app's declared visibility surface for no benefit. Both
// drift directions are bugs; this test pins the three lists together.

// `require` (rather than ESM `import`) matches the pattern used by
// `app-plugin.test.ts`; the Node builtin module specifiers are not resolvable
// through this project's `customConditions`/bundler TS resolution.
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

// Provided by the Jest CommonJS transform at runtime; declared here because
// the Node global types are not part of this project's TS program.
declare const __dirname: string;

import { describe, expect, it } from '@jest/globals';

const repoRoot = join(__dirname, '..', '..');

function readRepoFile(relativePath: string): string {
  return readFileSync(join(repoRoot, relativePath), 'utf8');
}

/** First capture group of a match, falling back to the full match. */
function groupOf(match: RegExpMatchArray): string {
  return match[1] ?? match[0];
}

/** Package ids declared in the library AndroidManifest `<queries>` block. */
function manifestPackages(): Set<string> {
  const manifest = readRepoFile(
    join('android', 'src', 'main', 'AndroidManifest.xml')
  );
  return new Set(
    [...manifest.matchAll(/<package android:name="([^"]+)"\s*\/>/g)].map(groupOf)
  );
}

/** Package ids queried by the Kotlin PackageManagerProbe (all three maps). */
function kotlinProbePackages(): Set<string> {
  const source = readRepoFile(
    join(
      'android',
      'src',
      'main',
      'java',
      'com',
      'margelo',
      'nitro',
      'rootjaildetect',
      'HybridPackageManagerProbe.kt'
    )
  );
  // Every package key in the probe's maps appears as `"com.example" to "Label"`.
  return new Set(
    [...source.matchAll(/"([a-z0-9_.]+)"\s+to\s+"/g)].map(groupOf)
  );
}

/** Package ids added to the app manifest by the Expo config plugin. */
function pluginPackages(): Set<string> {
  const source = readRepoFile('app.plugin.js');
  const setBlock = source.match(/const packages = new Set\(\[([\s\S]*?)\]\)/);
  const block = setBlock?.[1];
  if (block === undefined) {
    throw new Error('Could not locate the packages Set in app.plugin.js');
  }
  return new Set(
    [...block.matchAll(/'([a-z0-9_.]+)'/g)].map(groupOf)
  );
}

describe('Android package visibility stays in sync with the probe', () => {
  it('every package queried by the Kotlin probe is declared in the library manifest', () => {
    const declared = manifestPackages();
    const queried = kotlinProbePackages();
    expect(queried.size).toBeGreaterThan(0);
    const missing = [...queried].filter((id) => !declared.has(id));
    expect(missing).toEqual([]);
  });

  it('every package queried by the Kotlin probe is declared by the Expo config plugin', () => {
    const declared = pluginPackages();
    const queried = kotlinProbePackages();
    const missing = [...queried].filter((id) => !declared.has(id));
    expect(missing).toEqual([]);
  });

  it('the library manifest and the Expo config plugin declare the same package set', () => {
    expect(pluginPackages()).toEqual(manifestPackages());
  });

  it('every declared package is actually queried by the probe (no dead visibility grants)', () => {
    const queried = kotlinProbePackages();
    const dead = [...manifestPackages()].filter((id) => !queried.has(id));
    expect(dead).toEqual([]);
  });
});
