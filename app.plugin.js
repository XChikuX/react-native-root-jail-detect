/**
 * Expo config plugin for @psync/anti-jailbreak.
 *
 * The module autolinks through React Native. This plugin adds:
 *   - narrowly scoped Android package visibility for known root-management apps;
 *   - `LSApplicationQueriesSchemes` entries for the default iOS URL-scheme
 *     probe list (`cydia`, `sileo`, `zbra`, `filza`).
 * It never requests `QUERY_ALL_PACKAGES`.
 *
 * `@expo/config-plugins` is an optional peer dependency. The plugin is loaded
 * exclusively by the Expo prebuild pipeline, which always provides it as a
 * transitive dependency of `expo`. Bare React Native apps (without Expo) never
 * load this file; npm should still flag it as a soft requirement.
 */
function withAntiJailbreak(config, props = {}) {
  // `require` lazily so require-time resolution happens only inside Expo
  // prebuild, never in the bare-app build.
  const {
    withAndroidManifest,
    withInfoPlist,
  } = require('@expo/config-plugins');

  // Default iOS schemes, matching the C++ runner defaults. Hosts can pass
  // `urlSchemes: []` to skip adding any schemes, or a custom list to merge.
  const urlSchemes = Array.isArray(props.urlSchemes)
    ? props.urlSchemes
    : ['cydia', 'sileo', 'zbra', 'filza'];

  let modified = withAndroidManifest(config, (mod) => {
    const manifest = mod.modResults.manifest;
    const queries = manifest.queries ?? [];
    const packages = new Set([
      'com.topjohnwu.magisk',
      'me.weishu.kernelsu',
      'me.bmax.apatch',
      'org.lsposed.manager',
    ]);

    const existing = new Set(
      queries.flatMap((query) =>
        (query.package ?? []).map((entry) => entry.$?.['android:name'])
      )
    );
    const missing = [...packages]
      .filter((packageName) => !existing.has(packageName))
      .map((packageName) => ({ $: { 'android:name': packageName } }));

    if (missing.length > 0) {
      queries.push({ package: missing });
      manifest.queries = queries;
    }
    return mod;
  });

  if (urlSchemes.length > 0) {
    modified = withInfoPlist(modified, (mod) => {
      const infoPlist = mod.modResults;
      const existing = new Set(infoPlist.LSApplicationQueriesSchemes ?? []);
      const merged = [
        ...existing,
        ...urlSchemes.filter((scheme) => !existing.has(scheme)),
      ];
      if (merged.length > 50) {
        console.warn(
          '[@psync/anti-jailbreak] LSApplicationQueriesSchemes would exceed the iOS 15+ 50-entry cap. ' +
            'Only the first 50 entries are effective; the remainder will silently return NO from canOpenURL.'
        );
      }
      infoPlist.LSApplicationQueriesSchemes = merged.slice(0, 50);
      return mod;
    });
  }

  return modified;
}

module.exports = withAntiJailbreak;
