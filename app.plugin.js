/**
 * Expo config plugin for @psync/anti-jailbreak.
 *
 * The module autolinks through React Native. This plugin only adds narrowly
 * scoped Android package visibility for known root-management applications;
 * it never requests QUERY_ALL_PACKAGES.
 *
 * `@expo/config-plugins` is an optional peer dependency. The plugin is loaded
 * exclusively by the Expo prebuild pipeline, which always provides it as a
 * transitive dependency of `expo`. Bare React Native apps (without Expo) never
 * load this file; npm should still flag it as a soft requirement.
 */
function withAntiJailbreak(config) {
  // `require` lazily so require-time resolution happens only inside Expo
  // prebuild, never in the bare-app build.
  const { withAndroidManifest } = require('@expo/config-plugins');

  return withAndroidManifest(config, (mod) => {
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
}

module.exports = withAntiJailbreak;
