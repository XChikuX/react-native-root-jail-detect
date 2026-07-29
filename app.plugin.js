const { withAndroidManifest } = require('@expo/config-plugins');

/**
 * Expo config plugin for @psync/anti-jailbreak.
 *
 * The module autolinks through React Native. This plugin only adds narrowly
 * scoped Android package visibility for known root-management applications;
 * it never requests QUERY_ALL_PACKAGES.
 */
function withAntiJailbreak(config) {
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
