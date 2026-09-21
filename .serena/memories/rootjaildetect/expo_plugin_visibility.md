# Expo config plugin + Android `<queries>` visibility

`app.plugin.js` (committed; ships in npm package) is an Expo prebuild plugin that synchronizes AndroidManifest `<queries>` and `Info.plist LSApplicationQueriesSchemes`. Contract tests pin this:

- `src/__tests__/app-plugin.test.ts` — plugin must not crash on bare-RN consumers (lazy `@expo/config-plugins` require)
- `src/__tests__/package-visibility.test.ts` — three-way consistency between: (a) library `AndroidManifest.xml`, (b) plugin `app.plugin.js` Set, (c) Kotlin `HybridPackageManagerProbe.kt` map keys

## Plugin lazy-load contract

`require('@expo/config-plugins')` must live INSIDE the exported function — never at module scope. Reason: bare-RN consumers (no Expo dependency) `require('../app.plugin')` for autolinking discovery; a top-level require throws and the package can't be installed.

`@expo/config-plugins` is in `peerDependenciesMeta` with `optional: true`. npm surfaces it as a soft requirement without forcing install.

## Plugin default schemes

```js
const urlSchemes = Array.isArray(props.urlSchemes)
  ? props.urlSchemes
  : ['cydia', 'sileo', 'zbra', 'filza'];
```

And `schemeCap: 50` by default, `25` for apps linked on iOS 27+ (host passes `schemeCap` to override). Plugin warns via `console.warn` if the merged list exceeds the cap (does NOT throw — prebuild is non-blocking).

## `<queries>` package list

Currently 31 packages (root/hiding/risky) — single source of truth in `app.plugin.js` Set. The library's `AndroidManifest.xml` repeats them verbatim. The Kotlin probe's three maps repeat them verbatim. Three locations, one list. Drift = silent detection miss or dead visibility grant.

## Test-driven enforcement

`src/__tests__/package-visibility.test.ts` is the lint-equivalent for this contract. Adding a package: edit all three files in one commit. CI fails on drift.

## Why a custom visibility list, not `QUERY_ALL_PACKAGES`

`QUERY_ALL_PACKAGES` is a privacy-violating flag that broadens Android 11+ (API 30+) visibility to **all installed apps**. App stores reject it without explicit justification. The repo's narrow list contains only packages KNOWN to be associated with root/hiding/risky behavior; a normal user has none of them installed. The repo never requests `QUERY_ALL_PACKAGES`.

## Plugin returns `config` (idempotent)

Standard Expo plugin shape: receive config, return modified config (or original if unchanged). Mutation happens via the `with*` helpers which take a callback for the mod. Don't bypass the helpers — prebuild registers them for stability.