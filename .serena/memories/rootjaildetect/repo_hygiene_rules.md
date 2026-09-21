# Repo hygiene rules (transient / convention reminders)

Compact rules that come up often and are easy to forget. Pulled from CLAUDE.md "Rules for public API changes", "Coding style", "Documentation and contribution requirements".

## Rules-of-thumb reminder

- Public API change → 11-file checklist (`.nitro.ts` + `.ts` types + `wrappers.ts` + `index.tsx` + `cpp/Hybrid*` + Kotlin/Swift edge + `nitro.json` + podspec/`build.gradle`/`CMakeLists.txt` + `README.md` + `example/src/App.tsx` + Jest)
- Keep module registration name exactly `RootJailDetect` — string passed to `createHybridObject<RootJailDetect>('RootJailDetect')` must match the `nitro.json` autolinking key.
- HybridObject native classes **must be constructible with no arguments** because Nitro autolinks them. But constructors must STILL explicitly call `HybridObject(TAG)` (see `rootjaildetect/native_object_lifecycle`).

## Conventional Commits

Repo uses Conventional Commits (`feat`, `fix`, `refactor`, `docs`, `test`, `chore`). Message validation handled by `@commitlint/config-conventional` (`@commitlint` v21). `release-it` uses `@release-it/conventional-changelog` with the angular preset to generate the changelog.

## Code style anchors

- TypeScript/JS: single quotes, 2-space indent, ES5 trailing commas (Prettier config in `package.json`).
- ESLint 10 native flat config (`eslint.config.mjs`). Do NOT reintroduce `FlatCompat` wrapper for `@react-native/eslint-config` — it uses internals removed in v10.
- Jest 30 with a `jest/environment.js` shim that re-exports `jest-environment-node`. The shim exists because the npm 11 direct-dep conflict on `jest-environment-node` would break `bun publish`. Do NOT add a `package.json` `overrides` entry.
- Strict TypeScript, including unused and unchecked-index checks. TypeScript 7+ removed `noImplicitUseStrict` / `noStrictGenericChecks` — do not reintroduce them.
- C++20, std::chrono, RAII for resources.

## Commit / branch / publish policy

- **Do not commit, tag, push, or create branches unless explicitly requested.**
- **Do not release / publish (`bun run release`) unless explicitly requested.**
- "Minimally update CLAUDE.md" or similar requests imply ONLY that file.
- "Do nothing else" / "and do nothing else" = strict scope.

## Tests

- Jest tests run with `--maxWorkers=2` (the spec is in CLAUDE.md and CI).
- Mock `NitroModules.createHybridObject` BEFORE importing `src/index.tsx` so the lazy root handle points at the mock for the whole suite.
- Reset module-level state (e.g. `setDetectionCallback(undefined)`) in `beforeEach`. The Jest shim pins `testEnvironment` so modules stay single-instance per test file.
- Native heuristics are hard to validate with Jest alone. Pure helpers → `bun run native-test` host tests; everything else → example app on device.

## Build commands that are NOT used (anti-patterns)

- `bun run turbo run build:ios|build:android` → CI only. Local workstation use is unreliable (env-var stripping per CLAUDE.md).
- `bun run specs` may fail with `nitrogen: command not found` despite `package.json` defining it. Fallback: `bunx nitrogen@0.36.1`.
- `npm` instead of `bun` for repository development — workspace is Bun-managed. Use `bun install --frozen-lockfile`.

## "Don't fix unrelated bugs while implementing a scoped change"

Strict scoping. If you encounter a side issue (e.g. typo in another file, an unused import elsewhere), mention it in the final summary and let the user decide. Don't bundle the fix.

## Documentation sync discipline

README, example app, and signal catalog stay in sync with code:

- README signal table ↔ `cpp/SignalCatalog.cpp` weights
- README "Public API" summary ↔ `src/index.tsx` exports
- README example snippets ↔ `example/src/App.tsx`
- Example app screens ↔ public API surface
- Add a signal → add reason text in `src/wrappers.ts` `signalReasons` and a pinned `getDetectionReasons()` test case so the JS catalog reason never falls through to the raw id (the test "returns human-readable text for every cataloged signal id" pins this).