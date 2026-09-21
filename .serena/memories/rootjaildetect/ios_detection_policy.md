# iOS detection policy (v0.13.0 — current)

Consolidated from CLAUDE.md "iOS detection policy" and `cpp/IOSMatchers.hpp`/`cpp/IOSChecks.cpp`. The detection code shipped in v0.12.0 carried fabricated literals (TrollStore bundle paths, bare `/private/preboot/<name>`, marker files) and order-coupled classification. v0.13.0 was a remediation pass; the rules below are the floor for any future addition.

## Probe table invariants

`IOS_ARTIFACT_PROBES` in `cpp/IOSMatchers.hpp` (8 entries) is **evidence-backed only**. Every literal must have a public source — jailbreak tool documentation or source. Unverified literals are removed, not kept "to be re-added later".

**Removed as unverified** (do NOT add back without a source):

- `/private/preboot/{jb,dopamine,palera1n}` — real layout is `/private/preboot/<UUID>/jb` via the `/var/jb` symlink
- `/var/jb/.installed_{dopamine,palera1n}` — no source evidence
- Both TrollStore bundle paths — TrollStore installs into normal containers; since v1.3 it also hijacks `apple-magnifier://` to defeat scheme probes (opa334/TrollStore README 2022-10)

**Classification is a pure table lookup**, never substring matching. Path → class is determined by iterating the probe table; iteration order does not matter. `IOSMatchersTests.cpp` pins this (the v0.12.0 bug was order-coupled: first matching class won, missing the secondary class on hybrid devices).

## dyld image matching

`matchLoadedImage()` in `cpp/IOSMatchers.hpp`:

- **Case-insensitive tokens** (`ellekit` in any capitalization, etc.) — v0.12.0 had case-sensitive matching that missed mixed case.
- **Provenance rules** `/var/jb/` and `/.jbroot` → hook verdict (catches fully-renamed frameworks loaded from bootstrap).
- **At most ONE dyld signal per pass** — intentional. Don't "fix" this; the catalog aggregates via `IOS_DYLD_HOOK` id.
- Benign lookalike guards (`legitgadget` not matching, `libRosaliaCore` ≠ `rosalie`) are pinned in `IOSMatcherTests.cpp`. Don't widen the substrings.

## Roothide ceiling (documented expected-FN)

Roothide randomizes `.jbroot-<id>` bootstrap under `/var/containers/Bundle/Application/.jbroot-<brand>` to defeat path-table detection. Only **loaded** roothide images are caught (via the provenance rule). `IOSMatcherTests.cpp` pins this as an expected negative on the path table.

**Never claim roothide coverage in user-facing copy.**

## LSApplicationQueriesSchemes prerequisite

`UIApplication.canOpenURL` silently returns `false` for any scheme NOT in the host app's `LSApplicationQueriesSchemes` Info.plist key. The cap is 50 for apps linked on iOS 15+, 25 for iOS 27+ (where `canOpenURL` itself is deprecated but functional).

- Repo Expo config plugin (`app.plugin.js`) merges the default schemes (`cydia`, `sileo`, `zbra`, `filza`) during prebuild. Pass `schemeCap: 25` if the app links on iOS 27+.
- Bare RN apps must add the key manually; this is documented in `src/specs/UrlSchemeOptions.ts` JSDoc.
- Default behavior: warn via `console.warn` (NOT throw) when the list exceeds the cap.

## URL schemes: one probe per Swift↔C++ call

`cpp/IOSChecks.cpp` calls `probe->canOpenUrl(scheme)` once per scheme rather than passing a `string[]`. Crossing the Swift-C++ boundary with `std::vector` triggers Sequence-conformance interop overhead. Each scheme → one call is the cheaper shape.

## `LSApplicationQueriesSchemes` ordering

Info.plist merging in `app.plugin.js` deduplicates by `Set`, preserves order from the host app first then the merged-from-default list. Files don't share canonical ordering between prebuilds — fine.

## AppTransaction migration (deferred)

`Bundle.appStoreReceiptURL` is deprecated since iOS 18. The modern replacement is StoreKit 2 `AppTransaction.shared` (iOS 16+, JWS verification on-device). Currently implemented in `ios/HybridAppStoreReceiptProbe.swift` with `appStoreReceiptURL` as the iOS 15 + AppTransaction-failure fallback. The StoreKit 2 path IS the modern path — keep both for the foreseeable future. Don't drop the fallback until min target moves to iOS 16+.

## Sandbox-write signal split

v0.13.0 split the Android and iOS sandbox-write signals (`android.sandbox.write` vs `ios.sandbox.write`). The iOS reason text deliberately names the failure mode ("the process sandbox is absent or escaped") because writes succeed in fewer environments on iOS than Android and the wording should match the platform's actual semantics.