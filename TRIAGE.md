# Triage — iOS Build Failures (`@psync/anti-jailbreak`)

Status of the recurring iOS (fastlane) build failures encountered while shipping
the `UrlSchemeProbe` Swift HybridObject. This document captures what failed,
what is fixed, what is blocked, and the recommended paths forward.

Last updated: 2026-07-30

---

## Issue summary

| # | Error | Status | Fix |
|---|-------|--------|-----|
| 1 | `only virtual member functions can be marked 'override'` (C++, `getMemorySize`) | ✅ Fixed | Renamed to `getExternalMemorySize` with `noexcept` |
| 2 | `overriding declaration requires an 'override' keyword` (Swift, `init()`) | ✅ Fixed | `public init()` → `public override init()` |
| 3 | `value of type '...std__vector_std__string_' has no member 'map'` (Swift, generated `_cxx.swift`) | ⛔ Blocked | See options below |

---

## Issue 1 — C++ `getMemorySize` override (FIXED)

**Symptom**

```
cpp/HybridRootJailDetect.hpp:41:28
  size_t getMemorySize() override;
                         ^ only virtual member functions can be marked 'override'
```

Same error on `HybridSecurityWatchdog.hpp` and `HybridUrlSchemeProbe.hpp`.

**Root cause**

`NitroModules` `HybridObject` base class declares:

```cpp
virtual inline size_t getExternalMemorySize() noexcept { return 0; }
```

There is **no** `getMemorySize()` method on the base. The `override` keyword on
a non-existent base method is rejected by the compiler.

This rename has existed in NitroModules since at least **0.25.0** on npm
(verified across 0.25.0, 0.30.0, 0.33.0, 0.34.0, 0.35.x, 0.36.x).

**Fix applied**

Renamed `getMemorySize` → `getExternalMemorySize` (with `noexcept`) in:

- `cpp/HybridRootJailDetect.hpp` + `.cpp`
- `cpp/HybridSecurityWatchdog.hpp` + `.cpp`
- `cpp/HybridUrlSchemeProbe.hpp` + `.cpp`

Signature now matches the base exactly: `size_t getExternalMemorySize() noexcept override`.

**Why Android passed but iOS failed**

iOS consumes NitroModules as a source-built CocoaPod with live C++ headers.
Android consumes a prefab/prebuilt header snapshot via Gradle that can be
satisfied by a cached earlier build. The same incorrect override can fail iOS
while a cached Android build appears to pass.

---

## Issue 2 — Swift `init()` override (FIXED)

**Symptom**

```
ios/HybridUrlSchemeProbe.swift:14:10
  public init() { }
         ^ overriding declaration requires an 'override' keyword
```

**Root cause**

The nitrogen-generated base class `HybridUrlSchemeProbeSpec_base`
(`nitrogen/generated/ios/swift/HybridUrlSchemeProbeSpec.swift:29`) declares a
designated initializer:

```swift
open class HybridUrlSchemeProbeSpec_base {
  public init() { }
}
```

`HybridUrlSchemeProbeSpec` is `HybridUrlSchemeProbeSpec_protocol & HybridUrlSchemeProbeSpec_base`,
so the subclass inherits that `init()`. In Swift, a subclass initializer that
matches a superclass designated initializer must be marked `override`.

**Fix applied**

`ios/HybridUrlSchemeProbe.swift` line 14:

```swift
public override init() { }
```

**Verification**

The generated `HybridObject` Swift protocol requires `memorySize`, `dispose`,
and `toString` — all three have default implementations via the protocol
extension, so the implementation class does not need to provide them. The
`checkSchemes(schemes:)` signature matches the generated protocol exactly.
Only `HybridUrlSchemeProbe` is Swift-backed; the root and watchdog
HybridObjects are pure C++ with no Swift files.

---

## Issue 3 — Swift `std::vector` `.map()` (BLOCKED)

**Symptom**

```
node_modules/@psync/anti-jailbreak/nitrogen/generated/ios/swift/HybridUrlSchemeProbeSpec_cxx.swift:130
  let __result = try self.__implementation.checkSchemes(schemes: schemes.map({ __item in String(__item) }))
                                                                      ~~~~~~~^ has no member 'map'
```

**Root cause — environmental, not a code bug**

The generated code IS the canonical NitroModules pattern. The official
NitroModules test suite
([`HybridTestObjectSwiftKotlinSpec_cxx.swift`](https://github.com/mrousavy/nitro/blob/main/packages/react-native-nitro-test/nitrogen/generated/ios/swift/HybridTestObjectSwiftKotlinSpec_cxx.swift))
uses the exact same pattern for `bounceStrings`:

```swift
public final func bounceStrings(array: bridge.std__vector_std__string_) -> bridge.Result_std__vector_std__string__ {
  do {
    let __result = try self.__implementation.bounceStrings(array: array.map({ __item in String(__item) }))
    ...
```

The `.map()` call relies on Swift's C++ interop making `std::vector` conform to
`Sequence`. This normally works when `SWIFT_OBJC_INTEROP_MODE = objcxx` is set —
and it IS set in both NitroModules' podspec and this library's
`nitrogen/generated/ios/RootJailDetect+autolinking.rb`.

The fact that it does not work in the consumer's build points to one of:

1. **Consumer's Xcode/Swift version** is older or has a regression in
   `std::vector` Sequence conformance under C++ interop. Swift's C++ interop
   matured significantly over Xcode 15 → 16.
2. **Module visibility issue**, possibly related to the unusual
   `SWIFT_INSTALL_OBJC_HEADER = NO` setting in the autolinking.rb (added "for
   Static linkage on Xcode 26.4"). This setting is not present in NitroModules'
   own podspec.
3. **NitroModules consumer-version mismatch** — the consumer's
   `react-native-nitro-modules` is older than the `0.36.1` nitrogen that
   generated this code.

**Constraint**

The failing line is in **generated code** under `nitrogen/generated/`. Project
policy (and NitroModules policy) forbids hand-editing generated files. The fix
must come from the `.nitro.ts` spec or the environment.

**Cannot validate from Windows host** — the C++/Swift core is not
Windows-compilable. Native validation requires macOS/Linux/WSL with the NDK and
Xcode toolchains.

---

## Recommended paths for Issue 3

### Option A — Fix the environment (preferred if it works)

Confirm the consumer's toolchain matches what generated the code:

1. **Xcode version** — verify the fastlane/CI Xcode is ≥ 16.4 (the minimum
   NitroModules currently documents). Older Xcode versions have weaker C++
   interop and may not reliably provide `std::vector` Sequence conformance.
2. **NitroModules version** — verify the consumer's
   `react-native-nitro-modules` matches the nitrogen CLI version used to
   generate this code. The repo currently has a version split (see
   "Pre-existing version split" below).
3. **Interop setting** — confirm `SWIFT_OBJC_INTEROP_MODE = objcxx` is applied
   to the consumer's pod target for `@psync/anti-jailbreak` (it is set in the
   shipped `RootJailDetect+autolinking.rb`, but it should be verified in the
   consumer's build settings).

If the environment is the sole cause, **no code change is needed** — the
generated code is correct.

### Option B — Refactor to `canOpenUrl(scheme: string): boolean` (robust)

Eliminate the `string[]` parameter from the Swift↔C++ boundary entirely.
`UIApplication.canOpenURL` takes a single URL anyway, so this is also
semantically cleaner.

This is a safe change because `UrlSchemeProbe` is an **internal** HybridObject
— it is not exported from `src/`, not referenced by any JS-facing API, and is
only consumed by `cpp/IOSChecks.cpp`. Confirmed via grep.

**Required changes:**

1. `src/specs/UrlSchemeProbe.nitro.ts` — change method:
   ```ts
   canOpenUrl(scheme: string): boolean
   ```
2. `ios/HybridUrlSchemeProbe.swift` — implement `canOpenUrl(scheme: String) throws -> Bool`
   returning `app.canOpenURL(URL(string: "\(scheme)://")!)`.
3. `cpp/HybridUrlSchemeProbe.hpp` + `.cpp` — change the override to
   `bool canOpenUrl(const std::string& scheme) override` (no-op stub returning
   `false`).
4. `cpp/IOSChecks.cpp` — replace the single `probe->checkSchemes(urlSchemes)`
   call with a loop that filters `urlSchemes` by `probe->canOpenUrl(scheme)`.
5. `bun run specs` — regenerate.
6. Run JS-side validation (`typecheck`, `lint`, `test`, `build`).

This sidesteps the entire class of Swift/C++ std-container interop issues and
removes the build's dependency on a specific Xcode feature working reliably.

**Tradeoff:** requires a regeneration + C++ change. Native build validation on
macOS is still required.

---

## Pre-existing version split (background risk)

The repo currently exercises three different NitroModules ABIs across its
workspaces:

| Location | `react-native-nitro-modules` |
|----------|------------------------------|
| `package.json` `peerDependencies` | `~0.35.1` |
| root `bun.lock` | `0.36.1` |
| `example/` `bun.lock` | `0.35.10` |

The generated `nitrogen/generated/` was produced by nitrogen `0.36.1`.

Consumers of the published package will bring their own NitroModules version.
If it diverges from what generated the committed code, build mismatches
(like Issue 3) become more likely.

**Recommended follow-up:** decide whether the example should match the
library's NitroModules, and whether the peer range should formally widen
(e.g. `~0.35.1 || ~0.36.0`) when 0.36 is adopted.

---

## Validation status

| Check | Status |
|-------|--------|
| `bun run typecheck` | ✅ Pass |
| `bun run lint` | ✅ Pass |
| `bun run test --maxWorkers=2` | ✅ Pass (22/22) |
| `bun run build` | ✅ Pass |
| `bun run turbo run build:ios` | ⛔ Not run (Windows host) |
| `bun run turbo run build:android` | ⛔ Not run (Windows host) |

Native iOS/Android builds are not compilable on this Windows host per
`CLAUDE.md`. Native validation requires macOS/Linux/WSL.

---

## Next actions

1. **Decide on Issue 3 path** — Option A (verify/fix environment) or Option B
   (refactor spec to `canOpenUrl`). If proceeding with Option B, the changes
   are mechanical and listed above.
2. **Run native builds on macOS** to confirm whichever fix lands:
   ```sh
   bun install --frozen-lockfile
   bun run typecheck && bun run lint && bun run test --maxWorkers=2 && bun run build
   bun run turbo run build:ios --cache-dir=.turbo/ios
   bun run turbo run build:android --cache-dir=.turbo/android
   ```
3. **Reconcile the version split** (optional, separate task).
4. **Commit and release** only when the user explicitly requests it.
