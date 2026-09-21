# Consumer-side runtime crashes (diagnosis)

JS logs never see a native crash. Diagnose with `adb logcat` (look for `DEBUG`, `libc`, `Fatal signal`, `RootJailDetectOnLoad` tags) or on iOS Console.app. This is the most-frequent failure path for new consumers. Order of likelihood from a triage pass (2026-08):

## 1. `react-native-nitro-modules` version skew (most common)

Symptom: silent native crash at import or first call.

- Peer range is `>=0.35.10` and verified through `<0.37.0`. `<0.35.0` has different `HybridObject` virtuals; `0.37.x+` has unverified ABI changes (may have renamed `getExternalMemorySize` again).
- iOS consumes as source-built CocoaPod (live headers); Android consumes as prefab/prebuilt snapshot. A rename can break iOS while a cached Android build still passes. Clear both caches and rebuild natively when bumping.

## 2. Uncaught C++ exception escaping a `noexcept` path

Symptom: SIGABRT (`signal 6`) + `Abort message:` logcat line naming the exception type.

- "Cannot default-construct HybridObject!" → constructor missed the required `HybridObject(TAG)` virtual-base initializer. See `rootjaildetect/native_object_lifecycle` memory.
- The check runners are `noexcept` by design → any escaping exception is `std::terminate`, never a JS rejection.

## 3. R8/ProGuard rename

Symptom: process abort at `System.loadLibrary("RootJailDetect")`, logcat `RootJailDetect: full native registration failed`, then per-HybridObject fallback to C++ no-op stubs.

- Consumers MUST NOT repackage `com.margelo.nitro.rootjaildetect.**`. The classes are looked up by name from C++ via JNI.
- `android/consumer-rules.pro` AND `android/proguard-rules.pro` both bundle keep rules into the AAR so consumer R8 passes preserve the JNI-registered classes.
- Bundled via `consumerProguardFiles 'consumer-rules.pro'` in `android/build.gradle` (applies automatically to consumers).

## 4. `System.loadLibrary("RootJailDetect")` failure

Symptom: UnsatisfiedLinkError at import.

- Autolinking not applied in host app (Expo prebuild gap or manual linking issue). Verify the `@psync/anti-jailbreak` appears in `react-native.config.js` deps and the consumer's `gradle.properties` has `newArchEnabled=true`.

## Triage by symptom timing

| Timing | Likely cause |
|---|---|
| At import | load/autolinking — check version skew + autolinking |
| On first `checkDetailed()` | probe path — PackageManager JNI for Android, URL scheme for iOS |
| Silent death seconds after start on rooted/emulator device | watchdog `TERMINATE` working **by design** — retest with `LOG_ONLY` |
| Release-only | R8 renaming Kotlin classes |

## Markers in logcat

- `RootJailDetect: full native registration failed (...)` — cpp-adapter fallback fired
- `[NitroModules] 🔥 RootJailDetect is boosted by nitro!` — autolinking applied (good)
- `SecurityWatchdog detected a compromised device.` — LOG_ONLY path fired
- `SecurityWatchdog would throw for a compromised device.` — demoted THROW_EXCEPTION (cannot throw from background thread)

## iOS main-thread deadlock

`HybridUrlSchemeProbe.canOpenUrl` uses `DispatchQueue.main.sync` to call `UIApplication.canOpenURL`. If the consumer blocks the main thread at startup (e.g. inside `AppRegistry.registerComponent`'s callback or a top-level sync method), the probe deadlocks.

Mitigations:

- Pass `configure({ urlSchemes: { schemes: [] } })` to skip URL-scheme checks
- Delay the first `checkDetailed()` until after the main thread is responsive (typical)

Bounded by the `configure({ timeoutMs: ... })` budget, so the deadlock doesn't freeze the app forever — but the timeout clock doesn't advance on the main thread while the consumer blocks it.

## Fixed-in versions

- v0.9.1: watchdog use-after-free, ProGuard keeps, cpp-adapter fallback
- v0.9.2: `PackageManagerProbe` context fix
- `206feb8`: `consumer-rules.pro` bundled into the AAR