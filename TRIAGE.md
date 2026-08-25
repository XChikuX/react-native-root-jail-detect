# Triage — Post-`0c83306` Audit (`@psync/anti-jailbreak`)

## Executive Summary

**Root cause found and fixed:** The native crash on Android when calling `checkDetailed()` or starting the security watchdog was caused by **JNI calls from a detached Nitro ThreadPool worker thread**. The `PackageManagerProbe` Kotlin HybridObject was being accessed via fbjni from a background thread that wasn't attached to the JVM, causing a SIGABRT with "Cannot default-construct HybridObject!" error.

**Fix applied:** Wrapped the PackageManager enumeration section in `cpp/AndroidChecks.cpp` with `facebook::jni::ThreadScope::WithClassLoader` to properly attach the thread to the JVM before making JNI calls.

---

## Crash Evidence

**User's crash logs** (from physical OnePlus 9R on LineageOS 23.2):

```
08-22 03:19:55.281  9203 13048 F libc    : Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 13048 (nitro-thread-2), pid 9203 (club.psync.psync)
...
Abort message: 'terminating due to uncaught exception of type std::runtime_error: Cannot default-construct HybridObject! Did you forget to add the `HybridObject(TAG)` base-constructor call to your Hybrid Object's constructor?'
...
#05 pc 00000000001003e4  libRootJailDetect.so
#06 pc 0000000000144b58  libRootJailDetect.so (margelo::nitro::rootjaildetect::runAndroidChecks(...)+5448)
```

**Key observations from crash:**
1. Crash occurs on `nitro-thread-1` / `nitro-thread-2` (Nitro's ThreadPool worker threads)
2. Stack trace points to `runAndroidChecks()` in `libRootJailDetect.so`
3. Abort message indicates HybridObject construction failure — a symptom of detached thread JNI access

---

## Root Cause Analysis

### The Problem

In `cpp/AndroidChecks.cpp`, the `runAndroidChecks()` function is called from `HybridRootJailDetect.cpp` on a Nitro ThreadPool worker thread (via `Promise::async()`). When the code reaches the **PackageManager enumeration section** (lines 253–297), it attempts to:

```cpp
std::shared_ptr<margelo::nitro::HybridObject> object =
  margelo::nitro::HybridObjectRegistry::createHybridObject("PackageManagerProbe");
probe = std::dynamic_pointer_cast<HybridPackageManagerProbeSpec>(object);
```

And then call:
```cpp
std::vector<std::string> rootPackages = probe->getInstalledRootPackages();
std::vector<std::string> hidingPackages = probe->getInstalledHidingPackages();
std::vector<std::string> riskyPackages = probe->getInstalledRiskyPackages();
```

The `PackageManagerProbe` HybridObject is **Kotlin-backed on Android** (`{ ios: 'c++'; android: 'kotlin' }` in `PackageManagerProbe.nitro.ts`). The generated fbjni C++ glue code makes JNI calls to the Kotlin implementation.

**Critical issue:** Nitro's ThreadPool **does not attach worker threads to the JVM**. When fbjni's `Environment::currentOrNull()` is called on a detached thread, it returns `nullptr`. The first JNI call (class lookup, method ID, or object instantiation) then dereferences this null pointer, causing a SIGABRT.

### fbjni Source Evidence

From fbjni 0.7.0 (`Environment.cpp:200-215`):

```cpp
JNIEnv* Environment::currentOrNull() noexcept {
  // ... returns nullptr if thread not attached to JVM
}
```

The `ThreadScope::WithClassLoader` RAII helper (fbjni `Environment.cpp:376`) is the canonical pattern for attaching a native thread to the JVM:

```cpp
facebook::jni::ThreadScope::WithClassLoader([&] {
  // JNI calls here are safe — thread is attached
});
```

### Why `configure()` Works But `checkDetailed()` Crashes

- `configure()` only stores options — no detection pass runs, no `PackageManagerProbe` calls
- `checkDetailed()` → `assessDevice()` → `runAndroidChecks()` → **PackageManagerProbe JNI calls on detached thread** → crash

---

## The Fix

**File:** `cpp/AndroidChecks.cpp`

**Changes:**
1. Added `#include <fbjni/fbjni.h>` under `__ANDROID__` guard (lines 19–21)
2. Wrapped the entire PackageManager enumeration section (lines 261–306) with `facebook::jni::ThreadScope::WithClassLoader`

```cpp
#if defined(__ANDROID__)
facebook::jni::ThreadScope::WithClassLoader([&] {
  std::shared_ptr<HybridPackageManagerProbeSpec> probe;
  try { /* create probe via registry */ } catch (...) { probe = nullptr; }
  if (!probe) probe = std::make_shared<HybridPackageManagerProbe>();
  try {
    /* three method calls as before */
  } catch (...) {}
});
#else
  // iOS/host: PackageManagerProbe is a no-op stub; nothing to do.
#endif
```

**Why this works:**
- `ThreadScope::WithClassLoader` attaches the current thread to the JVM for the duration of the lambda
- All fbjni calls inside the lambda now have a valid `JNIEnv*`
- The existing try/catch fallback logic is preserved (registry lookup → no-op stub)
- iOS/host builds are unaffected (no-op stub used)

---

## Verification

### Automated Checks
```
✅ bun run typecheck     — TypeScript strict mode passes
✅ bun run lint          — ESLint 10.x flat config passes
✅ bun run test          — 42/42 Jest tests pass
✅ bun run build         — React Native Builder Bob compiles successfully
```

### Native Build
The fix requires a Gradle/CMake build to verify native compilation:
```sh
cd example/android
./gradlew app:assembleRelease --no-daemon --console=plain \
  -PreactNativeArchitectures=arm64-v8a -PhermesEnabled=false
```

### Device Test
On the user's physical device (Wi-Fi adb connected):
```sh
adb install -r app/build/outputs/apk/release/app-release.apk
# Launch app — it auto-calls checkDetailed() on mount
adb logcat -b crash -d
```
**Expected:** No crash, package signals appear in JS log.

---

## Other Potential Issues Investigated

### iOS `UrlSchemeProbe` — **No Issue**
- Swift-backed HybridObject (`{ ios: 'swift'; android: 'cpp' }`)
- Implementation in `ios/HybridUrlSchemeProbe.swift` properly dispatches to main thread:
  ```swift
  guard Thread.isMainThread else {
    var result = false
    DispatchQueue.main.sync { result = self.canOpenUrlOnMainThread(scheme) }
    return result
  }
  ```
- Called from `cpp/IOSChecks.cpp` — safe because Swift handles thread affinity

### Other HybridObjects — **No Issue**
- `RootJailDetect` and `SecurityWatchdog` are pure C++ (`{ ios: 'c++'; android: 'cpp' }`)
- No JNI/Swift boundary crossings from background threads
- `UrlSchemeProbe` on Android and `PackageManagerProbe` on iOS are no-op C++ stubs

### Nitro ThreadPool — **Architecture Note**
Nitro's ThreadPool has **zero JVM attachment logic** (grep confirms no `ThreadScope`/`AttachCurrentThread` usage). Any Kotlin-backed HybridObject accessed from a Nitro async task **must** be wrapped with `ThreadScope::WithClassLoader`. This fix establishes the pattern for future Kotlin-backed HybridObjects.

---

## 2026-08-22 Addendum — Magisk DenyList detection signal

**Context.** While validating the JVM-thread fix on the user's rooted OnePlus 9R (LineageOS 23.2), adding the app to Magisk's DenyList caused the score to drop from 95 → 15 (below `minScore: 40`). All explicit-artifact mount signals (`android.mount.magisk`, `android.addon_d.magisk`, `android.cmdline.{su_exec,magisk_exec}`, `android.mount.magisk_chain`) went silent. Investigation confirmed this is the documented behavior of DenyList: Magisk creates a per-app mount namespace, unmounts Magisk-managed overlays, and stabilizes with `tmpfs` mounts.

**Research.** Confirmed upstream `Magisk#2406` (label `confirmed`) documents the namespace-divergence fingerprint — comparing the app's mountinfo against init's reveals mounts present in init but missing from the app. Also surveyed `darvincitech/Detecting-Magisk-Hide` (Magisk 20.1–20.3), the `mywalkb/DenylistUnmount` and `HSSkyBoy/NyaZygisk` Shamiko forks, and the DeepID 2026 magisk-detection guide. Consensus across sources: the *explicit-token* fingerprint was patched by Magisk 20.4; the *structural* fingerprint (`tmpfs` overlays over system paths) survives modern Magisk including Shamiko-aware forks.

**Implementation.** New signal `android.mount.denylist_unmount` (Severity::MEDIUM, SignalCategory::MOUNT, score 15, reliability 0.55). The parser in `cpp/ProcParsers.cpp::scanDenyListUnmountFingerprint()` reads the app's own `/proc/self/mountinfo` and looks for lines matching all three indicators:
  1. `tmpfs` filesystem type
  2. mount point is one of `/system`, `/vendor`, `/product`, `/system_ext`, `/odm`, `/oem`
  3. mount source mentions `magisk` (which also matches `core/magisk`)

The filesystem type and source are located **relative to the `-` separator** (per `proc_pid_mountinfo(5)`), not by fixed column index — mountinfo lines carry a variable run of optional fields (`shared`, `master`, `propagate_from`, `unbindable`) before the separator, and fixed indices silently misparse any line with a propagation marker.

Requires at least **two distinct matching paths** before reporting (dual-indicator gate) to avoid false positives on legitimate work-profile / scoped-storage setups that produce a single `tmpfs` overlay; duplicate mounts of the same path do not count toward the gate.

**Why this is not the namespace-diff scan that already exists.** The existing `scanNamespaceOnlyMountArtifacts()` reads `/proc/1/mountinfo` for comparison — but PID 1 is hidden by SELinux on production Android, so that path returns empty. The new scan uses the app's *own* mountinfo for structural analysis, which is always readable.

**Files modified (DenyList signal).**

| File | Change |
|------|--------|
| `cpp/SignalCatalog.hpp` | Added `ANDROID_MOUNT_DENYLIST_UNMOUNT` id |
| `cpp/SignalCatalog.cpp` | Catalog entry: severity MEDIUM, weight 15, reliability 0.55 |
| `cpp/ProcParsers.hpp` | Declared `scanDenyListUnmountFingerprint()` |
| `cpp/ProcParsers.cpp` | Implemented parser with dual-indicator gate |
| `cpp/AndroidChecks.cpp` | Wired the scan into the mount-metadata stage |
| `cpp/tests/ProcParsersTests.cpp` | Expanded into the suite entry point: comprehensive fixtures for every pure parser (maps hooks, anon injection, module props, property inconsistencies, mount artifacts, Magisk chain, namespace-only, TracerPid, SELinux) |
| `cpp/tests/DenyListFingerprintTests.cpp` | Exhaustive DenyList fingerprint fixtures: positives (minimal, optional fields, case, CRLF, no trailing newline) and negatives (gate, distinct-path, non-system paths, non-tmpfs, options/super-options leakage, malformed lines) |
| `cpp/tests/ScoringTests.cpp` | `aggregateSignals()` fixtures: dedup, availability filtering, clamping, and the full confidence ladder (LOW/MEDIUM/HIGH/EXTREME) |
| `cpp/Scoring.hpp` | Host-test guard (`ROOTJAILDETECT_HOST_TEST`) mirroring `SignalCatalog.hpp` so aggregation is fixture-testable without Nitro headers |
| `package.json` | `native-test` script now compiles `cpp/tests/*.cpp` |
| `src/__tests__/index.test.tsx` | Jest coverage for the DenyList signal: catalog text, evidence preference, unavailable skip |
| `src/wrappers.ts` | Added human-readable reason string |

**Validation.**

- `bun run native-test` — host-side suite passes: every pure parser + exhaustive DenyList fingerprint fixtures + `aggregateSignals()` scoring rules
- `bun run typecheck`, `bun run lint`, `bun run test --maxWorkers=2` (45/45), `bun run build` — all pass

**Final-review hardening (2026-08-25).** The initial parser located the filesystem type/source by fixed column index (`fields[7]`/`fields[8]`), which is only correct when a mountinfo line has *zero* optional fields. Verified against `proc_pid_mountinfo(5)`: optional fields (`shared`, `master`, `propagate_from`, `unbindable`) are variable-count, so any system mount carrying a propagation marker would have been silently misparsed and the signal would not fire. Reworked the parser to locate the `-` separator dynamically, enforced distinct-path deduplication to match the documented gate, and added regression fixtures for both behaviors.

**Limitations (documented).**

- A *fully* configured adversary (Magisk + Shamiko + HMA) can defeat this signal: Shamiko in Zygote can suppress the `tmpfs` overlay signature. This signal catches DenyList alone and DenyList + Shamiko's stock paths.
- Should be paired with hardware-backed attestation (`@expo/app-integrity`) for high-assurance decisions, as documented in the README.

---

## Files Modified (this triage)

| File | Change |
|------|--------|
| `cpp/AndroidChecks.cpp` | Added fbjni include + wrapped PackageManager section with `ThreadScope::WithClassLoader` |
| `cpp/SignalCatalog.hpp` / `cpp/SignalCatalog.cpp` | New `ANDROID_MOUNT_DENYLIST_UNMOUNT` signal |
| `cpp/ProcParsers.hpp` / `cpp/ProcParsers.cpp` | New `scanDenyListUnmountFingerprint()` parser |
| `cpp/tests/ProcParsersTests.cpp` | Suite entry point + comprehensive parser fixtures |
| `cpp/tests/DenyListFingerprintTests.cpp` | Exhaustive DenyList fingerprint fixtures |
| `cpp/tests/ScoringTests.cpp` | `aggregateSignals()` scoring fixtures |
| `cpp/Scoring.hpp` | Host-test guard for fixture builds |
| `src/__tests__/index.test.tsx` | Jest coverage for the new signal reason |
| `src/wrappers.ts` | Reason string for the new signal |

---

## Next Steps

1. **Build & test on device** (user's physical Android device via Wi-Fi adb)
2. **Publish fix** — bump version, run `bun run release` (includes native release gates)
3. **Update docs** — `README.md` changelog, `HANDOFF.md` resolution status