# Android detection policy (current)

## Score / signal catalog invariants

`cpp/SignalCatalog.hpp` weights mirror README's Signal Catalog table; weights are tuned so a fully-cleaned modern Magisk namespace yields no signals above `minScore` — absence is never evidence of compromise.

## Pure/impure split (CRITICAL)

Detection heuristics split into deterministic pure helpers and impure side-effecting probes, mirroring the iOS detection code (`cpp/IOSMatchers.hpp` / `cpp/IOSChecks.cpp`):

- **Pure** (host-testable with fixture strings): `cpp/ProcParsers.*`, `cpp/IOSMatchers.hpp`, `cpp/Scoring.hpp`, `cpp/SignalCatalog.*`, `cpp/InstallOriginResolver.*`. Every function takes already-read input and returns structured findings. Host tests run under `-DROOTJAILDETECT_HOST_TEST`.
- **Impure** (platform API calls): `cpp/AndroidProbes.*` (filesystem stat, `__system_property_get`), `cpp/AndroidChecks.*` (orchestrator), `cpp/TcpProbe.*` (loopback TCP connects). These are NOT host-testable.

New heuristics: extract the pure matching into a header-only file in the same vein as `IOSMatchers.hpp` or `ProcParsers.cpp`. Drop a `cpp/tests/FooTests.cpp` alongside the existing suites.

## Mountinfo parsing (must locate fields relative to `-`)

`cpp/ProcParsers.cpp` `parseMountinfoLine()` finds fstype/source **relative to the `-` separator** because optional fields (`shared`, `master`, `propagate_from`, `unbindable`) are variable-count. Fixed column indices silently misparse (bug shipped once, caught in review).

Both `scanDenyListUnmountFingerprint()` and `scanMountsForOverlayFs()` use this helper. Adding a new mountinfo scanner? Reuse the helper.

## DenyList unmount fingerprint — v0.13.0 rework

`android.mount.denylist_unmount` (low 5, reliability 0.40, hypothesis):

- **Indicator A gate**: ≥ 2 **distinct** canonical system paths (`/system`, `/vendor`, `/product`, `/system_ext`, `/odm`, `/oem`) with `tmpfs` fstype, **any** source. v0.13.0 dropped v0.12.0's requirement that the source be `magisk`-named — modern Magisk v24+ `revert_unmount()` cleans fully and partial cleanups use randomized sources (Kitsune, magisk forks, unmount modules, `EBUSY`).
- **Indicator B** (evidence enrichment only): surviving magisk tokens (source, `/adb/modules` root, `.magisk` path) append `;residual-magisk-artifacts`. Indicator B alone never fires — visible artifacts are the explicit-mount signal's domain.
- Modern official Magisk v24+ `revert_unmount()` cleans fully → honest expected-FN. Do NOT market as DenyList-proof.

## Overlayfs signal — exact partition-root only

`android.mount.overlayfs` (medium 10, reliability 0.55):

- Triggers only on EXACT canonical partition root mountpoints (`/system`, `/vendor`, `/product`, ...). Subpath mounts (`/system/app`) never fire.
- Classification:
  - `;user-writable-backing` evidence flag when lowerdir/upperdir/workdir contains `/data`/`/storage`/`/sdcard`. The meta-module class.
  - Block/vendor-backed or uninspectable → remount/GSI class.
  - **Fully OEM-backed** → suppressed. `kOemBackingPrefixes` in `cpp/ProcParsers.cpp` lists `/mnt/vendor/mi_ext/`, `/product/pangu/`. Additions require a real-device corpus sample — don't auto-add.
- Stock Xiaomi HyperOS/MIUI ships OEM overlays at **subpaths**; subpath mounts never fire by design (documented decision, not an accident).

## Magisk chain signal (hypothesis, low)

`android.mount.magisk_chain` (low 5) — counts any `overlay` line in mountinfo. Stock Xiaomi OEM layering can co-fire it. Acceptable at hypothesis weight; raise only with OEM corpus fixtures.

## Property consistency signals (cross-checks)

`android.props.inconsistent_*` signals fire when Android build properties disagree about debuggable state / verified-boot state / fingerprint state — useful on devices where Shamiko has reset the obvious leaks but not the consistency. Cat-and-mouse heuristic, deliberately low.

## PackageManager visibility — must stay in sync

The Kotlin probe (`android/src/main/java/com/margelo/nitro/rootjaildetect/HybridPackageManagerProbe.kt`), the library `AndroidManifest.xml` `<queries>`, and the Expo config plugin `app.plugin.js` all enumerate the SAME list of root/hiding/risky package ids. Three callers of one list. **Drift is a detection miss** (probe throws `NameNotFoundException` because visibility is missing) or **dead visibility** (declared but never queried → wider surface for no benefit).

`src/__tests__/package-visibility.test.ts` pins all three to be equal. Adding a package: add to all three files in one commit.

`HybridPackageManagerProbe.kt` calls `NitroModules.applicationContext` directly (not from a parameter). Throw `IllegalStateException("Android application context is unavailable")` if null. From a C++-created thread (Nitro worker, watchdog), the call must run inside `facebook::jni::ThreadScope::WithClassLoader` — see `cpp/AndroidChecks.cpp:288`.

## Read inconsistency signals

- `cpp/AndroidChecks.cpp` is the ONLY place that knows the full set of Android checks. New checks go through `runAndroidChecks(...)`, never duplicated.
- `cpp/DeviceRiskAssessment.cpp` calls `runAndroidChecks` under `#if defined(__ANDROID__)`; iOS gets an empty set.

## Package visibility getInstallerPackageName

`getInstallerPackageName()` (consumed by `getInstallOrigin()`): on API 30+ uses `getInstallSourceInfo(...).installingPackageName`; on older versions `getInstallerPackageName(...)`. Returns `null` for ADB/system installs — `InstallOriginResolver` maps nullopt → `UNKNOWN`, never `OTHER`. This is the ASYMMETRY with Android's scored `android.install.origin.other` signal: the getter is purely informational on this side; the scored signal is a separate signal id and only fires on the explicit non-Play path.