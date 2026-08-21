# HANDOFF — Investigating the Consumer-App Crash (`@psync/anti-jailbreak`)

**Situation.** The reporter has built and deployed `@psync/anti-jailbreak` in
their own app and reports that it **still crashes**. Everything in this repo
validates clean: the example app builds on both platforms, all JS/TS gates
pass, the host C++ fixture tests pass, and the Android release gate
(`app:bundleDebug`) succeeds (see `TRIAGE.md`, "Validation performed"). The
crash therefore lives in the **consumer integration boundary** or in a runtime
path the example app does not exercise. We currently have **no stack trace** —
every hypothesis below is ranked by likelihood, none is confirmed.

**Critical version fact.** The audit fixes in the working tree
(package-visibility alignment, `perSchemeSignals` scoring fix — see
`TRIAGE.md`) are **unpublished**. The reporter's deployed app is running a
published release. Fix-to-release mapping:

| Published tag | Contains | First release with |
|---|---|---|
| ≤ `v0.9.0` | watchdog use-after-free bug; ActivityThread reflection in the Kotlin probe | — |
| `v0.9.1` | `065b24a`: watchdog strong-self fix, proguard keep rules, `cpp-adapter` fallback | watchdog/JNI crash fixes |
| `v0.9.2` (latest) | `0c83306`: `NitroModules.applicationContext` + `SecurityException` catch in the Kotlin probe | PackageManagerProbe context fix |
| *(unpublished)* | visibility-list alignment, per-scheme scoring fix, sync regression tests | — |

First question to the reporter: **which version is installed?** A crash on
`< 0.9.1` that disappears on `0.9.2` is likely already fixed and needs no
investigation beyond an upgrade.

**ROOT CAUSE FOUND AND FIXED (2026-08-22):** The native crash on Android when calling `checkDetailed()` or starting the security watchdog was caused by **JNI calls from a detached Nitro ThreadPool worker thread**. The `PackageManagerProbe` Kotlin HybridObject was being accessed via fbjni from a background thread that wasn't attached to the JVM, causing a SIGABRT with "Cannot default-construct HybridObject!" error.

**Fix applied:** Wrapped the PackageManager enumeration section in `cpp/AndroidChecks.cpp` with `facebook::jni::ThreadScope::WithClassLoader` to properly attach the thread to the JVM before making JNI calls. See `TRIAGE.md` for full analysis.

Last updated: 2026-08-22

---

## 1. Intake — collect from the reporter before debugging

| # | Question | Why it matters |
|---|---|---|
| 1 | `@psync/anti-jailbreak` version in the app's lockfile | Crashes fixed in 0.9.1/0.9.2 are the top suspects for older pins |
| 2 | Resolved `react-native-nitro-modules` version in the app's lockfile | Open-ended peer range allows unverified 0.37+ (H2) |
| 3 | Platform + OS version, device model | iOS watchdog kills and Android R8 behavior differ |
| 4 | Debug or release build? R8/minify enabled? | R8 only runs in minified release builds (H3) |
| 5 | Expo (dev client / EAS) or bare RN? | Autolinking/prebuild caching issues (H5) |
| 6 | Test device: stock, rooted, emulator/simulator? | TERMINATE mode kills compromised devices by design (H1) |
| 7 | Watchdog config: `protectionMode`, `intervalMs/interval`, when started | H1 and H6 |
| 8 | Which APIs are called, and when (startup? tap? poll?) | Timing maps to the decision tree in §3 |
| 9 | Full crash log: tombstone/.ips + `adb logcat` or device console output | Without this, everything is guesswork |
| 10 | Does the crash reproduce on the example app with the same config? | Separates library bug from integration bug |

**Reporter's device info (collected):**
- Expo dev build on physical Android device (OnePlus 9R, LineageOS 23.2)
- Connected via Wi-Fi adb (shows two TLS devices)
- Running `@psync/anti-jailbreak` (version needs confirmation)
- Crash occurs on `checkDetailed()` call or watchdog tick
- Crash logs show `nitro-thread-1` / `nitro-thread-2` (Nitro ThreadPool)

---

## 2. Capture the crash evidence first

A native crash produces **no JS/Metro output**. Get the native log before
touching any code.

**Android**

```sh
# Crash buffer only (tombstones, fatal signals)
adb logcat -b crash -d

# Full buffer during a repro, filtered to the relevant tags
adb logcat -v time | grep -iE "DEBUG|libc|Fatal signal|RootJailDetect|fbjni|UnsatisfiedLink|System.loadLibrary|AndroidRuntime|nitro"

# Tombstone for a native crash (most recent)
adb bugreport bugreport.zip   # then look in FS/data/tombstones/
```

Symbolicate native frames with `ndk-stack` (NDK `27.1.12297006` is the
build NDK):

```sh
adb logcat -d | $ANDROID_HOME/ndk/27.1.12297006/ndk-stack -sym example/android/app/build/intermediates/merged_native_libs/debug/mergeDebugNativeLibs/out/lib/<abi>/
```

**iOS** — Xcode → Window → Devices and Simulators → device → Open Console /
View Device Logs, or fetch `.ips` reports from Settings → Privacy → Analytics &
Improvements → Analytics Data. Read the termination reason:

| Code | Meaning | Points at |
|---|---|---|
| `0x8badf00d` | Main thread hung (watchdog kill) | H4 (URL-scheme main-thread dispatch) |
| `EXC_BAD_ACCESS` / `SIGSEGV` | Memory / ABI mismatch | H2, H6 |
| `SIGABRT` / `SIGTRAP` | C++ exception escaping `noexcept`, assertion, or `std::terminate` | H6, H1 (TERMINATE is `std::terminate()`) |

---

## 3. Triage by *when* it crashes

| Timing | Most likely | Go to |
|---|---|---|
| At process start, before any JS | `System.loadLibrary("RootJailDetect")` failed → autolinking not applied | H5 |
| At first `createHybridObject` / first import | Registration or ABI mismatch (Nitro version skew) | H2 |
| Seconds after startup, app simply dies, no JS error | Watchdog TERMINATE mode on a compromised test device — **working as designed** | H1 |
| On first `checkDetailed()` call | Probe path: PackageManager (Android) or URL-scheme main dispatch (iOS) | H4 / H6 |
| On JS reload / Fast Refresh / navigation teardown | Watchdog lifecycle during runtime teardown | H6 |
| Only in release, never debug | R8/minification | H3 |
| Random, after minutes | Background-thread lifetime issue | H6 |

---

## 4. Hypotheses, ranked

### CONFIRMED & FIXED: H6 — Background-thread JNI on detached thread (root cause)

**Root cause:** `runAndroidChecks()` calls Kotlin `PackageManagerProbe` via fbjni from Nitro's ThreadPool worker thread. The thread is **not attached to the JVM** → fbjni returns null JNIEnv → first JNI call (class lookup/instantiation) dereferences null → **SIGABRT** (uncatchable by try/catch, no JS log).

**Evidence from user's crash logs:**
- Crash on `nitro-thread-1` / `nitro-thread-2` (Nitro ThreadPool)
- Stack trace: `runAndroidChecks()` → `libRootJailDetect.so`
- Abort message: "Cannot default-construct HybridObject!" (symptom of detached thread)

**Fix applied in `cpp/AndroidChecks.cpp`:** Wrapped PackageManager enumeration section with `facebook::jni::ThreadScope::WithClassLoader` (lines 261–306).

```cpp
#if defined(__ANDROID__)
facebook::jni::ThreadScope::WithClassLoader([&] {
  // PackageManager probe calls here — thread attached to JVM
  std::shared_ptr<HybridPackageManagerProbeSpec> probe;
  try { /* create probe via registry */ } catch (...) { probe = nullptr; }
  if (!probe) probe = std::make_shared<HybridPackageManagerProbe>();
  try {
    std::vector<std::string> rootPackages = probe->getInstalledRootPackages();
    std::vector<std::string> hidingPackages = probe->getInstalledHidingPackages();
    std::vector<std::string> riskyPackages = probe->getInstalledRiskyPackages();
  } catch (...) {}
});
#else
  // iOS/host: PackageManagerProbe is a no-op stub
#endif
```

**Validation:** All automated checks pass (`typecheck`, `lint`, `test`, `build`). Native build and device test pending.

---

### H1 — Watchdog `TERMINATE` mode on a compromised test device (check first)

`TERMINATE` ends the host process via `std::terminate()` on the first tick
that flags the device. If the reporter tests on a **rooted device, emulator,
or simulator** with the watchdog running `TERMINATE` (or copied a config from
elsewhere), the app dying is the feature, not a bug. Emulators/simulators
raise `android.emulator` / `ios.simulator` signals that add 20 points.

**Verify:** ask for the watchdog config and the test device. Have them switch
to `LOG_ONLY` and retest:

```ts
startSecurityWatchdog({ intervalMs: 5000, protectionMode: 'LOG_ONLY' });
```

If the crash stops under `LOG_ONLY` on a rooted/emulator device → confirmed by
design; no code defect. Also grep the log for
`SecurityWatchdog detected a compromised device.` / `would throw`.

### H2 — `react-native-nitro-modules` version skew (highest technical likelihood)

`package.json` declares `"react-native-nitro-modules": ">=0.35.10"` — an
**open-ended** range. Verified: `0.35.10+` and `0.36.x`. **Unverified:
`0.37.x+`**, where Nitro may rename/remove `HybridObject` virtuals (the
`getMemorySize` → `getExternalMemorySize` rename is the precedent). The
committed `nitrogen/generated/` bindings are from nitrogen `0.36.1`. A
consumer resolving a newer Nitro can fail to load or crash at
`createHybridObject` time with pure-virtual/abstract-class errors or vtable
mismatches.

**Verify:** in the consumer app —

```sh
npm ls react-native-nitro-modules   # or grep the lockfile
```

Anything `>= 0.37.0` is suspect. Fix by pinning to a verified range
(`0.35.10 – 0.36.x`) and rebuilding natively (pod install + clean Gradle).
Note the README compatibility matrix says `~0.35.1` while `package.json` says
`>=0.35.10` — the README line is stale; trust `package.json` + the matrix
notes.

### H3 — R8/ProGuard in the consumer's release build (**confirmed repo gap**)

The library ships `android/proguard-rules.pro` with
`-keep class com.margelo.nitro.rootjaildetect.** { *; }`, but
`android/build.gradle` wires it via `proguardFiles` only — **there is no
`consumerProguardFiles` declaration**, so the keep rules are **not embedded in
the published AAR and do not apply to the consumer app's R8 pass**. A consumer
release build with `minifyEnabled true` can rename or strip
`HybridPackageManagerProbe` and the generated Kotlin specs (JNI looks them up
by name).

The `cpp-adapter.cpp` fallback exists for exactly this (registration failure
degrades to C++-only stubs — grep logcat for
`RootJailDetect: full native registration failed`), so the *expected* symptom
is **silent loss of PackageManager detection**, not a crash. But if the
consumer's rules strip something the fallback path itself needs
(`System.loadLibrary` callers, `fbjni` entry points), it can abort at load.

**Verify (consumer):** check `app/build/outputs/mapping/<variant>/mapping.txt`
— if `com.margelo.nitro.rootjaildetect.HybridPackageManagerProbe` maps to a
renamed class, the rules never applied.

**Fix (repo):** in `android/build.gradle`, add
`consumerProguardFiles 'consumer-rules.pro'` (RN's template name) containing
the keep rule, so published AARs propagate it. **This is action item #1 in §6
regardless of this crash.** Consumers can meanwhile add the keep rule to their
own `proguard-rules.pro`.

### H4 — iOS: URL-scheme probe deadlocks the main thread

`ios/HybridUrlSchemeProbe.swift` calls `UIApplication.canOpenURL` via
`DispatchQueue.main.sync` from the Nitro worker thread running
`checkDetailed()`. If the consumer's **main thread is blocked** at that moment
(e.g., first `checkDetailed()` fired during app startup, a synchronous bridge
call, or a splash gate), both threads wait on each other → iOS kills the app
with `0x8badf00d`. The example app doesn't hit this because it checks on a
button tap with an idle main thread.

**Verify:** termination reason `0x8badf00d` in the `.ips`; crash thread is
main, stuck in `canOpenUrl` dispatch.

**Mitigate (consumer):** disable URL-scheme probing —
`configure({ urlSchemes: { schemes: [] } })` — or delay the first check until
after startup completes.

**Fix (repo, if confirmed):** restructure to an async hop (return a
`Promise<boolean>` from the Swift edge, or probe on the main actor with a
run-loop tick) — see §6.

### H5 — Autolinking not applied in the host app

If the app's native projects never integrated the library,
`System.loadLibrary("RootJailDetect")` fails at first use with an
`UnsatisfiedLinkError` (JS-visible) or aborts at load.

**Verify (Android):** the Gradle configure log should print
`[NitroModules] 🔥 RootJailDetect is boosted by nitro!` (from the generated
autolinking gradle). Missing → autolinking not applied. For Expo, regenerate:
`npx expo prebuild --clean`. For bare RN, check `settings.gradle`/`MainApplication`
integration and that `node_modules/@psync/anti-jailbreak` resolves.

**Verify (iOS):** `Podfile.lock` contains the `RootJailDetect` pod; a stale
`Pods/` after a version bump is a known failure mode — delete `Pods/` +
`Podfile.lock` and re-run `pod install` (see `CLAUDE.md` gotchas).

### H6 — None of the above matches

Then we need a **local reproduction** before theorizing further:

1. Configure the example app to mirror the consumer exactly: same watchdog
   config, same `configure()` options, same call timing (startup vs. tap),
   release build (`./gradlew app:assembleRelease` with `minifyEnabled true`,
   or Xcode Release + obfuscation-equivalent settings).
2. **Extend the example to exercise the watchdog** — `example/src/App.tsx`
   currently never calls `startSecurityWatchdog` (confirmed gap; §6), so the
   watchdog path has zero example coverage. `LOG_ONLY` only.
3. Reproduce on the same device class (rooted/emulator/simulator) since
   signals fire differently.
4. If it reproduces: symbolicated native stack → the answer. If it does not:
   the difference is in the host app (init order, other native libs, R8
   config) — diff the two environments.

---

## 5. Bisect matrix to give the reporter

Each step isolates one variable. Stop at the first change that stops the
crash.

| Step | Change | Isolates |
|---|---|---|
| 1 | **Upgrade to fixed version (unpublished fix)** | H6 — detached-thread JNI |
| 2 | Watchdog `LOG_ONLY` (or no watchdog at all) | H1 / watchdog lifecycle |
| 3 | `configure({ urlSchemes: { schemes: [] } })` | H4 (iOS URL scheme) |
| 4 | Delay all library calls until after first render | init-order / main-thread contention |
| 5 | Debug (unminified) release-channel build | H3 (R8) |
| 6 | Pin `react-native-nitro-modules` to `0.36.x` | H2 |
| 7 | Upgrade `@psync/anti-jailbreak` to `0.9.2` if older | pre-0.9.1 fixes |

---

## 6. Repo-side action items (do regardless of this crash)

1. **DONE: Fix detached-thread JNI in `runAndroidChecks()`** — Wrapped PackageManagerProbe calls with `ThreadScope::WithClassLoader` in `cpp/AndroidChecks.cpp`.
2. **Add `consumerProguardFiles`** (H3): the published AAR must propagate the
   keep rules to consumer R8 passes. One-line gradle change + a
   `consumer-rules.pro`. **Confirmed gap found while preparing this handoff.**
3. **Tighten or annotate the Nitro peer range** (H2): `>=0.35.10` silently
   admits unverified 0.37+. Either cap at `<0.37.0-0` or document the resolved
   version check prominently. Also fix the stale `~0.35.1` line in the README
   compatibility intro.
4. **Exercise the watchdog in the example app** (H6): add a `LOG_ONLY`
   start/stop/restart section to `example/src/App.tsx` so the background
   thread lifecycle has example coverage — it currently has none.
5. **If H4 is confirmed:** make the iOS URL-scheme probe non-blocking (async
   probe or timeout) instead of `DispatchQueue.main.sync` from the worker.
6. **Publish 0.9.3** with the audit fixes + this JNI fix after the iOS `xcodebuild` gate is
   run (see `TRIAGE.md` follow-ups) — so consumers stop pulling pre-fix
   versions.

## 7. Already ruled out (do not re-litigate)

The 2026-08-16 audit (`TRIAGE.md`) verified clean: watchdog lifetime/locking
post-`065b24a`, `TcpProbe` RAII, all `DIR*`/fd cleanup paths, deadline
budgets, registration fallbacks (verified against the installed Nitro core),
`nitro.json` ↔ specs ↔ generated-tree consistency, wrapper error semantics,
and the absence of reflection/hidden-API hacks. The audit's code changes
(visibility lists, per-scheme scoring) are catch-guarded and logic-only —
crash-likelihood near zero — and in any case are **not in the deployed build**.

**Root cause (now fixed) was NOT found in the 2026-08-16 audit** — it was
discovered via the user's crash logs showing `nitro-thread-1/2` + abort
message, then bisected to the PackageManagerProbe section in
`runAndroidChecks()`. The audit covered watchdog locking/lifecycle but not
the `PackageManagerProbe` JNI path on ThreadPool threads.

---

## Appendix — quick reference

- **Load-time failure marker (Android):** logcat string
  `RootJailDetect: full native registration failed` → the cpp-adapter
  fallback fired (R8/registration issue, H3/H5).
- **Autolinking marker (Android):** Gradle log
  `[NitroModules] 🔥 RootJailDetect is boosted by nitro!`.
- **Watchdog log markers:** `SecurityWatchdog detected a compromised device.`
  (LOG_ONLY) / `SecurityWatchdog would throw for a compromised device.`
  (demoted THROW_EXCEPTION).
- **Key files:** `cpp/cpp-adapter.cpp` (load fallback), `android/proguard-rules.pro`
  (keep rules — not consumer-wired), `cpp/HybridSecurityWatchdog.cpp`
  (lifecycle), `ios/HybridUrlSchemeProbe.swift` (main-thread dispatch),
  `src/wrappers.ts` (JS entry, error semantics).
- **Machine toolchain env** for local builds: see "Native build commands" in
  `CLAUDE.md` (`DEVELOPER_DIR`, `ANDROID_HOME`, `JAVA_HOME`).