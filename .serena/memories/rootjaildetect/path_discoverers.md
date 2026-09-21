# Path discovery cheat sheet

Discoverable in one read of `CLAUDE.md` but worth pinning as "where to look first" by intent:

| Intent | Read first |
|---|---|
| Add a public JS API | `src/specs/*.nitro.ts` + `src/specs/*.ts` + `src/wrappers.ts` + `src/index.tsx` |
| Add a signal id | `cpp/SignalCatalog.hpp` (define), `cpp/SignalCatalog.cpp` (weight), `src/wrappers.ts` `signalReasons` (text), README's Signal Catalog table |
| Add a detection heuristic | `cpp/ProcParsers.hpp`/`.cpp` (Android pure) or `cpp/IOSMatchers.hpp` (iOS pure) → host-testable. Then `cpp/AndroidProbes.hpp`/`.cpp` or `cpp/IOSChecks.cpp` for the impure side. Then `cpp/tests/FooTests.cpp` |
| Add a Nitro HybridObject | `src/specs/Foo.nitro.ts` + `nitro.json` autolinking entry + `bun run specs` |
| Add an iOS Swift edge | `ios/HybridFoo.swift` — match `HybridFooProbeSpec_base` designated init pattern; class `final`; `init() override` |
| Add an Android Kotlin edge | `android/src/main/java/com/margelo/nitro/rootjaildetect/HybridFoo.kt` — `@DoNotStrip @Keep` |
| Bump nitrogen | regenerated codegen, all `nitrogen/generated/` files, plus `package.json` peer range |
| Add a configuration option | `src/specs/RootJailDetectOptions.ts` or `SecurityWatchdogOptions.ts` + `cpp/DeviceRiskAssessment.hpp` `ResolvedRootJailDetectOptions` + `cpp/HybridRootJailDetect.cpp` `configure()` |
| Add a host-test suite | `cpp/tests/FooTests.cpp` (`void runFooTests()` no main) + forward-decl/call in `ProcParsersTests.cpp` + add `cpp/Foo.cpp` to `package.json` `native-test` script |
| Update a weight/severity | `cpp/SignalCatalog.cpp` `lookupSignal()` + README Signal Catalog table + `src/wrappers.ts` `signalReasons` text doesn't change but verify |
| Modify iOS artifact paths | `cpp/IOSMatchers.hpp` `IOS_ARTIFACT_PROBES` + `cpp/tests/IOSMatcherTests.cpp` pinned fixtures |
| Modify Android mountinfo logic | `cpp/ProcParsers.cpp` `parseMountinfoLine()` (use `-` separator) + `cpp/tests/DenyListFingerprintTests.cpp` / `OverlayFsTests.cpp` / `MountCorpusTests.cpp` |
| Modify scoring rules | `cpp/Scoring.hpp` + `cpp/tests/ScoringTests.cpp` |
| Add a root package id | `HybridPackageManagerProbe.kt` map + `app.plugin.js` Set + `android/src/main/AndroidManifest.xml` `<queries>` (one commit, package-visibility test pins it) |
| Add a watchdog failure mode | `ProtectionMode` type union in `src/specs/ProtectionMode.ts` + `cpp/HybridSecurityWatchdog.cpp` `run()` `switch` |
| Change `checkDetailed()` semantics | `cpp/HybridRootJailDetect.cpp` `checkDetailed()` + `cpp/DeviceRiskAssessment.cpp` `assessDevice()` — single source of truth; follow `is...Detected` derivation in `src/wrappers.ts` |

## Type/symbol search tips

- Symbol files (classes, types) live one-per-file in `src/specs/`. Nitro codegen requires named types.
- Pure helpers are header-only where possible (`cpp/Scoring.hpp`, `cpp/IOSMatchers.hpp`, parts of `cpp/InstallOriginResolver.hpp`).
- Host tests are flat in `cpp/tests/`, owned by `ProcParsersTests.cpp::main()`.
- The shared C++ core lives in `cpp/` (NOT `src/cpp/`); there is no JS bridge mismatch — `cpp-adapter.cpp` owns `JNI_OnLoad`.

## Things that DON'T live where you'd guess

- The `signalReasons` text catalog lives in `src/wrappers.ts` (NOT in `cpp/`); RN bridges require JS for human-readable strings. C++ emits signal ids only.
- The `DetectionEventCallback` telemetry hook lives in `src/wrappers.ts`; not a native concept.
- The C++ `ResolvedRootJailDetectOptions` struct (defaults: `minScore=40`, `timeoutMs=600`, `enablePlayIntegrity=false`) is the single source of option defaults; `cpp/DeviceRiskAssessment.hpp`. The TS `RootJailDetectOptions` JSDoc mirrors these.
- The `InstallOrigin` union is defined in `src/specs/InstallOrigin.ts` and the matching C++ stand-in lives in `cpp/InstallOriginResolver.hpp` (under `HOST_TEST` guard) and the nitrogen-generated one in `nitrogen/generated/shared/c++/InstallOrigin.hpp`. The two must stay in lock-step.