# Native project linking & build wiring

## Library name registration (NEVER rename)

`androidCxxLibName: "RootJailDetect"` in `nitro.json` is referenced by:

- `System.loadLibrary("RootJailDetect")` in the generated Kotlin (`nitrogen/generated/android/...`)
- `add_library(RootJailDetect SHARED ...)` in `android/CMakeLists.txt`
- `nitro.json` `androidCxxLibName` field
- App-level references in `example/react-native.config.js`

Renaming breaks `System.loadLibrary` silently. Don't.

## `nitro.json` autolinking map

5 HybridObjects registered:

| Key | Language |
|---|---|
| `RootJailDetect` | `c++` all (via the `"all"` key) |
| `SecurityWatchdog` | `c++` all |
| `UrlSchemeProbe` | `ios: swift`, `android: c++` |
| `PackageManagerProbe` | `ios: c++`, `android: kotlin` |
| `AppStoreReceiptProbe` | `ios: swift`, `android: c++` |

The `"all"` key is the modern Nitro syntax for C++-on-both platforms. Adding a new HybridObject:

1. Add a `src/specs/Foo.nitro.ts` spec (one HybridObject per file)
2. Add an entry to `nitro.json` `autolinking` with the per-platform language + class name
3. Re-run `bun run specs` (nitrogen codegen) — do NOT hand-edit `nitrogen/generated/`
4. Implement in `cpp/HybridFoo.{hpp,cpp}` (C++), `android/src/main/java/com/margelo/nitro/rootjaildetect/HybridFoo.kt` (Kotlin), or `ios/HybridFoo.swift` (Swift) — matching the language per platform
5. Wire into the no-op stub pattern when one platform is C++ and the other is native (see `rootjaildetect/native_object_lifecycle`)

## `nitrogen/generated/`

Committed AND shipped (see `rootjaildetect/build_artifacts_published` memory). Contains:

- `shared/c++/` — abstract specs (`Hybrid*Spec.hpp/.cpp`), struct/enum headers
- `android/` — `RootJailDetectOnLoad.{cpp,hpp,kt}` + autolinking `.cmake` and `.gradle`
- `ios/` — `RootJailDetectAutolinking.swift/.mm`, `RootJailDetect+autolinking.rb`, Swift-C++ bridge headers

When bumping nitrogen: regenerate and commit. Hand-edits forbidden.

## Generated Android registration

The Kotlin `RootJailDetectPackage` (`android/src/main/java/com/rootjaildetect/RootJailDetectPackage.kt`) calls `RootJailDetectOnLoad.initializeNative()` in a static `init {}` block — runs at class load. `getModule(name, ...)` returns `null` because Nitro modules self-register; the `ReactModuleInfoProvider` returns an empty map. See `example/react-native.config.js` to see how this is wired into the example app (`RootJailDetectPackage::class.java` import path).

## Generated iOS registration

`RootJailDetectAutolinking.swift` + `.mm` register the Swift-backed HybridObjects via Obj-C bridge. The `SWIFT_OBJC_INTEROP_MODE = objcxx` flag (set in `nitrogen/generated/ios/RootJailDetect+autolinking.rb`) is required for Swift↔C++ bridging.

## Podspec

`RootJailDetect.podspec` does:

- Pull in `ios/**/*.{h,m,mm,swift}` and `cpp/**/*.{hpp,cpp}`
- Exclude `cpp/cpp-adapter.cpp` (Android-only — pulls `<jni.h>`/`<fbjni/fbjni.h>`)
- Load `nitrogen/generated/ios/RootJailDetect+autolinking.rb` which calls `add_nitrogen_files(s)` to pull in specs/bridges

## `undef-platform-macros.h`

`android/undef-platform-macros.h` and CMake's `-include` flag force `#undef ANDROID` before every translation unit. Reason: NDK toolchain defines `ANDROID` macro on the command line, which collides with nitrogen-generated `Platform::ANDROID` enumerator (`Platform::ANDROID` expands to `Platform::1`). Platform detection in this repo uses `__ANDROID__` (with underscores) — undefining `ANDROID` is safe.

Never remove this force-include. Symptom of removal: enums compile with wrong ordinals, then `Platform::IOS == 0` check returns true everywhere.

## Kotlin annotation rule

Kotlin edge HybridObjects (currently `HybridPackageManagerProbe`) MUST have:

```kotlin
@DoNotStrip
@Keep
class HybridPackageManagerProbe : HybridPackageManagerProbeSpec() { ... }
```

JNI instantiates by class name; `DoNotStrip` keeps the class from R8 stripping. `Keep` is a defensive belt-and-suspenders for consumer-side proguard.

## Java class naming convention

`com.margelo.nitro.rootjaildetect.HybridPackageManagerProbe` (per-generate, per-spec class). The wrapper package `com.margelo.nitro.rootjaildetect` matches all five HybridObjects (one per `nitro.json` autolinking entry). Don't repackage.