# iOS / Android build toolchain (validated on this machine)

## Machine-specific env vars (NOT in zshrc)

Per CLAUDE.md's "Native build commands" section, these are set per-shell-session:

```sh
export DEVELOPER_DIR="/Volumes/Xcode/Applications/Xcode.app/Contents/Developer"
export ANDROID_HOME="/Volumes/Xcode/Android/sdk"
export ANDROID_SDK_ROOT="/Volumes/Xcode/Android/sdk"
export JAVA_HOME="/usr/local/Cellar/openjdk@21/21.0.10/libexec/openjdk.jdk/Contents/Home"
```

`xcode-select` on this machine points at CommandLineTools which cannot build RN/CocoaPods — `DEVELOPER_DIR` overrides it for the process only.

## Why these are not `bun run turbo run build:*`

`turbo run build:ios|build:android` is CI-only. On a workstation:

- Turbo strips `DEVELOPER_DIR` from task env (not in `turbo.json` `build:ios.env`) — CocoaPods loses Xcode, fails
- Turbo may not forward custom `JAVA_HOME` to nested gradlew invocations on this toolchain mix

Use direct invocations instead:

```sh
# iOS: must come after first `pod install`
cd example/ios
xcodebuild -workspace RootJailDetectExample.xcworkspace \
  -scheme RootJailDetectExample -configuration Debug \
  -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 17' \
  -derivedDataPath build CODE_SIGNING_ALLOWED=NO build

# Android (single ABI keeps compile ~10min)
cd example/android
./gradlew app:bundleDebug --no-daemon --console=plain -PreactNativeArchitectures=arm64-v8a
```

## iOS build prerequisites

- `example/ios/Pods/` must exist (run `pod install` first; first run needs `~/Library/Caches/ReactNative/` pre-created for the hermes-engine tarball — use `create_directory` tool)
- Stale `Pods/` from a prebuild with mismatched codegen will error with "No podspec found for ReactAppDependencyProvider in build/generated/ios/..." — delete `Pods/` + `Podfile.lock` and rerun `pod install`
- `pod install` needs `unsandboxed: true` + `allow_all_hosts: true` (fetches from Maven Central + many CDN hosts; the heredoc-style `allow_hosts` list misses `repo1.maven.org`)
- `xcodebuild` CoreSimulatorService per-thread sandbox blocks — rerun with `unsandboxed: true` if it fails

## Android build prerequisites

- JDK 21 in `example/android/gradle.properties`:
  - `org.gradle.java.installations.auto-download=false`
  - `org.gradle.java.installations.auto-detect=false`
  - `org.gradle.java.installations.paths=...openjdk@21...`
  - **Do NOT delete those lines** — without them Gradle tries foojay auto-provisioning which fails on this kernel string.
- Library targets JVM 17 bytecode (`sourceCompatibility VERSION_17`) — JDK 21 runtime is fine, but Kotlin `jvmTarget = "17"` and app-level `compilerOptions.jvmTarget.set(JvmTarget.JVM_17)` MUST agree.

## AGP / Gradle daemon caught-spinner gotcha

Gradle 9.0.0 + AGP 8.12.0 (from `@react-native/gradle-plugin`) has been observed busy-spinning a daemon JVM on `:app:mergeDebugShaders`. The library compiles cleanly anyway. Recovery: `jps` → `kill <pid>` → retry with `--info`. Reproducible: downgrade Gradle wrapper to `8.x` known to match AGP 8.12.

**Never run two `./gradlew` invocations concurrently** — they fight over `~/.gradle/daemon/9.0.0/registry.bin.lock`.

## Release gates (release-it hooks, see `package.json`)

```sh
bun run release
```

Runs:

1. `before:bump`:
   - `bun run release:preflight` (typecheck, lint, jest, build, host-test) — fails → aborts **before** any version bump
   - `bun run release:android` (`./gradlew app:bundleDebug` arm64-v8a in `example/android`)
2. `after:bump`:
   - `bun run release:pods` (`pod install --no-repo-update` in `example/ios`)
   - `git add example/ios/Podfile.lock` (landed in the release commit so the lockfile tracks the **new** released version)

**Do NOT move `pod install` to `before:bump`** — podspec reads version from `package.json` at install time and would record the **old** version, recreating the drift this gate was built to prevent.

These hooks require the env vars above set in the shell that runs them.

## Codegen pinning

`nitrogen@0.36.1` is the only version validated against the committed `nitrogen/generated/` tree.

- CLI not in `node_modules/.bin`; `bun run specs` resolves via Bun workspace. If it errors with "command not found", run directly: `bunx nitrogen@0.36.1`.
- `bunx` first run may need `fs_write_paths: [/Users/gwako/.bun]` in the sandbox.
- Bumping nitrogen → regenerate + commit; hand-edits forbidden.