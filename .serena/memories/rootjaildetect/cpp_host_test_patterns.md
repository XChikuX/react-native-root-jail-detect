# C++ host-test build (`bun run native-test`)

## Single-`main()` convention

`cpp/tests/` is a flat directory of fixture test files. ONE file owns `int main()`; sibling suites expose `run*Tests()` entry points forwarded from `main()`. **Adding a second `main()` breaks the link** (duplicate symbols).

`cpp/tests/ProcParsersTests.cpp` owns `main()`. It forwards to:

- `runDenyListFingerprintTests()` — DenyListFingerprintTests.cpp
- `runOverlayFsTests()` — OverlayFsTests.cpp
- `runMountCorpusTests()` — MountCorpusTests.cpp
- `runIOSMatcherTests()` — IOSMatcherTests.cpp
- `runScoringTests()` — ScoringTests.cpp
- `runInstallOriginResolverTests()` — InstallOriginResolverTests.cpp

Adding a new test suite: declare `void runMyNewSuite();` in `ProcParsersTests.cpp`, add a forward-decl block, call from `main()`. Never put `int main()` in a sibling file.

## HOST_TEST guard + host-side enums/structs

Pure C++ helpers meant to be host-tested cannot `#include` the nitrogen-generated `*.hpp` headers (they pull in NitroModules/jsi and won't resolve in a host clang build). The pattern in this repo:

- `cpp/SignalCatalog.hpp`, `cpp/Scoring.hpp`, `cpp/InstallOriginResolver.hpp`: each owns a `#if defined(ROOTJAILDETECT_HOST_TEST)` block with shape-agreeing stand-in enums/structs, then `#else` `#include "X.hpp"` for the generated code.
- Tests `-DROOTJAILDETECT_HOST_TEST` (see `native-test` script in `package.json`).
- Field types and enum values must MATCH the generated ones (e.g. `enum class Confidence { LOW, MEDIUM, HIGH, EXTREME }` literal order).

Forgetting this guard surfaces as `'Xxx.hpp' file not found` at host-test compile time.

## `native-test` script — the two gotchas

```sh
c++ -std=c++20 -Wall -Wextra -DROOTJAILDETECT_HOST_TEST -Icpp cpp/tests/*.cpp cpp/ProcParsers.cpp cpp/SignalCatalog.cpp cpp/InstallOriginResolver.cpp -o /tmp/anti-jailbreak-proc-tests && /tmp/anti-jailbreak-proc-tests
```

1. **Hardcoded `/tmp/`**: the `native-test` script writes its binary to `/tmp/anti-jailbreak-proc-tests`. Sandboxed terminals (and previous test runs owned by another user) can't delete that file. Override with `OUT="$TMPDIR/anti-jailbreak-proc-tests"` and a manual linker invocation if rerunning.
2. **Source list**: any new pure helper added under `cpp/` that's used by the tests MUST be added to this list explicitly — the glob `cpp/tests/*.cpp` only picks up test files; helpers must be named on the command line. `InstallOriginResolver.cpp` had to be added when shipped. (Better long-term: a tiny `cpp/tests/CMakeLists.txt`. Out of scope here.)

## `-Wreturn-mismatch` traps

Void `run*Tests()` must NOT have a `return 0;` (return type mismatch). When converting `int main() { … }` into a `void run*Tests()` entrypoint, drop the trailing `return 0;`.

## Test isolation pattern

Tests use `assert()` (not any test framework) and abort directly on failure. They do not print PASS markers — failure mode is a sudden abort. Don't add `EXPECT_*` macros; keep the host-test build dependency-free.

## Adding a new pure helper module

1. Create `cpp/Foo.hpp` / `cpp/Foo.cpp` with pure functions (no `#include` of platform headers, no fbjni, no NitroModules).
2. If it uses `DetectionSignal` / `SignalCategory` / `Severity` etc., add the `#if defined(ROOTJAILDETECT_HOST_TEST)` guard block matching the generated shape — or just rely on `SignalCatalog.hpp` for those types.
3. Create `cpp/tests/FooTests.cpp` with `void runFooTests()` entry point. Don't add `main()`.
4. Add `void runFooTests();` forward-decl + call in `cpp/tests/ProcParsersTests.cpp`.
5. Add `cpp/Foo.cpp` to the `native-test` script source list in `package.json`.
6. Add `cpp/Foo.cpp` to `android/CMakeLists.txt` `add_library(... SHARED ...)` (see Android side).