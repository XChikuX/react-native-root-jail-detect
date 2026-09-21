# Native HybridObject construction & JNI classloader patterns

## Virtual-base constructor init rule (CRITICAL)

Every C++ HybridObject implementation constructor MUST explicitly initialize the virtual base: `HybridFoo() : HybridObject(TAG) {}`. The nitrogen-generated `Hybrid*Spec` bases inherit `HybridObject` **virtually**, so:

- A defaulted constructor (`= default`) invokes Nitro's **throwing** default `HybridObject()` instead
- The check runners (`runAndroidChecks`, `runIOSChecks`) are `noexcept` by design
- → Throwing escapes as `std::terminate` → SIGABRT with no JS log

This exact bug crashed consumer apps when the `PackageManagerProbe` stub was constructed as a fallback. It applies to:

- `HybridRootJailDetect`
- `HybridSecurityWatchdog`
- `HybridUrlSchemeProbe`
- `HybridPackageManagerProbe`
- `HybridAppStoreReceiptProbe`

When generating a new edge HybridObject, copy the pattern from `cpp/HybridAppStoreReceiptProbe.cpp` (newest precedent).

## HybridObjectRegistry lookup pattern

When C++ code needs to call a Swift/Kotlin edge HybridObject at check time (not load time):

```cpp
std::shared_ptr<HybridFooSpec> probe;
try {
  std::shared_ptr<margelo::nitro::HybridObject> object =
    margelo::nitro::HybridObjectRegistry::createHybridObject("Foo");
  probe = std::dynamic_pointer_cast<HybridFooSpec>(object);
} catch (...) {
  probe = nullptr;
}
if (!probe) {
  probe = std::make_shared<HybridFoo>();   // C++ stub fallback
}
```

`dynamic_pointer_cast` is required (not `static_pointer_cast`) — `HybridObject` is virtual. This pattern is in:

- `cpp/AndroidChecks.cpp:288` (PackageManager probe — see following section)
- `cpp/IOSChecks.cpp` (UrlScheme probe)
- `cpp/HybridRootJailDetect.cpp` (AppStoreReceipt probe for `getInstallOrigin`)

## Two-level fallback for Kotlin edges

`cpp-adapter.cpp` has a `try/catch` around `registerAllNatives()` that re-registers the pure-C++ HybridObjects individually if the generated registration throws. This is because the Kotlin `PackageManagerProbe` registration touches JVM classes at `JNI_OnLoad` time; R8/proguard renaming or missing classes in consumer apps makes `registerAllNatives()` throw. Without this guard, the throw escapes `JNI_OnLoad` and the process aborts at `System.loadLibrary` time with no JS log. The check-time registry lookup then resolves to the no-op C++ stub for that consumer.

## JNI ThreadScope for non-Java-created threads

JNI calls made from C++-created threads (Nitro worker pool, watchdog's raw `std::thread`) need:

```cpp
facebook::jni::ThreadScope::WithClassLoader([&] {
  // HybridObjectRegistry::createHybridObject(...) etc.
});
```

Natively-created threads resolve classes through the **boot classloader**, not the app classloader — so even a correctly-registered Kotlin probe appears missing without this wrapper. Used in `cpp/AndroidChecks.cpp:288` for `PackageManagerProbe`.

Watch for: only applies to JNI class lookup (Kotlin/Java side). C++→Swift interop is different — Swift edge probes are reached synchronously without classloader scoping.

## Watchdog lifecycle (use-after-free class bug)

`HybridSecurityWatchdog::start()` and `stop()` return `Promise<void>::async(...)`. Captures in those lambdas must be `std::shared_ptr<self>` (`std::dynamic_pointer_cast<HybridSecurityWatchdog>(shared_from_this())`), never raw `this`. Raw `this` was a use-after-free crash path that surfaced as a native abort with no JS log when JS runtime teardown/reload destroyed the watchdog mid-transition.

The pattern uses TWO mutexes:
- `_startMutex` (held for the entire start/stop decision) so two concurrent Nitro worker `start()` calls cannot both spawn `run()` threads.
- `_lifecycleMutex` (held only briefly during the timed sleep in `run()`) backs the `_wake` condition variable and protects the thread handle move/join.

`run()` takes `_lifecycleMutex` only during its `_wake.wait_for()` — so the join in `start()`/`stop()` cannot deadlock against `run()` sleeping on it. This is intentional.

## Promise chain semantics for setDetectionCallback

The telemetry callback (`setDetectionCallback`) fires from JS promise resolution, not from native. In `src/wrappers.ts` `checkDetailed()` and `assessRisk()` both invoke `maybeEmitDetectionEvent(result)` after awaiting `getRoot().checkDetailed()`. The legacy boolean wrappers (`isDeviceCompromised`, `isEmulator`, `isDebuggerAttached`) intentionally do NOT emit telemetry — telemetry is a structural-API thing in this repo.