# Watchdog thread safety — runtime invariants

`cpp/HybridSecurityWatchdog.*` is the most fragile piece in the C++ core (long-lived mutable state + background thread + JS-callable async API). The invariants below are NOT optional.

## Use-after-free class (fixed in v0.9.1)

`start()` and `stop()` are `Promise<void>::async(...)` (run on Nitro worker threads). Lambdas capture:

```cpp
std::shared_ptr<HybridSecurityWatchdog> self =
  std::dynamic_pointer_cast<HybridSecurityWatchdog>(shared_from_this());
return Promise<void>::async([self, this, options]() { ... });
```

Raw `this` capture = use-after-free crash if JS runtime teardown/reload destroys the watchdog mid-transition. Symptom: native abort with no JS log. **Always capture `self` in watchdog async paths.** Don't refactor `start`/`stop` to capture `this` only.

## Two-mutex serialization

- `_startMutex` (held for the entire decision phase) so two concurrent Nitro `start()` calls cannot both observe "not running" and both spawn a `run()` thread. Held only for the duration of: (1) check `_isRunning`, (2) move old thread handle, (3) launch new thread. Never held while running detection or thread actions.
- `_lifecycleMutex` (held briefly during `_wake.wait_for()` in `run()` and during thread-handle move in `start`/`stop`). Backs the condition variable and protects the `_thread` handle.

`run()` takes `_lifecycleMutex` ONLY during its timed sleep. So the `thread.join()` in `start()`/`stop()` (which briefly takes `_lifecycleMutex` to move the handle, then joins outside the lock) cannot deadlock against `run()`.

## `THROW_EXCEPTION` demoted to logged warning

Documented in `src/specs/ProtectionMode.ts`. The watchdog runs each check on a background thread; it cannot synchronously throw into the JS runtime. Logged as "would throw for a compromised device." Retained in the union for API completeness + future JS event mechanism.

## `TERMINATE` is destructive

`std::terminate()` ends the host process. **Never exercise in automated tests or routine manual validation.** Default `LOG_ONLY` for safe testing. To react to a compromised device from JS code: poll `checkDetailed()` (or the legacy `isDeviceCompromised()`) from the JS thread and throw there.

## Repeated start/stop correctness

Both `start()` (when already running) and `stop()` (when not running) are no-ops and resolve successfully. Tested in `cpp/tests/...` (?) — verify when changing.

## Interval validation

`intervalMs` must be positive finite. Throw `std::invalid_argument` for ≤0 or non-finite. The thrown exception escapes the `Promise<void>::async` lambda and rejects the resolved Promise back to JS; the JS wrapper (`startSecurityWatchdog`) doesn't await it (legacy sync signature) but logs.

## Validator: `setInterval` non-positive range

`run()` uses `std::chrono::duration<double, std::milli>` — fractional interval values work but produce a non-integer-ms sleep. Documented behavior. Don't tighten to integer ms.

## Lifecycle interaction with JS module-level state

The watchdog is created lazily by `HybridRootJailDetect::getWatchdog()` and shared across JS calls (one handle per JS module instance). JS-side: `_watchdog` in `HybridRootJailDetect._watchdog` is `std::shared_ptr<HybridSecurityWatchdogSpec>` (so the JS handle never destroys the native one independently). Reap on `HybridRootJailDetect` destruction.

## Debug markers

- `SecurityWatchdog detected a compromised device.` — LOG_ONLY path, on iOS also logged via `os_log` (see #if defined(__APPLE__) block) so it surfaces in `xcrun simctl spawn booted log show` and Console.app, not just stderr.
- `SecurityWatchdog would throw for a compromised device.` — demoted THROW_EXCEPTION
- No log line on TERNIMATE — it `std::terminate()`s.