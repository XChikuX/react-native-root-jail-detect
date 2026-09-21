# Public JS wrapper semantics

## Two-tier error behavior (preserved from v1)

| Wrapper | Native rejection |
|---|---|
| `isDeviceCompromised()` | logs + **rethrows** |
| `checkDetailed()`, `configure()` | propagates directly |
| `isEmulator()`, `isDebuggerAttached()`, `getDetectionReasons()`, `getInstallOrigin()` | logs + safe fallback (`false`, `false`, `[]`, `'unknown'`) |
| `startSecurityWatchdog()`, `stopSecurityWatchdog()` | legacy synchronous signature — fire async without awaiting, **log only** |

The two-tier split is contract, not bug. Adding new public wrappers: choose the tier explicitly. Default to the **fallback tier** unless an exception is documented in the wrapper's JSDoc.

## Telemetry emits only on the structured path

`setDetectionCallback` fires from `checkDetailed()`/`assessRisk()` post-await — never from the boolean wrappers. Doc-invoked consumers poll `checkDetailed()` rather than the booleans when they need telemetry.

## `assessRisk` is a documented alias

Both `checkDetailed()` and `assessRisk()` resolve to `getRoot().checkDetailed()` and emit telemetry. Implemented as a second `Promise<...>::async` in C++ that delegates to `checkDetailed()`. There is **no** behavioral difference; both names hit the same native pass. Deprecated in user-facing copy in favor of `checkDetailed()`.

## `setDetectionCallback(undefined)` deregisters

The `_detectionCallback` module-level state lives in `src/wrappers.ts`. Jest tests reset it explicitly in `beforeEach` because it persists across tests in the same module instance (the `jest/environment.js` shim pins `testEnvironment`).

## Lazy root HybridObject

`_root` is module-level state. Wrappers and the watchdog share one detection core: created on first call, cached, never re-created. Tests mock `NitroModules.createHybridObject` BEFORE importing `src/index.tsx` so the cached handle points at the mock for the whole suite.

## `getInstallOrigin()` is informational-only

- Lives in `src/specs/RootJailDetect.nitro.ts` as a Promise method
- Returns `InstallOrigin = 'app_store' | 'testflight' | 'google_play' | 'other' | 'unknown'`
- Never contributes to `CompromiseAssessment.score` or `.compromised`
- Never produces a signal id on iOS (per repo policy: absence is legitimate in too many benign states)
- Android scored signal `android.install.origin.other` (low 10, reliability 0.35) is a separate path — both ship intentionally
- Falls in the **safe-fallback tier** (`'unknown'`) on native rejection