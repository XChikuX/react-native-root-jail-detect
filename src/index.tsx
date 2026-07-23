// Public entry point for `react-native-root-jail-detect`.
//
// This file is a barrel only. All detection logic lives in the native Nitro
// HybridObjects (`src/specs/*.nitro.ts`); legacy boolean wrappers live in
// `src/wrappers.ts`. Per the api-design rules, the only runtime declaration
// here is re-export of the wrapper functions and types.
//
// The detailed, scored API is the primary API going forward. The legacy
// published names (`isDeviceCompromised`, `isEmulator`, `isDebuggerAttached`,
// `getDetectionReasons`, `startSecurityWatchdog`, `stopSecurityWatchdog`) are
// preserved as thin wrappers over `checkDetailed()` so existing consumers do
// not need to change call sites.

export type {
  Confidence,
  DetectionSignal,
  DeviceRiskResult,
  Platform,
  ProtectionMode,
  RootJailDetectOptions,
  SecurityWatchdogOptions,
  Severity,
} from './specs';

export type { RootJailDetect, SecurityWatchdog } from './specs';

export {
  checkDetailed,
  configure,
  getDetectionReasons,
  isDebuggerAttached,
  isDeviceCompromised,
  isEmulator,
  startSecurityWatchdog,
  stopSecurityWatchdog,
} from './wrappers';

export type { LegacySecurityWatchdogOptions } from './wrappers';

// Backwards-compatible default export. Existing consumers that import the
// default object keep working unchanged.
import {
  checkDetailed as _checkDetailed,
  configure as _configure,
  getDetectionReasons as _getDetectionReasons,
  isDebuggerAttached as _isDebuggerAttached,
  isDeviceCompromised as _isDeviceCompromised,
  isEmulator as _isEmulator,
  startSecurityWatchdog as _startSecurityWatchdog,
  stopSecurityWatchdog as _stopSecurityWatchdog,
} from './wrappers';

export default {
  checkDetailed: _checkDetailed,
  configure: _configure,
  getDetectionReasons: _getDetectionReasons,
  isDebuggerAttached: _isDebuggerAttached,
  isDeviceCompromised: _isDeviceCompromised,
  isEmulator: _isEmulator,
  startSecurityWatchdog: _startSecurityWatchdog,
  stopSecurityWatchdog: _stopSecurityWatchdog,
};
