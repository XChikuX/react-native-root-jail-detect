// Public entry point for `@psync/anti-jailbreak`.
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
  CompromiseAssessment,
  Confidence,
  DetectionSignal,
  DeviceRiskResult,
  Platform,
  ProtectionMode,
  RootJailDetect,
  RootJailDetectOptions,
  SecurityWatchdog,
  SecurityWatchdogOptions,
  Severity,
  SignalCategory,
  UrlSchemeOptions,
} from './specs';

export {
  assessRisk,
  checkDetailed,
  configure,
  getDetectionReasons,
  isDebuggerAttached,
  isDeviceCompromised,
  isEmulator,
  setDetectionCallback,
  startSecurityWatchdog,
  stopSecurityWatchdog,
} from './wrappers';

export type { DetectionEventCallback, LegacySecurityWatchdogOptions } from './wrappers';

// Backwards-compatible default export. Existing consumers that import the
// default object keep working unchanged.
import {
  assessRisk as _assessRisk,
  checkDetailed as _checkDetailed,
  configure as _configure,
  getDetectionReasons as _getDetectionReasons,
  isDebuggerAttached as _isDebuggerAttached,
  isDeviceCompromised as _isDeviceCompromised,
  isEmulator as _isEmulator,
  setDetectionCallback as _setDetectionCallback,
  startSecurityWatchdog as _startSecurityWatchdog,
  stopSecurityWatchdog as _stopSecurityWatchdog,
} from './wrappers';

export default {
  assessRisk: _assessRisk,
  checkDetailed: _checkDetailed,
  configure: _configure,
  getDetectionReasons: _getDetectionReasons,
  isDebuggerAttached: _isDebuggerAttached,
  isDeviceCompromised: _isDeviceCompromised,
  isEmulator: _isEmulator,
  setDetectionCallback: _setDetectionCallback,
  startSecurityWatchdog: _startSecurityWatchdog,
  stopSecurityWatchdog: _stopSecurityWatchdog,
};
