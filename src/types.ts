// Public type re-exports for the device-risk API.
//
// All public types live next to their Nitro specs under `src/specs/` so the
// TypeScript contract, the codegen, and the native implementations stay in
// sync. This file re-exports them so callers can import from a single path
// and so older import sites that targeted `src/types.ts` keep resolving.
//
// See README.md for the full API contract and error semantics.

export type {
  CompromiseAssessment,
  Confidence,
  DetectionSignal,
  DeviceRiskResult,
  Platform,
  ProtectionMode,
  RootJailDetectOptions,
  SecurityWatchdogOptions,
  Severity,
  SignalCategory,
  UrlSchemeOptions,
} from './specs';
