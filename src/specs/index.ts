// Barrel for Nitro specs and their named codegen helper types.
//
// Each `.nitro.ts` file owns one HybridObject spec; each named codegen type
// (struct, string-literal union, options object) lives in its own focused
// `.ts` file because Nitro requires named types for native codegen. This file
// only re-exports — it does not define or branch.

export type { Confidence } from './Confidence';
export type { DetectionSignal } from './DetectionSignal';
export type { DeviceRiskResult } from './DeviceRiskResult';
export type { Platform } from './Platform';
export type { ProtectionMode } from './ProtectionMode';
export type { RootJailDetect } from './RootJailDetect.nitro';
export type { RootJailDetectOptions } from './RootJailDetectOptions';
export type { SecurityWatchdog } from './SecurityWatchdog.nitro';
export type { SecurityWatchdogOptions } from './SecurityWatchdogOptions';
export type { Severity } from './Severity';
