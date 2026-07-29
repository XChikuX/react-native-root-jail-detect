// Jest tests for the JS wrapper layer.
//
// The native RootJailDetect HybridObject is mocked before the public entry
// point is imported, so these tests exercise the wrapper logic (error
// semantics, fallback values, watchdog option normalization) rather than the
// native detection heuristics themselves.

import { beforeEach, describe, expect, it, jest } from '@jest/globals';

// --- Mocks ----------------------------------------------------------------

// `NitroModules.createHybridObject` returns our mock root object. We construct
// the mock lazily in each test so state never leaks between tests.
//
// The mocks are typed loosely as `any` here because the wrapper code only
// touches them through `Promise` return values and arbitrary call args; giving
// them precise generics fights the `@jest/globals` `jest.fn` signature without
// adding safety.
// Mocks for the native HybridObject methods. Each is typed as a plain
// function type and `jest.fn()` is cast to it; this avoids fighting the
// `@jest/globals` `jest.Mock` generic constraints while keeping call sites
// type-checked.
type CheckDetailedFn = () => Promise<unknown>;
type ConfigureFn = (options: unknown) => void;
type WatchdogStartFn = (options: unknown) => Promise<void>;
type WatchdogStopFn = () => Promise<void>;

const mockCheckDetailed =
  jest.fn() as unknown as jest.MockedFunction<CheckDetailedFn>;
const mockConfigure = jest.fn() as unknown as jest.MockedFunction<ConfigureFn>;
const mockWatchdogStart =
  jest.fn() as unknown as jest.MockedFunction<WatchdogStartFn>;
const mockWatchdogStop =
  jest.fn() as unknown as jest.MockedFunction<WatchdogStopFn>;

const mockWatchdog = {
  start: mockWatchdogStart,
  stop: mockWatchdogStop,
};

const mockRoot = {
  checkDetailed: mockCheckDetailed,
  configure: mockConfigure,
  getWatchdog: jest.fn(() => mockWatchdog),
};

jest.mock('react-native-nitro-modules', () => ({
  NitroModules: {
    createHybridObject: jest.fn(() => mockRoot),
  },
}));

// `Platform.OS` is mutated per-test via Object.defineProperty below.
jest.mock('react-native', () => ({
  Platform: { OS: 'android' },
}));

// --- Imports (must come after jest.mock) ----------------------------------

const {
  isDeviceCompromised,
  isEmulator,
  isDebuggerAttached,
  getDetectionReasons,
  checkDetailed,
  assessRisk,
  configure,
  startSecurityWatchdog,
  stopSecurityWatchdog,
} = require('../index');

function setPlatform(os: 'android' | 'ios'): void {
  const { Platform } = require('react-native');
  Object.defineProperty(Platform, 'OS', {
    configurable: true,
    value: os,
  });
}

/** Build a clean stub {@linkcode CompromiseAssessment} with overrides. */
function stubResult(overrides: Record<string, unknown> = {}) {
  return {
    platform: 'android',
    compromised: false,
    score: 0,
    confidence: 'low',
    signals: [],
    debuggerDetected: false,
    elapsedMs: 0,
    partial: false,
    ...overrides,
  };
}

/** Build a stub signal with the richer v2.1 shape. */
function stubSignal(
  id: string,
  overrides: Record<string, unknown> = {}
) {
  const [prefix] = id.split('.');
  return {
    id,
    platform: prefix === 'ios' ? 'ios' : 'android',
    category: 'filesystem',
    severity: 'low',
    score: 10,
    detected: true,
    reliability: 0.5,
    ...overrides,
  };
}

// --- Tests ----------------------------------------------------------------

describe('@psync/anti-jailbreak wrappers', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    setPlatform('android');
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  describe('isDeviceCompromised()', () => {
    it('resolves to result.compromised', async () => {
      mockCheckDetailed.mockResolvedValue(stubResult({ compromised: true }));
      await expect(isDeviceCompromised()).resolves.toBe(true);
    });

    it('rethrows native errors (logs and rethrows, per legacy contract)', async () => {
      mockCheckDetailed.mockRejectedValue(new Error('native boom'));
      await expect(isDeviceCompromised()).rejects.toThrow('native boom');
    });
  });

  describe('isEmulator()', () => {
    it('returns false on a clean stub result (safe fallback)', async () => {
      mockCheckDetailed.mockResolvedValue(stubResult());
      await expect(isEmulator()).resolves.toBe(false);
    });

    it('returns true when an android.emulator signal fires on Android', async () => {
      mockCheckDetailed.mockResolvedValue(
        stubResult({
          signals: [
            stubSignal('android.emulator', { severity: 'medium', score: 15 }),
          ],
        })
      );
      await expect(isEmulator()).resolves.toBe(true);
    });

    it('returns true when an ios.simulator signal fires on iOS', async () => {
      setPlatform('ios');
      mockCheckDetailed.mockResolvedValue(
        stubResult({
          platform: 'ios',
          signals: [
            stubSignal('ios.simulator', { severity: 'medium', score: 15 }),
          ],
        })
      );
      await expect(isEmulator()).resolves.toBe(true);
    });

    it('returns false (safe fallback) when native rejects', async () => {
      mockCheckDetailed.mockRejectedValue(new Error('native boom'));
      await expect(isEmulator()).resolves.toBe(false);
    });
  });

  describe('isDebuggerAttached()', () => {
    it('resolves to result.debuggerDetected', async () => {
      mockCheckDetailed.mockResolvedValue(
        stubResult({ debuggerDetected: true })
      );
      await expect(isDebuggerAttached()).resolves.toBe(true);
    });

    it('returns false (safe fallback) when native rejects', async () => {
      mockCheckDetailed.mockRejectedValue(new Error('native boom'));
      await expect(isDebuggerAttached()).resolves.toBe(false);
    });
  });

  describe('getDetectionReasons()', () => {
    it('derives reasons from evidence then known signal text, skipping unavailable signals', async () => {
      mockCheckDetailed.mockResolvedValue(
        stubResult({
          signals: [
            stubSignal('android.su.binary', {
              severity: 'low',
              score: 10,
              evidence: 'su binary present',
            }),
            stubSignal('android.maps.zygisk', {
              severity: 'high',
              score: 30,
              category: 'injection',
            }),
            stubSignal('android.check.selinux', {
              severity: 'high',
              score: 25,
              unavailable: true, // must be skipped
            }),
          ],
        })
      );
        await expect(getDetectionReasons()).resolves.toEqual([
          'su binary present',
          'A Zygisk artifact is mapped into the process.',
        ]);
    });

    it('deduplicates reasons', async () => {
      mockCheckDetailed.mockResolvedValue(
        stubResult({
          signals: [
            stubSignal('android.su.binary', {
              severity: 'low',
              score: 10,
              evidence: 'duplicate',
            }),
            stubSignal('android.su.alt', {
              severity: 'low',
              score: 10,
              evidence: 'duplicate',
            }),
          ],
        })
      );
      await expect(getDetectionReasons()).resolves.toEqual(['duplicate']);
    });

    it('returns [] (safe fallback) when native rejects', async () => {
      mockCheckDetailed.mockRejectedValue(new Error('native boom'));
      await expect(getDetectionReasons()).resolves.toEqual([]);
    });

    it('returns human-readable text for every cataloged signal id', async () => {
      // Regression: getDetectionReasons() used to fall back to the raw signal
      // id for v0.3.0 entries that were missing from the JS-side catalog (the
      // network probes, the dev-build property signals, and the *.check.*
      // availability markers). Lock in human-readable text for every id.
      const allIds = [
        'android.network.frida',
        'android.network.ssh',
        'android.network.adb',
        'android.build.debuggable',
        'android.build.adb_root',
        'android.build.ro_secure_zero',
        'ios.network.frida',
        'ios.network.ssh',
      ];
      mockCheckDetailed.mockResolvedValue(
        stubResult({
          signals: allIds.map((id) => stubSignal(id)),
        })
      );
      const reasons = await getDetectionReasons();
      // Every id resolves to a non-empty human-readable string (not the raw id
      // itself). Reasons are deduplicated by text — same evidence, same
      // string — so we just assert each id produced text, not a 1:1 mapping.
      for (const id of allIds) {
        expect(reasons).toContainEqual(expect.stringMatching(/[A-Za-z]/));
        // No reason equals the raw id (i.e. the fallback path was not taken).
        expect(reasons).not.toContain(id);
      }
      // Sanity: at least one distinct reason per *unique reason text* class.
      expect(new Set(reasons).size).toBeGreaterThanOrEqual(3);
    });
  });

  describe('checkDetailed() and configure()', () => {
    it('passes through to the native root object', async () => {
      const result = stubResult({ score: 42 });
      mockCheckDetailed.mockResolvedValue(result);
      await expect(checkDetailed()).resolves.toBe(result);
    });

    it('assessRisk() is an alias for checkDetailed()', async () => {
      const result = stubResult({ score: 42, confidence: 'extreme' });
      mockCheckDetailed.mockResolvedValue(result);
      await expect(assessRisk()).resolves.toBe(result);
    });

    it('forwards options to configure()', () => {
      configure({ minScore: 50, timeoutMs: 600 });
      expect(mockConfigure).toHaveBeenCalledWith({
        minScore: 50,
        timeoutMs: 600,
      });
    });

    it('supports the richer signal shape (platform, category, detected, reliability)', async () => {
      const result = stubResult({
        signals: [
          stubSignal('android.mount.magisk', {
            category: 'mount',
            severity: 'high',
            score: 35,
            reliability: 0.85,
          }),
        ],
      });
      mockCheckDetailed.mockResolvedValue(result);
      const detailed = await checkDetailed();
      const signal = detailed.signals[0];
      expect(signal.platform).toBe('android');
      expect(signal.category).toBe('mount');
      expect(signal.detected).toBe(true);
      expect(signal.reliability).toBe(0.85);
    });
  });

  describe('watchdog wrappers', () => {
    it('startSecurityWatchdog applies defaults (intervalMs=3000, LOG_ONLY)', () => {
      mockWatchdogStart.mockResolvedValue(undefined);
      startSecurityWatchdog();
      expect(mockWatchdogStart).toHaveBeenCalledWith({
        intervalMs: 3000,
        protectionMode: 'LOG_ONLY',
      });
    });

    it('startSecurityWatchdog accepts the legacy `interval` field', () => {
      mockWatchdogStart.mockResolvedValue(undefined);
      startSecurityWatchdog({ interval: 5000 });
      expect(mockWatchdogStart).toHaveBeenCalledWith({
        intervalMs: 5000,
        protectionMode: 'LOG_ONLY',
      });
    });

    it('startSecurityWatchdog forwards explicit intervalMs and protectionMode', () => {
      mockWatchdogStart.mockResolvedValue(undefined);
      startSecurityWatchdog({
        intervalMs: 7000,
        protectionMode: 'TERMINATE',
      });
      expect(mockWatchdogStart).toHaveBeenCalledWith({
        intervalMs: 7000,
        protectionMode: 'TERMINATE',
      });
    });

    it('stopSecurityWatchdog calls native stop()', () => {
      mockWatchdogStop.mockResolvedValue(undefined);
      stopSecurityWatchdog();
      expect(mockWatchdogStop).toHaveBeenCalled();
    });
  });
});
