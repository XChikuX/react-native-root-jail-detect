// Jest tests for the JS wrapper layer.
//
// The native RootJailDetect HybridObject is mocked before the public entry
// point is imported, so these tests exercise the wrapper logic (error
// semantics, fallback values, watchdog option normalization) rather than the
// native detection heuristics themselves.

import { beforeEach, describe, expect, it, jest } from '@jest/globals';

// Minimal shims for the F3.2 drift-guard test below: the React Native
// tsconfig has no `@types/node`, but Babel-compiled CJS modules still provide
// `require` and `__dirname` at runtime.
declare function require(id: string): any;
declare const __dirname: string;

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
  setDetectionCallback,
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
    // The telemetry callback is module-level state; reset it so registrations
    // made in one test never leak into the next.
    setDetectionCallback(undefined);
  });

  describe('isDeviceCompromised()', () => {
    it('resolves to result.compromised', async () => {
      mockCheckDetailed.mockResolvedValue(stubResult({ compromised: true }));
      await expect(isDeviceCompromised()).resolves.toBe(true);
    });

    it('rethrows native errors (logs and rethrows, per legacy contract)', async () => {
      const consoleSpy = jest.spyOn(console, 'error');
      mockCheckDetailed.mockRejectedValue(new Error('native boom'));
      await expect(isDeviceCompromised()).rejects.toThrow('native boom');
      expect(consoleSpy).toHaveBeenCalledWith(
        'Error checking device security:',
        expect.any(Error)
      );
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
      const consoleSpy = jest.spyOn(console, 'error');
      mockCheckDetailed.mockRejectedValue(new Error('native boom'));
      await expect(isEmulator()).resolves.toBe(false);
      expect(consoleSpy).toHaveBeenCalledWith(
        'Error checking emulator status:',
        expect.any(Error)
      );
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
      const consoleSpy = jest.spyOn(console, 'error');
      mockCheckDetailed.mockRejectedValue(new Error('native boom'));
      await expect(isDebuggerAttached()).resolves.toBe(false);
      expect(consoleSpy).toHaveBeenCalledWith(
        'Error checking debugger status:',
        expect.any(Error)
      );
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
      const consoleSpy = jest.spyOn(console, 'error');
      mockCheckDetailed.mockRejectedValue(new Error('native boom'));
      await expect(getDetectionReasons()).resolves.toEqual([]);
      expect(consoleSpy).toHaveBeenCalledWith(
        'Error checking detection reasons:',
        expect.any(Error)
      );
    });

    it('falls back to raw signal id when evidence is missing and signal is unmapped', async () => {
      mockCheckDetailed.mockResolvedValue(
        stubResult({
          signals: [stubSignal('custom.unmapped.signal', { evidence: undefined })],
        })
      );
      await expect(getDetectionReasons()).resolves.toEqual([
        'custom.unmapped.signal',
      ]);
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
        'android.sandbox.write',
        'android.check.sandbox',
        'android.package_manager.root',
        'ios.network.frida',
        'ios.network.ssh',
        'ios.sandbox.write',
          'ios.check.sandbox',
          'android.maps.anon_injection',
          'android.package_manager.hma',
          'android.package_manager.risky',
          'android.modules.magisk',
          'android.modules.hiding',
          'android.modules.spoofing',
          'android.addon_d.magisk',
          'android.install_recovery',
          'android.hosts.writable',
          'android.custom_rom',
          'android.lineage',
          'android.lsposed.cache',
          'android.props.inconsistent_debuggable',
          'android.props.inconsistent_verifiedboot',
          'android.props.inconsistent_fingerprint',
          'android.magisk.disable_prop',
          'android.zygisk.variant.official',
          'android.zygisk.variant.assistant',
          'android.zygisk.variant.next',
          'android.zygisk.variant.rezygisk',
          'android.sandbox.write.system_dir',
          'android.cmdline.su_exec',
          'android.cmdline.magisk_exec',
          'android.env.path_magisk',
          'android.mount.magisk_chain',
          'android.mount.denylist_unmount',
          'android.mount.overlayfs',
          'android.check.modules',
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

    it('maps the PackageManagerProbe and sandbox signal ids to human-readable text', async () => {
      const newIds = [
        'android.sandbox.write',
        'android.check.sandbox',
        'android.package_manager.root',
        'ios.sandbox.write',
        'ios.check.sandbox',
      ];
      mockCheckDetailed.mockResolvedValue(
        stubResult({ signals: newIds.map((id) => stubSignal(id)) })
      );
      const reasons = await getDetectionReasons();
      expect(reasons).toContain(
        'A known root management package was detected via PackageManager.'
      );
      // The iOS sandbox-write reason was deliberately split from the Android
      // one (F6 of IOS_PLAN.md): a successful write outside the sandbox means
      // the process sandbox is absent or escaped, which deserves its own
      // accurate wording instead of deduping into the generic shared text.
      expect(reasons).toContain(
        'A write outside the app sandbox succeeded — the process sandbox is absent or escaped (an unsandboxing tweak, escaped entitlements, or active tampering).'
      );
      expect(reasons).toContain('A sandbox write to a restricted path succeeded.');
      expect(reasons).toContain(
        'The sandbox write test did not complete within the time budget.'
      );
      // Platform variants no longer share one text across this set, so the
      // five ids map to four distinct reasons; no raw signal id may leak
      // through the fallback path.
      expect(reasons).toHaveLength(4);
      for (const id of newIds) {
        expect(reasons).not.toContain(id);
      }
    });

    it('maps new Android static signals to human-readable reasons', async () => {
      mockCheckDetailed.mockResolvedValue(
        stubResult({
          signals: [
            stubSignal('android.maps.anon_injection'),
            stubSignal('android.package_manager.hma'),
            stubSignal('android.modules.magisk'),
            stubSignal('android.addon_d.magisk'),
          ],
        })
      );
      await expect(getDetectionReasons()).resolves.toEqual([
        'A cluster of executable anonymous memory mappings was found.',
        'A hiding or hooking-related package was detected via PackageManager.',
        'A readable Magisk module tree contains module metadata.',
        'A Magisk persistence script was found under addon.d.',
      ]);
    });

    it('maps the Magisk DenyList unmount fingerprint to human-readable text', async () => {
      mockCheckDetailed.mockResolvedValue(
        stubResult({
          signals: [
            stubSignal('android.mount.denylist_unmount', {
              category: 'mount',
              severity: 'low',
              score: 5,
              reliability: 0.4,
            }),
          ],
        })
      );
      await expect(getDetectionReasons()).resolves.toEqual([
        'The app mount namespace shows the structural fingerprint of Magisk DenyList unmount cleanup (tmpfs overlays over system paths).',
      ]);
    });

    it('prefers the redacted native evidence over the catalog text for the DenyList signal', async () => {
      mockCheckDetailed.mockResolvedValue(
        stubResult({
          signals: [
            stubSignal('android.mount.denylist_unmount', {
              category: 'mount',
              severity: 'low',
              score: 5,
              evidence: 'tmpfs-over-system-paths=/system,/vendor;residual-magisk-artifacts',
            }),
          ],
        })
      );
      await expect(getDetectionReasons()).resolves.toEqual([
        'tmpfs-over-system-paths=/system,/vendor;residual-magisk-artifacts',
      ]);
    });

    it('skips the DenyList signal when it is marked unavailable', async () => {
      mockCheckDetailed.mockResolvedValue(
        stubResult({
          signals: [
            stubSignal('android.mount.denylist_unmount', {
              category: 'mount',
              severity: 'low',
              score: 5,
              unavailable: true,
            }),
          ],
        })
      );
      await expect(getDetectionReasons()).resolves.toEqual([]);
    });

    it('maps the overlay-filesystem signal to human-readable text', async () => {
      mockCheckDetailed.mockResolvedValue(
        stubResult({
          signals: [
            stubSignal('android.mount.overlayfs', {
              category: 'mount',
              severity: 'medium',
              score: 10,
              reliability: 0.55,
            }),
          ],
        })
      );
      await expect(getDetectionReasons()).resolves.toEqual([
        'An overlay filesystem is mounted over a system partition (modified system image — adb remount, GSI, or systemless-overlay root).',
      ]);
    });

    it('surfaces the user-writable backing flag from the overlayfs evidence', async () => {
      mockCheckDetailed.mockResolvedValue(
        stubResult({
          signals: [
            stubSignal('android.mount.overlayfs', {
              category: 'mount',
              severity: 'medium',
              score: 10,
              evidence: 'overlay-over-system-paths=/system;user-writable-backing',
            }),
          ],
        })
      );
      await expect(getDetectionReasons()).resolves.toEqual([
        'overlay-over-system-paths=/system;user-writable-backing',
      ]);
    });
  });

  describe('setDetectionCallback() telemetry', () => {
    it('does not emit when no callback is registered', async () => {
      const spy = jest.fn();
      mockCheckDetailed.mockResolvedValue(stubResult({ score: 12 }));
      await checkDetailed();
      expect(spy).not.toHaveBeenCalled();
    });

    it('emits the assessment and metadata after checkDetailed() resolves', async () => {
      const result = stubResult({ score: 42, compromised: true });
      mockCheckDetailed.mockResolvedValue(result);
      const spy = jest.fn();
      setDetectionCallback(spy);

      await expect(checkDetailed()).resolves.toBe(result);

      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith(result, {
        platform: 'android',
        timestampMs: expect.any(Number),
      });
    });

    it('emits after assessRisk() too (alias path)', async () => {
      const result = stubResult({ score: 7, confidence: 'medium' });
      mockCheckDetailed.mockResolvedValue(result);
      const spy = jest.fn();
      setDetectionCallback(spy);

      await assessRisk();

      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith(result, {
        platform: 'android',
        timestampMs: expect.any(Number),
      });
    });

    it('reports Platform.OS in the event metadata', async () => {
      setPlatform('ios');
      mockCheckDetailed.mockResolvedValue(stubResult({ platform: 'ios' }));
      const spy = jest.fn();
      setDetectionCallback(spy);

      await checkDetailed();

      expect(spy).toHaveBeenCalledWith(
        expect.objectContaining({ platform: 'ios' }),
        { platform: 'ios', timestampMs: expect.any(Number) }
      );
    });

    it('setDetectionCallback(undefined) deregisters the callback', async () => {
      const spy = jest.fn();
      setDetectionCallback(spy);
      setDetectionCallback(undefined);
      mockCheckDetailed.mockResolvedValue(stubResult());

      await checkDetailed();

      expect(spy).not.toHaveBeenCalled();
    });

    it('does not emit when the native pass rejects', async () => {
      const spy = jest.fn();
      setDetectionCallback(spy);
      mockCheckDetailed.mockRejectedValue(new Error('native boom'));

      await expect(checkDetailed()).rejects.toThrow('native boom');
      expect(spy).not.toHaveBeenCalled();
    });

    it('swallows callback exceptions without failing checkDetailed()', async () => {
      const consoleSpy = jest.spyOn(console, 'error');
      const boom = new Error('telemetry boom');
      mockCheckDetailed.mockResolvedValue(stubResult({ score: 5 }));
      setDetectionCallback(() => {
        throw boom;
      });

      await expect(checkDetailed()).resolves.toEqual(
        expect.objectContaining({ score: 5 })
      );
      expect(consoleSpy).toHaveBeenCalledWith('Detection callback threw:', boom);
    });

    it('is exposed as a named export and on the default object', () => {
      const defaultExport = require('../index').default;
      expect(typeof setDetectionCallback).toBe('function');
      expect(defaultExport.setDetectionCallback).toBe(setDetectionCallback);
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

    it('logs console error when startSecurityWatchdog native promise rejects', async () => {
      const consoleSpy = jest.spyOn(console, 'error');
      const err = new Error('watchdog start failed');
      mockWatchdogStart.mockRejectedValue(err);

      startSecurityWatchdog();

      // Wait a tick for the fireAsync promise catch handler to run
      await new Promise<void>((resolve) => setTimeout(() => resolve(), 0));

      expect(consoleSpy).toHaveBeenCalledWith(
        'Failed to start security watchdog:',
        err
      );
    });

    it('logs console error when stopSecurityWatchdog native promise rejects', async () => {
      const consoleSpy = jest.spyOn(console, 'error');
      const err = new Error('watchdog stop failed');
      mockWatchdogStop.mockRejectedValue(err);

      stopSecurityWatchdog();

      // Wait a tick for the fireAsync promise catch handler to run
      await new Promise<void>((resolve) => setTimeout(() => resolve(), 0));

      expect(consoleSpy).toHaveBeenCalledWith(
        'Failed to stop security watchdog:',
        err
      );
    });
  });

  // F3.2 drift guard: the host-side fixture tests (`bun run native-test`)
  // compile a hand-declared `DetectionSignal` stand-in under
  // `ROOTJAILDETECT_HOST_TEST` (see `cpp/Scoring.hpp`). If the nitrogen-
  // generated struct ever changes shape, the stand-in would silently drift
  // and the fixture suite would validate fiction. This test parses the
  // committed generated header and asserts it still declares exactly the
  // field set the stand-in mirrors, so drift fails loudly in CI instead.
  describe('host-test stand-in drift guard (F3.2)', () => {
    const fs = require('fs') as { readFileSync(filePath: string, encoding: string): string };
    const pathMod = require('path') as { join(...parts: string[]): string };
    const generatedHeaderPath = pathMod.join(
      __dirname,
      '..',
      '..',
      'nitrogen',
      'generated',
      'shared',
      'c++',
      'DetectionSignal.hpp'
    );

    it('generated DetectionSignal declares the stand-in field set', () => {
      const header = fs.readFileSync(generatedHeaderPath, 'utf8');
      // Keep in sync with the stand-in in `cpp/Scoring.hpp` (order matters:
      // the stand-in is compared member-for-member by the fixture tests).
      const standInFields = [
        'id',
        'platform',
        'category',
        'severity',
        'score',
        'detected',
        'reliability',
        'evidence',
        'unavailable',
      ];
      const structBody = header.match(
        /struct DetectionSignal final \{([\s\S]*?)friend bool operator==/
      );
      expect(structBody).not.toBeNull();
      for (const field of standInFields) {
        expect(structBody?.[1]).toMatch(new RegExp(`\\b${field}\\s+SWIFT_PRIVATE`));
      }
      // No extra public data members beyond the stand-in set (a new field in
      // the generated struct must be mirrored into the stand-in).
      const declaredFields: string[] =
        structBody?.[1]?.match(/\b(\w+)\s+SWIFT_PRIVATE/g) ?? [];
      expect(
        declaredFields.map((f: string) => f.replace(/\s+SWIFT_PRIVATE/, ''))
      ).toEqual(standInFields);
    });
  });
});
