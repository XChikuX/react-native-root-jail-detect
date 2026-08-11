import type { HybridObject } from 'react-native-nitro-modules';

/**
 * Android edge HybridObject for PackageManager enumeration of known root packages.
 *
 * This probes the Android PackageManager for installed packages that are commonly
 * associated with root access (Magisk, SuperSU, KingRoot, etc.). On iOS this
 * object is a no-op stub because PackageManager is Android-specific.
 */
export interface PackageManagerProbe extends HybridObject<{ ios: 'c++'; android: 'kotlin' }> {
  /**
   * Check if any known root management packages are installed.
   * Returns a list of detected package names.
   */
  getInstalledRootPackages(): string[];

  /** Check for hiding/framework manager packages such as HMA and LSPosed. */
  getInstalledHidingPackages(): string[];

  /** Check for applications associated with risky patching or piracy tools. */
  getInstalledRiskyPackages(): string[];
}
