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
}