import { Platform } from 'react-native';

import RootJailDetect from './NativeRootJailDetect';

/**
 * Check if the device is compromised (rooted/jailbroken)
 *
 * This method performs multiple security checks to detect if the device
 * has been rooted (Android) or jailbroken (iOS).
 *
 * @returns Promise<boolean> - true if device is compromised, false otherwise
 *
 * @example
 * ```typescript
 * import { isDeviceCompromised } from 'react-native-device-security';
 *
 * const checkSecurity = async () => {
 *   try {
 *     const isCompromised = await isDeviceCompromised();
 *     if (isCompromised) {
 *       Alert.alert('Security Warning', 'This device appears to be rooted/jailbroken');
 *     }
 *   } catch (error) {
 *     console.error('Security check failed:', error);
 *   }
 * };
 * ```
 */
export async function isDeviceCompromised(): Promise<boolean> {
  try {
    const result = await RootJailDetect.isDeviceCompromised();
    return Boolean(result);
  } catch (error) {
    console.error('Error checking device security:', error);
    throw error;
  }
}

/**
 * Check if running in emulator (Android) or simulator (iOS)
 *
 * @returns Promise<boolean> - true if running in emulator/simulator
 */
export async function isEmulator(): Promise<boolean> {
  try {
    if (Platform.OS === 'android' && RootJailDetect.isEmulator) {
      return Boolean(await RootJailDetect.isEmulator());
    } else if (Platform.OS === 'ios' && RootJailDetect.isSimulator) {
      return Boolean(await RootJailDetect.isSimulator());
    }
    return false;
  } catch (error) {
    console.error('Error checking emulator status:', error);
    return false;
  }
}

/**
 * Check if debugger is attached (iOS only)
 *
 * @returns Promise<boolean> - true if debugger is attached
 */

export async function isDebuggerAttached(): Promise<boolean> {
  try {
    if (Platform.OS === 'ios' && RootJailDetect.isDebuggerAttached) {
      return Boolean(await RootJailDetect.isDebuggerAttached());
    }
    return false;
  } catch (error) {
    console.error('Error checking debugger status:', error);
    return false;
  }
}

export type { RootJailDetect };
export default {
  isDeviceCompromised,
  isEmulator,
  isDebuggerAttached,
};
