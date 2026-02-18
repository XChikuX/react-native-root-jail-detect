import { Platform } from 'react-native';

import RootJailDetect from './NativeRootJailDetect';

/**
 * Checks if the device is compromised (rooted on Android, jailbroken on iOS)
 * @returns {Promise<boolean>} A promise that resolves
 * to true if the device is compromised, false otherwise
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
 * Checks if the app is running in an emulator/simulator
 * @returns {Promise<boolean>} A promise that resolves
 * to true if running in emulator/simulator, false otherwise
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
 * Checks if a debugger is attached to the app (iOS only)
 * @returns {Promise<boolean>} A promise that resolves
 * to true if a debugger is attached, false otherwise
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
