import { TurboModuleRegistry, type TurboModule } from 'react-native';

/**
 * Spec
 *
 * TypeScript interface that defines the contract between
 * the JavaScript layer and the native RootJailDetect module.
 *
 * This interface describes all security-related APIs
 * exposed by the native implementation.
 */
export interface Spec extends TurboModule {
  /**
   * Checks whether the current device is compromised
   * (rooted on Android or jailbroken on iOS).
   *
   * This method invokes native security heuristics
   * and returns the result asynchronously.
   *
   * @returns Promise that resolves to true if the device
   *          is compromised, false otherwise
   */
  isDeviceCompromised(): Promise<boolean>;

  /**
   * Determines whether the application is running
   * inside an Android emulator environment.
   *
   * This method is primarily used on Android devices.
   *
   * @returns Promise that resolves to true if running
   *          on an emulator, false otherwise
   */
  isEmulator?(): Promise<boolean>;

  /**
   * Determines whether the application is running
   * inside an iOS simulator environment.
   *
   * This method is primarily used on iOS devices.
   *
   * @returns Promise that resolves to true if running
   *          on a simulator, false otherwise
   */
  isSimulator?(): Promise<boolean>;

  /**
   * Checks whether a debugger is currently attached
   * to the running application process.
   *
   * This helps detect debugging, reverse engineering,
   * and runtime inspection attempts.
   *
   * @returns Promise that resolves to true if a debugger
   *          is attached, false otherwise
   */
  isDebuggerAttached?(): Promise<boolean>;
}

/**
 * RootJailDetect Native Module
 *
 * Retrieves and enforces the native RootJailDetect
 * TurboModule implementation at runtime.
 *
 * If the native module is not properly linked,
 * this call will throw an error.
 */
export default TurboModuleRegistry.getEnforcing<Spec>('RootJailDetect');
