export interface RootJailDetectModule {
  /**
   * Check if the device is compromised (rooted on Android, jailbroken on iOS)
   * @returns Promise that resolves to true if device is compromised, false otherwise
   */
  isDeviceCompromised(): Promise<boolean>;

  /**
   * Check if the app is running in an emulator/simulator
   * @returns Promise that resolves to true if running in emulator/simulator
   */
  isEmulator?(): Promise<boolean>;

  /**
   * Check if a debugger is attached (iOS only)
   * @returns Promise that resolves to true if debugger is attached
   */
  isDebuggerAttached?(): Promise<boolean>;
}
