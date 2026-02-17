import { TurboModuleRegistry, type TurboModule } from 'react-native';

export interface Spec extends TurboModule {
  isDeviceCompromised(): Promise<boolean>;
  isEmulator?(): Promise<boolean>;
  isSimulator?(): Promise<boolean>;
  isDebuggerAttached?(): Promise<boolean>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('RootJailDetect');
