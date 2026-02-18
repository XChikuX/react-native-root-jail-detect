# React Native Root/Jail Detect

[![npm version](https://img.shields.io/npm/v/react-native-root-jail-detect.svg)](https://www.npmjs.com/package/react-native-root-jail-detect)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/rushikeshpandit/react-native-root-jail-detect/pulls)

A lightweight, blazing-fast React Native module to detect if a device is rooted (Android) or jailbroken (iOS). Perfect for apps that need to ensure device integrity for security-sensitive operations like banking, payments, or enterprise applications.

## Features

- **Fast** - Native implementation (Swift and Kotlin) for optimal performance
- **New Architecture Ready** - Fully supports React Native's new architecture (Fabric & TurboModules)
- **Google 16kb page size compliant** - Supporting Google's 16kb page size policy.
- **Simple API** - One method, returns a boolean. That's it.
- **Cross-platform** - Works seamlessly on both iOS and Android
- **Battle-tested** - Multiple detection methods for higher accuracy
- **Always Open Source** - MIT licensed, community-driven
- **Zero Dependencies** - No third-party libraries required

## Installation

```bash
npm install react-native-root-jail-detect
```

or

```bash
yarn add react-native-root-jail-detect
```

### iOS Setup

```bash
cd ios && pod install && cd .. && npx react-native run-ios
```

### Android Setup

For React Native 0.60+ with autolinking, no additional steps are required. Just rebuild your app:

```bash
npx react-native run-android
```

For manual linking (if needed), see [Manual Linking Guide](#manual-linking).

```bash
npx react-native run-android
```

## Usage

```typescript
import RootJailDetect from 'react-native-root-jail-detect';

// Basic usage
const checkDeviceSecurity = async () => {
  try {
    const isCompromised = await RootJailDetect.isDeviceRooted();
    
    if (isCompromised) {
      console.warn('Device is rooted/jailbroken!');
      // Handle accordingly - show warning, restrict features, etc.
    } else {
      console.log('Device is secure');
    }
  } catch (error) {
    console.error('Error checking device security:', error);
  }
};

// Call it when needed
checkDeviceSecurity();
```

### Real-world Example

```typescript
import React, { useEffect, useState } from 'react';
import { View, Text, StyleSheet, Alert } from 'react-native';
import RootJailDetect from 'react-native-root-jail-detect';

const App = () => {
  const [isSecure, setIsSecure] = useState<boolean | null>(null);

  useEffect(() => {
    checkDeviceSecurity();
  }, []);

  const checkDeviceSecurity = async () => {
    try {
      const isRooted = await RootJailDetect.isDeviceRooted();
      setIsSecure(!isRooted);

      if (isRooted) {
        Alert.alert(
          'Security Warning',
          'This device appears to be rooted/jailbroken. Some features may be restricted.',
          [{ text: 'OK' }]
        );
      }
    } catch (error) {
      console.error('Security check failed:', error);
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Device Security Status</Text>
      {isSecure === null ? (
        <Text>Checking...</Text>
      ) : (
        <Text style={isSecure ? styles.secure : styles.insecure}>
          {isSecure ? 'Secure' : 'Compromised'}
        </Text>
      )}
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: 'center', alignItems: 'center' },
  title: { fontSize: 24, fontWeight: 'bold', marginBottom: 20 },
  secure: { fontSize: 18, color: 'green' },
  insecure: { fontSize: 18, color: 'red' },
});

export default App;
```

## API Reference

### `isDeviceRooted()`

Returns a Promise that resolves to a boolean indicating whether the device is rooted (Android) or jailbroken (iOS).

**Returns:** `Promise<boolean>`

**Platform:** iOS, Android

**Example:**
```typescript
const isCompromised = await RootJailDetect.isDeviceRooted();
```


### `isEmulator()`

Returns a Promise that resolves to a boolean indicating whether the application is running on Emulator (Android) or Simulator (iOS).

**Returns:** `Promise<boolean>`

**Platform:** iOS, Android

**Example:**
```typescript
const isCompromised = await RootJailDetect.isEmulator();
```


### `isDebuggerAttached()`

Returns a Promise that resolves to a boolean indicating whether the debugger is attached to application.

**Returns:** `Promise<boolean>`

**Platform:** iOS, Android

**Example:**
```typescript
const isCompromised = await RootJailDetect.isDebuggerAttached();
```

## Detection Methods

### Android (Root Detection)

The module employs multiple detection techniques for comprehensive coverage:

1. **Build Tags Check** - Detects test-keys in build signature
2. **Binary Detection** - Scans for common root binaries (su, Superuser.apk)
3. **Runtime Execution** - Attempts to execute root commands

Common paths checked:
- `/system/app/Superuser.apk`
- `/sbin/su`
- `/system/bin/su`
- `/system/xbin/su`
- `/data/local/xbin/su`
- And more...

### iOS (Jailbreak Detection)

Multiple detection methods for accurate jailbreak identification:

1. **File System Checks** - Looks for jailbreak-related files and apps
2. **URL Scheme Detection** - Tests for Cydia URL schemes
3. **Sandbox Integrity** - Attempts to write outside the app sandbox

Common indicators checked:
- `/Applications/Cydia.app`
- `/Library/MobileSubstrate/`
- `/bin/bash`
- `/usr/sbin/sshd`
- And more...

## Manual Linking

If autolinking doesn't work, follow these steps:

### Android

1. Add to `android/settings.gradle`:
```gradle
include ':react-native-root-jail-detect'
project(':react-native-root-jail-detect').projectDir = new File(rootProject.projectDir, '../node_modules/react-native-root-jail-detect/android')
```

2. Add to `android/app/build.gradle`:
```gradle
dependencies {
    implementation project(':react-native-root-jail-detect')
}
```

3. Register in `MainApplication.kt`:
```kotlin
import com.rootjaildetect.RootJailDetectPackage

override fun getPackages(): List<ReactPackage> =
    PackageList(this).packages.apply {
        add(RootJailDetectPackage())
    }
```

## Use Cases

Perfect for apps requiring enhanced security:

- **Banking & Financial Apps** - Protect sensitive transactions
- **Enterprise Applications** - Enforce corporate security policies  
- **Gaming Apps** - Prevent cheating and unauthorized modifications
- **Security Apps** - Ensure device integrity for VPN, password managers
- **MDM Solutions** - Mobile device management compliance
- **Payment Gateways** - PCI-DSS compliance requirements

## Important Notes

- **Not Foolproof:** Sophisticated root/jailbreak concealment tools may bypass detection
- **Use as Part of Security Strategy:** Combine with other security measures (SSL pinning, code obfuscation, etc.)
- **Graceful Degradation:** Consider UX - don't block legitimate users unnecessarily
- **Regular Updates:** Root/jailbreak methods evolve; keep the library updated

## Contributing

We love contributions!

PRs are always welcome. Whether it's:
- Bug fixes
- New features
- Documentation improvements
- Adding tests
- Performance optimizations

### How to Contribute

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Found a bug? Have a feature request? [File an issue](https://github.com/rushikeshpandit/react-native-root-jail-detect/issues) on GitHub!

## License

MIT © Rushikesh Pandit

This project is and will always remain open source. Free to use, modify, and distribute.

## Acknowledgments

Built with ❤️ in India for the React Native community.

Special thanks to all [contributors](https://github.com/rushikeshpandit/react-native-root-jail-detect/graphs/contributors) who help make this library better!

## Links

- [GitHub Repository](https://github.com/rushikeshpandit/react-native-root-jail-detect)
- [npm Package](https://www.npmjs.com/package/react-native-root-jail-detect)
- [Issue Tracker](https://github.com/rushikeshpandit/react-native-root-jail-detect/issues)
- [Changelog](https://github.com/rushikeshpandit/react-native-root-jail-detect/blob/main/CHANGELOG.md)

---

**Star the repo if you find it useful!**

Made with ❤️ in India for the React Native community
