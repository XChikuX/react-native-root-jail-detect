# Detection Signals

`checkDetailed()` returns stable signal IDs. IDs are never renamed or reused;
weights may be adjusted as field evidence changes. A signal is heuristic evidence,
not proof that a user is malicious.

| ID | Platform | Severity | Weight | Meaning |
| --- | --- | --- | ---: | --- |
| `android.mount.magisk` | Android | high | 35 | Known Magisk, KernelSU, or APatch artifact in mount metadata. |
| `android.maps.zygisk` | Android | high | 30 | Zygisk artifact mapped into the app process. |
| `android.maps.lsposed` | Android | high | 30 | LSPosed/Xposed artifact mapped into the app process. |
| `android.maps.frida` | Android | high | 30 | Frida artifact mapped into the app process. |
| `android.maps.riru` | Android | high | 30 | Riru artifact mapped into the app process. |
| `android.selinux.permissive` | Android | high | 25 | SELinux reports permissive mode. Developer and custom-ROM devices can legitimately report this. |
| `android.root_manager.dir` | Android | medium | 20 | Accessible conventional root-manager location. |
| `android.bootloader.unlocked` | Android | medium | 20 | Verified boot reports an unlocked/orange state. |
| `android.emulator` | Android | medium | 20 | Multiple Android build properties indicate an emulator. |
| `android.su.binary` | Android | low | 10 | Conventional `su` location is accessible. |
| `android.build.test_keys` | Android | low | 10 | Build tags include `test-keys`; common on custom ROMs. |
| `android.mount.overlay` | Android | low | 10 | Known root artifact visible only in the app mount namespace. Namespace identity alone is never a signal. |
| `android.cmdline.instrumentation` | Android | high | 30 | Current command line exposes an instrumentation token. |
| `android.socket.instrumentation` | Android | high | 30 | Local socket metadata exposes an instrumentation token. |
| `android.debugger.tracerpid` | Android | informational | 0 | `TracerPid` is nonzero. |
| `ios.simulator` | iOS | medium | 20 | The process is running in the iOS simulator. |
| `ios.jailbreak.artifact` | iOS | medium | 20 | Conservative known jailbreak artifact is accessible. |
| `ios.dyld.hook` | iOS | high | 30 | Suspicious injection framework image is loaded. |
| `ios.debugger.sysctl` | iOS | informational | 0 | `sysctl` reports a debugger. |
| `android.check.maps` | Android | low | 0 | Memory maps check could not run or elapsed timeout budget. |
| `android.check.mounts` | Android | low | 0 | Mount metadata check could not run or elapsed timeout budget. |
| `android.check.selinux` | Android | low | 0 | SELinux check could not run or elapsed timeout budget. |
| `android.check.root_paths` | Android | low | 0 | Root paths check could not run or elapsed timeout budget. |
| `android.check.properties` | Android | low | 0 | System properties check could not run or elapsed timeout budget. |
| `android.check.debugger` | Android | low | 0 | Debugger check could not run or elapsed timeout budget. |
| `android.check.runtime` | Android | low | 0 | Runtime instrumentation check could not run or elapsed timeout budget. |
| `ios.check.jailbreak` | iOS | low | 0 | Jailbreak artifact check could not run or elapsed timeout budget. |
| `ios.check.dyld` | iOS | low | 0 | Loaded image scan could not run or elapsed timeout budget. |
| `ios.check.debugger` | iOS | low | 0 | Debugger check could not run or elapsed timeout budget. |

`*.check.*` signals are informational, zero-score signals with `unavailable:
true`. They mean a check could not run or the time budget elapsed, never that the
check was compromised.

Evidence is opt-in in debug builds and redacted to stable descriptions. Release
builds suppress evidence even if `includeEvidence` is configured.
