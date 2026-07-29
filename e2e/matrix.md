# Device Matrix

Record release validation here. Do not infer physical-device integrity from an
emulator or simulator build.

| Profile | Build | Expected observations | Recorded result |
| --- | --- | --- | --- |
| Stock locked Android | release | No high root signals | Pending |
| Unlocked stock Android | release | `android.bootloader.unlocked` may fire | Pending |
| Magisk with Zygisk | release | Mount or mapped-artifact signal when visible | Pending |
| Magisk with DenyList | release | Document visible residual signals only | Pending |
| Hiding stack | release | Document observed signals and false negatives | Pending |
| KernelSU/APatch | release | Mount/root-manager signal when visible | Pending |
| Android emulator | debug | `android.emulator` | Pending |
| Stock iPhone | release | No jailbreak signal | Pending |
| Xcode-attached iPhone | debug | Debugger true, compromised false by default | Pending |
| Jailbroken iPhone | release | Document independently visible signal(s) | Pending |
