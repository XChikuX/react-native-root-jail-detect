# Deferred signals & open items (from v0.13.0 postmortems)

Captured here for future revisits — not part of the shipped code, and not for "just check if needed" re-execution. Items move OUT of this memory once a fixture exists (corpus) or are removed.

## Deliberately not shipped (don't add without a corpus sample)

- `android.selinux.spoofed` — circumstantial inference fires on legit custom ROMs. Currently reading raw SELinux enforce; do not add a "spoofed" signal without a `cpp/tests/SELinuxCorpusTests.cpp`.
- `setprop` self-check (`props.writable_ro`) — unknown FP/FN profile.
- Namespace diff via `/proc/1/mountinfo` — unreadable on stock Android (dead code). Future shape: `statx(2)` with `STATX_ATTR_MOUNT_ROOT` (kernel-aware overlay detection).
- Abstract-socket probes (`@ksud`, `@apd`) — KernelSU moved su to a kernel supercall (no userspace socket); Magisk's daemon socket is filesystem-backed under its randomized DenyList-hidden tmpdir (no verifiable ground truth).
- Local Play Integrity token string matching — only guessable from device state, never from keybox string. Server-side only.

## Deferred (server-attestation)

- Play Integrity token acquisition (token-issuance, keybox revocation checks). `RootJailDetectOptions.enablePlayIntegrity` exists in the config as a documented deferred option; no client implementation.
- Hardware key attestation. Same gate: needs a verifier.

## Out of scope (security policy)

- Library self-hardening / anti-hook.
- Out-of-process Frida gadgets detection.
- Code obfuscation.
- Server-side revocation lists.

## Open measurement items (on-device corpus)

When WS-F/WS-I-F on-device measurement tooling is available:

- WS-F (Android): capture raw app-namespace `/proc/self/mountinfo` (adb shell sees a *different* namespace; needs in-process capture). Transplant real mountinfo dumps into `cpp/tests/MountCorpusTests.cpp` with device/OS/date provenance.
- WS-I-F (iOS): add live scheme-probe check post-plist-fix, rootless `/var/jb` + dangling-symlink TPs, dyld provenance TPs, roothide expected-FN pinning, TrollStore zero-observable confirmation.
- Hypothesis signals are EXPECTED no-fires on a fully-cleaned modern Magisk namespace. Absence of signals is not evidence of a clean device. If evidence-backed signals don't reach `minScore`, **add signals** — never inflate weights.

## Weight-recovery gates

We may raise `denylist_unmount` (currently 5) and `overlayfs` (currently 10) only after:

1. ZERO clean-corpus false positives
2. ≥1 committed reproducible TP fixture (Magisk/Kitsune partial cleanup; KSU/APatch root-level overlays; adb-remount/GSI)
3. Updated `cpp/tests/MountCorpusTests.cpp` clean fixtures

Current clean fixtures in `cpp/tests/MountCorpusTests.cpp` cover stock-Pixel, stock-Samsung, and a Xiaomi-style corpus.

## Parked signal ids (no active probe)

| Id | Weight | Notes |
|---|---|---|
| `ios.sideload.trollstore` | low 5, rel 0.35 | Re-arm only with verified observables (TrollStore hijacks `apple-magnifier://` since v1.3) |
| `ios.jailbreak.dopamine` | parked | Profile marker probe; rootless jailbreaks detected via `/var/jb` |
| `ios.jailbreak.palera1n` | parked | Same as above |

Re-arming a parked id requires:

- A source-cited observable (jailbreak tool docs or source)
- Clean-fixture confirmation (no FP on stock iOS / common iOS sandbox states)
- Updated `cpp/IOSMatchers.hpp` and `cpp/tests/IOSMatcherTests.cpp` pinning the rule

## External references (recheck dates before acting)

- Magisk master `native/src/core/mount.rs` `revert_unmount()` + `zygisk/hook.cpp` `DO_REVERT_UNMOUNT` — current as of Aug 2026
- AOSP `fs_mgr/README.overlayfs.md`
- AnyCheck issue #19 (2026-06-28) — stock Xiaomi OEM overlays
- Apple `canOpenURL` docs (undeclared → always false; cap 50 linked≥iOS 15, 25 linked≥iOS 27)
- The Apple Wiki "Roothide" (2026-08-03)
- opa334/TrollStore README (`apple-magnifier://` hijack since v1.3, 2022-10)

## External reference: reveny/Android-Native-Root-Detector

- Closed-source prebuilt `.so`; only `strings.xml` is public.
- Claims DenyList-surviving vectors via structural mount fingerprints + HMA/risky packages. The structural claim only holds for **incomplete** cleanups (see `denylist_unmount` documented FN profile).