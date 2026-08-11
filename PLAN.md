# PLAN — Closing the Detection Gap vs. Native Root Detector

> **Status:** Implemented (2026-08-11). Phases 1, 2, 4, 5 shipped; Phase 3 deferred by design.
> **Reference:** [`reveny/Android-Native-Root-Detector`](https://github.com/reveny/Android-Native-Root-Detector) v6.x–v7.7.0.
> **What's left:** on-device measurement (§6) and server-attested attestation (§5).

---

## 1. What this plan is about

A user on **LineageOS 16.2 + Magisk + Zygisk Assistant + Tricky Store + Play Integrity Fix**
reported that reveny's detector fires "Boot Integrity signals" and "Other signals" on their
device while this library did not. This plan mapped that gap and shipped the Android-side
static/runtime probes to close it.

**Important context:** reveny's detector ships as a closed, prebuilt `.so`. Only its
user-visible labels (strings.xml), release notes, and the user's device report are public.
Every inferred detection technique below is therefore labeled:

- ✅ **Evidence** — directly visible in the public repo or reported by the user.
- 🔬 **Hypothesis** — a plausible implementation of the closed `.so`; unverified, must be
  fixture-tested before it can carry meaningful weight.

Hypothesis-led signals ship as **low-weight corroboration** and are never the sole basis for
`compromised = true` (see the severity policy in §4).

---

## 2. Shipped (2026-08-11)

All Android work lives in shared C++ (`cpp/ProcParsers.*`, `cpp/AndroidProbes.*`,
`cpp/AndroidChecks.cpp`) plus the Kotlin `PackageManagerProbe` edge. No public TypeScript API
change; every new result surfaces as an additive `DetectionSignal` id.

| Area | Signal id(s) | Shipped severity / weight | Notes |
| --- | --- | --- | --- |
| Anonymous executable mappings | `android.maps.anon_injection` | low / 10 | ≥2 **unnamed** executable VMAs; named ART/JIT regions excluded (FP fix, commit `34e0904`). 🔬 |
| Zygisk variants | `android.zygisk.variant.{official,assistant,next,rezygisk}` | low / 5 each | Property-presence candidates only. 🔬 |
| Magisk module tree | `android.modules.{magisk,hiding,spoofing}` | low / 10 each | Unreadable tree → `android.check.modules` (unavailable), never "clean". Deadline-aware, capped at 128 entries. |
| Persistence markers | `android.addon_d.magisk` (medium / 20), `android.install_recovery` (low / 5) | ✅ evidence | User-pasted `/system/addon.d/99-magisk.sh`. |
| Hosts file | `android.hosts.writable` | low / 5 | Writability only; ad-blocking entries ignored. |
| Property inconsistencies | `android.props.inconsistent_{debuggable,verifiedboot,fingerprint}` (low / 5), `android.magisk.disable_prop` (low / 10) | 🔬 corroboration | Custom ROMs/OEM builds can disagree legitimately. |
| Custom ROM markers | `android.custom_rom` (low / 5), `android.lineage` (low / 5) | ✅ evidence | Provenance, not root proof. Weights reduced from 10 in commit `34e0904`. |
| PackageManager split | `android.package_manager.root` (high / 25), `.hma` (medium / 15), `.risky` (low / 5) | ✅ presence | Spec split into root/hiding/risky; `<queries>` + Expo plugin updated. HMA absence is not clean. |
| LSPosed cache | `android.lsposed.cache` | low / 10 | Presence ≠ active hook. |
| System-dir write | `android.sandbox.write.system_dir` | high / 30 | Should never succeed on stock. |
| PATH / exec probes | `android.cmdline.{su_exec,magisk_exec}` (low / 10), `android.env.path_magisk` (low / 5) | PATH walked natively | `popen("which …")` removed (commit `34e0904`) — no shell fork per pass. |
| Mount chain | `android.mount.magisk_chain` | low / 5 | Conservative layered-candidate rule. 🔬 |

Supporting changes:

- Default `timeoutMs` raised 400 → **600 ms** (`cpp/DeviceRiskAssessment.hpp`,
  `src/specs/RootJailDetectOptions.ts`, README).
- Host-side native fixture tests: `bun run native-test` (`cpp/tests/ProcParsersTests.cpp`,
  compiled with `-DROOTJAILDETECT_HOST_TEST`).
- Example app renders categories, a Module Tree notice, and a Property Consistency section.
- Signal catalog grew from ~38 to ~60 published ids.

### Shipped deltas vs. the original proposal

Per this plan's severity policy, 🔬 items landed lower than first proposed:

| Plan item | Proposed | Shipped |
| --- | --- | --- |
| Zygisk variants | maps/metadata fingerprints | property-presence candidates (low 5) |
| Modules | medium 15/20 | low 10/10/10 |
| Hosts writable | medium 15 | low 5 |
| Inconsistencies | low 10 | low 5 (magisk prop 10) |
| Custom ROM / Lineage | medium 15/20 | low 10 → later 5 |
| PackageManager HMA | medium 20 | medium 15 |
| LSPosed cache | high 25 | low 10 |
| cmdline/PATH | medium 20/15 | low 10/10/5 |
| Mount chain | medium 15 | low 5 |
| SELinux "spoofed" | — | **not shipped** (circumstantial inference is an FP generator) |

---

## 3. What was deliberately NOT shipped

- `android.selinux.spoofed` — inferring spoofing from circumstantial signals (SELinux
  enforcing + unlocked bootloader + anon VMAs) fires on legitimate custom-ROM devices.
  Only a reproducible userspace-vs-kernel contradiction would justify this signal.
- `setprop` self-check (`android.props.writable_ro`) — unknown FP/FN profile; held.
- `/proc/1/mountinfo` namespace diff — effectively dead code on stock Android (unreadable
  by untrusted apps); retained but documented. A future reshape would use `statx(2)` with
  `STATX_ATTR_MOUNT_ROOT`.

---

## 4. Severity policy

1. ✅-evidence signals may ship at their proposed weight.
2. 🔬-hypothesis signals ship at low weight (5–10) and are raised only after
   false-positive fixtures on clean devices justify it.
3. No single new signal may be the sole reason `compromised = true` until measured.
4. Signals with known FP risk carry `reliability < 0.8`.
5. Signal ids are public contract: never renamed or repurposed; weight/severity tuning is
   allowed.

---

## 5. Deferred — server-attested checks (Phase 3)

Out of scope for local detection; requires its own PR and server infrastructure:

1. **Play Integrity token acquisition** — Kotlin edge HybridObject calling
   `PlayIntegrity.requestIntegrityToken` with a caller-supplied nonce; wires up the existing
   `enablePlayIntegrity` flag.
2. **Hardware key attestation** — `KeyGenParameterSpec` + `KeyStore` certificate chain
   passed to the server.
3. **Leaked/revoked keybox checks** — server-side comparison only. No local string
   matching: not guessable from device state.

---

## 6. Remaining work — device measurement

Cannot be done from a workstation. On the target rooted LineageOS 16.2 device, run the
example app and verify:

- ✅-evidence signals fire (addon.d, LineageOS markers, Magisk props if present, HMA if
  visible to PackageManager).
- Whether `score` crosses `minScore` (default 40) is a **measurement, not a guarantee**.
- Hypothesis-led signals (anon-VMA, cross-prop inconsistency, module tree) may or may not
  fire; their absence is not evidence of a clean device.
- Module Tree / Property Consistency sections render observed data, including `unavailable`
  rows.

The success criterion is **honesty of the report on the device**, not a forced
`compromised = true`. If evidence-backed signals do not reach `minScore`, the next step is
more signals and Play Integrity (§5) — not inflating weights.

---

## 7. Gap analysis (retained for context)

Mapping of reveny's public labels to our coverage at the time of writing. "Evidence" and
"hypothesis" per §1.

| reveny label | Type | Our coverage |
| --- | --- | --- |
| `detected_magisk` / `detected_kernelsu_magisk` | ✅ label exists; internals 🔬 | Partial → improved via modules/addon.d/PATH probes |
| `detected_zygisk*` (variant-specific) | 🔬 | Property-presence candidates only |
| `found_injection` | 🔬 | `android.maps.anon_injection` (low weight) |
| `detected_lsposed` | 🔬 | maps tokens + `android.lsposed.cache` |
| `detected_magisk_module` | mixed | `android.modules.*` when tree is readable |
| mount inconsistency family | 🔬 | `android.mount.magisk_chain`; namespace diff is dead code on stock |
| `detected_root_app` / `detected_risky_app` / `detected_hide_my_applist` | ✅ presence | PackageManager root/hiding/risky split |
| `detected_root_solution` | ✅ user-pasted path | `android.addon_d.magisk` |
| `detected_modified_hosts_file` | 🔬 | `android.hosts.writable` (writability only) |
| `detected_resetprop` | 🔬 | `android.props.inconsistent_*` corroboration |
| `detected_abnormal_boot_state` | 🔬 | verified-boot + vbmeta cross-check |
| custom ROM / LineageOS labels | ✅ user on LineageOS 16.2 | `android.custom_rom`, `android.lineage` |
| `debug_fingerprint_detected` | 🔬 | test-keys + fingerprint/type inconsistency |
| `detected_custom_kernel`, `detected_gapps`, `detected_framework_patch` | 🔬 | **Missing** — FP profile unmeasured |
| `tee_is_broken`, `keybox_revoked_by_google`, `key_attestation_failed`, `detected_leaked_keybox` | ✅ label exists | **Missing** — hardware-backed; Phase 3 only |

---

## 8. Out of scope (explicitly)

1. Server-side keybox revocation lists.
2. Hardware key attestation (Phase 3 prerequisite).
3. JingMatrix-specific detection beyond the LSPosed family match.
4. Native self-injection / anti-hook hardening of the library itself (separate plan).
5. Out-of-process Frida gadgets (not detectable by app-scoped heuristics).
6. Code obfuscation of the library (hardening, not detection).

---

## 9. Risks and tradeoffs

1. **False positives** — mitigated by conservative weights, cross-checks, `reliability`
   hints, and the §4 policy.
2. **Performance** — new probes add ~50–100 ms per pass; absorbed by the 600 ms default
   budget. Module enumeration is deadline-aware and capped.
3. **Permissions** — no new permissions; denied probes report `unavailable`, never clean.
4. **Breaking changes** — none; all signals are additive ids.
5. **Catalog growth** — ~38 → ~60 ids, documented in the README Signal Catalog table.

---

## 10. Verification

Shipped-state verification (2026-08-11, direct Gradle/xcodebuild invocations):

- ✅ `bun run typecheck`, `bun run lint`, `bun run test --maxWorkers=2` (2 suites, 38 tests)
- ✅ `bun run build` (bob module + type definitions)
- ✅ `bun run native-test` (parser/catalog fixtures)
- ✅ Android example `./gradlew app:bundleDebug -PreactNativeArchitectures=arm64-v8a`
- ✅ iOS example `xcodebuild -sdk iphonesimulator`
- ⚠️ Regenerated `HybridPackageManagerProbeSpec.kt` contains trailing whitespace from the
  nitrogen 0.36.1 template (generated file; not hand-edited)

Re-run before any follow-up change:

```sh
bun run typecheck && bun run lint && bun run test --maxWorkers=2
bun run build && bun run native-test
bun run turbo run build:android --cache-dir=.turbo/android
bun run turbo run build:ios --cache-dir=.turbo/ios
```
