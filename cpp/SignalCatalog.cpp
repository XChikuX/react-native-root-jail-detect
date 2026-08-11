///
/// SignalCatalog.cpp
///

#include "SignalCatalog.hpp"

namespace margelo::nitro::rootjaildetect {

  // Small helper to add per-id category/reliability without making the table
  // unreadable. Reliability is a coarse 0-1 hint, not a precise statistic.
  namespace {
    constexpr SignalSpec makeSpec(std::string_view id, Severity severity,
                                  SignalCategory category, double score,
                                  double reliability) noexcept {
      return SignalSpec{id, severity, category, score, reliability};
    }

    // Return the platform prefix based on the signal id. This is derived from
    // the id string so the catalog stays the single source of truth.
    Platform signalPlatform(std::string_view id) noexcept {
      if (id.rfind("android.", 0) == 0) {
        return Platform::ANDROID;
      }
      if (id.rfind("ios.", 0) == 0) {
        return Platform::IOS;
      }
      // Unpublished ids should never reach this path; default to android so the
      // result is still well-formed.
      return Platform::ANDROID;
    }
  }

  Platform platformForSignal(std::string_view id) noexcept {
    return signalPlatform(id);
  }

  std::optional<SignalSpec> lookupSignal(std::string_view id) noexcept {
    // The catalog is small and stable; a flat lookup is clearer than a map and
    // avoids a static-initialization-order dependency. Add new signals here and
    // keep the weights aligned with the Signal Catalog in `README.md`.
    if (id == SignalId::ANDROID_MOUNT_MAGISK) return makeSpec(SignalId::ANDROID_MOUNT_MAGISK, Severity::HIGH, SignalCategory::MOUNT, 35.0, 0.85);
    if (id == SignalId::ANDROID_MAPS_ZYGISK) return makeSpec(SignalId::ANDROID_MAPS_ZYGISK, Severity::HIGH, SignalCategory::INJECTION, 30.0, 0.85);
    if (id == SignalId::ANDROID_MAPS_LSPOSED) return makeSpec(SignalId::ANDROID_MAPS_LSPOSED, Severity::HIGH, SignalCategory::HOOK, 30.0, 0.85);
    if (id == SignalId::ANDROID_MAPS_FRIDA) return makeSpec(SignalId::ANDROID_MAPS_FRIDA, Severity::HIGH, SignalCategory::INJECTION, 30.0, 0.80);
    if (id == SignalId::ANDROID_MAPS_RIRU) return makeSpec(SignalId::ANDROID_MAPS_RIRU, Severity::HIGH, SignalCategory::INJECTION, 30.0, 0.75);
    if (id == SignalId::ANDROID_SELINUX_PERMISSIVE) return makeSpec(SignalId::ANDROID_SELINUX_PERMISSIVE, Severity::HIGH, SignalCategory::PROPERTY, 25.0, 0.70);
    if (id == SignalId::ANDROID_ROOT_MANAGER_DIR) return makeSpec(SignalId::ANDROID_ROOT_MANAGER_DIR, Severity::MEDIUM, SignalCategory::FILESYSTEM, 20.0, 0.60);
    if (id == SignalId::ANDROID_BOOTLOADER_UNLOCKED) return makeSpec(SignalId::ANDROID_BOOTLOADER_UNLOCKED, Severity::MEDIUM, SignalCategory::SIGNATURE, 20.0, 0.70);
    if (id == SignalId::ANDROID_EMULATOR) return makeSpec(SignalId::ANDROID_EMULATOR, Severity::MEDIUM, SignalCategory::SIGNATURE, 20.0, 0.85);
    if (id == SignalId::ANDROID_SU_BINARY) return makeSpec(SignalId::ANDROID_SU_BINARY, Severity::LOW, SignalCategory::FILESYSTEM, 10.0, 0.45);
    if (id == SignalId::ANDROID_BUILD_TEST_KEYS) return makeSpec(SignalId::ANDROID_BUILD_TEST_KEYS, Severity::LOW, SignalCategory::SIGNATURE, 10.0, 0.55);
    // Low weight and high FP on legitimate dev builds; Shamiko hides these via resetprop.
    if (id == SignalId::ANDROID_DEBUG_BUILD) return makeSpec(SignalId::ANDROID_DEBUG_BUILD, Severity::LOW, SignalCategory::PROPERTY, 5.0, 0.35);
    if (id == SignalId::ANDROID_ADB_ROOT) return makeSpec(SignalId::ANDROID_ADB_ROOT, Severity::LOW, SignalCategory::PROPERTY, 5.0, 0.35);
    if (id == SignalId::ANDROID_RO_SECURE_ZERO) return makeSpec(SignalId::ANDROID_RO_SECURE_ZERO, Severity::LOW, SignalCategory::PROPERTY, 5.0, 0.35);
    if (id == SignalId::ANDROID_MOUNT_OVERLAY) return makeSpec(SignalId::ANDROID_MOUNT_OVERLAY, Severity::LOW, SignalCategory::MOUNT, 10.0, 0.40);
    if (id == SignalId::ANDROID_CMDLINE_INSTRUMENTATION) return makeSpec(SignalId::ANDROID_CMDLINE_INSTRUMENTATION, Severity::HIGH, SignalCategory::PROCESS, 30.0, 0.75);
    if (id == SignalId::ANDROID_SOCKET_INSTRUMENTATION) return makeSpec(SignalId::ANDROID_SOCKET_INSTRUMENTATION, Severity::HIGH, SignalCategory::PROCESS, 30.0, 0.75);
    if (id == SignalId::ANDROID_NETWORK_FRIDA) return makeSpec(SignalId::ANDROID_NETWORK_FRIDA, Severity::HIGH, SignalCategory::INJECTION, 30.0, 0.80);
    if (id == SignalId::ANDROID_NETWORK_SSH) return makeSpec(SignalId::ANDROID_NETWORK_SSH, Severity::HIGH, SignalCategory::PROCESS, 30.0, 0.60);
    if (id == SignalId::ANDROID_NETWORK_ADB) return makeSpec(SignalId::ANDROID_NETWORK_ADB, Severity::LOW, SignalCategory::PROCESS, 10.0, 0.40);
    if (id == SignalId::IOS_NETWORK_FRIDA) return makeSpec(SignalId::IOS_NETWORK_FRIDA, Severity::HIGH, SignalCategory::INJECTION, 30.0, 0.75);
    if (id == SignalId::IOS_NETWORK_SSH) return makeSpec(SignalId::IOS_NETWORK_SSH, Severity::HIGH, SignalCategory::PROCESS, 30.0, 0.60);
    // Informational: contributes 0 by default. Debugger state is reported
    // separately on `CompromiseAssessment.debuggerDetected` and only folds into
    // `compromised` when `treatDebuggerAsCompromise` is configured.
    if (id == SignalId::ANDROID_DEBUGGER_TRACERPID) return makeSpec(SignalId::ANDROID_DEBUGGER_TRACERPID, Severity::LOW, SignalCategory::DEBUGGER, 0.0, 0.90);
    if (id == SignalId::IOS_DYLD_HOOK) return makeSpec(SignalId::IOS_DYLD_HOOK, Severity::HIGH, SignalCategory::HOOK, 30.0, 0.80);
    if (id == SignalId::IOS_JAILBREAK_ARTIFACT) return makeSpec(SignalId::IOS_JAILBREAK_ARTIFACT, Severity::MEDIUM, SignalCategory::FILESYSTEM, 20.0, 0.60);
    // Medium weight until validated on physical rootless devices; see the Threat Model in `README.md`.
    if (id == SignalId::IOS_JAILBREAK_ROOTLESS) return makeSpec(SignalId::IOS_JAILBREAK_ROOTLESS, Severity::MEDIUM, SignalCategory::FILESYSTEM, 20.0, 0.55);
    if (id == SignalId::IOS_JAILBREAK_DOPAMINE) return makeSpec(SignalId::IOS_JAILBREAK_DOPAMINE, Severity::MEDIUM, SignalCategory::FILESYSTEM, 20.0, 0.55);
    if (id == SignalId::IOS_JAILBREAK_PALERA1N) return makeSpec(SignalId::IOS_JAILBREAK_PALERA1N, Severity::MEDIUM, SignalCategory::FILESYSTEM, 20.0, 0.55);
    if (id == SignalId::IOS_SIDeload_TROLLSTORE) return makeSpec(SignalId::IOS_SIDeload_TROLLSTORE, Severity::MEDIUM, SignalCategory::SANDBOX, 15.0, 0.50);
    if (id == SignalId::IOS_URLSCHEME_JAILBREAK_STORE) return makeSpec(SignalId::IOS_URLSCHEME_JAILBREAK_STORE, Severity::MEDIUM, SignalCategory::SANDBOX, 15.0, 0.45);
    if (id == SignalId::IOS_SIMULATOR) return makeSpec(SignalId::IOS_SIMULATOR, Severity::MEDIUM, SignalCategory::SIGNATURE, 20.0, 0.90);
    if (id == SignalId::IOS_CHECK_URLSCHEME) return makeSpec(SignalId::IOS_CHECK_URLSCHEME, Severity::LOW, SignalCategory::DEBUGGER, 0.0, 0.0);
    if (id == SignalId::IOS_DEBUGGER_SYSCTL) return makeSpec(SignalId::IOS_DEBUGGER_SYSCTL, Severity::LOW, SignalCategory::DEBUGGER, 0.0, 0.90);
    if (id == SignalId::IOS_CHECK_SANDBOX) return makeSpec(SignalId::IOS_CHECK_SANDBOX, Severity::LOW, SignalCategory::DEBUGGER, 0.0, 0.0);
    if (id == SignalId::IOS_SANDBOX_WRITE) return makeSpec(SignalId::IOS_SANDBOX_WRITE, Severity::HIGH, SignalCategory::SANDBOX, 30.0, 0.85);
    if (id == SignalId::ANDROID_CHECK_SANDBOX) return makeSpec(SignalId::ANDROID_CHECK_SANDBOX, Severity::LOW, SignalCategory::DEBUGGER, 0.0, 0.0);
    if (id == SignalId::ANDROID_SANDBOX_WRITE) return makeSpec(SignalId::ANDROID_SANDBOX_WRITE, Severity::HIGH, SignalCategory::SANDBOX, 30.0, 0.80);
    if (id == SignalId::ANDROID_PACKAGE_MANAGER_ROOT) return makeSpec(SignalId::ANDROID_PACKAGE_MANAGER_ROOT, Severity::HIGH, SignalCategory::PACKAGE, 25.0, 0.75);
    // These additions are deliberately conservative. Several are candidate
    // heuristics whose false-positive profile still needs device fixtures.
    if (id == SignalId::ANDROID_MODULES_MAGISK) return makeSpec(SignalId::ANDROID_MODULES_MAGISK, Severity::LOW, SignalCategory::PACKAGE, 10.0, 0.35);
    if (id == SignalId::ANDROID_MODULES_HIDING) return makeSpec(SignalId::ANDROID_MODULES_HIDING, Severity::LOW, SignalCategory::PACKAGE, 10.0, 0.45);
    if (id == SignalId::ANDROID_MODULES_SPOOFING) return makeSpec(SignalId::ANDROID_MODULES_SPOOFING, Severity::LOW, SignalCategory::PACKAGE, 10.0, 0.45);
    if (id == SignalId::ANDROID_ADDON_D_MAGISK) return makeSpec(SignalId::ANDROID_ADDON_D_MAGISK, Severity::MEDIUM, SignalCategory::FILESYSTEM, 20.0, 0.80);
    if (id == SignalId::ANDROID_INSTALL_RECOVERY) return makeSpec(SignalId::ANDROID_INSTALL_RECOVERY, Severity::LOW, SignalCategory::FILESYSTEM, 5.0, 0.35);
    if (id == SignalId::ANDROID_HOSTS_WRITABLE) return makeSpec(SignalId::ANDROID_HOSTS_WRITABLE, Severity::LOW, SignalCategory::FILESYSTEM, 5.0, 0.30);
    if (id == SignalId::ANDROID_CUSTOM_ROM) return makeSpec(SignalId::ANDROID_CUSTOM_ROM, Severity::LOW, SignalCategory::SIGNATURE, 5.0, 0.65);
    if (id == SignalId::ANDROID_LINEAGE) return makeSpec(SignalId::ANDROID_LINEAGE, Severity::LOW, SignalCategory::SIGNATURE, 5.0, 0.75);
    if (id == SignalId::ANDROID_LSPOSED_CACHE) return makeSpec(SignalId::ANDROID_LSPOSED_CACHE, Severity::LOW, SignalCategory::HOOK, 10.0, 0.40);
    if (id == SignalId::ANDROID_MAPS_ANON_INJECTION) return makeSpec(SignalId::ANDROID_MAPS_ANON_INJECTION, Severity::LOW, SignalCategory::INJECTION, 10.0, 0.25);
    if (id == SignalId::ANDROID_PROPS_INCONSISTENT_DEBUGGABLE) return makeSpec(SignalId::ANDROID_PROPS_INCONSISTENT_DEBUGGABLE, Severity::LOW, SignalCategory::PROPERTY, 5.0, 0.25);
    if (id == SignalId::ANDROID_PROPS_INCONSISTENT_VERIFIEDBOOT) return makeSpec(SignalId::ANDROID_PROPS_INCONSISTENT_VERIFIEDBOOT, Severity::LOW, SignalCategory::PROPERTY, 5.0, 0.30);
    if (id == SignalId::ANDROID_PROPS_INCONSISTENT_FINGERPRINT) return makeSpec(SignalId::ANDROID_PROPS_INCONSISTENT_FINGERPRINT, Severity::LOW, SignalCategory::PROPERTY, 5.0, 0.30);
    if (id == SignalId::ANDROID_MAGISK_DISABLE_PROP) return makeSpec(SignalId::ANDROID_MAGISK_DISABLE_PROP, Severity::LOW, SignalCategory::PROPERTY, 10.0, 0.55);
    if (id == SignalId::ANDROID_PACKAGE_MANAGER_HMA) return makeSpec(SignalId::ANDROID_PACKAGE_MANAGER_HMA, Severity::MEDIUM, SignalCategory::PACKAGE, 15.0, 0.65);
    if (id == SignalId::ANDROID_PACKAGE_MANAGER_RISKY) return makeSpec(SignalId::ANDROID_PACKAGE_MANAGER_RISKY, Severity::LOW, SignalCategory::PACKAGE, 5.0, 0.25);
    if (id == SignalId::ANDROID_ZYGISK_VARIANT_OFFICIAL) return makeSpec(SignalId::ANDROID_ZYGISK_VARIANT_OFFICIAL, Severity::LOW, SignalCategory::INJECTION, 5.0, 0.25);
    if (id == SignalId::ANDROID_ZYGISK_VARIANT_ASSISTANT) return makeSpec(SignalId::ANDROID_ZYGISK_VARIANT_ASSISTANT, Severity::LOW, SignalCategory::INJECTION, 5.0, 0.35);
    if (id == SignalId::ANDROID_ZYGISK_VARIANT_NEXT) return makeSpec(SignalId::ANDROID_ZYGISK_VARIANT_NEXT, Severity::LOW, SignalCategory::INJECTION, 5.0, 0.35);
    if (id == SignalId::ANDROID_ZYGISK_VARIANT_REZYGISK) return makeSpec(SignalId::ANDROID_ZYGISK_VARIANT_REZYGISK, Severity::LOW, SignalCategory::INJECTION, 5.0, 0.35);
    if (id == SignalId::ANDROID_SANDBOX_WRITE_SYSTEM_DIR) return makeSpec(SignalId::ANDROID_SANDBOX_WRITE_SYSTEM_DIR, Severity::HIGH, SignalCategory::SANDBOX, 30.0, 0.85);
    if (id == SignalId::ANDROID_CMDLINE_SU_EXEC) return makeSpec(SignalId::ANDROID_CMDLINE_SU_EXEC, Severity::LOW, SignalCategory::PROCESS, 10.0, 0.45);
    if (id == SignalId::ANDROID_CMDLINE_MAGISK_EXEC) return makeSpec(SignalId::ANDROID_CMDLINE_MAGISK_EXEC, Severity::LOW, SignalCategory::PROCESS, 10.0, 0.55);
    if (id == SignalId::ANDROID_ENV_PATH_MAGISK) return makeSpec(SignalId::ANDROID_ENV_PATH_MAGISK, Severity::LOW, SignalCategory::PROCESS, 5.0, 0.25);
    if (id == SignalId::ANDROID_MOUNT_MAGISK_CHAIN) return makeSpec(SignalId::ANDROID_MOUNT_MAGISK_CHAIN, Severity::LOW, SignalCategory::MOUNT, 5.0, 0.25);
    if (id == SignalId::ANDROID_CHECK_MAPS || id == SignalId::ANDROID_CHECK_MOUNTS ||
        id == SignalId::ANDROID_CHECK_SELINUX || id == SignalId::ANDROID_CHECK_ROOT_PATHS ||
        id == SignalId::ANDROID_CHECK_PROPERTIES || id == SignalId::ANDROID_CHECK_DEBUGGER ||
         id == SignalId::ANDROID_CHECK_RUNTIME || id == SignalId::ANDROID_CHECK_MODULES || id == SignalId::IOS_CHECK_JAILBREAK ||
        id == SignalId::IOS_CHECK_DYLD || id == SignalId::IOS_CHECK_DEBUGGER ||
        id == SignalId::IOS_CHECK_URLSCHEME) {
      return makeSpec(id, Severity::LOW, SignalCategory::DEBUGGER, 0.0, 0.0);
    }
    return std::nullopt;
  }

} // namespace margelo::nitro::rootjaildetect
