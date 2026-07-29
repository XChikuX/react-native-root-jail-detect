///
/// SignalCatalog.cpp
///

#include "SignalCatalog.hpp"

namespace margelo::nitro::rootjaildetect {

  std::optional<SignalSpec> lookupSignal(std::string_view id) noexcept {
    // The catalog is small and stable; a flat lookup is clearer than a map and
    // avoids a static-initialization-order dependency. Add new signals here and
    // keep the weights aligned with the risk table in `PLAN.md`.
    if (id == SignalId::ANDROID_MOUNT_MAGISK) return SignalSpec{SignalId::ANDROID_MOUNT_MAGISK, Severity::HIGH, 35.0};
    if (id == SignalId::ANDROID_MAPS_ZYGISK) return SignalSpec{SignalId::ANDROID_MAPS_ZYGISK, Severity::HIGH, 30.0};
    if (id == SignalId::ANDROID_MAPS_LSPOSED) return SignalSpec{SignalId::ANDROID_MAPS_LSPOSED, Severity::HIGH, 30.0};
    if (id == SignalId::ANDROID_MAPS_FRIDA) return SignalSpec{SignalId::ANDROID_MAPS_FRIDA, Severity::HIGH, 30.0};
    if (id == SignalId::ANDROID_MAPS_RIRU) return SignalSpec{SignalId::ANDROID_MAPS_RIRU, Severity::HIGH, 30.0};
    if (id == SignalId::ANDROID_SELINUX_PERMISSIVE) return SignalSpec{SignalId::ANDROID_SELINUX_PERMISSIVE, Severity::HIGH, 25.0};
    if (id == SignalId::ANDROID_ROOT_MANAGER_DIR) return SignalSpec{SignalId::ANDROID_ROOT_MANAGER_DIR, Severity::MEDIUM, 20.0};
    if (id == SignalId::ANDROID_BOOTLOADER_UNLOCKED) return SignalSpec{SignalId::ANDROID_BOOTLOADER_UNLOCKED, Severity::MEDIUM, 20.0};
    if (id == SignalId::ANDROID_EMULATOR) return SignalSpec{SignalId::ANDROID_EMULATOR, Severity::MEDIUM, 20.0};
    if (id == SignalId::ANDROID_SU_BINARY) return SignalSpec{SignalId::ANDROID_SU_BINARY, Severity::LOW, 10.0};
    if (id == SignalId::ANDROID_BUILD_TEST_KEYS) return SignalSpec{SignalId::ANDROID_BUILD_TEST_KEYS, Severity::LOW, 10.0};
    if (id == SignalId::ANDROID_MOUNT_OVERLAY) return SignalSpec{SignalId::ANDROID_MOUNT_OVERLAY, Severity::LOW, 10.0};
    if (id == SignalId::ANDROID_CMDLINE_INSTRUMENTATION) return SignalSpec{SignalId::ANDROID_CMDLINE_INSTRUMENTATION, Severity::HIGH, 30.0};
    if (id == SignalId::ANDROID_SOCKET_INSTRUMENTATION) return SignalSpec{SignalId::ANDROID_SOCKET_INSTRUMENTATION, Severity::HIGH, 30.0};
    if (id == SignalId::ANDROID_NETWORK_FRIDA) return SignalSpec{SignalId::ANDROID_NETWORK_FRIDA, Severity::HIGH, 30.0};
    if (id == SignalId::ANDROID_NETWORK_SSH) return SignalSpec{SignalId::ANDROID_NETWORK_SSH, Severity::HIGH, 30.0};
    if (id == SignalId::ANDROID_NETWORK_ADB) return SignalSpec{SignalId::ANDROID_NETWORK_ADB, Severity::LOW, 10.0};
    if (id == SignalId::IOS_NETWORK_FRIDA) return SignalSpec{SignalId::IOS_NETWORK_FRIDA, Severity::HIGH, 30.0};
    if (id == SignalId::IOS_NETWORK_SSH) return SignalSpec{SignalId::IOS_NETWORK_SSH, Severity::HIGH, 30.0};
    // Informational: contributes 0 by default. Debugger state is reported
    // separately on `DeviceRiskResult.debuggerDetected` and only folds into
    // `compromised` when `treatDebuggerAsCompromise` is configured.
    if (id == SignalId::ANDROID_DEBUGGER_TRACERPID) return SignalSpec{SignalId::ANDROID_DEBUGGER_TRACERPID, Severity::LOW, 0.0};
    if (id == SignalId::IOS_DYLD_HOOK) return SignalSpec{SignalId::IOS_DYLD_HOOK, Severity::HIGH, 30.0};
    if (id == SignalId::IOS_JAILBREAK_ARTIFACT) return SignalSpec{SignalId::IOS_JAILBREAK_ARTIFACT, Severity::MEDIUM, 20.0};
    // Medium weight until validated on physical rootless devices; see `PLAN.md` gap #1.
    if (id == SignalId::IOS_JAILBREAK_ROOTLESS) return SignalSpec{SignalId::IOS_JAILBREAK_ROOTLESS, Severity::MEDIUM, 20.0};
    if (id == SignalId::IOS_JAILBREAK_DOPAMINE) return SignalSpec{SignalId::IOS_JAILBREAK_DOPAMINE, Severity::MEDIUM, 20.0};
    if (id == SignalId::IOS_JAILBREAK_PALERA1N) return SignalSpec{SignalId::IOS_JAILBREAK_PALERA1N, Severity::MEDIUM, 20.0};
    if (id == SignalId::IOS_SIDeload_TROLLSTORE) return SignalSpec{SignalId::IOS_SIDeload_TROLLSTORE, Severity::MEDIUM, 15.0};
    if (id == SignalId::IOS_SIMULATOR) return SignalSpec{SignalId::IOS_SIMULATOR, Severity::MEDIUM, 20.0};
    if (id == SignalId::IOS_DEBUGGER_SYSCTL) return SignalSpec{SignalId::IOS_DEBUGGER_SYSCTL, Severity::LOW, 0.0};
    if (id == SignalId::ANDROID_CHECK_MAPS || id == SignalId::ANDROID_CHECK_MOUNTS ||
        id == SignalId::ANDROID_CHECK_SELINUX || id == SignalId::ANDROID_CHECK_ROOT_PATHS ||
        id == SignalId::ANDROID_CHECK_PROPERTIES || id == SignalId::ANDROID_CHECK_DEBUGGER ||
        id == SignalId::ANDROID_CHECK_RUNTIME || id == SignalId::IOS_CHECK_JAILBREAK ||
        id == SignalId::IOS_CHECK_DYLD || id == SignalId::IOS_CHECK_DEBUGGER) {
      return SignalSpec{id, Severity::LOW, 0.0};
    }
    return std::nullopt;
  }

} // namespace margelo::nitro::rootjaildetect
