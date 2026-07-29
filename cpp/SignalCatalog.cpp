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
    // Informational: contributes 0 by default. Debugger state is reported
    // separately on `DeviceRiskResult.debuggerDetected` and only folds into
    // `compromised` when `treatDebuggerAsCompromise` is configured.
    if (id == SignalId::ANDROID_DEBUGGER_TRACERPID) return SignalSpec{SignalId::ANDROID_DEBUGGER_TRACERPID, Severity::LOW, 0.0};
    if (id == SignalId::IOS_SIMULATOR) return SignalSpec{SignalId::IOS_SIMULATOR, Severity::MEDIUM, 20.0};
    return std::nullopt;
  }

} // namespace margelo::nitro::rootjaildetect
