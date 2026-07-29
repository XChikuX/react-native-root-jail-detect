///
/// SignalCatalog.hpp
///
/// Public, stable signal identifiers and their default severity/score weights.
///
/// Signal ids are part of the public contract: callers and backends use them to
/// reason about which checks fired, so an id must never be renamed or reused for
/// a different meaning once published. New checks add new ids; changing the
/// weight or severity of an existing id is allowed (it is a tuning change), but
/// repurposing an id is a breaking change that requires a version bump.
///
/// Weights mirror the risk table in `PLAN.md` and are intentionally conservative
/// to keep false-positive risk low on stock/custom-ROM devices. See the security
/// implementation guidelines in `CLAUDE.md` before adding a new signal.
///

#pragma once

#include "Severity.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace margelo::nitro::rootjaildetect {

  // Stable signal ids. Grouped by platform and severity for readability, but the
  // only thing that matters to consumers is the string value.
  namespace SignalId {
    // ---- Android: high severity ----
    /// Magisk/KernelSU/APatch overlay or artifact visible in mount metadata.
    inline constexpr std::string_view ANDROID_MOUNT_MAGISK = "android.mount.magisk";
    /// Zygisk library mapped into process memory.
    inline constexpr std::string_view ANDROID_MAPS_ZYGISK = "android.maps.zygisk";
    /// LSPosed/Xposed module library mapped into process memory.
    inline constexpr std::string_view ANDROID_MAPS_LSPOSED = "android.maps.lsposed";
    /// Frida agent library or thread artifact mapped into process memory.
    inline constexpr std::string_view ANDROID_MAPS_FRIDA = "android.maps.frida";
    /// Riru framework library mapped into process memory.
    inline constexpr std::string_view ANDROID_MAPS_RIRU = "android.maps.riru";
    /// SELinux not in enforcing mode on a production device.
    inline constexpr std::string_view ANDROID_SELINUX_PERMISSIVE = "android.selinux.permissive";

    // ---- Android: medium severity ----
    /// Root-manager data/application directory is accessible.
    inline constexpr std::string_view ANDROID_ROOT_MANAGER_DIR = "android.root_manager.dir";
    /// Verified boot reports an unlocked/orange state.
    inline constexpr std::string_view ANDROID_BOOTLOADER_UNLOCKED = "android.bootloader.unlocked";
    /// Strong emulator indicators across multiple vectors.
    inline constexpr std::string_view ANDROID_EMULATOR = "android.emulator";

    // ---- Android: low severity ----
    /// `su` binary found at a conventional location.
    inline constexpr std::string_view ANDROID_SU_BINARY = "android.su.binary";
    /// `ro.build.tags` reports `test-keys`.
    inline constexpr std::string_view ANDROID_BUILD_TEST_KEYS = "android.build.test_keys";
    /// Hidden overlay/bind-mount content surfaced through namespace comparison.
    inline constexpr std::string_view ANDROID_MOUNT_OVERLAY = "android.mount.overlay";

    // ---- Android: informational ----
    /// `TracerPid` in `/proc/self/status` is nonzero.
    inline constexpr std::string_view ANDROID_DEBUGGER_TRACERPID = "android.debugger.tracerpid";

    // ---- iOS (reserved; land in PR 3) ----
    inline constexpr std::string_view IOS_SIMULATOR = "ios.simulator";
  } // namespace SignalId

  /// Default weight and severity for a signal id. The weight is the value this
  /// signal contributes to the aggregated risk score before clamping to 100.
  struct SignalSpec final {
    std::string_view id;
    Severity severity;
    double score;
  };

  /// Look up the default {@link SignalSpec} for an id. Returns `std::nullopt`
  /// for unknown ids so callers cannot accidentally invent weights for ids that
  /// are not part of the public catalog.
  std::optional<SignalSpec> lookupSignal(std::string_view id) noexcept;

} // namespace margelo::nitro::rootjaildetect
