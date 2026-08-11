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
/// Weights mirror the Signal Catalog in `README.md` and are intentionally conservative
/// to keep false-positive risk low on stock/custom-ROM devices. See the security
/// implementation guidelines in `CLAUDE.md` before adding a new signal.
///

#pragma once

#include "Platform.hpp"
#include "Severity.hpp"
#include "SignalCategory.hpp"

#include <cstddef>
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
    /// `ro.debuggable` is set (userdebug/eng build or hidden by Shamiko).
    inline constexpr std::string_view ANDROID_DEBUG_BUILD = "android.build.debuggable";
    /// `service.adb.root` is set (development build or hidden by Shamiko).
    inline constexpr std::string_view ANDROID_ADB_ROOT = "android.build.adb_root";
    /// `ro.secure` is `0` (development build or hidden by Shamiko).
    inline constexpr std::string_view ANDROID_RO_SECURE_ZERO = "android.build.ro_secure_zero";
    /// Hidden overlay/bind-mount content surfaced through namespace comparison.
    inline constexpr std::string_view ANDROID_MOUNT_OVERLAY = "android.mount.overlay";

    // ---- Android: high severity (runtime instrumentation) ----
    /// Frida or other instrumentation artifact in the process command line.
    inline constexpr std::string_view ANDROID_CMDLINE_INSTRUMENTATION = "android.cmdline.instrumentation";
    /// Local instrumentation socket exposed by the current process namespace.
    inline constexpr std::string_view ANDROID_SOCKET_INSTRUMENTATION = "android.socket.instrumentation";
    /// Frida server listening on the default loopback port (27042).
    inline constexpr std::string_view ANDROID_NETWORK_FRIDA = "android.network.frida";
    /// SSH server listening on loopback ( Jailbroken iOS / some Android setups).
    inline constexpr std::string_view ANDROID_NETWORK_SSH = "android.network.ssh";
    /// ADB daemon listening on loopback (emulator or rare TCP-mode adbd).
    inline constexpr std::string_view ANDROID_NETWORK_ADB = "android.network.adb";

    // ---- iOS network ----
    /// Frida server listening on the default loopback port (27042).
    inline constexpr std::string_view IOS_NETWORK_FRIDA = "ios.network.frida";
    /// SSH server listening on loopback (ports 22 or 44).
    inline constexpr std::string_view IOS_NETWORK_SSH = "ios.network.ssh";

    // ---- Android: informational ----
    /// `TracerPid` in `/proc/self/status` is nonzero.
    inline constexpr std::string_view ANDROID_DEBUGGER_TRACERPID = "android.debugger.tracerpid";

    // ---- Check availability (informational) ----
    /// The maps-based runtime scan could not complete within the time budget.
    inline constexpr std::string_view ANDROID_CHECK_MAPS = "android.check.maps";
    /// The mount metadata scan could not complete within the time budget.
    inline constexpr std::string_view ANDROID_CHECK_MOUNTS = "android.check.mounts";
    /// The SELinux state check could not complete within the time budget.
    inline constexpr std::string_view ANDROID_CHECK_SELINUX = "android.check.selinux";
    /// The root path probe could not complete within the time budget.
    inline constexpr std::string_view ANDROID_CHECK_ROOT_PATHS = "android.check.root_paths";
    /// The Android property probe could not complete within the time budget.
    inline constexpr std::string_view ANDROID_CHECK_PROPERTIES = "android.check.properties";
    /// The debugger state check could not complete within the time budget.
    inline constexpr std::string_view ANDROID_CHECK_DEBUGGER = "android.check.debugger";
    /// The runtime instrumentation probe could not complete within the time budget.
    inline constexpr std::string_view ANDROID_CHECK_RUNTIME = "android.check.runtime";
    /// The jailbreak artifact probe could not complete within the time budget.
    inline constexpr std::string_view IOS_CHECK_JAILBREAK = "ios.check.jailbreak";
    /// The dyld image scan could not complete within the time budget.
    inline constexpr std::string_view IOS_CHECK_DYLD = "ios.check.dyld";
    /// The iOS debugger check could not complete within the time budget.
    inline constexpr std::string_view IOS_CHECK_DEBUGGER = "ios.check.debugger";

    // ---- iOS: high severity ----
    /// Suspicious injection/hook library loaded (MobileSubstrate, Substitute,
    /// Frida, libhooker, newer injection frameworks).
    inline constexpr std::string_view IOS_DYLD_HOOK = "ios.dyld.hook";

    // ---- iOS: medium severity ----
    /// Classic jailbreak artifact path or directory is accessible.
    inline constexpr std::string_view IOS_JAILBREAK_ARTIFACT = "ios.jailbreak.artifact";
    /// Rootless jailbreak bootstrap prefix is present (Dopamine, palera1n, etc.).
    inline constexpr std::string_view IOS_JAILBREAK_ROOTLESS = "ios.jailbreak.rootless";
    /// Dopamine-specific bootstrap marker present.
    inline constexpr std::string_view IOS_JAILBREAK_DOPAMINE = "ios.jailbreak.dopamine";
    /// palera1n-specific bootstrap marker present.
    inline constexpr std::string_view IOS_JAILBREAK_PALERA1N = "ios.jailbreak.palera1n";
    /// TrollStore persistence/helper presence. TrollStore is a sideloading tool,
    /// not a jailbreak — its detection is intentionally a separate signal.
    inline constexpr std::string_view IOS_SIDeload_TROLLSTORE = "ios.sideload.trollstore";
    /// One or more jailbreak-store URL schemes responded to `canOpenURL`.
    inline constexpr std::string_view IOS_URLSCHEME_JAILBREAK_STORE = "ios.urlscheme.jailbreak_store";
    /// The app is running in the iOS simulator.
    inline constexpr std::string_view IOS_SIMULATOR = "ios.simulator";

    // ---- iOS availability ---
    /// The URL-scheme check could not complete within the time budget.
    inline constexpr std::string_view IOS_CHECK_URLSCHEME = "ios.check.urlscheme";
    /// The sandbox write test could not complete within the time budget.
    inline constexpr std::string_view IOS_CHECK_SANDBOX = "ios.check.sandbox";

    // ---- iOS: high severity (sandbox escape) ----
    /// Sandbox write succeeded (writing outside app sandbox).
    inline constexpr std::string_view IOS_SANDBOX_WRITE = "ios.sandbox.write";

    // ---- iOS: informational ----
    /// `sysctl` reports P_TRACED for this process.
    inline constexpr std::string_view IOS_DEBUGGER_SYSCTL = "ios.debugger.sysctl";

    // ---- Android: sandbox escape ----
    /// The sandbox write test could not complete within the time budget.
    inline constexpr std::string_view ANDROID_CHECK_SANDBOX = "android.check.sandbox";
    /// Sandbox write succeeded (writing to system directory).
    inline constexpr std::string_view ANDROID_SANDBOX_WRITE = "android.sandbox.write";

    // ---- Android: package enumeration ----
    /// Root package detected via PackageManager enumeration.
    inline constexpr std::string_view ANDROID_PACKAGE_MANAGER_ROOT = "android.package_manager.root";
  } // namespace SignalId

  // Basic compile-time string obfuscation for sensitive literals.
  // Uses a simple XOR with a compile-time key so literals don't appear
  // in plain text in the binary. Not a strong protection, but raises the bar
  // for casual static inspection.
  template <size_t N>
  struct ObfuscatedString {
    constexpr ObfuscatedString(const char (&str)[N])
        : size(N - 1) {
      for (size_t i = 0; i < size; ++i) {
        data[i] = str[i] ^ key(i);
      }
    }

    [[nodiscard]] std::string decrypt() const noexcept {
      std::string result;
      result.reserve(size);
      for (size_t i = 0; i < size; ++i) {
        result.push_back(data[i] ^ key(i));
      }
      return result;
    }

    const char* c_str() const noexcept {
      // Not thread-safe; intended for one-time decryption at startup.
      static thread_local std::string cached;
      if (cached.empty()) {
        cached = decrypt();
      }
      return cached.c_str();
    }

   private:
    static constexpr unsigned char key(size_t i) noexcept {
      // Simple per-position key derived from a fixed seed.
      return static_cast<unsigned char>(0x5A + (i * 0x17) ^ (i >> 2));
    }

    char data[N - 1];
    size_t size;
  };

  /// Default weight, severity, category, and reliability for a signal id. The
  /// weight is the value this signal contributes to the aggregated risk score
  /// before clamping to 100; reliability is a 0-1 hint for backend policy.
  struct SignalSpec final {
    std::string_view id;
    Severity severity;
    SignalCategory category;
    double score;
    double reliability;
  };

  /// Look up the default {@link SignalSpec} for an id. Returns `std::nullopt`
  /// for unknown ids so callers cannot accidentally invent weights for ids that
  /// are not part of the public catalog.
  std::optional<SignalSpec> lookupSignal(std::string_view id) noexcept;

  /// Derive the platform prefix from a signal id (e.g. `android.maps.zygisk`
  /// -> Platform::ANDROID). Unpublished ids fall back to ANDROID so the result
  /// stays well-formed without inventing metadata.
  Platform platformForSignal(std::string_view id) noexcept;

} // namespace margelo::nitro::rootjaildetect
