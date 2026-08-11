///
/// AndroidProbes.hpp
///
/// Android-specific probes that require platform APIs not available on iOS or
/// in a pure unit-test environment:
///   - filesystem existence checks for root-manager directories and `su`
///     binaries (uses `stat(2)`);
///   - reads of Android system properties (`__system_property_get`) for
///     verified-boot and build-tag signals.
///
/// Every probe degrades gracefully: a missing path or an unreadable property is
/// reported as "no finding", never as evidence of compromise. Property reads
/// that return an empty value are treated as unavailable.
///
/// These functions are only compiled under `#if defined(__ANDROID__)`. The
/// orchestrator in `AndroidChecks.cpp` is the only intended caller.
///

#pragma once

#include "ProcParsers.hpp"

#include <chrono>
#include <vector>

namespace margelo::nitro::rootjaildetect {

  struct ModuleProbeResult final {
    std::vector<ProcFinding> findings;
    /// False means the directory could not be inspected. It must not be
    /// interpreted as an empty or clean module tree.
    bool available = false;
  };

  /// Probe well-known root-manager data/application directories and conventional
  /// `su` binary locations. Multiple paths may exist; each distinct signal id is
  /// reported once (the caller deduplicates further during scoring).
  ///
  /// Returns one `ProcFinding` per matched path. `evidence` is the path that was
  /// found, suitable for redaction when `includeEvidence` is enabled.
  std::vector<ProcFinding> probeRootPaths() noexcept;

/// Read Android system properties that carry verified-boot and build signals:
///   - `ro.build.tags` (`test-keys` -> low-severity build signal)
///   - `ro.boot.verifiedbootstate` (`orange`/`unlocked` -> bootloader signal)
///   - `ro.boot.flash.locked` (`0` -> bootloader signal)
///   - `ro.debuggable`, `service.adb.root`, `ro.secure` -> low-severity debug
///     build signals (high false-positive on userdebug/eng devices; hidden by
///     Shamiko). `ro.build.selinux` is intentionally NOT read because it is an
///     unreliable SELinux indicator.
///
/// Returns one `ProcFinding` per signal that fired.
  std::vector<ProcFinding> probeBuildProperties() noexcept;

  /// Extended property probe including Magisk leaks and consistency checks.
  std::vector<ProcFinding> probeSystemAttributes() noexcept;

  /// Enumerate readable Magisk module manifests. The result distinguishes an
  /// unreadable directory from a readable empty directory.
  ModuleProbeResult probeMagiskModules() noexcept;
  ModuleProbeResult probeMagiskModules(
    std::chrono::steady_clock::time_point deadline
  ) noexcept;

  /// Probe persistence markers associated with Magisk's addon.d integration.
  std::vector<ProcFinding> probeAddonD() noexcept;

  /// Probe the weaker stock-compatible recovery installation marker.
  std::vector<ProcFinding> probeInstallRecovery() noexcept;

  /// Probe hosts writability only; ordinary ad-blocking entries are ignored.
  std::vector<ProcFinding> probeHostsFile() noexcept;

  /// Probe custom-ROM and LineageOS property markers.
  std::vector<ProcFinding> probeCustomRom() noexcept;

  /// Probe LSPosed cache/module markers that are accessible to the app UID.
  std::vector<ProcFinding> probeLspdCache() noexcept;

  /// Attempt a short write/remove probe in immutable Android system locations.
  std::vector<ProcFinding> probeSystemDirectoryWrite() noexcept;

  /// Probe static `which` commands and the process PATH for candidate markers.
  std::vector<ProcFinding> probeEnvironmentAndCommands() noexcept;

} // namespace margelo::nitro::rootjaildetect
