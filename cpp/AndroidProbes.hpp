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

#include <vector>

namespace margelo::nitro::rootjaildetect {

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

} // namespace margelo::nitro::rootjaildetect
