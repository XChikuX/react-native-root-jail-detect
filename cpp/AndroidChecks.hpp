///
/// AndroidChecks.hpp
///
/// Orchestrates the Android scored baseline: reads the
/// relevant `/proc` and `/sys` files, runs the pure parsers, probes
/// root-manager paths and system properties, and folds everything into a
/// deduplicated list of `DetectionSignal`s plus the informational debugger flag.
///
/// This file is the only place that knows the full set of Android checks; the
/// shared C++ HybridObject in `HybridRootJailDetect.cpp` calls into it under
/// `#if defined(__ANDROID__)` so iOS stays unaffected. Per-check deadline
/// enforcement lands in a later phase; for now all Phase 1 checks are fast local
/// reads and the caller measures the total elapsed time against `timeoutMs`.
///

#pragma once

#include "DetectionSignal.hpp"

#include <chrono>
#include <vector>

namespace margelo::nitro::rootjaildetect {

  /// Output of the Android Phase 1 detection pass.
  struct AndroidCheckResult final {
    std::vector<DetectionSignal> signals;
    /// True when `TracerPid` indicates a tracer is attached. Reported on
    /// `DeviceRiskResult.debuggerDetected`; does not affect the score unless the
    /// caller configures `treatDebuggerAsCompromise`.
    bool debuggerDetected = false;
    bool partial = false;
  };

  /// Run the Android Phase 1 detection pass. `includeEvidence` controls whether
  /// redacted evidence strings are attached to each emitted signal. This
  /// function never throws; every probe degrades to "no finding" on failure.
  AndroidCheckResult runAndroidChecks(bool includeEvidence,
                                      std::chrono::steady_clock::time_point deadline) noexcept;

} // namespace margelo::nitro::rootjaildetect
