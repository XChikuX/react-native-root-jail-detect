///
/// Scoring.hpp
///
/// Pure aggregation of fired signals into the scored fields of
/// `DeviceRiskResult`. Kept header-only and side-effect-free so it is trivially
/// unit-testable with fixture signals.
///
/// Rules (see `PLAN.md` -> Risk model):
///   - Each signal id is counted at most once (equivalent evidence is not
///     double-counted). When the same id fires multiple times, the first
///     occurrence wins and later ones are dropped.
///   - `unavailable` signals contribute no score and must not raise confidence.
///   - The total score is the sum of contributing signal weights, clamped to
///     [0, 100].
///   - Confidence is derived from the strongest contributing signal, not from
///     the raw count, so a single high-severity hit is enough to be `MEDIUM`.
///

#pragma once

#include "Confidence.hpp"
#include "DetectionSignal.hpp"

#include <algorithm>
#include <vector>

namespace margelo::nitro::rootjaildetect {

  struct AggregatedScore final {
    double score = 0.0;
    Confidence confidence = Confidence::LOW;
    // Deduplicated, availability-filtered signals in first-seen order. The
    // caller may still want to surface `unavailable` signals for diagnostics,
    // so the raw input is not mutated here; this vector is the contributing set.
    std::vector<DetectionSignal> contributing;
  };

  /// Aggregate `signals` into a clamped score and a confidence level.
  inline AggregatedScore aggregateSignals(const std::vector<DetectionSignal>& signals) noexcept {
    AggregatedScore result;
    std::vector<std::string> seenIds;
    seenIds.reserve(signals.size());

    for (const DetectionSignal& signal : signals) {
      // Unavailable checks carry no evidence and must not affect the score.
      if (signal.unavailable.value_or(false)) {
        continue;
      }
      // Deduplicate by id so the same underlying condition is not counted twice
      // (for example, multiple `su` paths or multiple Frida artifacts).
      if (std::find(seenIds.begin(), seenIds.end(), signal.id) != seenIds.end()) {
        continue;
      }
      seenIds.push_back(signal.id);

      result.score += signal.score;
      result.contributing.push_back(signal);

      // Confidence tracks the strongest contributor seen so far.
      if (signal.severity > result.confidence) {
        result.confidence = signal.severity;
      }
    }

    // Clamp to the documented 0-100 range. Negative weights are not part of the
    // public catalog, but clamp defensively in case a caller synthesizes one.
    if (result.score < 0.0) {
      result.score = 0.0;
    } else if (result.score > 100.0) {
      result.score = 100.0;
    }

    // Promote confidence: any HIGH signal implies at least MEDIUM confidence,
    // and reaching the MEDIUM severity band also implies MEDIUM. We only report
    // HIGH confidence when multiple distinct high-severity signals fire, which
    // is a stronger indicator than a single (possibly spoofable) hit.
    if (result.confidence == Severity::HIGH) {
      result.confidence = Confidence::MEDIUM;
      size_t highCount = 0;
      for (const DetectionSignal& signal : result.contributing) {
        if (signal.severity == Severity::HIGH) {
          ++highCount;
        }
      }
      if (highCount >= 2) {
        result.confidence = Confidence::HIGH;
      }
    }

    return result;
  }

} // namespace margelo::nitro::rootjaildetect
