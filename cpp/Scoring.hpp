///
/// Scoring.hpp
///
/// Pure aggregation of fired signals into the scored fields of
/// `CompromiseAssessment`. Kept header-only and side-effect-free so it is
/// trivially unit-testable with fixture signals.
///
/// Rules (see the Signal Catalog in `README.md`):
///   - Each signal id is counted at most once (equivalent evidence is not
///     double-counted). When the same id fires multiple times, the first
///     occurrence wins and later ones are dropped.
///   - `unavailable` signals contribute no score and must not raise confidence.
///   - The total score is the sum of contributing signal weights, clamped to
///     [0, 100].
///   - Confidence is derived from the strongest contributing signal and from
///     the diversity of independent evidence.
///

#pragma once

#include "Confidence.hpp"
#include "DetectionSignal.hpp"
#include "SignalCategory.hpp"

#include <algorithm>
#include <set>
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

  namespace detail {
    /// Maps a Severity to the semantically equivalent Confidence level.
    /// Both enums use the same ordinal values (LOW=0, MEDIUM=1, HIGH=2) but are
    /// distinct C++ scoped enum types and cannot be compared or assigned across
    /// types.
    inline Confidence severityToConfidence(Severity severity) noexcept {
      switch (severity) {
        case Severity::LOW:
          return Confidence::LOW;
        case Severity::MEDIUM:
          return Confidence::MEDIUM;
        case Severity::HIGH:
          return Confidence::HIGH;
        default:
          return Confidence::LOW;
      }
    }
  }

  /// Aggregate `signals` into a clamped score and a confidence level.
  inline AggregatedScore aggregateSignals(const std::vector<DetectionSignal>& signals) noexcept {
    AggregatedScore result;
    std::vector<std::string> seenIds;
    seenIds.reserve(signals.size());

    Severity highestSeverity = Severity::LOW;

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

      // Track the strongest contributor seen so far using its own enum type.
      if (signal.severity > highestSeverity) {
        highestSeverity = signal.severity;
      }
    }

    // Map the highest-severity contributor to a base confidence level.
    result.confidence = detail::severityToConfidence(highestSeverity);

    // Clamp to the documented 0-100 range. Negative weights are not part of the
    // public catalog, but clamp defensively in case a caller synthesizes one.
    if (result.score < 0.0) {
      result.score = 0.0;
    } else if (result.score > 100.0) {
      result.score = 100.0;
    }

    // Promote confidence based on the strength and diversity of signals.
    // A single high-severity hit is enough for MEDIUM; multiple high-severity
    // hits raise it to HIGH; multiple high-severity hits across independent
    // categories with a score near the top of the range qualify as EXTREME.
    if (highestSeverity == Severity::HIGH) {
      size_t highCount = 0;
      std::set<SignalCategory> highCategories;
      for (const DetectionSignal& signal : result.contributing) {
        if (signal.severity == Severity::HIGH) {
          ++highCount;
          highCategories.insert(signal.category);
        }
      }

      if (highCount >= 2) {
        result.confidence = Confidence::HIGH;
      } else {
        result.confidence = Confidence::MEDIUM;
      }

      if (highCategories.size() >= 2 && highCount >= 2 && result.score >= 80.0) {
        result.confidence = Confidence::EXTREME;
      }
    } else if (highestSeverity == Severity::MEDIUM) {
      // Multiple distinct medium-severity signals are more trustworthy than one.
      size_t mediumCount = 0;
      for (const DetectionSignal& signal : result.contributing) {
        if (signal.severity == Severity::MEDIUM) {
          ++mediumCount;
        }
      }
      if (mediumCount >= 2) {
        result.confidence = Confidence::HIGH;
      }
    }

    return result;
  }

} // namespace margelo::nitro::rootjaildetect
