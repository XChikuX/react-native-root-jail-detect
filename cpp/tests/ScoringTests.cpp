///
/// ScoringTests.cpp
///
/// Fixture coverage for `aggregateSignals()` in `Scoring.hpp` — the pure
/// score/confidence aggregation behind `CompromiseAssessment`. Every rule in
/// the doc comment is exercised: per-id deduplication, availability
/// filtering, score clamping, and the severity/diversity confidence ladder.
///
/// Compiled in host-test mode (`-DROOTJAILDETECT_HOST_TEST`), which swaps the
/// nitrogen-generated enums/structs for shape-agreeing stand-ins.
///

#include "SignalCatalog.hpp"
#include "Scoring.hpp"

#include <cassert>
#include <optional>
#include <string>
#include <vector>

using namespace margelo::nitro::rootjaildetect;

namespace {

  DetectionSignal makeSignal(
    std::string id,
    SignalCategory category,
    Severity severity,
    double score,
    std::optional<bool> unavailable = std::nullopt
  ) {
    DetectionSignal signal;
    signal.id = std::move(id);
    signal.category = category;
    signal.severity = severity;
    signal.score = score;
    signal.unavailable = unavailable;
    return signal;
  }

  double scoreOf(const std::vector<DetectionSignal>& signals) {
    return aggregateSignals(signals).score;
  }

  Confidence confidenceOf(const std::vector<DetectionSignal>& signals) {
    return aggregateSignals(signals).confidence;
  }

} // namespace

void runScoringTests() {
  // ---- Empty input ---------------------------------------------------------
  {
    const auto result = aggregateSignals({});
    assert(result.score == 0.0);
    assert(result.confidence == Confidence::LOW);
    assert(result.contributing.empty());
  }

  // ---- Availability filtering ---------------------------------------------
  // `unavailable` signals carry no evidence and must not contribute.
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.su.binary", SignalCategory::FILESYSTEM, Severity::HIGH, 30.0, true),
    };
    const auto result = aggregateSignals(signals);
    assert(result.score == 0.0);
    assert(result.confidence == Confidence::LOW);
    assert(result.contributing.empty());
  }

  // `unavailable` defaults to "available" when absent (`std::nullopt`).
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.su.binary", SignalCategory::FILESYSTEM, Severity::HIGH, 30.0),
    };
    const auto result = aggregateSignals(signals);
    assert(result.score == 30.0);
    assert(result.contributing.size() == 1);
  }

  // `unavailable: false` is an explicit "available" and contributes.
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.su.binary", SignalCategory::FILESYSTEM, Severity::LOW, 5.0, false),
    };
    assert(scoreOf(signals) == 5.0);
  }

  // ---- Deduplication -------------------------------------------------------
  // The same signal id is counted once; the first occurrence wins.
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.mount.magisk", SignalCategory::MOUNT, Severity::HIGH, 35.0),
      makeSignal("android.mount.magisk", SignalCategory::MOUNT, Severity::LOW, 1.0),
      makeSignal("android.mount.magisk", SignalCategory::MOUNT, Severity::MEDIUM, 12.0),
    };
    const auto result = aggregateSignals(signals);
    assert(result.score == 35.0);
    assert(result.contributing.size() == 1);
    assert(result.contributing.front().score == 35.0);
    assert(result.contributing.front().severity == Severity::HIGH);
  }

  // Distinct ids are summed, not collapsed.
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.mount.magisk", SignalCategory::MOUNT, Severity::HIGH, 35.0),
      makeSignal("android.su.binary", SignalCategory::FILESYSTEM, Severity::LOW, 10.0),
      makeSignal("android.emulator", SignalCategory::PROPERTY, Severity::MEDIUM, 15.0),
    };
    const auto result = aggregateSignals(signals);
    assert(result.score == 60.0);
    assert(result.contributing.size() == 3);
  }

  // ---- Clamping ------------------------------------------------------------
  // Scores above 100 clamp to the documented ceiling.
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.mount.magisk", SignalCategory::MOUNT, Severity::HIGH, 90.0),
      makeSignal("android.maps.zygisk", SignalCategory::INJECTION, Severity::HIGH, 90.0),
    };
    assert(scoreOf(signals) == 100.0);
  }

  // Defensive floor: a synthesized negative weight cannot go below zero.
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("synthetic.negative", SignalCategory::FILESYSTEM, Severity::LOW, -10.0),
    };
    assert(scoreOf(signals) == 0.0);
  }

  // ---- Confidence ladder ---------------------------------------------------
  // No contributing signals → LOW.
  assert(confidenceOf({}) == Confidence::LOW);

  // Single LOW → LOW.
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.su.binary", SignalCategory::FILESYSTEM, Severity::LOW, 10.0),
    };
    assert(confidenceOf(signals) == Confidence::LOW);
  }

  // Single MEDIUM → MEDIUM.
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.emulator", SignalCategory::PROPERTY, Severity::MEDIUM, 15.0),
    };
    assert(confidenceOf(signals) == Confidence::MEDIUM);
  }

  // Two MEDIUM signals → promoted to HIGH (independent corroboration).
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.emulator", SignalCategory::PROPERTY, Severity::MEDIUM, 15.0),
      makeSignal("android.custom_rom", SignalCategory::PROPERTY, Severity::MEDIUM, 10.0),
    };
    assert(confidenceOf(signals) == Confidence::HIGH);
  }

  // Single HIGH → MEDIUM (one strong hit is not enough for HIGH).
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.mount.magisk", SignalCategory::MOUNT, Severity::HIGH, 35.0),
    };
    assert(confidenceOf(signals) == Confidence::MEDIUM);
  }

  // Two HIGH hits → HIGH.
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.mount.magisk", SignalCategory::MOUNT, Severity::HIGH, 35.0),
      makeSignal("android.maps.zygisk", SignalCategory::INJECTION, Severity::HIGH, 30.0),
    };
    assert(confidenceOf(signals) == Confidence::HIGH);
  }

  // Two HIGH hits across two categories with score >= 80 → EXTREME.
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.mount.magisk", SignalCategory::MOUNT, Severity::HIGH, 45.0),
      makeSignal("android.maps.zygisk", SignalCategory::INJECTION, Severity::HIGH, 40.0),
    };
    const auto result = aggregateSignals(signals);
    assert(result.score == 85.0);
    assert(result.confidence == Confidence::EXTREME);
  }

  // Two HIGH hits in the *same* category stay HIGH even with a high score
  // (diversity across categories is required for EXTREME).
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.mount.magisk", SignalCategory::MOUNT, Severity::HIGH, 45.0),
      makeSignal("android.mount.magisk_chain", SignalCategory::MOUNT, Severity::HIGH, 40.0),
    };
    const auto result = aggregateSignals(signals);
    assert(result.score == 85.0);
    assert(result.confidence == Confidence::HIGH);
  }

  // HIGH severity plus extra LOW signals still respects the count-based
  // promotion (a lone HIGH stays MEDIUM regardless of LOW companions).
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.mount.magisk", SignalCategory::MOUNT, Severity::HIGH, 35.0),
      makeSignal("android.su.binary", SignalCategory::FILESYSTEM, Severity::LOW, 10.0),
    };
    assert(confidenceOf(signals) == Confidence::MEDIUM);
  }

  // MEDIUM promotion counts only MEDIUM signals: one MEDIUM + two LOW stays
  // MEDIUM, not HIGH.
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.emulator", SignalCategory::PROPERTY, Severity::MEDIUM, 15.0),
      makeSignal("android.su.binary", SignalCategory::FILESYSTEM, Severity::LOW, 10.0),
      makeSignal("android.build.test_keys", SignalCategory::PROPERTY, Severity::LOW, 5.0),
    };
    assert(confidenceOf(signals) == Confidence::MEDIUM);
  }

  // Unavailable HIGH signals do not participate in the confidence ladder.
  {
    const std::vector<DetectionSignal> signals = {
      makeSignal("android.check.mounts", SignalCategory::MOUNT, Severity::HIGH, 25.0, true),
      makeSignal("android.su.binary", SignalCategory::FILESYSTEM, Severity::LOW, 10.0),
    };
    const auto result = aggregateSignals(signals);
    assert(result.score == 10.0);
    assert(result.confidence == Confidence::LOW);
    assert(result.contributing.size() == 1);
  }

  // ---- Hypothesis signals are never a sole compromise basis (WS-B) --------
  // Policy: hypothesis signals ship at weight 5-10 with reliability < 0.8,
  // and no individual heuristic may reach the default minScore (40.0,
  // ResolvedRootJailDetectOptions). Weights may only rise after the
  // on-device measurement program records zero clean-corpus FPs and a
  // reproducible TP fixture (see CLAUDE.md detection policy).
  {
    const auto denyList = lookupSignal(SignalId::ANDROID_MOUNT_DENYLIST_UNMOUNT);
    assert(denyList.has_value());
    assert(denyList->score == 5.0);
    assert(denyList->severity == Severity::LOW);
    assert(denyList->reliability == 0.40 && denyList->reliability < 0.8);

    const auto overlayFs = lookupSignal(SignalId::ANDROID_MOUNT_OVERLAYFS);
    assert(overlayFs.has_value());
    assert(overlayFs->score == 10.0);
    assert(overlayFs->severity == Severity::MEDIUM);
    assert(overlayFs->reliability == 0.55 && overlayFs->reliability < 0.8);

    const auto installOrigin = lookupSignal(SignalId::ANDROID_INSTALL_ORIGIN_OTHER);
    assert(installOrigin.has_value());
    assert(installOrigin->score == 10.0);
    assert(installOrigin->severity == Severity::LOW);
    assert(installOrigin->reliability == 0.35 && installOrigin->reliability < 0.8);

    constexpr double kDefaultMinScore = 40.0;
    assert(denyList->score < kDefaultMinScore);
    assert(overlayFs->score < kDefaultMinScore);
    assert(installOrigin->score < kDefaultMinScore);
    assert(denyList->score + overlayFs->score < kDefaultMinScore);

    // End-to-end through the aggregator with catalog-faithful weights: both
    // hypothesis signals together stay far below the compromise threshold.
    const std::vector<DetectionSignal> signals = {
      makeSignal(std::string(SignalId::ANDROID_MOUNT_DENYLIST_UNMOUNT),
                 denyList->category, denyList->severity, denyList->score),
      makeSignal(std::string(SignalId::ANDROID_MOUNT_OVERLAYFS),
                 overlayFs->category, overlayFs->severity, overlayFs->score),
    };
    const auto result = aggregateSignals(signals);
    assert(result.score == 15.0);
    assert(result.score < kDefaultMinScore);
    assert(result.confidence == Confidence::MEDIUM);
  }
}
