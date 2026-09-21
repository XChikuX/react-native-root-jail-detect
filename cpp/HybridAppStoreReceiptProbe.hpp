///
/// HybridAppStoreReceiptProbe.hpp
///
/// No-op C++ implementation of the `AppStoreReceiptProbe` HybridObject. On iOS
/// the real implementation is the Swift `HybridAppStoreReceiptProbe` class; on
/// Android (and any host build) this stub is used because `NSBundle` /
/// `appStoreReceiptURL` is iOS-only.
///
/// This object is **internal** — it is not exported from `src/` and is not
/// referenced by any JS-facing API. It exists only so the shared C++ core can
/// resolve the iOS install-origin heuristic through the same HybridObject
/// pattern as the other platform edges (`UrlSchemeProbe`,
/// `PackageManagerProbe`).
///

#pragma once

#include "HybridAppStoreReceiptProbeSpec.hpp"

#include <cstddef>
#include <string>

namespace margelo::nitro::rootjaildetect {

  class HybridAppStoreReceiptProbe final : public HybridAppStoreReceiptProbeSpec {
  public:
    HybridAppStoreReceiptProbe();

  public:
    std::string getReceiptState() override;

  public:
    size_t getExternalMemorySize() noexcept override;
  };

} // namespace margelo::nitro::rootjaildetect
