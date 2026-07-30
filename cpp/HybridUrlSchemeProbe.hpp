///
/// HybridUrlSchemeProbe.hpp
///
/// No-op C++ implementation of the `UrlSchemeProbe` HybridObject. On iOS the
/// real implementation is the Swift `HybridUrlSchemeProbe` class; on Android
/// (and any host build) this stub is used because URL-scheme checks are
/// iOS-only.
///

#pragma once

#include "HybridUrlSchemeProbeSpec.hpp"

#include <cstddef>
#include <string>

namespace margelo::nitro::rootjaildetect {

  class HybridUrlSchemeProbe final : public HybridUrlSchemeProbeSpec {
  public:
    HybridUrlSchemeProbe();

  public:
    bool canOpenUrl(const std::string& scheme) override;

  public:
    size_t getExternalMemorySize() noexcept override;
  };

} // namespace margelo::nitro::rootjaildetect
