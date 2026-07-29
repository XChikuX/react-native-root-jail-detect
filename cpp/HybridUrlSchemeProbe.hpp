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
#include <vector>

namespace margelo::nitro::rootjaildetect {

  class HybridUrlSchemeProbe final : public HybridUrlSchemeProbeSpec {
  public:
    HybridUrlSchemeProbe();

  public:
    std::vector<std::string> checkSchemes(const std::vector<std::string>& schemes) override;

  public:
    size_t getMemorySize() override;
  };

} // namespace margelo::nitro::rootjaildetect
