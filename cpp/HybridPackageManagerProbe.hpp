///
/// HybridPackageManagerProbe.hpp
///
/// No-op C++ implementation of the `PackageManagerProbe` HybridObject. On Android
/// the real implementation is the Kotlin `HybridPackageManagerProbe` class; on iOS
/// (and any host build) this stub is used because PackageManager checks are
/// Android-only.
///

#pragma once

#include "HybridPackageManagerProbeSpec.hpp"

#include <cstddef>
#include <vector>
#include <string>

namespace margelo::nitro::rootjaildetect {

class HybridPackageManagerProbe final : public HybridPackageManagerProbeSpec {
 public:
  HybridPackageManagerProbe();

 public:
  std::vector<std::string> getInstalledRootPackages() override;
  std::vector<std::string> getInstalledHidingPackages() override;
  std::vector<std::string> getInstalledRiskyPackages() override;

 public:
  size_t getExternalMemorySize() noexcept override;
};

} // namespace margelo::nitro::rootjaildetect
