///
/// HybridPackageManagerProbe.cpp
///
/// No-op C++ stub for Android PackageManager root package enumeration.
/// The real implementation is in Kotlin on Android.
///

#include "HybridPackageManagerProbe.hpp"

namespace margelo::nitro::rootjaildetect {

HybridPackageManagerProbe::HybridPackageManagerProbe() = default;

std::vector<std::string> HybridPackageManagerProbe::getInstalledRootPackages() {
  // No-op on iOS/host. The Android implementation lives in Kotlin.
  return {};
}

std::vector<std::string> HybridPackageManagerProbe::getInstalledHidingPackages() {
  return {};
}

std::vector<std::string> HybridPackageManagerProbe::getInstalledRiskyPackages() {
  return {};
}

size_t HybridPackageManagerProbe::getExternalMemorySize() noexcept {
  return sizeof(*this);
}

} // namespace margelo::nitro::rootjaildetect
