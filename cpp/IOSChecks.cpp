///
/// IOSChecks.cpp
///

#include "IOSChecks.hpp"
#include "SignalCatalog.hpp"

#include <chrono>
#include <cstring>
#include <optional>
#include <string>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>
#endif

namespace margelo::nitro::rootjaildetect {

  namespace {

    DetectionSignal signal(std::string_view id, Severity severity, double score,
                           std::string_view evidence, bool includeEvidence) {
      return DetectionSignal(std::string(id), severity, score,
                             includeEvidence ? std::optional<std::string>(std::string(evidence))
                                             : std::nullopt,
                             std::nullopt);
    }

    DetectionSignal unavailable(std::string_view id) {
      return DetectionSignal(std::string(id), Severity::LOW, 0.0, std::nullopt, true);
    }

    bool expired(std::chrono::steady_clock::time_point deadline) noexcept {
      return std::chrono::steady_clock::now() >= deadline;
    }

  } // namespace

  IOSCheckResult runIOSChecks(bool includeEvidence,
                              std::chrono::steady_clock::time_point deadline) noexcept {
    IOSCheckResult result;
#if defined(__APPLE__)
#if TARGET_OS_SIMULATOR
    result.signals.push_back(signal(SignalId::IOS_SIMULATOR, Severity::MEDIUM, 20.0,
                                    "ios-simulator", includeEvidence));
    return result;
#else
    if (expired(deadline)) {
      result.partial = true;
      result.signals.push_back(unavailable("ios.check.jailbreak"));
      return result;
    }

    constexpr const char* kJailbreakPaths[] = {
      "/private/jb",
      "/var/jb",
      "/Applications/Cydia.app",
      "/Library/MobileSubstrate/MobileSubstrate.dylib",
    };
    for (const char* path : kJailbreakPaths) {
      struct stat status {};
      if (::stat(path, &status) == 0) {
        result.signals.push_back(signal(SignalId::IOS_JAILBREAK_ARTIFACT, Severity::MEDIUM, 20.0,
                                        "known-jailbreak-artifact", includeEvidence));
        break;
      }
    }

    if (expired(deadline)) {
      result.partial = true;
      result.signals.push_back(unavailable("ios.check.dyld"));
      return result;
    }

    for (uint32_t index = 0; index < _dyld_image_count(); ++index) {
      const char* image = _dyld_get_image_name(index);
      if (image == nullptr) {
        continue;
      }
      const std::string path(image);
      if (path.find("MobileSubstrate") != std::string::npos || path.find("Substitute") != std::string::npos ||
          path.find("Frida") != std::string::npos || path.find("libhooker") != std::string::npos) {
        result.signals.push_back(signal(SignalId::IOS_DYLD_HOOK, Severity::HIGH, 30.0,
                                        "suspicious-loaded-image", includeEvidence));
        break;
      }
    }

    if (expired(deadline)) {
      result.partial = true;
      result.signals.push_back(unavailable("ios.check.debugger"));
      return result;
    }

    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    kinfo_proc process {};
    size_t size = sizeof(process);
    if (::sysctl(mib, 4, &process, &size, nullptr, 0) == 0 &&
        (process.kp_proc.p_flag & P_TRACED) != 0) {
      result.debuggerDetected = true;
      result.signals.push_back(signal(SignalId::IOS_DEBUGGER_SYSCTL, Severity::LOW, 0.0,
                                      "sysctl-traced", includeEvidence));
    }
#endif
#else
    (void) includeEvidence;
    (void) deadline;
#endif
    return result;
  }

} // namespace margelo::nitro::rootjaildetect
