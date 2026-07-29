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

    // Build a `DetectionSignal` from a signal id by looking up the catalog
    // weight/severity. This is the same path AndroidChecks uses so that
    // changes to the signal catalog (id renames, weight tuning) flow through
    // to iOS without duplicating the literal values here. If the id is not in
    // the catalog (which should never happen for ids produced by this file),
    // we emit a zero-weight placeholder so the result stays well-formed.
    DetectionSignal buildSignal(std::string_view id, const std::string& evidence,
                                bool includeEvidence) noexcept {
      std::optional<SignalSpec> spec = lookupSignal(id);
      if (!spec.has_value()) {
        return DetectionSignal(
          std::string(id),
          Severity::LOW,
          0.0,
          includeEvidence ? std::optional<std::string>(evidence) : std::nullopt,
          std::nullopt
        );
      }
      return DetectionSignal(
        std::string(spec->id),
        spec->severity,
        spec->score,
        includeEvidence ? std::optional<std::string>(evidence) : std::nullopt,
        std::nullopt
      );
    }

    DetectionSignal unavailableSignal(std::string_view id) noexcept {
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
    result.signals.push_back(buildSignal(SignalId::IOS_SIMULATOR, "ios-simulator", includeEvidence));
    return result;
#else
    if (expired(deadline)) {
      result.partial = true;
      result.signals.push_back(unavailableSignal(SignalId::IOS_CHECK_JAILBREAK));
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
        result.signals.push_back(
          buildSignal(SignalId::IOS_JAILBREAK_ARTIFACT, "known-jailbreak-artifact", includeEvidence)
        );
        break;
      }
    }

    if (expired(deadline)) {
      result.partial = true;
      result.signals.push_back(unavailableSignal(SignalId::IOS_CHECK_DYLD));
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
        result.signals.push_back(
          buildSignal(SignalId::IOS_DYLD_HOOK, "suspicious-loaded-image", includeEvidence)
        );
        break;
      }
    }

    if (expired(deadline)) {
      result.partial = true;
      result.signals.push_back(unavailableSignal(SignalId::IOS_CHECK_DEBUGGER));
      return result;
    }

    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    kinfo_proc process {};
    size_t size = sizeof(process);
    if (::sysctl(mib, 4, &process, &size, nullptr, 0) == 0 &&
        (process.kp_proc.p_flag & P_TRACED) != 0) {
      result.debuggerDetected = true;
      result.signals.push_back(buildSignal(SignalId::IOS_DEBUGGER_SYSCTL, "sysctl-traced", includeEvidence));
    }
#endif
#else
    (void) includeEvidence;
    (void) deadline;
#endif
    return result;
  }

} // namespace margelo::nitro::rootjaildetect
